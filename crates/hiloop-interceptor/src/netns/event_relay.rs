//! Private event relay between namespace-scoped capture processes and the host exporter.

use std::{io, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use hiloop_core::{
    capture::{CaptureCompletionReport, L7_CAPTURE},
    event::{AttributeKey, AttributeValue, Event, SignalType},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use crate::{
    proxy::PROXY_SOURCE,
    seams::{ExportError, Exporter, provenance_keys},
};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 16;
const AUTH_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize, Deserialize)]
enum RelayRequest {
    Authenticate(String),
    Export(Vec<Event>),
    Completion(Box<RelayCompletion>),
    Flush,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayCompletion {
    report: CaptureCompletionReport,
    event: Event,
}

#[derive(Debug, Serialize, Deserialize)]
enum RelayResponse {
    Ok,
    Error(String),
}

/// Namespace-side exporter that sends normalized event batches to the host process.
#[derive(Debug)]
pub(super) struct EventRelayExporter {
    stream: Mutex<UnixStream>,
    can_complete: bool,
}

impl EventRelayExporter {
    pub(super) async fn connect_gateway(path: &Path, token: String) -> io::Result<Self> {
        Self::connect(path, token, false).await
    }

    pub(super) async fn connect_for_workload(path: &Path, token: String) -> io::Result<Self> {
        Self::connect(path, token, true).await
    }

    async fn connect(path: &Path, token: String, can_complete: bool) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path).await?;
        authenticate(&mut stream, token).await?;
        Ok(Self {
            stream: Mutex::new(stream),
            can_complete,
        })
    }

    async fn request(&self, request: &RelayRequest) -> Result<(), ExportError> {
        let mut stream = self.stream.lock().await;
        request_on(&mut stream, request).await
    }
}

async fn request_on(stream: &mut UnixStream, request: &RelayRequest) -> Result<(), ExportError> {
    write_frame(&mut *stream, request)
        .await
        .map_err(relay_export_error)?;
    match read_frame(&mut *stream).await.map_err(relay_export_error)? {
        RelayResponse::Ok => Ok(()),
        RelayResponse::Error(message) => Err(ExportError::other("netns-event-relay", message)),
    }
}

async fn authenticate(stream: &mut UnixStream, token: String) -> io::Result<()> {
    write_frame(&mut *stream, &RelayRequest::Authenticate(token)).await?;
    match read_frame(&mut *stream).await? {
        RelayResponse::Ok => Ok(()),
        RelayResponse::Error(message) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
        }
    }
}

#[async_trait]
impl Exporter for EventRelayExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        let mut stream = self.stream.lock().await;
        let empty_frame_bytes = serde_json::to_vec(&RelayRequest::Export(Vec::new()))
            .map_err(|error| relay_export_error(invalid_data(error)))?
            .len();
        let mut batch = Vec::new();
        let mut frame_bytes = empty_frame_bytes;
        for event in events {
            let event_bytes = serde_json::to_vec(event)
                .map_err(|error| relay_export_error(invalid_data(error)))?
                .len();
            let separator = usize::from(!batch.is_empty());
            if !batch.is_empty()
                && frame_bytes
                    .saturating_add(separator)
                    .saturating_add(event_bytes)
                    > MAX_FRAME_BYTES
            {
                request_on(
                    &mut stream,
                    &RelayRequest::Export(std::mem::take(&mut batch)),
                )
                .await?;
                frame_bytes = empty_frame_bytes;
            }
            frame_bytes = frame_bytes
                .saturating_add(usize::from(!batch.is_empty()))
                .saturating_add(event_bytes);
            batch.push(event.clone());
        }
        if !batch.is_empty() {
            request_on(&mut stream, &RelayRequest::Export(batch)).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.request(&RelayRequest::Flush).await
    }

    async fn export_completion(
        &self,
        event: &Event,
        report: &CaptureCompletionReport,
    ) -> Result<(), ExportError> {
        if !self.can_complete {
            return Err(ExportError::rejected(
                "netns-event-relay",
                "this relay connection cannot publish capture completion",
            ));
        }
        self.request(&RelayRequest::Completion(Box::new(RelayCompletion {
            report: report.clone(),
            event: event.clone(),
        })))
        .await
    }
}

/// Host-side relay listener that serializes namespace event delivery through one exporter.
pub(super) struct EventRelayServer {
    listener: UnixListener,
    exporter: Arc<dyn Exporter>,
    capture: RelayCaptureReport,
    gateway_token: String,
    workload_token: String,
    connections: Arc<Semaphore>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct NetworkObservations {
    pub(super) full: u64,
    pub(super) metadata_only: u64,
}

#[derive(Debug, Default)]
struct RelayCaptureState {
    network: NetworkObservations,
    relayed_events: u64,
    completion: Option<(CaptureCompletionReport, Event)>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RelayCaptureReport {
    state: Arc<Mutex<RelayCaptureState>>,
}

impl RelayCaptureReport {
    pub(super) async fn network(&self) -> NetworkObservations {
        self.state.lock().await.network
    }

    pub(super) async fn take_completion(&self) -> Option<(CaptureCompletionReport, Event)> {
        self.state.lock().await.completion.take()
    }

    pub(super) async fn relayed_events(&self) -> u64 {
        self.state.lock().await.relayed_events
    }
}

impl std::fmt::Debug for EventRelayServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventRelayServer")
            .finish_non_exhaustive()
    }
}

impl EventRelayServer {
    pub(super) fn bind(
        path: &Path,
        exporter: Arc<dyn Exporter>,
        gateway_token: String,
        workload_token: String,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(path)?,
            exporter,
            capture: RelayCaptureReport::default(),
            gateway_token,
            workload_token,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    pub(super) fn capture_report(&self) -> RelayCaptureReport {
        self.capture.clone()
    }

    pub(super) async fn serve(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        continue;
                    };
                    let exporter = Arc::clone(&self.exporter);
                    let capture = self.capture.clone();
                    let gateway_token = self.gateway_token.clone();
                    let workload_token = self.workload_token.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        serve_connection(
                            stream,
                            exporter,
                            capture,
                            gateway_token,
                            workload_token,
                        )
                        .await
                    });
                }
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    match joined {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => eprintln!(
                            "hiloop-interceptor: warning: rejected a private event-relay connection: {error}"
                        ),
                        Err(error) => eprintln!(
                            "hiloop-interceptor: warning: private event-relay connection task failed: {error}"
                        ),
                    }
                }
            }
        }
        connections.shutdown().await;
        Ok(())
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    exporter: Arc<dyn Exporter>,
    capture: RelayCaptureReport,
    gateway_token: String,
    workload_token: String,
) -> io::Result<()> {
    let request = tokio::time::timeout(AUTH_TIMEOUT, read_frame(&mut stream))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "event-relay authentication timed out",
            )
        })??;
    let role = match request {
        RelayRequest::Authenticate(token) if token == workload_token => RelayRole::Workload,
        RelayRequest::Authenticate(token) if token == gateway_token => RelayRole::Gateway,
        RelayRequest::Authenticate(_) => {
            write_frame(
                &mut stream,
                &RelayResponse::Error("event-relay authentication failed".to_owned()),
            )
            .await?;
            return Ok(());
        }
        _ => {
            write_frame(
                &mut stream,
                &RelayResponse::Error("event-relay authentication is required".to_owned()),
            )
            .await?;
            return Ok(());
        }
    };
    write_frame(&mut stream, &RelayResponse::Ok).await?;
    loop {
        let request = match read_frame(&mut stream).await {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let result = match request {
            RelayRequest::Authenticate(_) => Err(ExportError::rejected(
                "netns-event-relay",
                "event-relay connection is already authenticated",
            )),
            RelayRequest::Export(events) => {
                record_network_observations(&capture, &events).await;
                exporter.export(&events).await
            }
            RelayRequest::Completion(completion) => {
                if role == RelayRole::Workload {
                    let RelayCompletion { report, event } = *completion;
                    let mut state = capture.state.lock().await;
                    if state.completion.is_some() {
                        Err(ExportError::rejected(
                            "netns-event-relay",
                            "capture completion was already reported",
                        ))
                    } else {
                        state.completion = Some((report, event));
                        Ok(())
                    }
                } else {
                    Err(ExportError::rejected(
                        "netns-event-relay",
                        "connection is not authorized to publish capture completion",
                    ))
                }
            }
            RelayRequest::Flush => exporter.flush().await,
        };
        let response = match result {
            Ok(()) => RelayResponse::Ok,
            Err(error) => RelayResponse::Error(error.to_string()),
        };
        write_frame(&mut stream, &response).await?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayRole {
    Gateway,
    Workload,
}

async fn record_network_observations(capture: &RelayCaptureReport, events: &[Event]) {
    let raw_source = AttributeKey::from_static(provenance_keys::RAW_SOURCE);
    let l7_capture = AttributeKey::from_static(L7_CAPTURE);
    let mut state = capture.state.lock().await;
    state.relayed_events = state.relayed_events.saturating_add(events.len() as u64);
    for event in events {
        let proxy_source = matches!(
            event.attributes.get(&raw_source),
            Some(AttributeValue::String(source)) if source == PROXY_SOURCE
        );
        if !proxy_source && event.signal != SignalType::Net {
            continue;
        }
        if matches!(
            event.attributes.get(&l7_capture),
            Some(AttributeValue::Bool(false))
        ) {
            state.network.metadata_only += 1;
        } else {
            state.network.full += 1;
        }
    }
}

async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netns event-relay frame exceeds 4 MiB",
        ));
    }
    let length = u32::try_from(payload.len()).map_err(invalid_data)?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

async fn read_frame<T: DeserializeOwned>(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<T> {
    let length = reader.read_u32().await?;
    let length = usize::try_from(length).map_err(invalid_data)?;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netns event-relay frame exceeds 4 MiB",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(invalid_data)
}

fn relay_export_error(error: io::Error) -> ExportError {
    ExportError::with_source("netns-event-relay", "private event relay failed", error)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use hiloop_core::{
        capture::{
            CaptureCompletionReport, CaptureEventDelivery, CaptureEvidenceTrust,
            CaptureSourceReport, CaptureSourcesReport,
        },
        event::{AttributeKey, EventName, SignalType},
        identity::{Hlc, RunContext},
    };

    use super::*;
    use crate::seams::testing::MemoryExporter;

    #[tokio::test]
    async fn relays_event_batches_and_flushes_over_the_private_socket() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(
            &path,
            memory.clone(),
            "gateway-token".to_owned(),
            "workload-token".to_owned(),
        )
        .expect("bind relay");
        let capture = server.capture_report();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let relay = EventRelayExporter::connect_for_workload(&path, "workload-token".to_owned())
            .await
            .expect("connect relay");
        let event = Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Net,
            EventName::from_static("fixture.event"),
        )
        .with_attribute(AttributeKey::from_static("l7_capture"), false);

        relay
            .export(std::slice::from_ref(&event))
            .await
            .expect("export");
        relay.flush().await.expect("flush");
        let completion = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery::default(),
            None,
            None,
            None,
        )
        .expect("valid completion");
        let completion_event = completion.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 2,
                logical: 0,
            },
        );
        relay
            .export_completion(&completion_event, &completion)
            .await
            .expect("completion");
        let events = memory.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name.as_str(), event.name.as_str());
        assert_eq!(capture.relayed_events().await, 1);
        assert_eq!(
            capture.network().await,
            NetworkObservations {
                full: 0,
                metadata_only: 1,
            }
        );
        let (relayed_completion, relayed_event) =
            capture.take_completion().await.expect("typed completion");
        assert_eq!(relayed_completion, completion);
        assert_eq!(
            serde_json::to_value(relayed_event).expect("relayed event json"),
            serde_json::to_value(completion_event).expect("completion event json")
        );

        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }

    #[tokio::test]
    async fn rejects_forged_completion_and_isolates_malformed_connections() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(
            &path,
            memory,
            "gateway-token".to_owned(),
            "workload-token".to_owned(),
        )
        .expect("bind relay");
        let capture = server.capture_report();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let completion = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery::default(),
            None,
            None,
            None,
        )
        .expect("valid completion");
        let event = completion.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
        );

        let error = EventRelayExporter::connect_for_workload(&path, "wrong-token".to_owned())
            .await
            .expect_err("forged connection is rejected");
        assert!(error.to_string().contains("authentication failed"));
        assert!(capture.take_completion().await.is_none());

        let mut malformed = UnixStream::connect(&path).await.expect("malformed client");
        malformed
            .write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("malformed frame");
        malformed.shutdown().await.expect("close malformed client");

        let trusted = EventRelayExporter::connect_for_workload(&path, "workload-token".to_owned())
            .await
            .expect("trusted client");
        trusted
            .export_completion(&event, &completion)
            .await
            .expect("trusted completion");
        assert_eq!(
            capture
                .take_completion()
                .await
                .expect("trusted completion")
                .0,
            completion
        );

        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }

    #[tokio::test]
    async fn splits_an_export_batch_before_the_bounded_frame_limit() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(
            &path,
            memory.clone(),
            "gateway-token".to_owned(),
            "workload-token".to_owned(),
        )
        .expect("bind relay");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let relay = EventRelayExporter::connect_gateway(&path, "gateway-token".to_owned())
            .await
            .expect("connect relay");
        let event = Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Log,
            EventName::from_static("fixture.large"),
        )
        .with_attribute(
            AttributeKey::from_static("fixture.body"),
            "x".repeat(64 * 1024),
        );

        relay
            .export(&vec![event; 80])
            .await
            .expect("chunked export");
        assert_eq!(memory.events().len(), 80);

        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }
}
