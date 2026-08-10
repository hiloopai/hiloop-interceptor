//! Private event relay between namespace-scoped capture processes and the host exporter.

use std::{io, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use hiloop_core::event::Event;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    task::JoinSet,
};

use crate::seams::{ExportError, Exporter};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
enum RelayRequest {
    Export(Vec<Event>),
    Flush,
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
}

impl EventRelayExporter {
    pub(super) async fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self {
            stream: Mutex::new(UnixStream::connect(path).await?),
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
}

/// Host-side relay listener that serializes namespace event delivery through one exporter.
pub(super) struct EventRelayServer {
    listener: UnixListener,
    exporter: Arc<dyn Exporter>,
}

impl std::fmt::Debug for EventRelayServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventRelayServer")
            .finish_non_exhaustive()
    }
}

impl EventRelayServer {
    pub(super) fn bind(path: &Path, exporter: Arc<dyn Exporter>) -> io::Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(path)?,
            exporter,
        })
    }

    pub(super) async fn serve(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        self.serve_with_drain_timeout(shutdown, RELAY_DRAIN_TIMEOUT)
            .await
    }

    async fn serve_with_drain_timeout(
        self,
        shutdown: impl Future<Output = ()>,
        drain_timeout: Duration,
    ) -> io::Result<()> {
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        let mut first_error = None;
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let exporter = Arc::clone(&self.exporter);
                    connections.spawn(async move { serve_connection(stream, exporter).await });
                }
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    record_connection_error(&mut first_error, joined);
                }
            }
        }
        let listener = self.listener.into_std()?;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    let stream = UnixStream::from_std(stream)?;
                    let exporter = Arc::clone(&self.exporter);
                    connections.spawn(async move { serve_connection(stream, exporter).await });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        drop(listener);
        let drain = async {
            while let Some(joined) = connections.join_next().await {
                record_connection_error(&mut first_error, joined);
            }
        };
        if tokio::time::timeout(drain_timeout, drain).await.is_err() {
            connections.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "event relay drain timed out after {}s",
                    drain_timeout.as_secs_f64()
                ),
            ));
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn record_connection_error(
    first_error: &mut Option<io::Error>,
    joined: Result<io::Result<()>, tokio::task::JoinError>,
) {
    if first_error.is_some() {
        return;
    }
    if let Err(error) = joined.map_err(io::Error::other).and_then(|result| result) {
        *first_error = Some(error);
    }
}

async fn serve_connection(mut stream: UnixStream, exporter: Arc<dyn Exporter>) -> io::Result<()> {
    loop {
        let request = match read_frame(&mut stream).await {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let result = match request {
            RelayRequest::Export(events) => exporter.export(&events).await,
            RelayRequest::Flush => exporter.flush().await,
        };
        let response = match result {
            Ok(()) => RelayResponse::Ok,
            Err(error) => RelayResponse::Error(error.to_string()),
        };
        write_frame(&mut stream, &response).await?;
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
    use tokio::sync::{Notify, oneshot};

    use hiloop_core::{
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
        let server = EventRelayServer::bind(&path, memory.clone()).expect("bind relay");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let relay = EventRelayExporter::connect(&path)
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
        );

        relay
            .export(std::slice::from_ref(&event))
            .await
            .expect("export");
        relay.flush().await.expect("flush");
        let events = memory.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name.as_str(), event.name.as_str());

        drop(relay);
        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }

    #[tokio::test]
    async fn splits_an_export_batch_before_the_bounded_frame_limit() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(&path, memory.clone()).expect("bind relay");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let relay = EventRelayExporter::connect(&path)
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

        drop(relay);
        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }

    #[derive(Debug)]
    struct BlockingExporter {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Notify,
    }

    #[async_trait]
    impl Exporter for BlockingExporter {
        async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
            if let Some(started) = self.started.lock().await.take() {
                let _ = started.send(());
            }
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn shutdown_drains_an_in_flight_export_before_returning() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let (started_tx, started_rx) = oneshot::channel();
        let exporter = Arc::new(BlockingExporter {
            started: Mutex::new(Some(started_tx)),
            release: Notify::new(),
        });
        let server = EventRelayServer::bind(&path, exporter.clone()).expect("bind relay");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = shutdown_rx.await;
        }));
        let relay = Arc::new(
            EventRelayExporter::connect(&path)
                .await
                .expect("connect relay"),
        );
        let event = Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Net,
            EventName::from_static("fixture.tail"),
        );
        let export = {
            let relay = Arc::clone(&relay);
            tokio::spawn(async move { relay.export(&[event]).await })
        };
        started_rx.await.expect("export reached host exporter");

        shutdown_tx.send(()).expect("send shutdown");
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "shutdown must not abort the export");

        exporter.release.notify_one();
        export
            .await
            .expect("export task")
            .expect("in-flight export completes");
        drop(relay);
        task.await.expect("relay task").expect("relay server");
    }

    #[tokio::test]
    async fn shutdown_drains_connections_already_waiting_to_be_accepted() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(&path, memory.clone()).expect("bind relay");
        let relay = Arc::new(
            EventRelayExporter::connect(&path)
                .await
                .expect("connect relay"),
        );
        let event = Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Net,
            EventName::from_static("fixture.queued"),
        );
        let export = {
            let relay = Arc::clone(&relay);
            tokio::spawn(async move { relay.export(&[event]).await })
        };

        let task = tokio::spawn(server.serve(std::future::ready(())));
        export
            .await
            .expect("export task")
            .expect("queued export completes");
        drop(relay);
        task.await.expect("relay task").expect("relay server");
        assert_eq!(memory.events().len(), 1);
    }

    #[tokio::test]
    async fn shutdown_reports_a_peer_that_never_closes() {
        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("events.sock");
        let memory = Arc::new(MemoryExporter::default());
        let server = EventRelayServer::bind(&path, memory).expect("bind relay");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_with_drain_timeout(
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_millis(20),
        ));
        let relay = EventRelayExporter::connect(&path)
            .await
            .expect("connect relay");

        shutdown_tx.send(()).expect("send shutdown");
        let error = task
            .await
            .expect("relay task")
            .expect_err("open peer prevents a complete drain");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(relay);
    }
}
