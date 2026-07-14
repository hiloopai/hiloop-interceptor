//! Private event relay between namespace-scoped capture processes and the host exporter.

#[cfg(test)]
use std::sync::Arc;
use std::{io, path::Path};

use async_trait::async_trait;
use hiloop_core::event::Event;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::UnixStream,
    sync::Mutex,
};
#[cfg(test)]
use tokio::{net::UnixListener, task::JoinSet};

use crate::seams::{ExportError, Exporter};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

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
        write_frame(&mut *stream, request)
            .await
            .map_err(relay_export_error)?;
        match read_frame(&mut *stream).await.map_err(relay_export_error)? {
            RelayResponse::Ok => Ok(()),
            RelayResponse::Error(message) => Err(ExportError::other("netns-event-relay", message)),
        }
    }
}

#[async_trait]
impl Exporter for EventRelayExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        self.request(&RelayRequest::Export(events.to_vec())).await
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.request(&RelayRequest::Flush).await
    }
}

/// Host-side relay listener that serializes namespace event delivery through one exporter.
#[cfg(test)]
pub(super) struct EventRelayServer {
    listener: UnixListener,
    exporter: Arc<dyn Exporter>,
}

#[cfg(test)]
impl std::fmt::Debug for EventRelayServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventRelayServer")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl EventRelayServer {
    pub(super) fn bind(path: &Path, exporter: Arc<dyn Exporter>) -> io::Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(path)?,
            exporter,
        })
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
                    let exporter = Arc::clone(&self.exporter);
                    connections.spawn(async move { serve_connection(stream, exporter).await });
                }
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    joined.map_err(io::Error::other)??;
                }
            }
        }
        connections.shutdown().await;
        Ok(())
    }
}

#[cfg(test)]
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
    use hiloop_core::{
        event::{EventName, SignalType},
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

        shutdown_tx.send(()).expect("send shutdown");
        task.await.expect("relay task").expect("relay server");
    }
}
