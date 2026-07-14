//! Honest opaque TCP byte forwarding and typed capture-loss events.

use std::{
    error::Error as StdError,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use hiloop_core::{
    capture::{
        ByteCounts, CaptureContractError, NetPassthroughReason, OriginalDestination,
        TlsFlowIdentity, TlsPassthroughReason, TransportProtocol,
    },
    event::Event,
    identity::{Hlc, RunContext},
};
use rustls::{AlertDescription, Error as RustlsError};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
};

use super::{HandshakeFailure, HandshakeFailureDecision, TrustAlert};

/// Raw splice or required-event delivery failure.
#[derive(Debug, thiserror::Error)]
pub enum TlsTransportError {
    /// Byte counters exceeded the Event-v1 integer contract.
    #[error(transparent)]
    CaptureContract(#[from] CaptureContractError),
    /// The raw transport failed after some bytes may have crossed.
    #[error("raw TCP splice failed: {0}")]
    Copy(#[source] io::Error),
    /// The typed capture-loss event could not enter its bounded queue.
    #[error("capture event queue closed during raw TCP splice")]
    EventChannelClosed,
    /// Both transport and required event delivery failed.
    #[error("raw TCP splice failed and its capture event queue was closed: {0}")]
    CopyAndEventChannelClosed(#[source] io::Error),
}

/// Copy an admitted TLS flow byte-for-byte and emit exactly one W1 passthrough event.
pub async fn raw_tls_splice<C, U>(
    client: C,
    upstream: U,
    context: &RunContext,
    started_at: Hlc,
    reason: TlsPassthroughReason,
    flow: &TlsFlowIdentity,
    event_tx: &mpsc::Sender<Event>,
) -> Result<ByteCounts, TlsTransportError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let copied = copy_bidirectional_counted(client, upstream).await;
    let counts = ByteCounts::new(copied.upstream, copied.downstream)?;
    let event = Event::tls_passthrough(context, started_at, reason, flow, counts);
    finish_splice(copied.result, event_tx.send(event).await, counts)
}

/// Copy an admitted non-HTTP TCP flow and emit its W1 metadata-only event.
pub async fn raw_tcp_splice<C, U>(
    client: C,
    upstream: U,
    context: &RunContext,
    started_at: Hlc,
    destination: OriginalDestination,
    event_tx: &mpsc::Sender<Event>,
) -> Result<ByteCounts, TlsTransportError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let copied = copy_bidirectional_counted(client, upstream).await;
    let counts = ByteCounts::new(copied.upstream, copied.downstream)?;
    let event = Event::net_passthrough(
        context,
        started_at,
        TransportProtocol::Tcp,
        destination,
        NetPassthroughReason::UnsupportedApplicationProtocol,
        counts,
    );
    finish_splice(copied.result, event_tx.send(event).await, counts)
}

/// Emit the exact W1 failure event produced by a policy-engine handshake decision.
pub async fn emit_interception_failure(
    event_tx: &mpsc::Sender<Event>,
    context: &RunContext,
    timestamp: Hlc,
    flow: &TlsFlowIdentity,
    decision: HandshakeFailureDecision,
    secret_bound: bool,
) -> Result<(), TlsTransportError> {
    event_tx
        .send(Event::tls_interception_failed(
            context,
            timestamp,
            decision.reason(),
            flow,
            decision.retry_required(),
            secret_bound,
        ))
        .await
        .map_err(|_| TlsTransportError::EventChannelClosed)
}

/// Map a structured rustls client-handshake error into the closed learning taxonomy.
pub fn classify_client_handshake_error(error: &io::Error) -> HandshakeFailure {
    if let Some(rustls) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RustlsError>())
    {
        return classify_rustls_error(rustls);
    }
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(rustls) = current.downcast_ref::<RustlsError>() {
            return classify_rustls_error(rustls);
        }
        source = current.source();
    }

    match error.kind() {
        io::ErrorKind::UnexpectedEof => HandshakeFailure::Eof,
        io::ErrorKind::TimedOut => HandshakeFailure::Timeout,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => HandshakeFailure::Reset,
        io::ErrorKind::InvalidData => HandshakeFailure::ProtocolMismatch,
        _ => HandshakeFailure::Internal,
    }
}

fn classify_rustls_error(error: &RustlsError) -> HandshakeFailure {
    match error {
        RustlsError::AlertReceived(AlertDescription::UnknownCA) => {
            HandshakeFailure::ClientTrustAlert(TrustAlert::UnknownCa)
        }
        RustlsError::AlertReceived(AlertDescription::BadCertificate) => {
            HandshakeFailure::ClientTrustAlert(TrustAlert::BadCertificate)
        }
        RustlsError::AlertReceived(AlertDescription::CertificateUnknown) => {
            HandshakeFailure::ClientTrustAlert(TrustAlert::CertificateUnknown)
        }
        _ => HandshakeFailure::ProtocolMismatch,
    }
}

fn finish_splice(
    copy: io::Result<()>,
    event: Result<(), mpsc::error::SendError<Event>>,
    counts: ByteCounts,
) -> Result<ByteCounts, TlsTransportError> {
    match (copy, event) {
        (Ok(()), Ok(())) => Ok(counts),
        (Err(error), Ok(())) => Err(TlsTransportError::Copy(error)),
        (Ok(()), Err(_)) => Err(TlsTransportError::EventChannelClosed),
        (Err(error), Err(_)) => Err(TlsTransportError::CopyAndEventChannelClosed(error)),
    }
}

struct CountedCopy {
    upstream: u64,
    downstream: u64,
    result: io::Result<()>,
}

async fn copy_bidirectional_counted<C, U>(client: C, upstream: U) -> CountedCopy
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, client_write) = tokio::io::split(client);
    let (mut upstream_read, upstream_write) = tokio::io::split(upstream);
    let upstream_count = Arc::new(AtomicU64::new(0));
    let downstream_count = Arc::new(AtomicU64::new(0));
    let mut upstream_write = CountingWriter::new(upstream_write, Arc::clone(&upstream_count));
    let mut client_write = CountingWriter::new(client_write, Arc::clone(&downstream_count));

    let to_upstream = async {
        tokio::io::copy(&mut client_read, &mut upstream_write).await?;
        upstream_write.shutdown().await
    };
    let to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    let result = tokio::try_join!(to_upstream, to_client).map(|_| ());

    CountedCopy {
        upstream: upstream_count.load(Ordering::Relaxed),
        downstream: downstream_count.load(Ordering::Relaxed),
        result,
    }
}

struct CountingWriter<W> {
    inner: W,
    count: Arc<AtomicU64>,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, count: Arc<AtomicU64>) -> Self {
        Self { inner, count }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(written)) = result {
            self.count.fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use hiloop_core::{
        capture::{
            OriginalDestination, TlsFlowIdentity, TlsInterceptionFailedReason, TlsPassthroughReason,
        },
        identity::{Hlc, RunContext},
    };
    use rustls::{AlertDescription, Error as RustlsError};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::mpsc,
    };

    use super::*;
    use crate::netns::{HandshakeFailure, HandshakeFailureDecision, TrustAlert};

    #[tokio::test]
    async fn modal_like_first_connection_splices_and_emits_exact_event() {
        let (gateway_client, mut child) = tokio::io::duplex(256);
        let (gateway_upstream, mut origin) = tokio::io::duplex(256);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let context = RunContext::new_local_root();
        let flow = tls_flow("api.modal.com", 443, "ch1:modal");

        let splice = tokio::spawn(async move {
            raw_tls_splice(
                gateway_client,
                gateway_upstream,
                &context,
                timestamp(),
                TlsPassthroughReason::PreclassifiedTrustIncompatible,
                &flow,
                &event_tx,
            )
            .await
        });
        let origin_task = tokio::spawn(async move {
            let mut request = Vec::new();
            origin
                .read_to_end(&mut request)
                .await
                .expect("origin request");
            assert_eq!(request, b"client hello and encrypted request");
            origin
                .write_all(b"server hello and encrypted response")
                .await
                .expect("origin response");
            origin.shutdown().await.expect("origin shutdown");
        });

        child
            .write_all(b"client hello and encrypted request")
            .await
            .expect("child request");
        child.shutdown().await.expect("child write shutdown");
        let mut response = Vec::new();
        child
            .read_to_end(&mut response)
            .await
            .expect("child response");
        assert_eq!(response, b"server hello and encrypted response");
        origin_task.await.expect("origin task");
        let counts = splice.await.expect("splice task").expect("raw splice");
        assert_eq!(counts.upstream(), 34);
        assert_eq!(counts.downstream(), 35);

        let event = event_rx.recv().await.expect("tls.passthrough event");
        let value = serde_json::to_value(event).expect("serialize event");
        assert_eq!(value["name"], json!("tls.passthrough"));
        assert_eq!(
            value["attributes"],
            json!({
                "client_hello_fingerprint": "ch1:modal",
                "downstream_bytes": 35,
                "l7_capture": false,
                "original_destination.ip": "203.0.113.10",
                "original_destination.port": 443,
                "reason": "preclassified_trust_incompatible",
                "server_name": "api.modal.com",
                "upstream_bytes": 34,
            })
        );
        assert!(
            value["payload_ref"].is_null(),
            "raw TLS has no false L7 body"
        );
    }

    #[tokio::test]
    async fn opaque_tcp_splice_emits_net_passthrough() {
        let (gateway_client, mut child) = tokio::io::duplex(64);
        let (gateway_upstream, mut origin) = tokio::io::duplex(64);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let context = RunContext::new_local_root();
        let destination = destination(22);

        let splice = tokio::spawn(async move {
            raw_tcp_splice(
                gateway_client,
                gateway_upstream,
                &context,
                timestamp(),
                destination,
                &event_tx,
            )
            .await
        });
        child.write_all(b"ssh").await.expect("child bytes");
        child.shutdown().await.expect("child shutdown");
        let mut bytes = Vec::new();
        origin.read_to_end(&mut bytes).await.expect("origin bytes");
        assert_eq!(bytes, b"ssh");
        origin.shutdown().await.expect("origin shutdown");
        splice.await.expect("splice task").expect("raw splice");

        let value = serde_json::to_value(event_rx.recv().await.expect("net event"))
            .expect("serialize event");
        assert_eq!(value["name"], json!("net.passthrough"));
        assert_eq!(value["attributes"]["transport"], json!("tcp"));
        assert_eq!(
            value["attributes"]["reason"],
            json!("unsupported_application_protocol")
        );
        assert_eq!(value["attributes"]["l7_capture"], json!(false));
    }

    #[tokio::test]
    async fn interception_failure_is_emitted_with_retry_contract() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let context = RunContext::new_local_root();
        let decision = HandshakeFailureDecision::Failed {
            reason: TlsInterceptionFailedReason::ClientTrustRejected,
            retry_required: true,
            fatal: None,
        };
        emit_interception_failure(
            &event_tx,
            &context,
            timestamp(),
            &tls_flow("new.example.com", 443, "ch1:new"),
            decision,
            false,
        )
        .await
        .expect("emit failure");

        let value = serde_json::to_value(event_rx.recv().await.expect("failure event"))
            .expect("serialize event");
        assert_eq!(value["name"], json!("tls.interception_failed"));
        assert_eq!(value["attributes"]["retry_required"], json!(true));
        assert_eq!(
            value["attributes"]["reason"],
            json!("client_trust_rejected")
        );
        assert!(value["payload_ref"].is_null());
    }

    #[test]
    fn only_explicit_trust_alerts_are_definitive() {
        for (alert, expected) in [
            (AlertDescription::UnknownCA, TrustAlert::UnknownCa),
            (AlertDescription::BadCertificate, TrustAlert::BadCertificate),
            (
                AlertDescription::CertificateUnknown,
                TrustAlert::CertificateUnknown,
            ),
        ] {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                RustlsError::AlertReceived(alert),
            );
            assert_eq!(
                classify_client_handshake_error(&error),
                HandshakeFailure::ClientTrustAlert(expected)
            );
        }

        for (kind, expected) in [
            (io::ErrorKind::UnexpectedEof, HandshakeFailure::Eof),
            (io::ErrorKind::TimedOut, HandshakeFailure::Timeout),
            (io::ErrorKind::ConnectionReset, HandshakeFailure::Reset),
        ] {
            assert_eq!(
                classify_client_handshake_error(&io::Error::from(kind)),
                expected
            );
        }
        let non_trust_alert = io::Error::new(
            io::ErrorKind::InvalidData,
            RustlsError::AlertReceived(AlertDescription::ProtocolVersion),
        );
        assert_eq!(
            classify_client_handshake_error(&non_trust_alert),
            HandshakeFailure::ProtocolMismatch
        );
    }

    fn timestamp() -> Hlc {
        Hlc {
            wall_ns: 1,
            logical: 0,
        }
    }

    fn destination(port: u16) -> OriginalDestination {
        OriginalDestination::new("203.0.113.10".parse().expect("test IP"), port)
            .expect("test destination")
    }

    fn tls_flow(host: &str, port: u16, fingerprint: &str) -> TlsFlowIdentity {
        TlsFlowIdentity::new(destination(port))
            .with_server_name(host)
            .expect("server name")
            .with_client_hello_fingerprint(fingerprint)
            .expect("fingerprint")
    }
}
