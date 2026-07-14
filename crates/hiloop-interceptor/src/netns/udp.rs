use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use hiloop_core::{
    capture::{
        ByteCounts, CaptureContractError, CaptureFatalReason, NetPassthroughReason,
        OriginalDestination, TransportProtocol,
    },
    event::Event,
    identity::{Hlc, RunContext},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    time::{self, Instant},
};

use crate::egress::EgressPolicy;
use crate::netns::FatalReport;

/// Run-level handling for opaque non-DNS UDP, including QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpFlowDisposition {
    /// Raw-forward the flow and report that L7 content was not captured.
    Forward,
    /// Reject the flow because restrictive policy has no trustworthy application identity.
    DenyIdentityUnavailable,
    /// Close the relay and surface a strict-run fatal cause before forwarding.
    Fatal(CaptureFatalReason),
}

/// Select the only permitted non-DNS UDP behavior for a run.
pub fn udp_flow_disposition(has_secret_binding: bool, policy: &EgressPolicy) -> UdpFlowDisposition {
    if has_secret_binding {
        UdpFlowDisposition::Fatal(CaptureFatalReason::SecretTransportUnsupported)
    } else if policy.is_allow_all() {
        UdpFlowDisposition::Forward
    } else {
        UdpFlowDisposition::DenyIdentityUnavailable
    }
}

/// Stable identity for one client-to-origin UDP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    client: SocketAddr,
    destination: SocketAddr,
}

impl UdpFlowKey {
    /// Create a flow whose client and destination use the same address family.
    pub fn new(client: SocketAddr, destination: SocketAddr) -> Result<Self, UdpRelayError> {
        if client.is_ipv4() != destination.is_ipv4() {
            return Err(UdpRelayError::AddressFamilyMismatch {
                client,
                destination,
            });
        }
        if destination.port() == 0 {
            return Err(UdpRelayError::DestinationPortZero);
        }
        Ok(Self {
            client,
            destination,
        })
    }

    /// Workload-side source address for this flow.
    pub fn client(self) -> SocketAddr {
        self.client
    }

    /// Authoritative original destination recovered by transparent ingress.
    pub fn destination(self) -> SocketAddr {
        self.destination
    }
}

/// One response that must be returned to the workload with the flow's original source identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpChildDatagram {
    key: UdpFlowKey,
    payload: Vec<u8>,
}

impl UdpChildDatagram {
    /// Flow identity needed by the transparent downstream sender.
    pub fn key(&self) -> UdpFlowKey {
        self.key
    }

    /// Exact opaque response bytes received from the origin.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Downstream boundary implemented by transparent ingress and deterministic test sinks.
#[async_trait]
pub trait UdpChildSink: Send + Sync {
    /// Return one origin datagram to the workload under the original destination identity.
    async fn send(&self, datagram: UdpChildDatagram) -> io::Result<()>;

    /// Release downstream state when the flow emits its terminal summary.
    async fn close(&self, _key: UdpFlowKey) {}
}

/// Final accounting emitted exactly once when an admitted UDP flow closes or idles out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpFlowSummary {
    key: UdpFlowKey,
    upstream_bytes: u64,
    downstream_bytes: u64,
}

impl UdpFlowSummary {
    /// Flow represented by this terminal summary.
    pub fn key(self) -> UdpFlowKey {
        self.key
    }

    /// Bytes forwarded from the workload to the origin.
    pub fn upstream_bytes(self) -> u64 {
        self.upstream_bytes
    }

    /// Bytes forwarded from the origin to the workload.
    pub fn downstream_bytes(self) -> u64 {
        self.downstream_bytes
    }

    /// Build the W1 typed degradation event for this opaque flow.
    pub fn net_passthrough_event(
        self,
        context: &RunContext,
        timestamp: Hlc,
    ) -> Result<Event, CaptureContractError> {
        let destination =
            OriginalDestination::new(self.key.destination.ip(), self.key.destination.port())?;
        let counts = ByteCounts::new(self.upstream_bytes, self.downstream_bytes)?;
        Ok(Event::net_passthrough(
            context,
            timestamp,
            TransportProtocol::Udp,
            destination,
            NetPassthroughReason::UnsupportedTransportCapture,
            counts,
        ))
    }
}

/// A dual-stack raw UDP relay with one idle-bounded task and terminal summary per flow.
pub struct UdpFlowRelay {
    disposition: UdpFlowDisposition,
    idle_timeout: Duration,
    child_sink: Arc<dyn UdpChildSink>,
    summary_tx: mpsc::Sender<UdpFlowSummary>,
    flows: Arc<Mutex<HashMap<UdpFlowKey, mpsc::Sender<Vec<u8>>>>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for UdpFlowRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpFlowRelay")
            .field("disposition", &self.disposition)
            .field("idle_timeout", &self.idle_timeout)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl UdpFlowRelay {
    /// Construct a relay whose policy is fixed for the run before any flow begins.
    pub fn new(
        has_secret_binding: bool,
        policy: &EgressPolicy,
        idle_timeout: Duration,
        child_sink: Arc<dyn UdpChildSink>,
        summary_tx: mpsc::Sender<UdpFlowSummary>,
    ) -> Self {
        Self {
            disposition: udp_flow_disposition(has_secret_binding, policy),
            idle_timeout,
            child_sink,
            summary_tx,
            flows: Arc::new(Mutex::new(HashMap::new())),
            closed: AtomicBool::new(false),
        }
    }

    /// Forward one opaque datagram after applying the run-level policy matrix.
    ///
    /// Policy denial and binding fatality return before an upstream socket is created.
    pub async fn forward(&self, key: UdpFlowKey, payload: &[u8]) -> Result<(), UdpRelayError> {
        match self.disposition {
            UdpFlowDisposition::Forward => {}
            UdpFlowDisposition::DenyIdentityUnavailable => {
                return Err(UdpRelayError::Policy(
                    UdpFlowDisposition::DenyIdentityUnavailable,
                    key,
                ));
            }
            fatal @ UdpFlowDisposition::Fatal(_) => {
                self.close().await;
                return Err(UdpRelayError::Policy(fatal, key));
            }
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(UdpRelayError::Closed);
        }

        let sender = self.flow_sender(key).await?;
        match sender.send(payload.to_vec()).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.flows.lock().await.remove(&key);
                let sender = self.flow_sender(key).await?;
                sender
                    .send(error.0)
                    .await
                    .map_err(|_| UdpRelayError::Closed)
            }
        }
    }

    /// Stop admitting datagrams and close every active per-flow task.
    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.flows.lock().await.clear();
        }
    }

    /// Number of active flow tasks, exposed for lifecycle verification.
    pub async fn open_flow_count(&self) -> usize {
        self.flows.lock().await.len()
    }

    async fn flow_sender(&self, key: UdpFlowKey) -> Result<mpsc::Sender<Vec<u8>>, UdpRelayError> {
        let mut flows = self.flows.lock().await;
        if let Some(sender) = flows.get(&key) {
            return Ok(sender.clone());
        }
        let bind = match key.destination.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(UdpRelayError::Upstream)?;
        socket
            .connect(key.destination)
            .await
            .map_err(UdpRelayError::Upstream)?;
        let (sender, receiver) = mpsc::channel(32);
        flows.insert(key, sender.clone());
        tokio::spawn(run_flow(
            key,
            socket,
            receiver,
            self.idle_timeout,
            Arc::clone(&self.child_sink),
            self.summary_tx.clone(),
            Arc::clone(&self.flows),
        ));
        Ok(sender)
    }
}

async fn run_flow(
    key: UdpFlowKey,
    socket: UdpSocket,
    mut child_rx: mpsc::Receiver<Vec<u8>>,
    idle_timeout: Duration,
    child_sink: Arc<dyn UdpChildSink>,
    summary_tx: mpsc::Sender<UdpFlowSummary>,
    flows: Arc<Mutex<HashMap<UdpFlowKey, mpsc::Sender<Vec<u8>>>>>,
) {
    let mut upstream_bytes = 0_u64;
    let mut downstream_bytes = 0_u64;
    let mut response = vec![0_u8; 65_535];
    let idle = time::sleep(idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            child = child_rx.recv() => {
                let Some(payload) = child else { break };
                match socket.send(&payload).await {
                    Ok(length) if length == payload.len() => {
                        upstream_bytes = upstream_bytes.saturating_add(length as u64);
                        idle.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    _ => break,
                }
            }
            received = socket.recv(&mut response) => {
                let Ok(length) = received else { break };
                let datagram = UdpChildDatagram {
                    key,
                    payload: response[..length].to_vec(),
                };
                if child_sink.send(datagram).await.is_err() {
                    break;
                }
                downstream_bytes = downstream_bytes.saturating_add(length as u64);
                idle.as_mut().reset(Instant::now() + idle_timeout);
            }
            () = &mut idle => break,
        }
    }
    flows.lock().await.remove(&key);
    child_sink.close(key).await;
    let _ = summary_tx
        .send(UdpFlowSummary {
            key,
            upstream_bytes,
            downstream_bytes,
        })
        .await;
}

/// Typed UDP relay failure.
#[derive(Debug, thiserror::Error)]
pub enum UdpRelayError {
    /// Run policy rejected the flow before forwarding.
    #[error("UDP flow rejected: {0:?}")]
    Policy(UdpFlowDisposition, UdpFlowKey),
    /// The local relay was already closed.
    #[error("UDP relay is closed")]
    Closed,
    /// Client and destination address families did not match.
    #[error("UDP client {client} and destination {destination} use different address families")]
    AddressFamilyMismatch {
        /// Workload-side source address.
        client: SocketAddr,
        /// Recovered original destination.
        destination: SocketAddr,
    },
    /// The recovered original destination had port zero.
    #[error("UDP destination port must be nonzero")]
    DestinationPortZero,
    /// Opening or connecting the ordinary upstream socket failed.
    #[error("open UDP upstream: {0}")]
    Upstream(#[source] io::Error),
}

impl UdpRelayError {
    /// Policy outcome carried by a fail-closed rejection.
    pub fn disposition(&self) -> Option<UdpFlowDisposition> {
        match self {
            Self::Policy(disposition, _) => Some(*disposition),
            _ => None,
        }
    }

    /// Build the typed report sent through the fatal controller for a binding run.
    pub fn fatal_report(&self) -> Result<Option<FatalReport>, CaptureContractError> {
        let Self::Policy(UdpFlowDisposition::Fatal(reason), key) = self else {
            return Ok(None);
        };
        let destination = OriginalDestination::new(key.destination.ip(), key.destination.port())?;
        Ok(Some(FatalReport::destination(*reason, destination)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use async_trait::async_trait;
    use hiloop_core::capture::CaptureFatalReason;
    use hiloop_core::identity::{Hlc, RunContext};
    use serde_json::json;
    use tokio::sync::{Mutex, mpsc};

    use super::{
        UdpChildDatagram, UdpChildSink, UdpFlowDisposition, UdpFlowKey, UdpFlowRelay,
        udp_flow_disposition,
    };
    use crate::egress::{EgressMode, EgressPolicy};

    #[test]
    fn udp_policy_matrix_is_fail_closed_before_forwarding() {
        let allow_all = EgressPolicy::default();
        let restrictive =
            EgressPolicy::new(EgressMode::Deny, ["allowed.example.com".to_owned()], [])
                .expect("restrictive policy");

        assert_eq!(
            udp_flow_disposition(false, &allow_all),
            UdpFlowDisposition::Forward
        );
        assert_eq!(
            udp_flow_disposition(false, &restrictive),
            UdpFlowDisposition::DenyIdentityUnavailable
        );
        assert_eq!(
            udp_flow_disposition(true, &allow_all),
            UdpFlowDisposition::Fatal(CaptureFatalReason::SecretTransportUnsupported)
        );
        assert_eq!(
            udp_flow_disposition(true, &restrictive),
            UdpFlowDisposition::Fatal(CaptureFatalReason::SecretTransportUnsupported)
        );
    }

    #[tokio::test]
    async fn relay_preserves_dual_stack_datagrams_and_emits_one_summary_per_flow() {
        let (child_tx, mut child_rx) = mpsc::channel(4);
        let sink = Arc::new(ChannelChildSink(Mutex::new(child_tx)));
        let (summary_tx, mut summary_rx) = mpsc::channel(4);
        let relay = UdpFlowRelay::new(
            false,
            &EgressPolicy::default(),
            Duration::from_millis(20),
            sink,
            summary_tx,
        );

        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let echo = tokio::net::UdpSocket::bind(bind)
                .await
                .expect("bind UDP echo");
            let destination = echo.local_addr().expect("echo address");
            let echo_task = tokio::spawn(async move {
                let mut buffer = [0_u8; 64];
                let (length, peer) = echo.recv_from(&mut buffer).await.expect("echo receive");
                echo.send_to(&buffer[..length], peer)
                    .await
                    .expect("echo send");
            });
            let key = UdpFlowKey::new(
                if destination.is_ipv4() {
                    "169.254.254.2:40000".parse().expect("client IPv4")
                } else {
                    "[fd00:6869:6c6f:6f70::2]:40000"
                        .parse()
                        .expect("client IPv6")
                },
                destination,
            )
            .expect("matching flow families");

            relay
                .forward(key, b"quic-like-opaque-bytes")
                .await
                .expect("forward datagram");
            let response = tokio::time::timeout(Duration::from_secs(1), child_rx.recv())
                .await
                .expect("response timeout")
                .expect("response channel");
            assert_eq!(response.key(), key);
            assert_eq!(response.payload(), b"quic-like-opaque-bytes");
            echo_task.await.expect("echo task");

            let summary = tokio::time::timeout(Duration::from_secs(1), summary_rx.recv())
                .await
                .expect("summary timeout")
                .expect("summary channel");
            assert_eq!(summary.key(), key);
            assert_eq!(summary.upstream_bytes(), 22);
            assert_eq!(summary.downstream_bytes(), 22);
            let event = summary
                .net_passthrough_event(
                    &RunContext::new_local_root(),
                    Hlc {
                        wall_ns: 1,
                        logical: 0,
                    },
                )
                .expect("typed passthrough event");
            let event = serde_json::to_value(event).expect("serialize passthrough event");
            assert_eq!(event["name"], json!("net.passthrough"));
            assert_eq!(event["attributes"]["transport"], json!("udp"));
            assert_eq!(event["attributes"]["upstream_bytes"], json!(22));
            assert_eq!(event["attributes"]["downstream_bytes"], json!(22));
        }
    }

    #[tokio::test]
    async fn denied_and_binding_fatal_flows_open_no_upstream_socket() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        let key = UdpFlowKey::new("169.254.254.2:40000".parse().expect("client"), destination)
            .expect("matching flow families");
        let restrictive = EgressPolicy::new(EgressMode::Deny, [], ["127.0.0.1/32".to_owned()])
            .expect("restrictive policy");

        for (bindings, policy, expected) in [
            (
                false,
                &restrictive,
                UdpFlowDisposition::DenyIdentityUnavailable,
            ),
            (
                true,
                &EgressPolicy::default(),
                UdpFlowDisposition::Fatal(CaptureFatalReason::SecretTransportUnsupported),
            ),
        ] {
            let (child_tx, _child_rx) = mpsc::channel(1);
            let (summary_tx, _summary_rx) = mpsc::channel(1);
            let relay = UdpFlowRelay::new(
                bindings,
                policy,
                Duration::from_secs(1),
                Arc::new(ChannelChildSink(Mutex::new(child_tx))),
                summary_tx,
            );
            let error = relay
                .forward(key, b"must-not-leave")
                .await
                .expect_err("flow must fail closed");
            assert_eq!(error.disposition(), Some(expected));
            assert_eq!(relay.open_flow_count().await, 0);
            let fatal = error.fatal_report().expect("typed fatal report");
            assert_eq!(fatal.is_some(), bindings);
            if let Some(fatal) = fatal {
                let fatal = fatal.event(
                    &RunContext::new_local_root(),
                    Hlc {
                        wall_ns: 1,
                        logical: 0,
                    },
                );
                let fatal = serde_json::to_value(fatal).expect("serialize fatal event");
                assert_eq!(fatal["name"], json!("capture.fatal"));
                assert_eq!(
                    fatal["attributes"]["reason"],
                    json!("secret_transport_unsupported")
                );
                assert_eq!(
                    fatal["attributes"]["original_destination.ip"],
                    json!("127.0.0.1")
                );
            }
        }
    }

    struct ChannelChildSink(Mutex<mpsc::Sender<UdpChildDatagram>>);

    #[async_trait]
    impl UdpChildSink for ChannelChildSink {
        async fn send(&self, datagram: UdpChildDatagram) -> std::io::Result<()> {
            self.0
                .lock()
                .await
                .send(datagram)
                .await
                .map_err(std::io::Error::other)
        }
    }
}
