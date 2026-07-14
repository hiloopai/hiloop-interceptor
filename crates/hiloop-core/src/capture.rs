//! Typed capture event contracts carried by the existing [`Event`] schema.
//!
//! These types constrain event names, attribute keys, closed reason sets, and
//! scalar value shapes without adding another serialized event representation.

use std::{fmt, net::IpAddr, str::FromStr};

use thiserror::Error;

use crate::{
    event::{AttributeKey, Event, EventName, SignalType},
    identity::{Hlc, RunContext},
};

const CLIENT_HELLO_FINGERPRINT: &str = "client_hello_fingerprint";
const DOWNSTREAM_BYTES: &str = "downstream_bytes";
const L7_CAPTURE: &str = "l7_capture";
const ORIGINAL_DESTINATION_IP: &str = "original_destination.ip";
const ORIGINAL_DESTINATION_PORT: &str = "original_destination.port";
const REASON: &str = "reason";
const SERVER_NAME: &str = "server_name";
const UPSTREAM_BYTES: &str = "upstream_bytes";

/// Validation failures for capture contract values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureContractError {
    /// A required text field contained no non-whitespace content.
    #[error("{field} must not be blank")]
    Blank { field: &'static str },
    /// Port zero is not a routable destination port.
    #[error("original destination port must be greater than zero")]
    Port,
    /// Event v1 represents integers as signed 64-bit values.
    #[error("{field} exceeds the event-v1 signed integer range: {value}")]
    IntegerRange { field: &'static str, value: u64 },
}

/// Error returned when a network capture mode is outside the shared contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid network capture mode `{value}`; expected auto, netns, proxy, or off")]
pub struct ParseNetCaptureModeError {
    value: String,
}

macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    $(Self::$variant => $value),+
                })
            }
        }
    };
}

string_enum! {
    /// Requested transport mode for `hiloop run` network capture.
    pub enum NetCaptureMode {
        /// Select transparent capture when available and degrade only where policy permits.
        Auto => "auto",
        /// Require transparent Linux network-namespace capture.
        Netns => "netns",
        /// Require cooperative environment-proxy capture.
        Proxy => "proxy",
        /// Disable network capture, injection, and egress enforcement.
        Off => "off",
    }
}

impl FromStr for NetCaptureMode {
    type Err = ParseNetCaptureModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "netns" => Ok(Self::Netns),
            "proxy" => Ok(Self::Proxy),
            "off" => Ok(Self::Off),
            _ => Err(ParseNetCaptureModeError {
                value: value.to_owned(),
            }),
        }
    }
}

string_enum! {
    /// Transport implementation selected after preflight.
    pub enum SelectedNetCaptureMode {
        /// Transparent Linux network-namespace capture.
        Netns => "netns",
        /// Cooperative environment-proxy capture.
        Proxy => "proxy",
        /// Network capture was explicitly disabled.
        Off => "off",
        /// No child transport started because selection failed.
        None => "none",
    }
}

string_enum! {
    /// Capture policy implied by bindings and egress policy.
    pub enum CapturePolicy {
        /// No bindings and allow-all egress permit observable degradation.
        Observe => "observe",
        /// Restrictive egress requires inspectable application identity.
        PolicyStrict => "policy_strict",
        /// Any secret binding requires fail-closed inspection.
        SecretStrict => "secret_strict",
    }
}

string_enum! {
    /// Outcome of transport preflight for a run.
    pub enum CapturePreflight {
        /// Every requested primitive passed an actual-operation preflight.
        Passed => "passed",
        /// At least one requested primitive failed preflight.
        Failed => "failed",
        /// The requested mode does not use transparent-capture preflight.
        NotApplicable => "not_applicable",
    }
}

string_enum! {
    /// Closed reason set for a transport fallback or startup refusal.
    pub enum CaptureTransportDegradationReason {
        /// Transparent capture is not implemented on the host platform.
        UnsupportedPlatform => "unsupported_platform",
        /// The host denied creation of an unprivileged user namespace.
        UserNamespaceDenied => "user_namespace_denied",
        /// Transparent sockets or TPROXY policy could not be configured.
        TproxyUnavailable => "tproxy_unavailable",
        /// The namespace tunnel device was unavailable.
        TunUnavailable => "tun_unavailable",
        /// The version-pinned pasta helper was unavailable.
        PastaMissing => "pasta_missing",
        /// The capture path could not preserve host IPv6 connectivity.
        Ipv6Unavailable => "ipv6_unavailable",
        /// The namespace could not preserve the host resolver contract.
        ResolverUnavailable => "resolver_unavailable",
        /// Preflight passed but the transparent transport failed during startup.
        NetnsStartupFailed => "netns_startup_failed",
    }
}

string_enum! {
    /// Why an attempted TLS interception failed.
    pub enum TlsInterceptionFailedReason {
        /// The client explicitly rejected the interception certificate.
        ClientTrustRejected => "client_trust_rejected",
        /// The client closed without a definitive trust alert.
        AmbiguousHandshakeAbort => "ambiguous_handshake_abort",
        /// The handshake was incompatible for a non-trust reason.
        ProtocolMismatch => "protocol_mismatch",
        /// Establishing the origin-side TLS connection failed.
        ServerHandshakeFailed => "server_handshake_failed",
        /// Restrictive policy forbade the raw fallback that would be required.
        PolicyPassthroughForbidden => "policy_passthrough_forbidden",
        /// The interceptor failed independently of either TLS peer.
        InternalError => "internal_error",
    }
}

string_enum! {
    /// Why raw TLS passthrough began.
    pub enum TlsPassthroughReason {
        /// A reviewed exact compatibility entry selected passthrough.
        PreclassifiedTrustIncompatible => "preclassified_trust_incompatible",
        /// A definitive trust rejection selected passthrough for a later retry.
        LearnedTrustRejection => "learned_trust_rejection",
        /// Encrypted `ClientHello` hid the application routing identity.
        EncryptedClientHello => "encrypted_client_hello",
    }
}

string_enum! {
    /// Why a non-HTTP flow passed without L7 capture.
    pub enum NetPassthroughReason {
        /// The application protocol has no L7 capture implementation.
        UnsupportedApplicationProtocol => "unsupported_application_protocol",
        /// The transport has no content-capture implementation.
        UnsupportedTransportCapture => "unsupported_transport_capture",
    }
}

string_enum! {
    /// Transport carried by a `net.passthrough` event.
    pub enum TransportProtocol {
        /// Transmission Control Protocol.
        Tcp => "tcp",
        /// User Datagram Protocol, including QUIC.
        Udp => "udp",
    }
}

string_enum! {
    /// Closed fatal causes that terminate a strict run.
    pub enum CaptureFatalReason {
        /// A bound TLS client rejected the interception certificate.
        SecretBindUnterminatable => "secret_bind_unterminatable",
        /// Available routing identity could map to a bound secret ambiguously.
        SecretRouteAmbiguous => "secret_route_ambiguous",
        /// The dialed destination was not authorized for the bound host.
        SecretDestinationMismatch => "secret_destination_mismatch",
        /// A bound run attempted an application passthrough path.
        SecretPassthroughForbidden => "secret_passthrough_forbidden",
        /// SNI and request authority did not identify the same bound route.
        SecretRouteIdentityMismatch => "secret_route_identity_mismatch",
        /// The bound route used cleartext transport.
        SecretTransportInsecure => "secret_transport_insecure",
        /// The bound route used an application transport that cannot inject.
        SecretTransportUnsupported => "secret_transport_unsupported",
        /// The gateway dataplane failed after the child started.
        DataplaneFailed => "dataplane_failed",
    }
}

/// Original transport destination recovered before application classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalDestination {
    ip: IpAddr,
    port: u16,
}

impl OriginalDestination {
    /// Validate an original IP and nonzero port.
    pub fn new(ip: IpAddr, port: u16) -> Result<Self, CaptureContractError> {
        if port == 0 {
            return Err(CaptureContractError::Port);
        }
        Ok(Self { ip, port })
    }

    /// Original destination IP address.
    pub fn ip(self) -> IpAddr {
        self.ip
    }

    /// Original destination port.
    pub fn port(self) -> u16 {
        self.port
    }
}

/// TLS routing identity visible before HTTP parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFlowIdentity {
    destination: OriginalDestination,
    server_name: Option<String>,
    client_hello_fingerprint: Option<String>,
}

impl TlsFlowIdentity {
    /// Start an identity from the authoritative transport destination.
    pub fn new(destination: OriginalDestination) -> Self {
        Self {
            destination,
            server_name: None,
            client_hello_fingerprint: None,
        }
    }

    /// Attach visible TLS server name identity.
    pub fn with_server_name(
        mut self,
        server_name: impl Into<String>,
    ) -> Result<Self, CaptureContractError> {
        self.server_name = Some(nonblank("server_name", server_name)?);
        Ok(self)
    }

    /// Attach the normalized `ClientHello` fingerprint used for retry matching.
    pub fn with_client_hello_fingerprint(
        mut self,
        fingerprint: impl Into<String>,
    ) -> Result<Self, CaptureContractError> {
        self.client_hello_fingerprint = Some(nonblank("client_hello_fingerprint", fingerprint)?);
        Ok(self)
    }

    /// Authoritative original transport destination.
    pub fn destination(&self) -> OriginalDestination {
        self.destination
    }

    /// Visible TLS server name, when present.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Normalized `ClientHello` fingerprint, when present.
    pub fn client_hello_fingerprint(&self) -> Option<&str> {
        self.client_hello_fingerprint.as_deref()
    }
}

/// Final byte counts for an opaque bidirectional flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCounts {
    upstream: i64,
    downstream: i64,
}

impl ByteCounts {
    /// Convert unsigned transport counters into Event-v1 integer values.
    pub fn new(upstream: u64, downstream: u64) -> Result<Self, CaptureContractError> {
        Ok(Self {
            upstream: event_i64("upstream_bytes", upstream)?,
            downstream: event_i64("downstream_bytes", downstream)?,
        })
    }

    /// Bytes sent from the child toward the origin.
    pub fn upstream(self) -> i64 {
        self.upstream
    }

    /// Bytes sent from the origin toward the child.
    pub fn downstream(self) -> i64 {
        self.downstream
    }
}

impl Event {
    /// Build one typed event for a TLS interception attempt that did not become HTTP.
    pub fn tls_interception_failed(
        context: &RunContext,
        ts: Hlc,
        reason: TlsInterceptionFailedReason,
        flow: &TlsFlowIdentity,
        retry_required: bool,
        secret_bound: bool,
    ) -> Self {
        with_tls_flow(
            Self::new(
                context,
                ts,
                SignalType::Net,
                EventName::from_static("tls.interception_failed"),
            )
            .with_attribute(AttributeKey::from_static(REASON), reason.to_string())
            .with_attribute(AttributeKey::from_static("retry_required"), retry_required)
            .with_attribute(AttributeKey::from_static("secret_bound"), secret_bound),
            flow,
        )
    }

    /// Build one typed event when a raw TLS splice actually begins.
    pub fn tls_passthrough(
        context: &RunContext,
        ts: Hlc,
        reason: TlsPassthroughReason,
        flow: &TlsFlowIdentity,
        byte_counts: ByteCounts,
    ) -> Self {
        with_byte_counts(
            with_tls_flow(
                Self::new(
                    context,
                    ts,
                    SignalType::Net,
                    EventName::from_static("tls.passthrough"),
                )
                .with_attribute(AttributeKey::from_static(REASON), reason.to_string())
                .with_attribute(AttributeKey::from_static(L7_CAPTURE), false),
                flow,
            ),
            byte_counts,
        )
    }

    /// Build one typed metadata event for an opaque TCP or UDP flow.
    pub fn net_passthrough(
        context: &RunContext,
        ts: Hlc,
        transport: TransportProtocol,
        destination: OriginalDestination,
        reason: NetPassthroughReason,
        byte_counts: ByteCounts,
    ) -> Self {
        with_byte_counts(
            with_destination(
                Self::new(
                    context,
                    ts,
                    SignalType::Net,
                    EventName::from_static("net.passthrough"),
                )
                .with_attribute(
                    AttributeKey::from_static("transport"),
                    transport.to_string(),
                )
                .with_attribute(AttributeKey::from_static(REASON), reason.to_string())
                .with_attribute(AttributeKey::from_static(L7_CAPTURE), false),
                destination,
            ),
            byte_counts,
        )
    }

    /// Build the once-per-run transport selection event.
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor locks the seven required capture.transport attributes"
    )]
    pub fn capture_transport(
        context: &RunContext,
        ts: Hlc,
        requested: NetCaptureMode,
        selected: SelectedNetCaptureMode,
        capture_policy: CapturePolicy,
        preflight: CapturePreflight,
        ipv4_available: bool,
        ipv6_available: bool,
        degradation_reason: Option<CaptureTransportDegradationReason>,
    ) -> Self {
        let mut event = Self::new(
            context,
            ts,
            SignalType::Net,
            EventName::from_static("capture.transport"),
        )
        .with_attribute(
            AttributeKey::from_static("requested"),
            requested.to_string(),
        )
        .with_attribute(AttributeKey::from_static("selected"), selected.to_string())
        .with_attribute(
            AttributeKey::from_static("capture_policy"),
            capture_policy.to_string(),
        )
        .with_attribute(
            AttributeKey::from_static("preflight_result"),
            preflight.to_string(),
        )
        .with_attribute(AttributeKey::from_static("ipv4_available"), ipv4_available)
        .with_attribute(AttributeKey::from_static("ipv6_available"), ipv6_available);
        if let Some(reason) = degradation_reason {
            event = event.with_attribute(
                AttributeKey::from_static("degradation_reason"),
                reason.to_string(),
            );
        }
        event
    }

    /// Build the durable fatal cause for a strict run.
    pub fn capture_fatal(
        context: &RunContext,
        ts: Hlc,
        reason: CaptureFatalReason,
        flow: Option<TlsFlowIdentity>,
    ) -> Self {
        let event = Self::new(
            context,
            ts,
            SignalType::Net,
            EventName::from_static("capture.fatal"),
        )
        .with_attribute(AttributeKey::from_static(REASON), reason.to_string());
        match flow {
            Some(flow) => with_tls_flow(event, &flow),
            None => event,
        }
    }
}

fn nonblank(field: &'static str, value: impl Into<String>) -> Result<String, CaptureContractError> {
    let value = value.into();
    if value.trim().is_empty() {
        Err(CaptureContractError::Blank { field })
    } else {
        Ok(value)
    }
}

fn event_i64(field: &'static str, value: u64) -> Result<i64, CaptureContractError> {
    i64::try_from(value).map_err(|_| CaptureContractError::IntegerRange { field, value })
}

fn with_destination(event: Event, destination: OriginalDestination) -> Event {
    event
        .with_attribute(
            AttributeKey::from_static(ORIGINAL_DESTINATION_IP),
            destination.ip().to_string(),
        )
        .with_attribute(
            AttributeKey::from_static(ORIGINAL_DESTINATION_PORT),
            i64::from(destination.port()),
        )
}

fn with_tls_flow(mut event: Event, flow: &TlsFlowIdentity) -> Event {
    event = with_destination(event, flow.destination());
    if let Some(server_name) = flow.server_name() {
        event = event.with_attribute(AttributeKey::from_static(SERVER_NAME), server_name);
    }
    if let Some(fingerprint) = flow.client_hello_fingerprint() {
        event = event.with_attribute(
            AttributeKey::from_static(CLIENT_HELLO_FINGERPRINT),
            fingerprint,
        );
    }
    event
}

fn with_byte_counts(event: Event, counts: ByteCounts) -> Event {
    event
        .with_attribute(AttributeKey::from_static(UPSTREAM_BYTES), counts.upstream())
        .with_attribute(
            AttributeKey::from_static(DOWNSTREAM_BYTES),
            counts.downstream(),
        )
}
