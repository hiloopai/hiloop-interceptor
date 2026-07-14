//! Run-scoped TLS transport policy for transparent TCP flows.

use std::collections::HashSet;

use hiloop_core::capture::{
    CaptureFatalReason, CapturePolicy, TlsInterceptionFailedReason, TlsPassthroughReason,
};
use tokio::sync::RwLock;

use crate::{
    egress::{CanonicalHost, EgressPolicy, canonicalize_host},
    net_capture::CompatibilityRegistry,
};

use super::{AuthorizedRoute, DnsAnswerEvidence, RouteDenial, TcpProtocol};

/// Whether the admitted authority is relevant to the run's secret bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRoute {
    /// The authority matches no binding.
    Unbound,
    /// The authority matches one unambiguous binding route.
    Bound,
    /// Available routing evidence cannot identify one safe binding route.
    Ambiguous,
}

/// Policy-gate result presented to the TLS transport selector.
pub enum TlsPolicyFlow<'a> {
    /// W3 denied the route before upstream application I/O.
    Denied(&'a RouteDenial),
    /// W3 admitted the route and preserved its classified protocol identity.
    Admitted {
        /// Destination-pinned route authorized by W3.
        route: &'a AuthorizedRoute,
        /// Protocol parsed from the untouched client prefix.
        protocol: &'a TcpProtocol,
        /// Secret-route classification for this authority.
        secret_route: SecretRoute,
    },
}

/// Transport action selected after policy, binding, compatibility, ECH, and learning checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsTransportDecision {
    /// Preserve an earlier W3 denial without opening upstream transport.
    Denied(RouteDenial),
    /// Terminate TLS and inspect the HTTP authority and content.
    TerminateTls,
    /// Parse and capture cleartext HTTP.
    CaptureHttp,
    /// Raw-splice TLS for one closed, observable reason.
    PassthroughTls(TlsPassthroughReason),
    /// Raw-splice an unsupported non-HTTP TCP protocol in observe mode.
    PassthroughTcp,
    /// Fail a binding-strict run with the closed W1 reason.
    Fatal(CaptureFatalReason),
}

/// Explicit client trust alert that can definitively identify interception rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAlert {
    /// The client does not trust the interception issuer.
    UnknownCa,
    /// The client rejected the presented interception leaf.
    BadCertificate,
    /// The client reported an otherwise-unspecified certificate rejection.
    CertificateUnknown,
}

/// Closed handshake result used for retry learning and typed failure reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFailure {
    /// A definitive client-side trust alert.
    ClientTrustAlert(TrustAlert),
    /// The client closed without sending a TLS alert.
    Eof,
    /// The handshake exceeded its deadline or was cancelled.
    Timeout,
    /// The transport reset during the handshake.
    Reset,
    /// Origin-side TLS establishment failed.
    ServerHandshake,
    /// The `ClientHello` violated TLS framing.
    MalformedTls,
    /// TLS versions, ciphers, or messages were incompatible.
    ProtocolMismatch,
    /// The interceptor failed independently of either peer.
    Internal,
}

/// Result of a failed MITM handshake; the revealing connection always remains failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFailureDecision {
    /// Emit `tls.interception_failed`, then fail this connection.
    Failed {
        /// Closed W1 event reason.
        reason: TlsInterceptionFailedReason,
        /// Whether a matching later reconnect may raw-splice.
        retry_required: bool,
        /// Strict-run fatal cause for W5, when applicable.
        fatal: Option<CaptureFatalReason>,
    },
}

impl HandshakeFailureDecision {
    /// Whether this failure installed a run-scoped learned retry entry.
    pub fn retry_required(self) -> bool {
        match self {
            Self::Failed { retry_required, .. } => retry_required,
        }
    }

    /// Strict-run fatal cause, if this connection must close the run dataplane.
    pub fn fatal(self) -> Option<CaptureFatalReason> {
        match self {
            Self::Failed { fatal, .. } => fatal,
        }
    }

    /// Closed reason for the required `tls.interception_failed` event.
    pub fn reason(self) -> TlsInterceptionFailedReason {
        match self {
            Self::Failed { reason, .. } => reason,
        }
    }
}

/// Request-time authority mismatch after a successful TLS interception handshake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestAuthorityRejection {
    /// The request failed the non-secret route guard.
    #[error("request authority does not match the TLS server name")]
    Denied(RouteDenial),
    /// A secret-strict request could bypass binding identity.
    #[error("request authority violates secret route identity")]
    Fatal(CaptureFatalReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunPosture {
    Observe,
    PolicyStrict,
    SecretStrict,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LearnedTlsKey {
    server_name: String,
    port: u16,
    fingerprint: String,
}

/// Run-scoped implementation of the R1 TLS precedence and retry-learning policy.
pub struct TlsPolicyEngine {
    posture: RunPosture,
    registry: CompatibilityRegistry,
    learned: RwLock<HashSet<LearnedTlsKey>>,
}

impl TlsPolicyEngine {
    /// Derive the run-wide posture once, before any connection can consult bypass tables.
    pub fn new(
        has_secret_bindings: bool,
        egress: &EgressPolicy,
        registry: CompatibilityRegistry,
    ) -> Self {
        let posture = if has_secret_bindings {
            RunPosture::SecretStrict
        } else if egress.is_allow_all() {
            RunPosture::Observe
        } else {
            RunPosture::PolicyStrict
        };
        Self {
            posture,
            registry,
            learned: RwLock::new(HashSet::new()),
        }
    }

    /// W1 capture-policy value corresponding to this engine's immutable run posture.
    pub fn capture_policy(&self) -> CapturePolicy {
        match self.posture {
            RunPosture::Observe => CapturePolicy::Observe,
            RunPosture::PolicyStrict => CapturePolicy::PolicyStrict,
            RunPosture::SecretStrict => CapturePolicy::SecretStrict,
        }
    }

    /// Select one transport action in the R1 precedence order.
    pub async fn decide(&self, flow: TlsPolicyFlow<'_>) -> TlsTransportDecision {
        let (route, protocol, secret_route) = match flow {
            TlsPolicyFlow::Denied(denial) => {
                return TlsTransportDecision::Denied(denial.clone());
            }
            TlsPolicyFlow::Admitted {
                route,
                protocol,
                secret_route,
            } => (route, protocol, secret_route),
        };

        match self.posture {
            RunPosture::SecretStrict => Self::decide_secret_strict(protocol, secret_route),
            RunPosture::PolicyStrict => Self::decide_policy_strict(protocol),
            RunPosture::Observe => self.decide_observe(route, protocol, secret_route).await,
        }
    }

    fn decide_secret_strict(
        protocol: &TcpProtocol,
        secret_route: SecretRoute,
    ) -> TlsTransportDecision {
        if secret_route == SecretRoute::Ambiguous {
            return TlsTransportDecision::Fatal(CaptureFatalReason::SecretRouteAmbiguous);
        }
        match protocol {
            TcpProtocol::TlsClientHello(hello) if hello.encrypted_client_hello() => {
                TlsTransportDecision::Fatal(CaptureFatalReason::SecretRouteAmbiguous)
            }
            TcpProtocol::TlsClientHello(_) => TlsTransportDecision::TerminateTls,
            TcpProtocol::CleartextHttp(_) if secret_route == SecretRoute::Bound => {
                TlsTransportDecision::Fatal(CaptureFatalReason::SecretTransportInsecure)
            }
            TcpProtocol::CleartextHttp(_) => TlsTransportDecision::CaptureHttp,
            TcpProtocol::OtherTcp => {
                TlsTransportDecision::Fatal(CaptureFatalReason::SecretTransportUnsupported)
            }
        }
    }

    fn decide_policy_strict(protocol: &TcpProtocol) -> TlsTransportDecision {
        match protocol {
            TcpProtocol::TlsClientHello(hello) if hello.encrypted_client_hello() => {
                TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable)
            }
            TcpProtocol::TlsClientHello(_) => TlsTransportDecision::TerminateTls,
            TcpProtocol::CleartextHttp(_) => TlsTransportDecision::CaptureHttp,
            TcpProtocol::OtherTcp => TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable),
        }
    }

    async fn decide_observe(
        &self,
        route: &AuthorizedRoute,
        protocol: &TcpProtocol,
        secret_route: SecretRoute,
    ) -> TlsTransportDecision {
        if secret_route == SecretRoute::Ambiguous {
            return TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable);
        }
        match protocol {
            TcpProtocol::TlsClientHello(hello) => {
                if self
                    .registry
                    .contains(route.identity().host(), route.original_destination().port())
                {
                    return TlsTransportDecision::PassthroughTls(
                        TlsPassthroughReason::PreclassifiedTrustIncompatible,
                    );
                }
                if hello.encrypted_client_hello() {
                    return TlsTransportDecision::PassthroughTls(
                        TlsPassthroughReason::EncryptedClientHello,
                    );
                }
                if let Some(key) = learned_key(route, hello)
                    && self.learned.read().await.contains(&key)
                {
                    return TlsTransportDecision::PassthroughTls(
                        TlsPassthroughReason::LearnedTrustRejection,
                    );
                }
                TlsTransportDecision::TerminateTls
            }
            TcpProtocol::CleartextHttp(_) => TlsTransportDecision::CaptureHttp,
            TcpProtocol::OtherTcp => TlsTransportDecision::PassthroughTcp,
        }
    }

    /// Classify a failed handshake and install only a definitive observe-mode retry key.
    pub async fn record_handshake_failure(
        &self,
        flow: TlsPolicyFlow<'_>,
        failure: HandshakeFailure,
    ) -> HandshakeFailureDecision {
        let (route, hello, secret_route) = match flow {
            TlsPolicyFlow::Admitted {
                route,
                protocol: TcpProtocol::TlsClientHello(hello),
                secret_route,
            } => (route, hello, secret_route),
            TlsPolicyFlow::Admitted { secret_route, .. } => {
                return HandshakeFailureDecision::Failed {
                    reason: TlsInterceptionFailedReason::InternalError,
                    retry_required: false,
                    fatal: self.strict_failure_fatal(secret_route),
                };
            }
            TlsPolicyFlow::Denied(_) => {
                return HandshakeFailureDecision::Failed {
                    reason: TlsInterceptionFailedReason::InternalError,
                    retry_required: false,
                    fatal: None,
                };
            }
        };

        let definitive_trust_rejection = matches!(failure, HandshakeFailure::ClientTrustAlert(_));
        let mut retry_required = false;
        if self.posture == RunPosture::Observe
            && definitive_trust_rejection
            && let Some(key) = learned_key(route, hello)
        {
            self.learned.write().await.insert(key);
            retry_required = true;
        }

        let reason = if self.posture == RunPosture::PolicyStrict && definitive_trust_rejection {
            TlsInterceptionFailedReason::PolicyPassthroughForbidden
        } else {
            failure_reason(failure)
        };
        HandshakeFailureDecision::Failed {
            reason,
            retry_required,
            fatal: self.strict_failure_fatal(secret_route),
        }
    }

    fn strict_failure_fatal(&self, secret_route: SecretRoute) -> Option<CaptureFatalReason> {
        (self.posture == RunPosture::SecretStrict).then_some(match secret_route {
            SecretRoute::Bound => CaptureFatalReason::SecretBindUnterminatable,
            SecretRoute::Unbound => CaptureFatalReason::SecretPassthroughForbidden,
            SecretRoute::Ambiguous => CaptureFatalReason::SecretRouteAmbiguous,
        })
    }

    /// Enforce request-time SNI/authority equality after decrypting HTTP/1 or HTTP/2.
    pub fn validate_request_authority(
        &self,
        route: &AuthorizedRoute,
        authority: &str,
        _secret_route: SecretRoute,
    ) -> Result<(), RequestAuthorityRejection> {
        let destination = canonicalize_host(authority)
            .map(|destination| destination.with_default_port(route.original_destination().port()));
        if destination
            .as_ref()
            .is_ok_and(|value| value == route.identity())
        {
            return Ok(());
        }
        if self.posture == RunPosture::SecretStrict {
            Err(RequestAuthorityRejection::Fatal(
                CaptureFatalReason::SecretRouteIdentityMismatch,
            ))
        } else {
            Err(RequestAuthorityRejection::Denied(
                RouteDenial::DestinationMismatch,
            ))
        }
    }

    /// Require exact child-visible DNS pinning before terminating a bound domain route.
    pub fn validate_termination_destination(
        &self,
        route: &AuthorizedRoute,
        dns: &dyn DnsAnswerEvidence,
        secret_route: SecretRoute,
    ) -> Result<(), CaptureFatalReason> {
        if secret_route == SecretRoute::Ambiguous {
            return Err(CaptureFatalReason::SecretRouteAmbiguous);
        }
        if secret_route != SecretRoute::Bound {
            return Ok(());
        }
        match route.identity().host() {
            CanonicalHost::Ip(ip) if *ip == route.original_destination().ip() => Ok(()),
            CanonicalHost::Domain(hostname)
                if dns.contains_unexpired(hostname, route.original_destination().ip()) =>
            {
                Ok(())
            }
            CanonicalHost::Domain(_) | CanonicalHost::Ip(_) => {
                Err(CaptureFatalReason::SecretDestinationMismatch)
            }
        }
    }
}

fn learned_key(
    route: &AuthorizedRoute,
    hello: &super::ClientHelloIdentity,
) -> Option<LearnedTlsKey> {
    hello.server_name()?;
    let CanonicalHost::Domain(server_name) = route.identity().host() else {
        return None;
    };
    Some(LearnedTlsKey {
        server_name: server_name.clone(),
        port: route.original_destination().port(),
        fingerprint: hello.fingerprint().to_owned(),
    })
}

fn failure_reason(failure: HandshakeFailure) -> TlsInterceptionFailedReason {
    match failure {
        HandshakeFailure::ClientTrustAlert(_) => TlsInterceptionFailedReason::ClientTrustRejected,
        HandshakeFailure::Eof | HandshakeFailure::Timeout | HandshakeFailure::Reset => {
            TlsInterceptionFailedReason::AmbiguousHandshakeAbort
        }
        HandshakeFailure::ServerHandshake => TlsInterceptionFailedReason::ServerHandshakeFailed,
        HandshakeFailure::MalformedTls | HandshakeFailure::ProtocolMismatch => {
            TlsInterceptionFailedReason::ProtocolMismatch
        }
        HandshakeFailure::Internal => TlsInterceptionFailedReason::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::IpAddr};

    use hiloop_core::capture::{
        CaptureFatalReason, TlsInterceptionFailedReason, TlsPassthroughReason,
    };

    use super::*;
    use crate::{
        egress::{EgressMode, EgressPolicy},
        net_capture::CompatibilityRegistry,
        netns::{
            AuthorizedRoute, ClassificationProgress, DnsAnswerEvidence, RouteDenial, TcpProtocol,
            authorize_route, classify_tcp_prefix,
        },
    };

    const ECH_EXTENSION: u16 = 0xfe0d;

    #[tokio::test]
    async fn policy_precedence_is_table_driven() {
        struct Case {
            name: &'static str,
            bindings: bool,
            restrictive: bool,
            flow: FlowFixture,
            secret_route: SecretRoute,
            expected: TlsTransportDecision,
        }

        let cases = [
            Case {
                name: "denied before TLS selection",
                bindings: false,
                restrictive: false,
                flow: FlowFixture::Denied(RouteDenial::IdentityUnavailable),
                secret_route: SecretRoute::Unbound,
                expected: TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable),
            },
            Case {
                name: "ambiguous secret route is fatal",
                bindings: true,
                restrictive: false,
                flow: FlowFixture::Tls("api.modal.com", 443, false),
                secret_route: SecretRoute::Ambiguous,
                expected: TlsTransportDecision::Fatal(CaptureFatalReason::SecretRouteAmbiguous),
            },
            Case {
                name: "binding strict ignores compatibility registry",
                bindings: true,
                restrictive: false,
                flow: FlowFixture::Tls("api.modal.com", 443, false),
                secret_route: SecretRoute::Bound,
                expected: TlsTransportDecision::TerminateTls,
            },
            Case {
                name: "binding strict terminates unbound TLS too",
                bindings: true,
                restrictive: false,
                flow: FlowFixture::Tls("ordinary.example.com", 443, false),
                secret_route: SecretRoute::Unbound,
                expected: TlsTransportDecision::TerminateTls,
            },
            Case {
                name: "restrictive policy ignores compatibility registry",
                bindings: false,
                restrictive: true,
                flow: FlowFixture::Tls("api.modal.com", 443, false),
                secret_route: SecretRoute::Unbound,
                expected: TlsTransportDecision::TerminateTls,
            },
            Case {
                name: "exact compatibility entry splices first connection",
                bindings: false,
                restrictive: false,
                flow: FlowFixture::Tls("api.modal.com", 443, false),
                secret_route: SecretRoute::Unbound,
                expected: TlsTransportDecision::PassthroughTls(
                    TlsPassthroughReason::PreclassifiedTrustIncompatible,
                ),
            },
            Case {
                name: "default TLS is MITM",
                bindings: false,
                restrictive: false,
                flow: FlowFixture::Tls("ordinary.example.com", 443, false),
                secret_route: SecretRoute::Unbound,
                expected: TlsTransportDecision::TerminateTls,
            },
        ];

        for case in cases {
            let policy = if case.restrictive {
                restrictive_policy()
            } else {
                EgressPolicy::default()
            };
            let engine =
                TlsPolicyEngine::new(case.bindings, &policy, CompatibilityRegistry::current());
            let fixture = case.flow.build(&policy);
            let decision = engine.decide(fixture.flow(case.secret_route)).await;
            assert_eq!(decision, case.expected, "{}", case.name);
        }
    }

    #[tokio::test]
    async fn compatibility_registry_is_exact_and_strict_modes_cannot_use_it() {
        for (host, port, expected) in [
            (
                "api.modal.com",
                443,
                TlsTransportDecision::PassthroughTls(
                    TlsPassthroughReason::PreclassifiedTrustIncompatible,
                ),
            ),
            ("sub.api.modal.com", 443, TlsTransportDecision::TerminateTls),
            ("modal.com", 443, TlsTransportDecision::TerminateTls),
            ("api.modal.com", 8443, TlsTransportDecision::TerminateTls),
        ] {
            let policy = EgressPolicy::default();
            let engine = engine(false, &policy);
            let fixture = FlowFixture::Tls(host, port, false).build(&policy);
            assert_eq!(
                engine.decide(fixture.flow(SecretRoute::Unbound)).await,
                expected,
                "{host}:{port}"
            );
        }
    }

    #[tokio::test]
    async fn trust_rejection_learns_only_for_the_next_matching_connection() {
        let policy = EgressPolicy::default();
        let engine = engine(false, &policy);
        let fixture = FlowFixture::Tls("new.example.com", 443, false).build(&policy);

        assert_eq!(
            engine.decide(fixture.flow(SecretRoute::Unbound)).await,
            TlsTransportDecision::TerminateTls
        );
        let failure = engine
            .record_handshake_failure(
                fixture.admitted(SecretRoute::Unbound),
                HandshakeFailure::ClientTrustAlert(TrustAlert::UnknownCa),
            )
            .await;
        assert_eq!(
            failure,
            HandshakeFailureDecision::Failed {
                reason: TlsInterceptionFailedReason::ClientTrustRejected,
                retry_required: true,
                fatal: None,
            }
        );
        assert_eq!(
            engine.decide(fixture.flow(SecretRoute::Unbound)).await,
            TlsTransportDecision::PassthroughTls(TlsPassthroughReason::LearnedTrustRejection,)
        );

        let different_fingerprint =
            FlowFixture::TlsWithCipher("new.example.com", 443, 0x1302).build(&policy);
        assert_eq!(
            engine
                .decide(different_fingerprint.flow(SecretRoute::Unbound))
                .await,
            TlsTransportDecision::TerminateTls
        );
    }

    #[tokio::test]
    async fn ambiguous_failures_never_poison_later_capture() {
        for failure in [
            HandshakeFailure::Eof,
            HandshakeFailure::Timeout,
            HandshakeFailure::Reset,
            HandshakeFailure::ServerHandshake,
            HandshakeFailure::MalformedTls,
            HandshakeFailure::ProtocolMismatch,
            HandshakeFailure::Internal,
        ] {
            let policy = EgressPolicy::default();
            let engine = engine(false, &policy);
            let fixture = FlowFixture::Tls("new.example.com", 443, false).build(&policy);
            let decision = engine
                .record_handshake_failure(fixture.admitted(SecretRoute::Unbound), failure)
                .await;
            assert!(!decision.retry_required());
            assert_eq!(
                engine.decide(fixture.flow(SecretRoute::Unbound)).await,
                TlsTransportDecision::TerminateTls
            );
        }
    }

    #[tokio::test]
    async fn strict_modes_never_learn_from_trust_rejection() {
        for (bindings, policy, secret_route, fatal) in [
            (
                true,
                EgressPolicy::default(),
                SecretRoute::Bound,
                Some(CaptureFatalReason::SecretBindUnterminatable),
            ),
            (
                true,
                EgressPolicy::default(),
                SecretRoute::Unbound,
                Some(CaptureFatalReason::SecretPassthroughForbidden),
            ),
            (false, restrictive_policy(), SecretRoute::Unbound, None),
        ] {
            let engine = TlsPolicyEngine::new(bindings, &policy, CompatibilityRegistry::current());
            let fixture = FlowFixture::Tls("new.example.com", 443, false).build(&policy);
            let failure = engine
                .record_handshake_failure(
                    fixture.admitted(secret_route),
                    HandshakeFailure::ClientTrustAlert(TrustAlert::CertificateUnknown),
                )
                .await;
            assert!(!failure.retry_required());
            assert_eq!(failure.fatal(), fatal);
            assert_eq!(
                engine.decide(fixture.flow(secret_route)).await,
                TlsTransportDecision::TerminateTls
            );
        }
    }

    #[tokio::test]
    async fn ech_and_opaque_tcp_obey_run_posture() {
        for (bindings, policy, protocol, secret_route, expected) in [
            (
                false,
                EgressPolicy::default(),
                FlowFixture::Tls("hidden.example.com", 443, true),
                SecretRoute::Unbound,
                TlsTransportDecision::PassthroughTls(TlsPassthroughReason::EncryptedClientHello),
            ),
            (
                true,
                EgressPolicy::default(),
                FlowFixture::Tls("hidden.example.com", 443, true),
                SecretRoute::Unbound,
                TlsTransportDecision::Fatal(CaptureFatalReason::SecretRouteAmbiguous),
            ),
            (
                false,
                restrictive_policy(),
                FlowFixture::Tls("hidden.example.com", 443, true),
                SecretRoute::Unbound,
                TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable),
            ),
            (
                false,
                EgressPolicy::default(),
                FlowFixture::OtherTcp(443),
                SecretRoute::Unbound,
                TlsTransportDecision::PassthroughTcp,
            ),
            (
                true,
                EgressPolicy::default(),
                FlowFixture::OtherTcp(443),
                SecretRoute::Unbound,
                TlsTransportDecision::Fatal(CaptureFatalReason::SecretTransportUnsupported),
            ),
            (
                false,
                restrictive_policy(),
                FlowFixture::OtherTcp(443),
                SecretRoute::Unbound,
                TlsTransportDecision::Denied(RouteDenial::IdentityUnavailable),
            ),
        ] {
            let engine = TlsPolicyEngine::new(bindings, &policy, CompatibilityRegistry::current());
            let fixture = protocol.build(&policy);
            assert_eq!(engine.decide(fixture.flow(secret_route)).await, expected);
        }
    }

    #[test]
    fn cross_origin_authority_is_rejected_in_every_posture() {
        for (bindings, policy, secret_route, expected) in [
            (
                false,
                EgressPolicy::default(),
                SecretRoute::Unbound,
                RequestAuthorityRejection::Denied(RouteDenial::DestinationMismatch),
            ),
            (
                false,
                restrictive_policy(),
                SecretRoute::Unbound,
                RequestAuthorityRejection::Denied(RouteDenial::DestinationMismatch),
            ),
            (
                true,
                EgressPolicy::default(),
                SecretRoute::Bound,
                RequestAuthorityRejection::Fatal(CaptureFatalReason::SecretRouteIdentityMismatch),
            ),
        ] {
            let engine = TlsPolicyEngine::new(bindings, &policy, CompatibilityRegistry::current());
            let fixture = FlowFixture::Tls("api.example.com", 443, false).build(&policy);
            let route = fixture.route();
            assert!(
                engine
                    .validate_request_authority(route, "api.example.com", secret_route)
                    .is_ok()
            );
            assert_eq!(
                engine.validate_request_authority(route, "other.example.com", secret_route),
                Err(expected)
            );
        }
    }

    #[test]
    fn bound_destination_requires_exact_unexpired_dns_evidence() {
        let policy = EgressPolicy::default();
        let engine = engine(true, &policy);
        let fixture = FlowFixture::Tls("api.example.com", 443, false).build(&policy);
        let route = fixture.route();

        for dns in [
            FakeDns::default(),
            FakeDns::default().answer("api.example.com", "203.0.113.10", false),
            FakeDns::default().answer("api.example.com", "203.0.113.11", true),
        ] {
            assert_eq!(
                engine.validate_termination_destination(route, &dns, SecretRoute::Bound),
                Err(CaptureFatalReason::SecretDestinationMismatch)
            );
        }
        let dns = FakeDns::default().answer("api.example.com", "203.0.113.10", true);
        assert!(
            engine
                .validate_termination_destination(route, &dns, SecretRoute::Bound)
                .is_ok()
        );
    }

    fn engine(bindings: bool, policy: &EgressPolicy) -> TlsPolicyEngine {
        TlsPolicyEngine::new(bindings, policy, CompatibilityRegistry::current())
    }

    fn restrictive_policy() -> EgressPolicy {
        EgressPolicy::new(EgressMode::Deny, [], ["203.0.113.0/24".to_owned()])
            .expect("restrictive policy")
    }

    enum FlowFixture {
        Denied(RouteDenial),
        Tls(&'static str, u16, bool),
        TlsWithCipher(&'static str, u16, u16),
        OtherTcp(u16),
    }

    impl FlowFixture {
        fn build(self, policy: &EgressPolicy) -> BuiltFlow {
            match self {
                Self::Denied(denial) => BuiltFlow {
                    denial: Some(denial),
                    route: None,
                    protocol: TcpProtocol::OtherTcp,
                },
                Self::Tls(host, port, ech) => build_admitted(policy, tls(host, ech, 0x1301), port),
                Self::TlsWithCipher(host, port, cipher) => {
                    build_admitted(policy, tls(host, false, cipher), port)
                }
                Self::OtherTcp(port) => build_admitted(policy, TcpProtocol::OtherTcp, port),
            }
        }
    }

    struct BuiltFlow {
        denial: Option<RouteDenial>,
        route: Option<AuthorizedRoute>,
        protocol: TcpProtocol,
    }

    impl BuiltFlow {
        fn flow(&self, secret_route: SecretRoute) -> TlsPolicyFlow<'_> {
            match (&self.denial, &self.route) {
                (Some(denial), None) => TlsPolicyFlow::Denied(denial),
                (None, Some(route)) => TlsPolicyFlow::Admitted {
                    route,
                    protocol: &self.protocol,
                    secret_route,
                },
                _ => panic!("invalid test flow"),
            }
        }

        fn admitted(&self, secret_route: SecretRoute) -> TlsPolicyFlow<'_> {
            let route = self.route();
            TlsPolicyFlow::Admitted {
                route,
                protocol: &self.protocol,
                secret_route,
            }
        }

        fn route(&self) -> &AuthorizedRoute {
            self.route.as_ref().expect("admitted route")
        }
    }

    fn build_admitted(policy: &EgressPolicy, protocol: TcpProtocol, port: u16) -> BuiltFlow {
        let destination = hiloop_core::capture::OriginalDestination::new(
            "203.0.113.10".parse().expect("test IP"),
            port,
        )
        .expect("test destination");
        let dns = FakeDns::default().answer("hidden.example.com", "203.0.113.10", true);
        match authorize_route(policy, &dns, destination, &protocol) {
            Ok(route) => BuiltFlow {
                denial: None,
                route: Some(route),
                protocol,
            },
            Err(denial) => BuiltFlow {
                denial: Some(denial),
                route: None,
                protocol,
            },
        }
    }

    #[derive(Default)]
    struct FakeDns {
        answers: BTreeMap<String, Vec<(IpAddr, bool)>>,
    }

    impl FakeDns {
        fn answer(mut self, host: &str, address: &str, unexpired: bool) -> Self {
            self.answers
                .entry(host.to_owned())
                .or_default()
                .push((address.parse().expect("test IP"), unexpired));
            self
        }
    }

    impl DnsAnswerEvidence for FakeDns {
        fn contains_unexpired(&self, hostname: &str, address: IpAddr) -> bool {
            self.answers.get(hostname).is_some_and(|answers| {
                answers
                    .iter()
                    .any(|(answer, unexpired)| *answer == address && *unexpired)
            })
        }
    }

    fn tls(host: &str, ech: bool, cipher: u16) -> TcpProtocol {
        let mut name = vec![0];
        push_u16(&mut name, host.len());
        name.extend_from_slice(host.as_bytes());
        let mut names = Vec::new();
        push_u16(&mut names, name.len());
        names.extend_from_slice(&name);
        let mut extensions = extension(0, &names);
        if ech {
            extensions.extend_from_slice(&extension(ECH_EXTENSION, &[0, 1, 2]));
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[1; 32]);
        body.push(0);
        body.extend_from_slice(&[
            0,
            2,
            u8::try_from(cipher >> 8).expect("cipher high byte"),
            u8::try_from(cipher & 0xff).expect("cipher low byte"),
            1,
            0,
        ]);
        push_u16(&mut body, extensions.len());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, u8::try_from(body.len()).expect("small hello")];
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        push_u16(&mut record, handshake.len());
        record.extend_from_slice(&handshake);

        let ClassificationProgress::Classified(protocol) =
            classify_tcp_prefix(&record).expect("test ClientHello")
        else {
            panic!("test ClientHello was incomplete");
        };
        protocol
    }

    fn extension(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        push_u16(&mut result, usize::from(kind));
        push_u16(&mut result, payload.len());
        result.extend_from_slice(payload);
        result
    }

    fn push_u16(target: &mut Vec<u8>, value: usize) {
        let value = u16::try_from(value).expect("test value fits u16");
        target.extend_from_slice(&value.to_be_bytes());
    }
}
