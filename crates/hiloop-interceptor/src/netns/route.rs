//! Routing-identity normalization and destination-pinned egress admission.

use std::net::{IpAddr, SocketAddr};

use hiloop_core::capture::OriginalDestination;

use crate::egress::{
    CanonicalHost, CanonicalizeError, Destination, EgressDecision, EgressMode, EgressPolicy,
    canonicalize_host,
};

use super::TcpProtocol;

/// Exact DNS evidence returned to the workload by the run-scoped resolver.
pub trait DnsAnswerEvidence: Send + Sync {
    /// Whether `address` is in the exact, unexpired answer set returned for `hostname`.
    fn contains_unexpired(&self, hostname: &str, address: IpAddr) -> bool;
}

/// Fail-closed evidence provider used before the W6 DNS tracker is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDnsAnswerEvidence;

impl DnsAnswerEvidence for NoDnsAnswerEvidence {
    fn contains_unexpired(&self, _hostname: &str, _address: IpAddr) -> bool {
        false
    }
}

/// Source of the normalized identity used for route authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingIdentitySource {
    /// Cleartext HTTP `Host` authority.
    HttpHost,
    /// Visible TLS SNI.
    TlsServerName,
    /// Original transport IP because no application identity was required.
    OriginalDestination,
}

/// A route that passed policy and destination reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRoute {
    original_destination: OriginalDestination,
    identity: Destination,
    source: RoutingIdentitySource,
}

impl AuthorizedRoute {
    /// Authoritative transport destination recovered from the accepted socket.
    pub fn original_destination(&self) -> OriginalDestination {
        self.original_destination
    }

    /// Canonical identity against which policy was evaluated.
    pub fn identity(&self) -> &Destination {
        &self.identity
    }

    /// Metadata source that supplied [`Self::identity`].
    pub fn identity_source(&self) -> RoutingIdentitySource {
        self.source
    }
}

/// Why a flow was denied before an upstream connection was opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteDenial {
    /// Restrictive policy could not observe a trustworthy application identity.
    #[error("egress identity is unavailable")]
    IdentityUnavailable,
    /// Visible routing metadata was not a valid authority.
    #[error("invalid routing identity: {source}")]
    InvalidIdentity {
        /// Canonicalization failure.
        source: CanonicalizeError,
    },
    /// Visible identity did not reconcile with the original destination.
    #[error("routing identity does not match the original destination")]
    DestinationMismatch,
    /// The configured egress policy denied the reconciled route.
    #[error("egress policy denied the route")]
    PolicyDenied {
        /// Rule that drove the decision, when one matched.
        rule_matched: Option<String>,
    },
}

/// Normalize application identity and apply egress policy before upstream I/O.
pub fn authorize_route(
    policy: &EgressPolicy,
    dns: &dyn DnsAnswerEvidence,
    original_destination: OriginalDestination,
    protocol: &TcpProtocol,
) -> Result<AuthorizedRoute, RouteDenial> {
    let original_identity = canonicalize_host(
        &SocketAddr::new(original_destination.ip(), original_destination.port()).to_string(),
    )
    .map_err(|source| RouteDenial::InvalidIdentity { source })?;
    let Some((identity, source)) = visible_identity(policy, original_destination, protocol)? else {
        return authorize_original(policy, original_destination, original_identity);
    };

    match identity.host() {
        CanonicalHost::Ip(_) => {
            if identity.host() != original_identity.host() {
                return Err(RouteDenial::DestinationMismatch);
            }
            require_policy(policy, &identity)?;
        }
        CanonicalHost::Domain(hostname) => {
            if !policy.is_allow_all() {
                let decision = policy.evaluate(&identity);
                match policy.mode() {
                    EgressMode::Deny if decision.allowed() => {
                        if !dns.contains_unexpired(hostname, original_destination.ip()) {
                            return Err(RouteDenial::DestinationMismatch);
                        }
                    }
                    EgressMode::Allow if !decision.allowed() => {
                        return Err(policy_denial(&decision));
                    }
                    EgressMode::Allow | EgressMode::Deny => {
                        require_policy(policy, &original_identity)?;
                    }
                }
            }
        }
    }

    Ok(AuthorizedRoute {
        original_destination,
        identity,
        source,
    })
}

fn visible_identity(
    policy: &EgressPolicy,
    original_destination: OriginalDestination,
    protocol: &TcpProtocol,
) -> Result<Option<(Destination, RoutingIdentitySource)>, RouteDenial> {
    let (authority, source) = match protocol {
        TcpProtocol::TlsClientHello(hello) if hello.encrypted_client_hello() => {
            return if policy.is_allow_all() {
                Ok(None)
            } else {
                Err(RouteDenial::IdentityUnavailable)
            };
        }
        TcpProtocol::TlsClientHello(hello) => {
            (hello.server_name(), RoutingIdentitySource::TlsServerName)
        }
        TcpProtocol::CleartextHttp(http) => (http.authority(), RoutingIdentitySource::HttpHost),
        TcpProtocol::OtherTcp => (None, RoutingIdentitySource::OriginalDestination),
    };
    let Some(authority) = authority else {
        return if policy.is_allow_all() {
            Ok(None)
        } else {
            Err(RouteDenial::IdentityUnavailable)
        };
    };
    let identity =
        canonicalize_host(authority).map_err(|source| RouteDenial::InvalidIdentity { source })?;
    if identity
        .port()
        .is_some_and(|port| port != original_destination.port())
    {
        return Err(RouteDenial::DestinationMismatch);
    }
    Ok(Some((
        identity.with_default_port(original_destination.port()),
        source,
    )))
}

fn authorize_original(
    policy: &EgressPolicy,
    original_destination: OriginalDestination,
    original_identity: Destination,
) -> Result<AuthorizedRoute, RouteDenial> {
    require_policy(policy, &original_identity)?;
    Ok(AuthorizedRoute {
        original_destination,
        identity: original_identity,
        source: RoutingIdentitySource::OriginalDestination,
    })
}

fn require_policy(policy: &EgressPolicy, identity: &Destination) -> Result<(), RouteDenial> {
    let decision = policy.evaluate(identity);
    if decision.allowed() {
        Ok(())
    } else {
        Err(policy_denial(&decision))
    }
}

fn policy_denial(decision: &EgressDecision) -> RouteDenial {
    RouteDenial::PolicyDenied {
        rule_matched: decision.rule_matched().map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::egress::{CanonicalHost, EgressMode};

    use super::*;
    use crate::netns::{ClassificationProgress, classify_tcp_prefix};

    const ECH_EXTENSION: u16 = 0xfe0d;

    #[derive(Default)]
    struct FakeDnsEvidence {
        answers: BTreeMap<String, Vec<(IpAddr, bool)>>,
    }

    impl FakeDnsEvidence {
        fn answer(mut self, host: &str, address: &str, unexpired: bool) -> Self {
            self.answers
                .entry(host.to_owned())
                .or_default()
                .push((address.parse().expect("test IP address"), unexpired));
            self
        }
    }

    impl DnsAnswerEvidence for FakeDnsEvidence {
        fn contains_unexpired(&self, hostname: &str, address: IpAddr) -> bool {
            self.answers.get(hostname).is_some_and(|answers| {
                answers
                    .iter()
                    .any(|(answer, unexpired)| *answer == address && *unexpired)
            })
        }
    }

    #[test]
    fn hostname_grant_requires_exact_unexpired_dns_answer() {
        let policy = policy(EgressMode::Deny, &["api.example.com"], &[]);
        let original = destination("203.0.113.10", 443);
        let protocol = tls("api.example.com", false);

        for dns in [
            FakeDnsEvidence::default(),
            FakeDnsEvidence::default().answer("api.example.com", "203.0.113.10", false),
            FakeDnsEvidence::default().answer("api.example.com", "203.0.113.11", true),
        ] {
            assert_eq!(
                authorize_route(&policy, &dns, original, &protocol),
                Err(RouteDenial::DestinationMismatch)
            );
        }

        let dns = FakeDnsEvidence::default()
            .answer("api.example.com", "203.0.113.11", true)
            .answer("api.example.com", "203.0.113.10", true);
        let route = authorize_route(&policy, &dns, original, &protocol).expect("exact DNS answer");
        assert_eq!(route.identity().host_str(), "api.example.com");
        assert_eq!(
            route.identity_source(),
            RoutingIdentitySource::TlsServerName
        );
    }

    #[test]
    fn shared_ip_never_overrides_visible_identity() {
        let policy = policy(EgressMode::Deny, &["allowed.example.com"], &[]);
        let original = destination("203.0.113.10", 443);
        let dns = FakeDnsEvidence::default()
            .answer("allowed.example.com", "203.0.113.10", true)
            .answer("blocked.example.com", "203.0.113.10", true);

        assert_eq!(
            authorize_route(&policy, &dns, original, &tls("blocked.example.com", false)),
            Err(RouteDenial::PolicyDenied { rule_matched: None })
        );
    }

    #[test]
    fn http_host_is_canonicalized_and_port_pinned() {
        let policy = EgressPolicy::default();
        let original = destination("127.0.0.1", 8080);
        let route = authorize_route(
            &policy,
            &NoDnsAnswerEvidence,
            original,
            &http(Some("ExAmPle.COM.:8080")),
        )
        .expect("allow-all HTTP route");
        assert_eq!(route.identity().host_str(), "example.com");
        assert_eq!(route.identity().port(), Some(8080));
        assert_eq!(route.identity_source(), RoutingIdentitySource::HttpHost);

        assert_eq!(
            authorize_route(
                &policy,
                &NoDnsAnswerEvidence,
                original,
                &http(Some("example.com:8081")),
            ),
            Err(RouteDenial::DestinationMismatch)
        );
    }

    #[test]
    fn ip_literal_identity_must_equal_original_destination() {
        let policy = EgressPolicy::default();
        let original = destination("203.0.113.10", 443);
        assert!(
            authorize_route(
                &policy,
                &NoDnsAnswerEvidence,
                original,
                &http(Some("203.0.113.10")),
            )
            .is_ok()
        );
        assert_eq!(
            authorize_route(
                &policy,
                &NoDnsAnswerEvidence,
                original,
                &http(Some("203.0.113.11")),
            ),
            Err(RouteDenial::DestinationMismatch)
        );
    }

    #[test]
    fn restrictive_policy_denies_ech_missing_identity_and_opaque_tcp() {
        let policy = policy(EgressMode::Deny, &[], &["203.0.113.0/24"]);
        let original = destination("203.0.113.10", 443);
        for protocol in [
            tls("public.example.com", true),
            http(None),
            TcpProtocol::OtherTcp,
        ] {
            assert_eq!(
                authorize_route(&policy, &NoDnsAnswerEvidence, original, &protocol),
                Err(RouteDenial::IdentityUnavailable)
            );
        }
    }

    #[test]
    fn cidr_grant_applies_to_original_ip_without_inventing_a_hostname() {
        let policy = policy(EgressMode::Deny, &[], &["203.0.113.0/24"]);
        let original = destination("203.0.113.10", 8443);
        let route = authorize_route(
            &policy,
            &NoDnsAnswerEvidence,
            original,
            &http(Some("unlisted.example.com")),
        )
        .expect("CIDR-authorized original destination");
        assert_eq!(route.identity().host_str(), "unlisted.example.com");
    }

    #[test]
    fn allow_all_admits_opaque_tcp_as_the_original_destination() {
        let original = destination("2001:db8::42", 22);
        let route = authorize_route(
            &EgressPolicy::default(),
            &NoDnsAnswerEvidence,
            original,
            &TcpProtocol::OtherTcp,
        )
        .expect("observation-only opaque TCP");
        assert_eq!(route.identity().host(), &CanonicalHost::Ip(original.ip()));
        assert_eq!(route.identity().port(), Some(22));
        assert_eq!(
            route.identity_source(),
            RoutingIdentitySource::OriginalDestination
        );
    }

    fn policy(mode: EgressMode, domains: &[&str], cidrs: &[&str]) -> EgressPolicy {
        EgressPolicy::new(
            mode,
            domains.iter().map(|value| (*value).to_owned()),
            cidrs.iter().map(|value| (*value).to_owned()),
        )
        .expect("test policy")
    }

    fn destination(ip: &str, port: u16) -> OriginalDestination {
        OriginalDestination::new(ip.parse().expect("test IP"), port).expect("test destination")
    }

    fn http(authority: Option<&str>) -> TcpProtocol {
        let host = authority.map_or(String::new(), |value| format!("Host: {value}\r\n"));
        let bytes = format!("GET / HTTP/1.1\r\n{host}\r\n");
        classified(bytes.as_bytes())
    }

    fn tls(server_name: &str, ech: bool) -> TcpProtocol {
        let mut name = vec![0];
        push_u16(&mut name, server_name.len());
        name.extend_from_slice(server_name.as_bytes());
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
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        push_u16(&mut body, extensions.len());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, u8::try_from(body.len()).expect("small hello")];
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        push_u16(&mut record, handshake.len());
        record.extend_from_slice(&handshake);
        classified(&record)
    }

    fn classified(bytes: &[u8]) -> TcpProtocol {
        let ClassificationProgress::Classified(protocol) =
            classify_tcp_prefix(bytes).expect("test protocol")
        else {
            panic!("test prefix did not classify");
        };
        protocol
    }

    fn extension(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut extension = kind.to_be_bytes().to_vec();
        push_u16(&mut extension, payload.len());
        extension.extend_from_slice(payload);
        extension
    }

    fn push_u16(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend_from_slice(
            &u16::try_from(value)
                .expect("small test value")
                .to_be_bytes(),
        );
    }
}
