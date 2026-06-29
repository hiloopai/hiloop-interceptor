//! Egress policy enforcement for intercepted HTTP(S) traffic.
//!
//! The proxy can restrict which destinations the wrapped harness is allowed to
//! reach. A run configures an [`EgressPolicy`] (allow-list or deny-list of domains
//! and CIDRs); the proxy enforces it at two points — the CONNECT authority (an
//! early SNI-host check) and the decrypted request's `Host`/`:authority` (the
//! authoritative check) — and short-circuits a denied destination with a `403`.
//!
//! # Threat model — this is a COOPERATIVE control, not a sandbox boundary
//!
//! This filter sees only traffic that flows through the injected proxy. Hostile
//! in-guest code can ignore the proxy env vars, open a raw socket, or resolve and
//! connect directly, and never touch this layer at all. **It is therefore a
//! cooperative guardrail — it constrains a well-behaved harness, not an adversary.**
//! The un-bypassable egress boundary is enforced host-side (provider network /
//! firewall CIDR rules), outside this process. Treat this module as defense in
//! depth and observability, never as the security perimeter.
//!
//! # Canonicalization
//!
//! Hosts are canonicalized ([`canonicalize_host`]) before matching so that
//! equivalent spellings cannot slip past the policy. The steps run in order and
//! reject on failure: reject control characters / NUL / `%` / CR / LF / whitespace;
//! reject userinfo (`@`); split off the port; parse the host with the WHATWG URL
//! host parser (which applies IDNA UTS-46 — NFC plus IDN→punycode — and detects IP
//! literals in every notation: dotted, decimal, hex, octal, IPv6, IPv4-mapped);
//! lowercase; strip exactly one trailing dot. A host that parses as an IP literal is
//! routed to the CIDR matcher, never the domain matcher, so `2130706433`,
//! `0x7f.0.0.1`, and `[::ffff:127.0.0.1]` are all treated as the addresses they
//! denote.
//!
//! # Matching
//!
//! Domain rules are **suffix-anchored at a label boundary**: a rule `example.com`
//! matches `example.com` and `api.example.com` but never `evil-example.com`. CIDR
//! rules match by network membership (IPv4 and IPv6; an IPv4-mapped IPv6 literal is
//! normalized to its IPv4 form first). In [`EgressMode::Deny`] the decision is
//! deny-by-default and **deny-wins**: a host is allowed only if no rule matches.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use url::Host;

/// Whether the configured `domains`/`cidrs` are an allow-list or a deny-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressMode {
    /// Allow everything except destinations matched by a rule (default).
    #[default]
    Allow,
    /// Deny everything except destinations matched by a rule (deny-by-default).
    Deny,
}

impl fmt::Display for EgressMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EgressMode::Allow => f.write_str("allow"),
            EgressMode::Deny => f.write_str("deny"),
        }
    }
}

/// An egress policy: a [mode](EgressMode) plus the domain and CIDR rules it applies.
///
/// The default ([`EgressMode::Allow`] with no rules) allows all egress — a no-op, so
/// a run that never configures egress is unaffected. Rules are parsed and validated
/// once at [construction](EgressPolicy::new); malformed entries are rejected.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    mode: EgressMode,
    domains: Vec<String>,
    cidrs: Vec<IpNet>,
}

/// A canonicalized destination ready for matching: its host plus the optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    host: CanonicalHost,
    port: Option<u16>,
}

impl Destination {
    /// The canonicalized host.
    pub fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// The destination port, when one was present in the authority.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The host rendered for telemetry (punycode domain or normalized IP literal).
    pub fn host_str(&self) -> String {
        self.host.to_string()
    }
}

/// A canonicalized host: either a punycode/lowercased domain or an IP literal.
///
/// IP literals (in any source notation) are normalized to their canonical address
/// form, with an IPv4-mapped IPv6 literal folded to its IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalHost {
    /// A registrable domain name, ASCII-lowercased and punycode-encoded, with any
    /// single trailing dot stripped.
    Domain(String),
    /// An IP literal.
    Ip(IpAddr),
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalHost::Domain(domain) => f.write_str(domain),
            CanonicalHost::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Why a host failed [`canonicalize_host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalizeError {
    /// The input contained a control character, NUL, `%`, CR, LF, or whitespace.
    IllegalCharacter,
    /// The input carried userinfo (an `@`), which an authority host must not.
    Userinfo,
    /// The host was empty.
    Empty,
    /// The host did not parse as a domain or IP literal.
    Invalid,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalizeError::IllegalCharacter => {
                f.write_str("host contains a control, NUL, percent, or whitespace character")
            }
            CanonicalizeError::Userinfo => f.write_str("host must not carry userinfo"),
            CanonicalizeError::Empty => f.write_str("host is empty"),
            CanonicalizeError::Invalid => f.write_str("host is not a valid domain or IP literal"),
        }
    }
}

impl std::error::Error for CanonicalizeError {}

/// Why an [`EgressPolicy`] failed to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPolicyError {
    /// A configured domain rule was not a valid host.
    Domain { rule: String },
    /// A configured CIDR rule did not parse as an IPv4/IPv6 network.
    Cidr { rule: String },
}

impl fmt::Display for EgressPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EgressPolicyError::Domain { rule } => {
                write!(f, "invalid egress domain rule `{rule}`")
            }
            EgressPolicyError::Cidr { rule } => write!(f, "invalid egress CIDR rule `{rule}`"),
        }
    }
}

impl std::error::Error for EgressPolicyError {}

/// The outcome of evaluating a destination against an [`EgressPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDecision {
    allowed: bool,
    /// The rule that drove the decision, when a rule matched.
    rule_matched: Option<String>,
}

impl EgressDecision {
    /// Whether the destination is permitted.
    pub fn allowed(&self) -> bool {
        self.allowed
    }

    /// The matched rule, when the decision was rule-driven (vs. a default).
    pub fn rule_matched(&self) -> Option<&str> {
        self.rule_matched.as_deref()
    }
}

impl EgressPolicy {
    /// Build a policy from a mode and the raw domain/CIDR rule strings.
    ///
    /// Domain rules are canonicalized (so a rule and a request host compare on the
    /// same footing); CIDR rules are parsed as IPv4/IPv6 networks. A malformed rule
    /// is rejected rather than silently ignored, so a typo can't quietly widen
    /// (allow-list) or narrow (deny-list) the policy.
    pub fn new(
        mode: EgressMode,
        domains: impl IntoIterator<Item = String>,
        cidrs: impl IntoIterator<Item = String>,
    ) -> Result<Self, EgressPolicyError> {
        let domains = domains
            .into_iter()
            .map(|rule| match canonicalize_host(&rule) {
                // A domain rule must denote a domain; an IP belongs in `cidrs`.
                Ok(Destination {
                    host: CanonicalHost::Domain(domain),
                    ..
                }) => Ok(domain),
                _ => Err(EgressPolicyError::Domain { rule }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cidrs = cidrs
            .into_iter()
            .map(|rule| parse_cidr_rule(&rule).ok_or(EgressPolicyError::Cidr { rule }))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            mode,
            domains,
            cidrs,
        })
    }

    /// The policy mode.
    pub fn mode(&self) -> EgressMode {
        self.mode
    }

    /// Whether this policy permits everything (the default, no-op policy).
    ///
    /// An allow-list with no rules denies nothing, so enforcement can be skipped
    /// entirely on the hot path.
    pub fn is_allow_all(&self) -> bool {
        self.mode == EgressMode::Allow && self.domains.is_empty() && self.cidrs.is_empty()
    }

    /// Evaluate an already-canonicalized destination.
    ///
    /// `deny-wins, deny-by-default`: in [`EgressMode::Deny`] a destination is
    /// allowed only if no rule matches; in [`EgressMode::Allow`] it is denied only
    /// if a rule matches.
    pub fn evaluate(&self, destination: &Destination) -> EgressDecision {
        let matched = self.matching_rule(&destination.host);
        let allowed = match self.mode {
            EgressMode::Allow => matched.is_none(),
            EgressMode::Deny => matched.is_some(),
        };
        EgressDecision {
            allowed,
            rule_matched: matched,
        }
    }

    /// The first rule that matches `host`, if any (the matched rule string for the
    /// telemetry event).
    fn matching_rule(&self, host: &CanonicalHost) -> Option<String> {
        match host {
            CanonicalHost::Domain(domain) => self
                .domains
                .iter()
                .find(|rule| domain_matches(domain, rule))
                .cloned(),
            CanonicalHost::Ip(ip) => {
                let ip = normalize_ip(*ip);
                self.cidrs
                    .iter()
                    .find(|net| net.contains(&ip))
                    .map(ToString::to_string)
            }
        }
    }
}

/// Parse a CIDR rule, accepting either a network (`10.0.0.0/8`) or a bare address
/// (`127.0.0.1`, treated as a host route). IPv4-mapped IPv6 networks are normalized.
fn parse_cidr_rule(rule: &str) -> Option<IpNet> {
    if let Ok(net) = IpNet::from_str(rule) {
        return Some(normalize_net(net));
    }
    // A bare address is a /32 (v4) or /128 (v6) host route.
    let ip = IpAddr::from_str(rule).ok()?;
    Some(IpNet::from(normalize_ip(ip)))
}

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form so a v4 CIDR
/// rule matches a v4-mapped literal and vice versa.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Normalize a network whose address is an IPv4-mapped IPv6 literal to its IPv4 form.
fn normalize_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
            // A mapped /N has 96 bits of prefix; the v4 prefix is the remainder.
            Some(v4) if v6.prefix_len() >= 96 => IpNet::from(
                ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96).unwrap_or_else(|_| {
                    ipnet::Ipv4Net::new(v4, 32).expect("32 is a valid v4 prefix")
                }),
            ),
            _ => IpNet::V6(v6),
        },
        v4 @ IpNet::V4(_) => v4,
    }
}

/// Whether a canonicalized `domain` is covered by domain `rule`, anchored at a label
/// boundary: `host == rule || host.ends_with(".{rule}")`. Never a bare substring or
/// raw suffix match, so `evil-example.com` is not covered by `example.com`.
fn domain_matches(domain: &str, rule: &str) -> bool {
    domain == rule
        || domain
            .strip_suffix(rule)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Canonicalize a destination authority (`host`, `host:port`, `[ipv6]:port`) into a
/// [`Destination`] ready for matching, applying the steps documented on the module.
///
/// Rejects on the first failed step rather than guessing intent.
pub fn canonicalize_host(authority: &str) -> Result<Destination, CanonicalizeError> {
    if authority.is_empty() {
        return Err(CanonicalizeError::Empty);
    }
    // Reject anything that could let an equivalent spelling slip past the policy:
    // control chars, NUL, CR, LF, whitespace, and `%` (percent-encoding).
    if authority
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '%' || c == '\0')
    {
        return Err(CanonicalizeError::IllegalCharacter);
    }
    // An authority host must not carry userinfo.
    if authority.contains('@') {
        return Err(CanonicalizeError::Userinfo);
    }

    let lowered = authority.to_ascii_lowercase();
    let (host_part, port, bracketed) = split_host_port(&lowered)?;
    if host_part.is_empty() {
        return Err(CanonicalizeError::Empty);
    }

    // A bracketed authority is always an IPv6 literal; `Host::parse` only accepts an
    // IPv6 literal with its brackets, so parse the inner address directly.
    if bracketed {
        let v6 = std::net::Ipv6Addr::from_str(host_part).map_err(|_| CanonicalizeError::Invalid)?;
        return Ok(Destination {
            host: CanonicalHost::Ip(normalize_ip(IpAddr::V6(v6))),
            port,
        });
    }

    // The WHATWG URL host parser applies IDNA UTS-46 (NFC + IDN→punycode) and
    // detects IP literals in every notation (dotted/decimal/hex/octal/IPv6/mapped).
    let host = match Host::parse(host_part).map_err(|_| CanonicalizeError::Invalid)? {
        Host::Domain(domain) => {
            // Strip exactly one trailing dot (the FQDN root label).
            let domain = domain.strip_suffix('.').unwrap_or(&domain).to_owned();
            if domain.is_empty() {
                return Err(CanonicalizeError::Empty);
            }
            CanonicalHost::Domain(domain)
        }
        Host::Ipv4(v4) => CanonicalHost::Ip(normalize_ip(IpAddr::V4(v4))),
        Host::Ipv6(v6) => CanonicalHost::Ip(normalize_ip(IpAddr::V6(v6))),
    };

    Ok(Destination { host, port })
}

/// Split an authority into `(host, port, bracketed)`. Handles bracketed IPv6
/// (`[::1]:443`) and leaves a bare host's port `None`. `bracketed` is set when the
/// authority used the `[...]` IPv6 literal form.
fn split_host_port(authority: &str) -> Result<(&str, Option<u16>, bool), CanonicalizeError> {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6: `[addr]` or `[addr]:port`.
        let (addr, tail) = rest.split_once(']').ok_or(CanonicalizeError::Invalid)?;
        let port = match tail {
            "" => None,
            tail => Some(parse_port(
                tail.strip_prefix(':').ok_or(CanonicalizeError::Invalid)?,
            )?),
        };
        return Ok((addr, port, true));
    }
    match authority.rsplit_once(':') {
        // A single `:` separates host from port; multiple `:` without brackets is a
        // bare (non-bracketed) IPv6, which Host::parse will reject downstream.
        Some((host, port)) if !host.contains(':') => Ok((host, Some(parse_port(port)?), false)),
        _ => Ok((authority, None, false)),
    }
}

fn parse_port(port: &str) -> Result<u16, CanonicalizeError> {
    port.parse().map_err(|_| CanonicalizeError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(authority: &str) -> Destination {
        canonicalize_host(authority).expect("canonicalize")
    }

    fn policy(mode: EgressMode, domains: &[&str], cidrs: &[&str]) -> EgressPolicy {
        EgressPolicy::new(
            mode,
            domains.iter().map(|s| (*s).to_owned()),
            cidrs.iter().map(|s| (*s).to_owned()),
        )
        .expect("policy")
    }

    #[test]
    fn default_policy_allows_everything() {
        let policy = EgressPolicy::default();
        assert!(policy.is_allow_all());
        assert!(policy.evaluate(&canon("anywhere.example.com")).allowed());
    }

    #[test]
    fn allow_mode_denies_only_matched_domains() {
        let policy = policy(EgressMode::Allow, &["blocked.com"], &[]);
        assert!(!policy.evaluate(&canon("blocked.com")).allowed());
        assert!(!policy.evaluate(&canon("api.blocked.com")).allowed());
        assert!(policy.evaluate(&canon("allowed.com")).allowed());
    }

    #[test]
    fn deny_mode_allows_only_matched_and_is_deny_by_default() {
        let policy = policy(EgressMode::Deny, &["api.anthropic.com"], &[]);
        assert!(policy.evaluate(&canon("api.anthropic.com")).allowed());
        // Deny-by-default: an unlisted host is denied.
        assert!(!policy.evaluate(&canon("example.com")).allowed());
    }

    #[test]
    fn domain_match_is_anchored_at_label_boundary() {
        let policy = policy(EgressMode::Deny, &["example.com"], &[]);
        // Subdomain matches.
        assert!(policy.evaluate(&canon("api.example.com")).allowed());
        // Exact matches.
        assert!(policy.evaluate(&canon("example.com")).allowed());
        // A lookalike that merely ends with the string must NOT match.
        let decision = policy.evaluate(&canon("evil-example.com"));
        assert!(!decision.allowed());
        assert_eq!(decision.rule_matched(), None);
    }

    #[test]
    fn matched_rule_is_reported() {
        let policy = policy(EgressMode::Allow, &["blocked.com"], &[]);
        let decision = policy.evaluate(&canon("api.blocked.com"));
        assert_eq!(decision.rule_matched(), Some("blocked.com"));
    }

    #[test]
    fn cidr_membership_v4() {
        let policy = policy(EgressMode::Deny, &[], &["10.0.0.0/8"]);
        assert!(policy.evaluate(&canon("10.1.2.3")).allowed());
        assert!(!policy.evaluate(&canon("11.0.0.1")).allowed());
    }

    #[test]
    fn cidr_membership_v6() {
        let policy = policy(EgressMode::Deny, &[], &["fd00::/8"]);
        assert!(policy.evaluate(&canon("[fd00::1]")).allowed());
        assert!(!policy.evaluate(&canon("[fe80::1]")).allowed());
    }

    #[test]
    fn ipv4_mapped_v6_matches_v4_cidr() {
        let policy = policy(EgressMode::Deny, &[], &["127.0.0.0/8"]);
        // `::ffff:127.0.0.1` must be treated as the v4 address it maps to.
        assert!(policy.evaluate(&canon("[::ffff:127.0.0.1]")).allowed());
    }

    #[test]
    fn bare_address_cidr_rule_is_a_host_route() {
        let policy = policy(EgressMode::Deny, &[], &["169.254.169.254"]);
        assert!(policy.evaluate(&canon("169.254.169.254")).allowed());
        assert!(!policy.evaluate(&canon("169.254.169.255")).allowed());
    }

    // --- canonicalization-bypass cases ---

    #[test]
    fn rejects_null_byte() {
        assert_eq!(
            canonicalize_host("exam\0ple.com"),
            Err(CanonicalizeError::IllegalCharacter)
        );
    }

    #[test]
    fn rejects_percent_encoding() {
        assert_eq!(
            canonicalize_host("examp%6ce.com"),
            Err(CanonicalizeError::IllegalCharacter)
        );
    }

    #[test]
    fn rejects_crlf_and_whitespace() {
        for bad in ["a\r\nb.com", "ex ample.com", "host\t.com"] {
            assert_eq!(
                canonicalize_host(bad),
                Err(CanonicalizeError::IllegalCharacter),
                "input: {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_userinfo() {
        assert_eq!(
            canonicalize_host("user@example.com"),
            Err(CanonicalizeError::Userinfo)
        );
        assert_eq!(
            canonicalize_host("user:pass@example.com"),
            Err(CanonicalizeError::Userinfo)
        );
    }

    #[test]
    fn uppercase_is_lowercased() {
        assert_eq!(
            canon("API.Example.COM").host(),
            &CanonicalHost::Domain("api.example.com".to_owned())
        );
    }

    #[test]
    fn idn_is_punycoded() {
        // Fullwidth "EXAMPLE.com" → ascii via IDNA UTS-46.
        assert_eq!(
            canon("\u{ff25}\u{ff38}\u{ff21}\u{ff2d}\u{ff30}\u{ff2c}\u{ff25}.com").host(),
            &CanonicalHost::Domain("example.com".to_owned())
        );
        // A Unicode label canonicalizes to its xn-- punycode form.
        assert_eq!(
            canon("\u{1f4a9}.example").host(),
            &CanonicalHost::Domain("xn--ls8h.example".to_owned())
        );
    }

    #[test]
    fn single_trailing_dot_is_stripped() {
        assert_eq!(
            canon("example.com.").host(),
            &CanonicalHost::Domain("example.com".to_owned())
        );
        // Stripping is exactly one dot; the policy still matches the fqdn-with-dot.
        let policy = policy(EgressMode::Deny, &["example.com"], &[]);
        assert!(policy.evaluate(&canon("example.com.")).allowed());
    }

    #[test]
    fn ip_in_every_notation_routes_to_cidr() {
        let policy = policy(EgressMode::Deny, &[], &["127.0.0.0/8"]);
        // dotted, decimal, hex, octal — all the same loopback address.
        for spelling in ["127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1"] {
            let dest = canon(spelling);
            assert!(
                matches!(dest.host(), CanonicalHost::Ip(_)),
                "{spelling} must be an IP"
            );
            assert!(
                policy.evaluate(&dest).allowed(),
                "{spelling} must match the v4 CIDR"
            );
        }
    }

    #[test]
    fn ip_literal_never_matches_a_domain_rule() {
        // An IP host only ever takes the CIDR path: a deny-list with a domain rule but
        // no CIDR rule must (deny-by-default) deny the IP, never "match" the domain.
        let policy = policy(EgressMode::Deny, &["example.com"], &[]);
        let decision = policy.evaluate(&canon("127.0.0.1"));
        assert!(!decision.allowed());
        assert_eq!(decision.rule_matched(), None);
    }

    #[test]
    fn port_is_parsed_and_kept() {
        let dest = canon("example.com:8443");
        assert_eq!(dest.port(), Some(8443));
        assert_eq!(
            dest.host(),
            &CanonicalHost::Domain("example.com".to_owned())
        );

        let v6 = canon("[::1]:443");
        assert_eq!(v6.port(), Some(443));
        assert_eq!(
            v6.host(),
            &CanonicalHost::Ip("::1".parse().expect("v6 literal"))
        );
    }

    #[test]
    fn empty_host_is_rejected() {
        assert_eq!(canonicalize_host(""), Err(CanonicalizeError::Empty));
        assert_eq!(canonicalize_host(":443"), Err(CanonicalizeError::Empty));
    }

    #[test]
    fn invalid_port_is_rejected() {
        assert_eq!(
            canonicalize_host("example.com:notaport"),
            Err(CanonicalizeError::Invalid)
        );
    }

    #[test]
    fn policy_rejects_malformed_rules() {
        assert!(matches!(
            EgressPolicy::new(EgressMode::Deny, ["bad host".to_owned()], []),
            Err(EgressPolicyError::Domain { .. })
        ));
        assert!(matches!(
            EgressPolicy::new(EgressMode::Deny, [], ["999.0.0.0/8".to_owned()]),
            Err(EgressPolicyError::Cidr { .. })
        ));
        // An IP in the domain list is rejected (it belongs in cidrs).
        assert!(matches!(
            EgressPolicy::new(EgressMode::Deny, ["10.0.0.1".to_owned()], []),
            Err(EgressPolicyError::Domain { .. })
        ));
    }

    #[test]
    fn mode_displays_as_lowercase() {
        assert_eq!(EgressMode::Allow.to_string(), "allow");
        assert_eq!(EgressMode::Deny.to_string(), "deny");
    }
}
