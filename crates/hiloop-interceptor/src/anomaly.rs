//! Request-body anomaly inspection for intercepted outbound traffic.
//!
//! The proxy already terminates TLS and sees plaintext request bodies, so this is
//! the layer that inspects those bodies for exfiltration-shaped patterns before they
//! leave the guest. Rules evaluate the *original* request body — its true length and
//! unredacted bytes — so a capture cap set below a threshold cannot truncate a large
//! upload out of detection. Inspection is read-only: it never emits the body, so a
//! matched anomaly never carries the secret it fired on into telemetry; each match is
//! reported as low-cardinality metadata (a rule name and a size), never body content.
//! The truncated+redacted copy is what continues on to capture/telemetry.
//!
//! # Threat model — cooperative detection, not a boundary
//!
//! Like [`crate::egress`], this only sees traffic that flows through the injected
//! proxy. Hostile in-guest code can bypass the proxy entirely, so this is a
//! **defense-in-depth detection layer**, not a security perimeter. It flags
//! suspicious *well-behaved* traffic for observability and (opt-in) blocks it; the
//! un-bypassable boundary is enforced host-side, outside this process.
//!
//! # Rules
//!
//! Three config-driven heuristics, each producing one [`AnomalyFlag`] on a match:
//!
//! - [`AnomalyRule::LargeBase64Blob`] — a large body dominated by base64-alphabet
//!   characters, the shape of an encoded archive/blob being smuggled out. Gated on
//!   both a size floor ([`AnomalyConfig::with_min_base64_bytes`]) and a character ratio
//!   ([`AnomalyConfig::with_base64_ratio`]) so ordinary JSON/prose does not trip it.
//! - [`AnomalyRule::SuspiciousContentType`] — a `Content-Type` on the configured
//!   suspicious list ([`AnomalyConfig::with_suspicious_content_types`]), e.g. an
//!   `application/octet-stream` or archive type on an otherwise-text API.
//! - [`AnomalyRule::UploadShapedRequest`] — a large-bodied write (`POST`/`PUT`/
//!   `PATCH`) over [`AnomalyConfig::with_max_upload_bytes`], the shape of a bulk upload
//!   to an allowed domain.
//!
//! Detection is **audit-by-default**: a match is flagged, not blocked, unless
//! [`AnomalyConfig::with_block_on_match`] is enabled.

use bytes::Bytes;

/// Body size (bytes) at or above which a base64-dominated body is flagged. Below this
/// floor even an all-base64 body is ignored, so small encoded fields (an inline image
/// thumbnail, a signed token) do not trip the rule. Chosen well above ordinary
/// encoded-field sizes but low enough to catch an exfiltrated blob.
pub const DEFAULT_MIN_BASE64_BYTES: u64 = 64 * 1024;

/// Fraction of a body's bytes that must belong to the base64 alphabet for it to count
/// as base64-dominated. High enough that natural-language or JSON prose (which carries
/// spaces, punctuation, and non-alphanumeric structure) stays well under it, while a
/// contiguous base64 payload sits near `1.0`.
pub const DEFAULT_BASE64_RATIO: f64 = 0.95;

/// Write-request body size (bytes) at or above which the request is flagged as
/// upload-shaped. Distinct from the base64 floor: this fires on *any* large write,
/// encoded or not, to a destination the egress policy already allowed.
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 4 * 1024 * 1024;

/// Content-Type values treated as suspicious on an agent-harness egress path, where
/// the expected shape is text/JSON. A binary or archive content-type on an outbound
/// request is worth flagging. Matched case-insensitively against the media type,
/// ignoring any `; charset=…` parameters.
pub const DEFAULT_SUSPICIOUS_CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-bzip2",
];

/// Which anomaly fired. The `&'static str` [`name`](AnomalyRule::name) is what reaches
/// telemetry — a stable, low-cardinality label, never body content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyRule {
    /// A large body dominated by base64-alphabet characters.
    LargeBase64Blob,
    /// A `Content-Type` on the suspicious list.
    SuspiciousContentType,
    /// A large-bodied write request (`POST`/`PUT`/`PATCH`).
    UploadShapedRequest,
}

impl AnomalyRule {
    /// The stable telemetry label for this rule.
    pub fn name(self) -> &'static str {
        match self {
            AnomalyRule::LargeBase64Blob => "large_base64_blob",
            AnomalyRule::SuspiciousContentType => "suspicious_content_type",
            AnomalyRule::UploadShapedRequest => "upload_shaped_request",
        }
    }
}

/// One anomaly match: the rule that fired plus the observed body size that triggered
/// it. Deliberately carries no body content, so it is safe to stamp onto telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnomalyFlag {
    /// The rule that matched.
    pub rule: AnomalyRule,
    /// The original (pre-truncation) body size that drove the match, in bytes. This is
    /// the true request-body length, not the truncated captured copy — a size-based rule
    /// evaluates the real upload, so a capture cap set below a threshold cannot hide it.
    pub observed_bytes: u64,
}

/// Configurable anomaly-detection policy: the one source of truth for every rule's
/// threshold and the block toggle.
///
/// [`AnomalyConfig::default`] is **disabled** — a run that never configures anomaly
/// detection pays nothing and flags nothing. Enable it with
/// [`AnomalyConfig::enabled`] (audit-only defaults) and adjust individual thresholds
/// as needed; the un-configured fields keep their `DEFAULT_*` values.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    enabled: bool,
    block_on_match: bool,
    min_base64_bytes: u64,
    base64_ratio: f64,
    max_upload_bytes: u64,
    suspicious_content_types: Vec<String>,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_on_match: false,
            min_base64_bytes: DEFAULT_MIN_BASE64_BYTES,
            base64_ratio: DEFAULT_BASE64_RATIO,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            suspicious_content_types: DEFAULT_SUSPICIOUS_CONTENT_TYPES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }
}

impl AnomalyConfig {
    /// An enabled policy carrying every `DEFAULT_*` threshold and audit-only behavior
    /// (matches are flagged, never blocked).
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// Whether inspection runs at all. When `false`, [`inspect`](AnomalyConfig::inspect)
    /// returns no flags without examining the body, so the hot path is untouched.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a matched request is rejected (`true`) or only flagged (`false`, the
    /// default). Only meaningful when the policy [is enabled](AnomalyConfig::is_enabled).
    pub fn blocks_on_match(&self) -> bool {
        self.enabled && self.block_on_match
    }

    /// Reject a request whenever any rule matches, rather than only flagging it.
    #[must_use]
    pub fn with_block_on_match(mut self, block: bool) -> Self {
        self.block_on_match = block;
        self
    }

    /// Override the base64-blob size floor (bytes).
    #[must_use]
    pub fn with_min_base64_bytes(mut self, bytes: u64) -> Self {
        self.min_base64_bytes = bytes;
        self
    }

    /// Override the base64-alphabet character ratio. Clamped to `0.0..=1.0`.
    #[must_use]
    pub fn with_base64_ratio(mut self, ratio: f64) -> Self {
        self.base64_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Override the upload-shaped write-body size floor (bytes).
    #[must_use]
    pub fn with_max_upload_bytes(mut self, bytes: u64) -> Self {
        self.max_upload_bytes = bytes;
        self
    }

    /// Replace the suspicious content-type list. Entries are compared
    /// case-insensitively against the request media type.
    #[must_use]
    pub fn with_suspicious_content_types(
        mut self,
        content_types: impl IntoIterator<Item = String>,
    ) -> Self {
        self.suspicious_content_types = content_types
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        self
    }

    /// Inspect one request against every rule, returning each match.
    ///
    /// `method` is the request method (upper- or lower-case), `content_type` the raw
    /// `Content-Type` header value if present, and `body` the **original** request body —
    /// its full pre-truncation length and unredacted bytes. Rules deliberately evaluate
    /// the original body, never the truncated/redacted captured copy, so a capture cap
    /// (`max_capture_bytes`) set below a threshold cannot truncate a large upload out of
    /// detection. Inspection is read-only: it never emits or logs body content — only the
    /// low-cardinality [`AnomalyFlag`]s (a rule name and a size) reach telemetry.
    ///
    /// Returns an empty vec when the policy is disabled or nothing matches; the common
    /// clean-body case allocates nothing. For a body that streams through frame by
    /// frame instead of arriving whole, feed a [`BodyScan`] and call
    /// [`AnomalyConfig::evaluate`] at end-of-stream — the rules are identical.
    pub fn inspect(
        &self,
        method: &str,
        content_type: Option<&str>,
        body: &Bytes,
    ) -> Vec<AnomalyFlag> {
        if !self.enabled {
            return Vec::new();
        }
        let mut scan = BodyScan::default();
        scan.observe(body);
        self.evaluate(method, content_type, &scan)
    }

    /// Evaluate every rule against an incrementally observed body (see [`BodyScan`]).
    ///
    /// The scan must have observed the **original** body — its full pre-truncation
    /// length and unredacted bytes, counted past any capture cap — preserving the same
    /// "a capture cap cannot hide a large upload" contract as
    /// [`AnomalyConfig::inspect`].
    pub fn evaluate(
        &self,
        method: &str,
        content_type: Option<&str>,
        scan: &BodyScan,
    ) -> Vec<AnomalyFlag> {
        if !self.enabled {
            return Vec::new();
        }
        let mut flags = Vec::new();
        let body_len = scan.total_bytes;

        if self.is_suspicious_content_type(content_type) {
            flags.push(AnomalyFlag {
                rule: AnomalyRule::SuspiciousContentType,
                observed_bytes: body_len,
            });
        }
        if is_write_method(method) && body_len >= self.max_upload_bytes {
            flags.push(AnomalyFlag {
                rule: AnomalyRule::UploadShapedRequest,
                observed_bytes: body_len,
            });
        }
        if body_len >= self.min_base64_bytes && scan.is_base64_dominated(self.base64_ratio) {
            flags.push(AnomalyFlag {
                rule: AnomalyRule::LargeBase64Blob,
                observed_bytes: body_len,
            });
        }
        flags
    }

    fn is_suspicious_content_type(&self, content_type: Option<&str>) -> bool {
        let Some(content_type) = content_type else {
            return false;
        };
        let media_type = media_type_of(content_type);
        self.suspicious_content_types
            .iter()
            .any(|suspicious| suspicious.eq_ignore_ascii_case(media_type))
    }
}

/// Extract the bare media type from a `Content-Type` value, dropping any parameters
/// (`; charset=…`, `; boundary=…`) and surrounding whitespace.
fn media_type_of(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
}

/// Whether `method` is a body-carrying write (`POST`/`PUT`/`PATCH`), case-insensitive.
fn is_write_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH")
}

/// Incrementally observed body statistics — the byte counters every rule needs,
/// accumulated frame by frame so a streamed (teed) body can be evaluated at
/// end-of-stream without ever buffering it in full. Feed each chunk to
/// [`BodyScan::observe`]; evaluate with [`AnomalyConfig::evaluate`].
#[derive(Debug, Clone, Default)]
pub struct BodyScan {
    /// Total observed body bytes.
    total_bytes: u64,
    /// Observed bytes belonging to the base64 alphabet (see [`is_base64_byte`]).
    base64_alphabet_bytes: u64,
}

impl BodyScan {
    /// Fold one body chunk into the counters. O(n) over the chunk, no allocation.
    pub fn observe(&mut self, chunk: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        self.base64_alphabet_bytes = self
            .base64_alphabet_bytes
            .saturating_add(chunk.iter().filter(|byte| is_base64_byte(**byte)).count() as u64);
    }

    /// Whether at least `ratio` of the observed bytes belong to the base64 alphabet
    /// (standard and URL-safe alphabets, plus `=` padding and ASCII whitespace, which
    /// line-wrapped encoders interleave). An empty body is never base64-dominated.
    ///
    /// This is a character-ratio heuristic, not a decode: it is O(n) with no
    /// allocation, so it stays cheap on the proxy hot path, and it deliberately
    /// tolerates the whitespace real encoders emit. It over-counts a body that merely
    /// happens to be all alphanumeric, which is why the rule also gates on a size
    /// floor.
    fn is_base64_dominated(&self, ratio: f64) -> bool {
        if self.total_bytes == 0 {
            return false;
        }
        // Compare counts as an integer threshold to avoid a float division: the body is
        // base64-dominated when `alphabet >= len * ratio`. `ratio` is clamped to
        // `0.0..=1.0` at construction, so the product never exceeds `len`.
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "ratio is clamped to 0.0..=1.0, so `len as f64 * ratio` is in 0..=len and its ceil fits u64; sub-mantissa precision loss only shifts the threshold by at most one byte on multi-petabyte bodies the capture cap forbids"
        )]
        let threshold = (self.total_bytes as f64 * ratio).ceil() as u64;
        self.base64_alphabet_bytes >= threshold
    }
}

/// Whether `byte` is a member of the base64 alphabet (either alphabet), padding, or the
/// ASCII whitespace that line-wrapping encoders insert.
fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        || matches!(byte, b'\n' | b'\r' | b'\t' | b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(bytes: impl Into<Vec<u8>>) -> Bytes {
        Bytes::from(bytes.into())
    }

    /// A base64-alphabet body of exactly `len` bytes.
    fn base64_body(len: usize) -> Bytes {
        body(vec![b'A'; len])
    }

    #[test]
    fn disabled_policy_flags_nothing() {
        let policy = AnomalyConfig::default();
        assert!(!policy.is_enabled());
        let flags = policy.inspect(
            "POST",
            Some("application/octet-stream"),
            &base64_body(1024 * 1024),
        );
        assert!(flags.is_empty(), "a disabled policy must never flag");
    }

    #[test]
    fn rule_names_are_stable() {
        assert_eq!(AnomalyRule::LargeBase64Blob.name(), "large_base64_blob");
        assert_eq!(
            AnomalyRule::SuspiciousContentType.name(),
            "suspicious_content_type"
        );
        assert_eq!(
            AnomalyRule::UploadShapedRequest.name(),
            "upload_shaped_request"
        );
    }

    #[test]
    fn block_toggle_only_applies_when_enabled() {
        assert!(
            !AnomalyConfig::default()
                .with_block_on_match(true)
                .blocks_on_match()
        );
        assert!(
            AnomalyConfig::enabled()
                .with_block_on_match(true)
                .blocks_on_match()
        );
        assert!(!AnomalyConfig::enabled().blocks_on_match());
    }

    // --- large base64 blob ---

    #[test]
    fn base64_blob_flagged_at_and_above_the_floor() {
        let policy = AnomalyConfig::enabled().with_min_base64_bytes(1024);
        // Exactly at the floor is flagged (>= boundary).
        let at = policy.inspect("POST", None, &base64_body(1024));
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].rule, AnomalyRule::LargeBase64Blob);
        assert_eq!(at[0].observed_bytes, 1024);
        // Above the floor is flagged.
        assert_eq!(
            policy.inspect("POST", None, &base64_body(4096)).len(),
            1,
            "above the floor is flagged"
        );
    }

    #[test]
    fn base64_blob_not_flagged_below_the_floor() {
        let policy = AnomalyConfig::enabled().with_min_base64_bytes(1024);
        // One byte under the floor: not flagged.
        let flags = policy.inspect("POST", None, &base64_body(1023));
        assert!(
            !flags.iter().any(|f| f.rule == AnomalyRule::LargeBase64Blob),
            "below the floor must not flag base64"
        );
    }

    #[test]
    fn large_binary_body_is_not_base64_dominated() {
        // A large body of non-base64 bytes (below the ratio) is not a base64 blob.
        let policy = AnomalyConfig::enabled().with_min_base64_bytes(1024);
        let binary = body(vec![0x00u8; 4096]);
        let flags = policy.inspect("POST", None, &binary);
        assert!(
            !flags.iter().any(|f| f.rule == AnomalyRule::LargeBase64Blob),
            "raw binary is not base64-dominated"
        );
    }

    #[test]
    fn json_prose_is_not_base64_dominated() {
        // A large JSON body has enough punctuation/whitespace-structure that only the
        // whitespace counts toward the alphabet; the braces/quotes/colons do not, so it
        // stays under the ratio.
        let policy = AnomalyConfig::enabled().with_min_base64_bytes(16);
        let mut json = Vec::new();
        for _ in 0..2000 {
            json.extend_from_slice(br#"{"k":"v"},"#);
        }
        let flags = policy.inspect("POST", Some("application/json"), &body(json));
        assert!(
            !flags.iter().any(|f| f.rule == AnomalyRule::LargeBase64Blob),
            "structured JSON must not read as a base64 blob"
        );
    }

    #[test]
    fn line_wrapped_base64_still_counts() {
        // PEM-style 64-char lines with newlines are still base64-dominated.
        let policy = AnomalyConfig::enabled().with_min_base64_bytes(64);
        let mut wrapped = Vec::new();
        for _ in 0..4 {
            wrapped.extend_from_slice(&[b'A'; 64]);
            wrapped.push(b'\n');
        }
        let flags = policy.inspect("POST", None, &body(wrapped));
        assert!(
            flags.iter().any(|f| f.rule == AnomalyRule::LargeBase64Blob),
            "line-wrapped base64 must still be detected"
        );
    }

    #[test]
    fn base64_ratio_is_configurable_and_clamped() {
        // A body that is 50% base64 chars: flagged at ratio 0.5, not at 0.95.
        let mut half = Vec::new();
        for _ in 0..1024 {
            half.push(b'A');
            half.push(0x00);
        }
        let lax = AnomalyConfig::enabled()
            .with_min_base64_bytes(16)
            .with_base64_ratio(0.5);
        assert!(
            lax.inspect("POST", None, &body(half.clone()))
                .iter()
                .any(|f| f.rule == AnomalyRule::LargeBase64Blob)
        );
        let strict = AnomalyConfig::enabled()
            .with_min_base64_bytes(16)
            .with_base64_ratio(0.95);
        assert!(
            !strict
                .inspect("POST", None, &body(half))
                .iter()
                .any(|f| f.rule == AnomalyRule::LargeBase64Blob)
        );
        // Out-of-range ratios clamp rather than panic on the NaN/compare path.
        assert!(
            AnomalyConfig::enabled()
                .with_min_base64_bytes(1)
                .with_base64_ratio(-1.0)
                .inspect("POST", None, &base64_body(4))
                .iter()
                .any(|f| f.rule == AnomalyRule::LargeBase64Blob),
            "a clamped-to-0 ratio flags any non-empty body"
        );
    }

    // --- suspicious content-type ---

    #[test]
    fn suspicious_content_type_cases() {
        let policy = AnomalyConfig::enabled();
        // (content_type, is_suspicious) — parametrized over the default list + allowed.
        let cases = [
            ("application/octet-stream", true),
            ("application/zip", true),
            ("application/gzip", true),
            // Case-insensitive and parameter-tolerant.
            ("Application/Octet-Stream; charset=binary", true),
            // Ordinary API content-types are allowed.
            ("application/json", false),
            ("application/json; charset=utf-8", false),
            ("text/plain", false),
        ];
        for (content_type, expected) in cases {
            let flagged = policy
                .inspect("POST", Some(content_type), &body(b"x".to_vec()))
                .iter()
                .any(|f| f.rule == AnomalyRule::SuspiciousContentType);
            assert_eq!(flagged, expected, "content-type: {content_type}");
        }
    }

    #[test]
    fn absent_content_type_is_not_suspicious() {
        let policy = AnomalyConfig::enabled();
        let flags = policy.inspect("POST", None, &body(b"x".to_vec()));
        assert!(
            !flags
                .iter()
                .any(|f| f.rule == AnomalyRule::SuspiciousContentType)
        );
    }

    #[test]
    fn suspicious_content_type_list_is_configurable() {
        let policy =
            AnomalyConfig::enabled().with_suspicious_content_types(["application/pdf".to_owned()]);
        // The custom entry fires.
        assert!(
            policy
                .inspect("POST", Some("application/pdf"), &body(b"x".to_vec()))
                .iter()
                .any(|f| f.rule == AnomalyRule::SuspiciousContentType)
        );
        // A default entry no longer does (the list was replaced).
        assert!(
            !policy
                .inspect("POST", Some("application/zip"), &body(b"x".to_vec()))
                .iter()
                .any(|f| f.rule == AnomalyRule::SuspiciousContentType)
        );
    }

    // --- upload-shaped request ---

    #[test]
    fn upload_shaped_write_cases() {
        let policy = AnomalyConfig::enabled().with_max_upload_bytes(1024);
        // (method, len, is_upload) — write verbs at/above the floor flag; GET never does.
        let cases = [
            ("POST", 1024, true),  // exactly at the floor
            ("PUT", 2048, true),   // above
            ("PATCH", 4096, true), // above
            ("post", 1024, true),  // case-insensitive
            ("POST", 1023, false), // one byte under
            ("GET", 4096, false),  // reads never upload-flag
            ("DELETE", 4096, false),
        ];
        for (method, len, expected) in cases {
            let flagged = policy
                .inspect(method, None, &body(vec![0u8; len]))
                .iter()
                .any(|f| f.rule == AnomalyRule::UploadShapedRequest);
            assert_eq!(flagged, expected, "method={method} len={len}");
        }
    }

    #[test]
    fn multiple_rules_can_fire_on_one_request() {
        // A large base64 blob uploaded with a suspicious content-type trips all three.
        let policy = AnomalyConfig::enabled()
            .with_min_base64_bytes(1024)
            .with_max_upload_bytes(1024);
        let flags = policy.inspect("POST", Some("application/octet-stream"), &base64_body(4096));
        let rules: Vec<AnomalyRule> = flags.iter().map(|f| f.rule).collect();
        assert!(rules.contains(&AnomalyRule::LargeBase64Blob));
        assert!(rules.contains(&AnomalyRule::SuspiciousContentType));
        assert!(rules.contains(&AnomalyRule::UploadShapedRequest));
        assert_eq!(flags.len(), 3);
    }
}
