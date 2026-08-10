//! Capture-side secret redaction.
//!
//! This module scrubs the *captured copy* of request and response bodies **before**
//! it is persisted to telemetry (events) or the blob store; it never touches the bytes
//! forwarded to the origin. Redaction is on by default ([`RedactionPolicy::default`])
//! and can be disabled for a run.
//!
//! Bodies are scrubbed against a conservative set of high-confidence secret patterns
//! ([`redact_body`]): bearer tokens and obvious API-key formats. The proxy buffers the
//! captured copy of each body (up to the capture cap) and redacts it once before
//! writing the blob, so a match is caught even when it straddles two response frames.
//!
//! Scope and limits — this is best-effort, not a proof of absence:
//! - only a fixed set of secret patterns is matched; secrets in an unrecognized format
//!   pass through;
//! - bytes beyond the proxy's capture cap (a finite default, configurable, bounding
//!   interceptor memory) are never captured, so they are neither persisted nor scanned;
//! - bodies are telemetry-only (never forwarded), so a rare false positive corrupts a
//!   captured copy at worst; the patterns stay deliberately narrow to avoid that.
//!
//! The proxy does not persist raw headers into telemetry, so headers need no scrubbing
//! today. Every match is replaced with [`REDACTION_PLACEHOLDER`].

use std::sync::LazyLock;

use bytes::Bytes;
use regex::bytes::{Regex, RegexSet};

/// Replacement written in place of any redacted secret.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

/// High-confidence secret body patterns. Conservative on purpose: each anchors on a
/// distinctive credential shape and matches only token-legal characters, so the
/// surrounding bytes (JSON `","}` punctuation, whitespace, quotes) survive untouched.
///
/// - `Bearer <token>` — RFC 6750 authorization values that leak into JSON/logs. The
///   token char class is restricted to base64url/JWT characters so a greedy `\S+`
///   can't swallow the rest of a JSON object after the token.
/// - `sk-…` / `hil_…` — provider/hiloop key prefixes, anchored on a `\b` word
///   boundary so the prefix isn't matched mid-word (e.g. `task-name`, `disk-space`);
///   the trailing char class stops at the closing quote/brace of a JSON string value.
/// - `AKIA[0-9A-Z]{16}` — AWS access key id, a fixed-width all-caps format.
const BODY_PATTERNS: &[&str] = &[
    r"(?i)Bearer\s+[A-Za-z0-9._+/=\-]+",
    r"\bsk-[A-Za-z0-9_-]+",
    r"\bhil_[A-Za-z0-9_-]+",
    r"AKIA[0-9A-Z]{16}",
];

/// One compiled regex per [`BODY_PATTERNS`] entry, plus a [`RegexSet`] to skip the
/// per-pattern replace passes entirely when a body contains no secrets (the common
/// case on the proxy hot path).
struct BodyMatcher {
    set: RegexSet,
    patterns: Vec<Regex>,
}

static BODY_MATCHER: LazyLock<BodyMatcher> = LazyLock::new(|| {
    let set = RegexSet::new(BODY_PATTERNS).expect("body redaction patterns must compile");
    let patterns = BODY_PATTERNS
        .iter()
        .map(|p| Regex::new(p).expect("body redaction pattern must compile"))
        .collect();
    BodyMatcher { set, patterns }
});

/// Whether and how captured data is scrubbed before it is persisted.
///
/// `Default` is **enabled**: redaction is on unless a run explicitly opts out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionPolicy {
    enabled: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl RedactionPolicy {
    /// Redaction enabled (the default).
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Redaction disabled — captured data is persisted verbatim.
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Redact secret patterns from a captured body, returning the scrubbed bytes.
    ///
    /// A no-op (returns the input unchanged) when the policy is disabled or no
    /// pattern matches, so the common hot-path case allocates nothing.
    #[must_use]
    pub fn redact_body(self, body: Bytes) -> Bytes {
        if !self.enabled {
            return body;
        }
        redact_body(body)
    }
}

/// Scrub every `BODY_PATTERNS` match from `body`, replacing each with
/// [`REDACTION_PLACEHOLDER`]. Returns the input untouched when nothing matches.
#[must_use]
pub fn redact_body(body: Bytes) -> Bytes {
    let matcher = &*BODY_MATCHER;
    if !matcher.set.is_match(&body) {
        return body;
    }

    let mut scrubbed = body.to_vec();
    for pattern in &matcher.patterns {
        if pattern.is_match(&scrubbed) {
            scrubbed = pattern
                .replace_all(&scrubbed, REDACTION_PLACEHOLDER.as_bytes())
                .into_owned();
        }
    }
    Bytes::from(scrubbed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(input: &str) -> String {
        let out = redact_body(Bytes::from(input.to_owned()));
        String::from_utf8(out.to_vec()).expect("utf8")
    }

    #[test]
    fn default_policy_is_enabled() {
        assert!(RedactionPolicy::default().is_enabled());
    }

    #[test]
    fn disabled_policy_leaves_body_untouched() {
        let body = Bytes::from_static(b"Bearer supersecret");
        let out = RedactionPolicy::disabled().redact_body(body.clone());
        assert_eq!(out, body);
    }

    #[test]
    fn enabled_policy_redacts_body() {
        let out = RedactionPolicy::enabled().redact_body(Bytes::from_static(b"Bearer supersecret"));
        assert_eq!(out.as_ref(), b"[REDACTED]");
    }

    #[test]
    fn clean_body_is_returned_unchanged() {
        let body = Bytes::from_static(b"{\"model\":\"claude\",\"prompt\":\"hello world\"}");
        let out = redact_body(body.clone());
        assert_eq!(out, body, "no allocation/change when nothing matches");
    }

    #[test]
    fn bearer_token_is_redacted() {
        assert_eq!(
            redact("Authorization: Bearer abc.def.ghi"),
            "Authorization: [REDACTED]"
        );
    }

    #[test]
    fn bearer_is_case_insensitive() {
        assert_eq!(redact("bearer abc123"), "[REDACTED]");
    }

    #[test]
    fn bearer_mid_json_body_redacts_only_the_token() {
        // Regression: a greedy `\S+` ate the trailing `","model":"x"}`, dropping the
        // rest of the body. The token char class must stop at the closing quote.
        assert_eq!(
            redact(r#"{"auth":"Bearer abc.def-ghi_123","model":"x"}"#),
            r#"{"auth":"[REDACTED]","model":"x"}"#
        );
    }

    #[test]
    fn bearer_jwt_token_is_fully_redacted() {
        // A JWT (base64url segments joined by `.`) is all token-legal, so the whole
        // token is replaced and nothing after the trailing space survives as part of it.
        assert_eq!(
            redact("Authorization: Bearer eyJhbGc.eyJzdWI.SflKxwRJ done"),
            "Authorization: [REDACTED] done"
        );
    }

    #[test]
    fn redacts_token_inside_json_value() {
        assert_eq!(
            redact("{\"key\":\"sk-ant-api03-XYZ123\"}"),
            "{\"key\":\"[REDACTED]\"}"
        );
    }

    #[test]
    fn redacts_multiple_secrets_in_one_body() {
        let out = redact("first sk-aaa then AKIA0123456789ABCDEF done");
        assert_eq!(out, "first [REDACTED] then [REDACTED] done");
    }

    #[test]
    fn secret_pattern_cases() {
        // (input, expected) — parametrized over the supported key formats.
        let cases = [
            ("sk-abc123DEF", "[REDACTED]"),
            ("hil_live_abc123", "[REDACTED]"),
            ("AKIAIOSFODNN7EXAMPLE", "[REDACTED]"),
            ("Bearer x", "[REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected, "input: {input}");
        }
    }

    #[test]
    fn conservative_patterns_do_not_eat_ordinary_prose() {
        // "sk" alone, a bare "AKIA" prefix without the 16-char body, and the word
        // "bearer" with no token must survive untouched.
        let prose = "the basketball score; AKIA short; just bearer";
        assert_eq!(redact(prose), prose);
    }

    #[test]
    fn key_prefixes_do_not_match_mid_word() {
        // The `\b` anchor keeps `sk-`/`hil_` from matching inside ordinary hyphenated
        // words; a standalone key (boundary before the prefix) is still redacted.
        let prose = "task-name, risk-level, disk-space and a while_loop are fine";
        assert_eq!(redact(prose), prose);
        assert_eq!(redact("key=sk-live-abc123"), "key=[REDACTED]");
    }
}
