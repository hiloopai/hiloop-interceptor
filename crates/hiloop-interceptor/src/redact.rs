//! Capture-side secret redaction.
//!
//! This module scrubs the *captured copy* of request and response bodies **before**
//! it is persisted to telemetry (events) or the blob store; it never touches the bytes
//! forwarded to the origin. Redaction is on by default ([`RedactionPolicy::default`])
//! and can be disabled for a run.
//!
//! Bodies are scrubbed against a conservative set of high-confidence credential detectors
//! ([`redact_body`]). The proxy buffers the
//! captured copy of each body (up to the capture cap) and redacts it once before
//! writing the blob, so a match is caught even when it straddles two response frames.
//!
//! Scope and limits — this is best-effort, not a proof of absence:
//! - only recognized credential shapes are matched; secrets in an unrecognized format
//!   pass through;
//! - binary bytes are preserved, while recognized credentials in adjacent valid UTF-8
//!   text runs are still scrubbed;
//! - bytes beyond the proxy's capture cap (a finite default, configurable, bounding
//!   interceptor memory) are never captured, so they are neither persisted nor scanned;
//! - bodies are telemetry-only (never forwarded), so a rare false positive corrupts a
//!   captured copy at worst; the enabled detector set stays deliberately narrow to avoid that.
//!
//! The proxy does not persist raw headers into telemetry, so headers need no scrubbing
//! today. Every match is replaced with [`REDACTION_PLACEHOLDER`].

use std::sync::LazyLock;

use bytes::Bytes;
use leakguard::detectors::{
    AwsAccessKey, AzureConnectionString, DiscordToken, GitHubToken, GoogleApiKey, Jwt, OpenAiKey,
    PrivateKey, SlackToken, StripeKey, TelegramToken, UrlCredentials,
};
use leakguard::{FnDetector, Kind, Match, Redactor};

/// Replacement written in place of any redacted secret.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

const MIN_CUSTOM_TOKEN_BYTES: usize = 12;

static BODY_REDACTOR: LazyLock<Redactor> = LazyLock::new(|| {
    Redactor::empty()
        .with_detector(FnDetector::new(
            Kind::Custom("BEARER_TOKEN"),
            detect_bearer_tokens,
        ))
        .with_detector(FnDetector::new(
            Kind::Custom("HILOOP_TOKEN"),
            detect_hiloop_tokens,
        ))
        .with_detector(Jwt)
        .with_detector(AwsAccessKey)
        .with_detector(UrlCredentials)
        .with_detector(GitHubToken)
        .with_detector(SlackToken)
        .with_detector(StripeKey)
        .with_detector(GoogleApiKey)
        .with_detector(OpenAiKey)
        .with_detector(PrivateKey)
        .with_detector(AzureConnectionString)
        .with_detector(TelegramToken)
        .with_detector(DiscordToken)
});

fn detect_bearer_tokens(input: &str, matches: &mut Vec<Match>) {
    let bytes = input.as_bytes();
    let mut cursor = 0;
    while cursor + 7 <= bytes.len() {
        let Some(start) = (cursor..=bytes.len() - 7)
            .find(|start| bytes[*start..*start + 7].eq_ignore_ascii_case(b"bearer "))
        else {
            break;
        };
        let token_start = start + 7;
        let mut end = token_start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || matches!(bytes[end], b'.' | b'_' | b'+' | b'/' | b'=' | b'-'))
        {
            end += 1;
        }
        if end.saturating_sub(token_start) >= MIN_CUSTOM_TOKEN_BYTES {
            matches.push(Match::new(Kind::Custom("BEARER_TOKEN"), start, end));
        }
        cursor = end.max(token_start);
    }
}

fn detect_hiloop_tokens(input: &str, matches: &mut Vec<Match>) {
    let bytes = input.as_bytes();
    let mut cursor = 0;
    while let Some(offset) = input[cursor..].find("hil_") {
        let start = cursor + offset;
        let valid_boundary =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let mut end = start + 4;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
        {
            end += 1;
        }
        if valid_boundary && end.saturating_sub(start) >= MIN_CUSTOM_TOKEN_BYTES {
            matches.push(Match::new(Kind::Custom("HILOOP_TOKEN"), start, end));
        }
        cursor = end;
    }
}

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

    /// Redact recognized credentials from a captured body, returning the scrubbed bytes.
    ///
    /// A no-op (returns the input unchanged) when the policy is disabled or no
    /// detector matches, so the common hot-path case allocates no output copy.
    #[must_use]
    pub fn redact_body(self, body: Bytes) -> Bytes {
        if !self.enabled {
            return body;
        }
        redact_body(body)
    }
}

/// Scrub every credential match from `body`, replacing each with
/// [`REDACTION_PLACEHOLDER`]. Binary bytes are preserved; every valid UTF-8 run is
/// scanned independently so binary framing cannot disable scrubbing for the rest of
/// the captured body. Returns the input untouched when nothing matches.
#[must_use]
pub fn redact_body(body: Bytes) -> Bytes {
    let matches = body_matches(&body);
    if matches.is_empty() {
        return body;
    }

    let removed = matches.iter().map(Match::len).sum::<usize>();
    let replacement = REDACTION_PLACEHOLDER.as_bytes();
    let mut scrubbed = Vec::with_capacity(
        body.len()
            .saturating_sub(removed)
            .saturating_add(matches.len() * replacement.len()),
    );
    let mut cursor = 0;
    for matched in matches {
        scrubbed.extend_from_slice(&body[cursor..matched.start]);
        scrubbed.extend_from_slice(replacement);
        cursor = matched.end;
    }
    scrubbed.extend_from_slice(&body[cursor..]);
    Bytes::from(scrubbed)
}

fn body_matches(body: &[u8]) -> Vec<Match> {
    let mut matches = Vec::new();
    let mut cursor = 0;
    while cursor < body.len() {
        let (valid, invalid_len) = match std::str::from_utf8(&body[cursor..]) {
            Ok(valid) => (valid, 0),
            Err(error) => {
                let valid_len = error.valid_up_to();
                let valid = std::str::from_utf8(&body[cursor..cursor + valid_len])
                    .expect("Utf8Error::valid_up_to identifies valid UTF-8");
                let invalid_len = error.error_len().unwrap_or(body.len() - cursor - valid_len);
                (valid, invalid_len)
            }
        };
        matches.extend(
            BODY_REDACTOR.find(valid).into_iter().map(|matched| {
                Match::new(matched.kind, cursor + matched.start, cursor + matched.end)
            }),
        );
        cursor += valid.len() + invalid_len;
        if invalid_len == 0 {
            break;
        }
    }
    matches
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
        let out = RedactionPolicy::enabled()
            .redact_body(Bytes::from_static(b"Bearer supersecret-token-here"));
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
            redact("Authorization: Bearer abc.def.ghi.long-token"),
            "Authorization: [REDACTED]"
        );
    }

    #[test]
    fn bearer_is_case_insensitive() {
        assert_eq!(redact("bearer abc1234567890xyz"), "[REDACTED]");
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
        // Synthetic fixtures must exceed the detector's minimum realistic token length.
        assert_eq!(
            redact("{\"key\":\"sk-ant-api03-XYZ1234567890abcdef\"}"),
            "{\"key\":\"[REDACTED]\"}"
        );
    }

    #[test]
    fn redacts_multiple_secrets_in_one_body() {
        let synthetic = "first sk-abc1234567890xyzABCDEF then AKIA0123456789ABCDEF done";
        let out = redact(synthetic);
        assert_eq!(out, "first [REDACTED] then [REDACTED] done");
    }

    #[test]
    fn credential_shape_cases() {
        // (input, expected) — parametrized over the supported key formats.
        let cases = [
            ("sk-abc123DEF456ghi789JKL", "[REDACTED]"),
            ("hil_live_abc123", "[REDACTED]"),
            ("AKIAIOSFODNN7EXAMPLE", "[REDACTED]"),
            ("Bearer abc1234567890xyz", "[REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected, "input: {input}");
        }
    }

    #[test]
    fn conservative_detectors_do_not_eat_ordinary_prose() {
        // "sk" alone, a bare "AKIA" prefix without the 16-char body, and the word
        // "bearer" with no token must survive untouched.
        let prose = "the basketball score; AKIA short; just bearer";
        assert_eq!(redact(prose), prose);
    }

    #[test]
    fn credential_catalog_redacts_github_tokens() {
        assert_eq!(
            redact("github_pat_11AA22BB33CC44DD55EE66FF77GG88HH99II00JJ"),
            REDACTION_PLACEHOLDER
        );
    }

    #[test]
    fn short_key_like_values_and_bearer_prose_are_preserved() {
        for prose in ["sk-abc", "the bearer of bad news arrived"] {
            assert_eq!(redact(prose), prose);
        }
    }

    #[test]
    fn useful_pii_and_opaque_values_are_not_over_redacted() {
        let body = r#"{"email":"alice@example.com","ip":"10.0.0.1","access_token":"opaque-value"}"#;
        assert_eq!(redact(body), body);
    }

    #[test]
    fn key_prefixes_do_not_match_mid_word() {
        // The `\b` anchor keeps `sk-`/`hil_` from matching inside ordinary hyphenated
        // words; a standalone key (boundary before the prefix) is still redacted.
        let prose = "task-name, risk-level, disk-space and a while_loop are fine";
        assert_eq!(redact(prose), prose);
        assert_eq!(
            redact("key=sk-live-abc1234567890xyzABCDEF"),
            "key=[REDACTED]"
        );
    }

    #[test]
    fn invalid_utf8_does_not_hide_credentials_in_valid_text_runs() {
        let body = Bytes::from_static(b"\xffsk-abc1234567890xyzABCDEF\xfe");
        assert_eq!(redact_body(body), Bytes::from_static(b"\xff[REDACTED]\xfe"));
    }
}
