//! Capture disposition for exchanges whose body bytes must never enter telemetry.

/// Whether a request/response body is captured or represented only by metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CaptureDisposition {
    #[default]
    Full,
    MetadataOnly(SensitiveExchange),
}

/// Closed set of sensitive exchange classes with body omission contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SensitiveExchange {
    OAuthToken,
    BoundSecret,
}

pub(crate) fn capture_disposition(
    method: &str,
    host: Option<&str>,
    path: &str,
) -> CaptureDisposition {
    if method != "POST" {
        return CaptureDisposition::Full;
    }
    let sensitive = matches!(
        (host, path),
        (Some("platform.claude.com"), "/v1/oauth/token")
            | (
                Some("auth.openai.com"),
                "/api/accounts/deviceauth/usercode"
                    | "/api/accounts/deviceauth/token"
                    | "/oauth/token"
            )
    );
    if sensitive {
        CaptureDisposition::MetadataOnly(SensitiveExchange::OAuthToken)
    } else {
        CaptureDisposition::Full
    }
}

impl SensitiveExchange {
    pub(crate) const fn omission_reason(self) -> &'static str {
        match self {
            Self::OAuthToken => "oauth_token_exchange",
            Self::BoundSecret => "bound_secret_exchange",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_supported_oauth_exchanges_are_metadata_only() {
        for (host, path) in [
            ("platform.claude.com", "/v1/oauth/token"),
            ("auth.openai.com", "/api/accounts/deviceauth/usercode"),
            ("auth.openai.com", "/api/accounts/deviceauth/token"),
            ("auth.openai.com", "/oauth/token"),
        ] {
            assert_eq!(
                capture_disposition("POST", Some(host), path),
                CaptureDisposition::MetadataOnly(SensitiveExchange::OAuthToken),
                "{host}{path}"
            );
        }
    }

    #[test]
    fn neighboring_routes_remain_full_capture() {
        for (method, host, path) in [
            ("GET", Some("platform.claude.com"), "/v1/oauth/token"),
            ("POST", Some("api.anthropic.com"), "/v1/messages"),
            (
                "POST",
                Some("platform.claude.com.evil.test"),
                "/v1/oauth/token",
            ),
            ("POST", Some("auth.openai.com"), "/oauth/token/extra"),
            ("POST", Some("auth.openai.com"), "/oauth%2Ftoken"),
            ("POST", None, "/oauth/token"),
        ] {
            assert_eq!(
                capture_disposition(method, host, path),
                CaptureDisposition::Full,
                "{method} {host:?}{path}"
            );
        }
    }
}
