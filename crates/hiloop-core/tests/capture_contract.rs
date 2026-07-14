use std::net::{IpAddr, Ipv4Addr};

use hiloop_core::{
    capture::{
        ByteCounts, CaptureFatalReason, CapturePolicy, CapturePreflight,
        CaptureTransportDegradationReason, NetCaptureMode, NetPassthroughReason,
        OriginalDestination, SelectedNetCaptureMode, TlsFlowIdentity, TlsInterceptionFailedReason,
        TlsPassthroughReason, TransportProtocol,
    },
    event::Event,
    identity::{Hlc, RunContext},
};
use serde_json::{Value, json};

fn context() -> RunContext {
    RunContext::new_local_root()
}

fn timestamp() -> Hlc {
    Hlc {
        wall_ns: 1,
        logical: 0,
    }
}

fn destination() -> OriginalDestination {
    OriginalDestination::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443)
        .expect("valid destination")
}

fn tls_flow() -> TlsFlowIdentity {
    TlsFlowIdentity::new(destination())
        .with_server_name("api.example.com")
        .expect("valid server name")
        .with_client_hello_fingerprint("ja4:t13d1516h2")
        .expect("valid fingerprint")
}

fn assert_event_contract(event: &Event, name: &str, attributes: &Value) {
    let value = serde_json::to_value(event).expect("serialize event");
    assert_eq!(value["name"], json!(name));
    assert_eq!(value["signal"], json!("net"));
    assert_eq!(&value["attributes"], attributes);
    assert!(value["payload_ref"].is_null());

    let decoded: Event = serde_json::from_value(value.clone()).expect("deserialize event");
    assert_eq!(
        serde_json::to_value(decoded).expect("reserialize event"),
        value
    );
}

#[test]
fn tls_interception_failed_event_shape_is_locked() {
    let event = Event::tls_interception_failed(
        &context(),
        timestamp(),
        TlsInterceptionFailedReason::ClientTrustRejected,
        &tls_flow(),
        true,
        false,
    );

    assert_event_contract(
        &event,
        "tls.interception_failed",
        &json!({
            "client_hello_fingerprint": "ja4:t13d1516h2",
            "original_destination.ip": "203.0.113.10",
            "original_destination.port": 443,
            "reason": "client_trust_rejected",
            "retry_required": true,
            "secret_bound": false,
            "server_name": "api.example.com",
        }),
    );
}

#[test]
fn tls_passthrough_event_shape_is_locked() {
    let event = Event::tls_passthrough(
        &context(),
        timestamp(),
        TlsPassthroughReason::PreclassifiedTrustIncompatible,
        &tls_flow(),
        ByteCounts::new(12, 34).expect("valid counts"),
    );

    assert_event_contract(
        &event,
        "tls.passthrough",
        &json!({
            "client_hello_fingerprint": "ja4:t13d1516h2",
            "downstream_bytes": 34,
            "l7_capture": false,
            "original_destination.ip": "203.0.113.10",
            "original_destination.port": 443,
            "reason": "preclassified_trust_incompatible",
            "server_name": "api.example.com",
            "upstream_bytes": 12,
        }),
    );
}

#[test]
fn net_passthrough_event_shape_is_locked() {
    let event = Event::net_passthrough(
        &context(),
        timestamp(),
        TransportProtocol::Udp,
        destination(),
        NetPassthroughReason::UnsupportedTransportCapture,
        ByteCounts::new(56, 78).expect("valid counts"),
    );

    assert_event_contract(
        &event,
        "net.passthrough",
        &json!({
            "downstream_bytes": 78,
            "l7_capture": false,
            "original_destination.ip": "203.0.113.10",
            "original_destination.port": 443,
            "reason": "unsupported_transport_capture",
            "transport": "udp",
            "upstream_bytes": 56,
        }),
    );
}

#[test]
fn capture_transport_event_shape_is_locked() {
    let event = Event::capture_transport(
        &context(),
        timestamp(),
        NetCaptureMode::Auto,
        SelectedNetCaptureMode::Proxy,
        CapturePolicy::Observe,
        CapturePreflight::Failed,
        true,
        true,
        Some(CaptureTransportDegradationReason::UserNamespaceDenied),
    );

    assert_event_contract(
        &event,
        "capture.transport",
        &json!({
            "capture_policy": "observe",
            "degradation_reason": "user_namespace_denied",
            "ipv4_available": true,
            "ipv6_available": true,
            "preflight_result": "failed",
            "requested": "auto",
            "selected": "proxy",
        }),
    );
}

#[test]
fn capture_fatal_event_shape_is_locked() {
    let event = Event::capture_fatal(
        &context(),
        timestamp(),
        CaptureFatalReason::SecretBindUnterminatable,
        Some(tls_flow()),
    );

    assert_event_contract(
        &event,
        "capture.fatal",
        &json!({
            "client_hello_fingerprint": "ja4:t13d1516h2",
            "original_destination.ip": "203.0.113.10",
            "original_destination.port": 443,
            "reason": "secret_bind_unterminatable",
            "server_name": "api.example.com",
        }),
    );
}

#[test]
fn capture_event_constructors_cannot_embed_sensitive_payloads() {
    let events = [
        Event::tls_interception_failed(
            &context(),
            timestamp(),
            TlsInterceptionFailedReason::InternalError,
            &tls_flow(),
            false,
            true,
        ),
        Event::capture_fatal(
            &context(),
            timestamp(),
            CaptureFatalReason::DataplaneFailed,
            Some(tls_flow()),
        ),
    ];

    for event in events {
        assert!(event.payload_ref.is_none());
        let keys = event
            .attributes
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(!keys.iter().any(|key| {
            key.contains("body") || key.contains("certificate") || key.contains("secret.name")
        }));
    }
}

#[test]
fn capture_contract_rejects_invalid_values() {
    assert!(OriginalDestination::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).is_err());
    assert!(ByteCounts::new(u64::MAX, 0).is_err());
    assert!(
        TlsFlowIdentity::new(destination())
            .with_server_name(" ")
            .is_err()
    );
    assert!(
        TlsFlowIdentity::new(destination())
            .with_client_hello_fingerprint("")
            .is_err()
    );
}

#[test]
fn closed_capture_enum_values_are_locked() {
    assert_eq!(
        [
            NetCaptureMode::Auto,
            NetCaptureMode::Netns,
            NetCaptureMode::Proxy,
            NetCaptureMode::Off,
        ]
        .map(|mode| mode.to_string()),
        ["auto", "netns", "proxy", "off"]
    );
    assert_eq!(
        [
            SelectedNetCaptureMode::Netns,
            SelectedNetCaptureMode::Proxy,
            SelectedNetCaptureMode::Off,
            SelectedNetCaptureMode::None,
        ]
        .map(|mode| mode.to_string()),
        ["netns", "proxy", "off", "none"]
    );
    assert_eq!(
        [
            CapturePolicy::Observe,
            CapturePolicy::PolicyStrict,
            CapturePolicy::SecretStrict,
        ]
        .map(|policy| policy.to_string()),
        ["observe", "policy_strict", "secret_strict"]
    );
    assert_eq!(
        [
            CapturePreflight::Passed,
            CapturePreflight::Failed,
            CapturePreflight::NotApplicable,
        ]
        .map(|preflight| preflight.to_string()),
        ["passed", "failed", "not_applicable"]
    );
    assert_eq!(
        [TransportProtocol::Tcp, TransportProtocol::Udp].map(|transport| transport.to_string()),
        ["tcp", "udp"]
    );
    assert_eq!(
        [
            TlsInterceptionFailedReason::ClientTrustRejected,
            TlsInterceptionFailedReason::AmbiguousHandshakeAbort,
            TlsInterceptionFailedReason::ProtocolMismatch,
            TlsInterceptionFailedReason::ServerHandshakeFailed,
            TlsInterceptionFailedReason::PolicyPassthroughForbidden,
            TlsInterceptionFailedReason::InternalError,
        ]
        .map(|reason| reason.to_string()),
        [
            "client_trust_rejected",
            "ambiguous_handshake_abort",
            "protocol_mismatch",
            "server_handshake_failed",
            "policy_passthrough_forbidden",
            "internal_error",
        ]
    );
    assert_eq!(
        [
            TlsPassthroughReason::PreclassifiedTrustIncompatible,
            TlsPassthroughReason::LearnedTrustRejection,
            TlsPassthroughReason::EncryptedClientHello,
        ]
        .map(|reason| reason.to_string()),
        [
            "preclassified_trust_incompatible",
            "learned_trust_rejection",
            "encrypted_client_hello",
        ]
    );
    assert_eq!(
        [
            NetPassthroughReason::UnsupportedApplicationProtocol,
            NetPassthroughReason::UnsupportedTransportCapture,
        ]
        .map(|reason| reason.to_string()),
        [
            "unsupported_application_protocol",
            "unsupported_transport_capture",
        ]
    );
    assert_eq!(
        [
            CaptureTransportDegradationReason::UnsupportedPlatform,
            CaptureTransportDegradationReason::UserNamespaceDenied,
            CaptureTransportDegradationReason::TproxyUnavailable,
            CaptureTransportDegradationReason::TunUnavailable,
            CaptureTransportDegradationReason::PastaMissing,
            CaptureTransportDegradationReason::Ipv6Unavailable,
            CaptureTransportDegradationReason::ResolverUnavailable,
            CaptureTransportDegradationReason::NetnsStartupFailed,
        ]
        .map(|reason| reason.to_string()),
        [
            "unsupported_platform",
            "user_namespace_denied",
            "tproxy_unavailable",
            "tun_unavailable",
            "pasta_missing",
            "ipv6_unavailable",
            "resolver_unavailable",
            "netns_startup_failed",
        ]
    );
    assert_eq!(
        [
            CaptureFatalReason::SecretBindUnterminatable,
            CaptureFatalReason::SecretRouteAmbiguous,
            CaptureFatalReason::SecretDestinationMismatch,
            CaptureFatalReason::SecretPassthroughForbidden,
            CaptureFatalReason::SecretRouteIdentityMismatch,
            CaptureFatalReason::SecretTransportInsecure,
            CaptureFatalReason::SecretTransportUnsupported,
            CaptureFatalReason::DataplaneFailed,
        ]
        .map(|reason| reason.to_string()),
        [
            "secret_bind_unterminatable",
            "secret_route_ambiguous",
            "secret_destination_mismatch",
            "secret_passthrough_forbidden",
            "secret_route_identity_mismatch",
            "secret_transport_insecure",
            "secret_transport_unsupported",
            "dataplane_failed",
        ]
    );
}
