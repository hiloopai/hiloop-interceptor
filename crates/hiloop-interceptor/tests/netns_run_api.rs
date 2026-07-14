#![cfg(feature = "test-support")]

use std::sync::Arc;

use hiloop_core::{
    capture::{CapturePolicy, CaptureTransportDegradationReason, NetCaptureMode},
    identity::{Hlc, RunContext},
};
use hiloop_interceptor::{
    NetnsRun, NetworkCapture, RunOptions,
    netns::{
        PreflightReport,
        testing::{FakeNetnsRun, FakeNetnsRunCall},
    },
    run,
};

fn options(command: Vec<String>, capture: NetworkCapture) -> RunOptions {
    RunOptions::new(
        RunContext::new_local_root(),
        command,
        None,
        None,
        None,
        false,
        capture,
        None,
        None,
    )
}

#[tokio::test]
async fn fake_exposes_preflight_separately_then_runs_through_the_same_port() {
    let (fake, handle) = FakeNetnsRun::exiting(PreflightReport::passed(true), 17);
    let report = fake.preflight().await;
    assert_eq!(handle.calls(), [FakeNetnsRunCall::Preflight]);

    let capture = NetworkCapture::netns(NetCaptureMode::Netns, report, Arc::new(fake));
    let code = run(&options(
        vec!["not-spawned-by-the-fake".to_owned()],
        capture,
    ))
    .await
    .expect("fake composed run");

    assert_eq!(
        format!("{code:?}"),
        format!("{:?}", std::process::ExitCode::from(17))
    );
    assert_eq!(
        handle.calls(),
        [FakeNetnsRunCall::Preflight, FakeNetnsRunCall::Run]
    );
}

#[tokio::test]
async fn failed_strict_preflight_never_invokes_the_composed_runner_or_child() {
    let failed = PreflightReport::failed(
        CaptureTransportDegradationReason::UserNamespaceDenied,
        "fixture denied user namespaces",
        true,
        false,
    );
    let (fake, handle) = FakeNetnsRun::exiting(failed, 0);
    let report = fake.preflight().await;
    let capture = NetworkCapture::netns(NetCaptureMode::Netns, report, Arc::new(fake));

    let error = run(&options(
        vec!["sh".to_owned(), "-c".to_owned(), "exit 99".to_owned()],
        capture,
    ))
    .await
    .expect_err("strict preflight must fail before the runner");

    assert!(error.to_string().contains("user_namespace_denied"));
    assert_eq!(handle.calls(), [FakeNetnsRunCall::Preflight]);
}

#[test]
fn selection_event_preserves_auto_fallback_inputs_and_strict_none_state() {
    let context = RunContext::new_local_root();
    let timestamp = Hlc {
        wall_ns: 1,
        logical: 0,
    };
    let failed = PreflightReport::failed(
        CaptureTransportDegradationReason::TproxyUnavailable,
        "fixture has no TPROXY",
        true,
        false,
    );

    let fallback = NetworkCapture::proxy_fallback(failed.clone()).transport_event(
        &context,
        timestamp,
        CapturePolicy::Observe,
    );
    let fallback = serde_json::to_value(fallback).expect("fallback event");
    assert_eq!(fallback["attributes"]["requested"], "auto");
    assert_eq!(fallback["attributes"]["selected"], "proxy");
    assert_eq!(fallback["attributes"]["preflight_result"], "failed");
    assert_eq!(
        fallback["attributes"]["degradation_reason"],
        "tproxy_unavailable"
    );

    let (fake, _) = FakeNetnsRun::failing(failed.clone(), "must not run");
    let strict = NetworkCapture::netns(NetCaptureMode::Netns, failed, Arc::new(fake))
        .transport_event(&context, timestamp, CapturePolicy::SecretStrict);
    let strict = serde_json::to_value(strict).expect("strict event");
    assert_eq!(strict["attributes"]["selected"], "none");
    assert_eq!(strict["attributes"]["capture_policy"], "secret_strict");
}
