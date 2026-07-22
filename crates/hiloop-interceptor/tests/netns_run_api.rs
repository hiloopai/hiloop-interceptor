#![cfg(feature = "test-support")]

use std::{net::Ipv6Addr, num::NonZeroU16, path::PathBuf, sync::Arc, time::Duration};

use hiloop_core::{
    capture::{
        CaptureFatalReason, CapturePolicy, CapturePreflight, CaptureTransportDegradationReason,
        NetCaptureMode, OriginalDestination,
    },
    identity::{Hlc, RunContext},
};
use hiloop_interceptor::{
    NetnsRun, NetworkCapture, RunOptions, SystemNetnsRun,
    netns::{
        FatalReport, FragmentedUdpBehavior, PreflightReport, SubstrateExit, SubstrateInfo,
        SystemNetworkProvisioner,
        testing::{
            FakeNetnsRun, FakeNetnsRunCall, FakeNetworkProvisioner, FakeProvisionerCall,
            FakeSessionOutcome, force_ipv4_only,
        },
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

fn info() -> SubstrateInfo {
    SubstrateInfo::new(
        NonZeroU16::new(15_001).expect("port"),
        1_500,
        "169.254.254.1".parse().expect("gateway IPv4"),
        "fd00:6869:6c6f:6f70::1".parse().expect("gateway IPv6"),
        "169.254.2.2".parse().expect("host IPv4"),
        "fd00:6869:6c6f:6f71::2"
            .parse::<Ipv6Addr>()
            .expect("host IPv6"),
        FragmentedUdpBehavior::Drop,
    )
    .expect("info")
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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_composer_builds_the_production_worker_and_ca_only_workload_commands() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events = temp.path().join("events.jsonl");
    let blobs = temp.path().join("blobs");
    let (provisioner, handle) = FakeNetworkProvisioner::passing(
        PreflightReport::passed(true),
        info(),
        SubstrateExit::Code(23),
    );
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        "/fixture/hiloop-interceptor",
    ));
    let report = runner.preflight().await;
    let capture = NetworkCapture::netns(NetCaptureMode::Netns, report, runner);
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec!["fixture-child".to_owned(), "literal arg".to_owned()],
        Some(events.clone()),
        None,
        Some(blobs),
        true,
        capture,
        None,
        None,
    );

    let code = run(&options).await.expect("composed fake run");
    assert_eq!(
        format!("{code:?}"),
        format!("{:?}", std::process::ExitCode::from(23))
    );

    let calls = handle.calls();
    assert_eq!(calls[0], FakeProvisionerCall::Preflight);
    let FakeProvisionerCall::Provision(request) = &calls[1] else {
        panic!("second call must provision")
    };
    assert_eq!(
        request.workload().program(),
        std::ffi::OsStr::new("/fixture/hiloop-interceptor")
    );
    assert_eq!(
        request.workload().arguments(),
        [
            "__hiloop-netns-captured-workload",
            "fixture-child",
            "literal arg"
        ]
        .map(std::ffi::OsString::from)
    );
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        assert_eq!(
            request
                .workload()
                .environment()
                .get(std::ffi::OsStr::new(name)),
            Some(&None),
            "{name} must be absent from the child"
        );
    }
    assert_eq!(
        request.gateway_worker().arguments(),
        [std::ffi::OsString::from("__hiloop-netns-gateway-worker")]
    );
    assert_eq!(
        &calls[2..],
        [
            FakeProvisionerCall::Wait,
            FakeProvisionerCall::CloseDataplane,
            FakeProvisionerCall::TerminateNamespace,
            FakeProvisionerCall::ReapHelpers,
        ]
    );

    let first: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(events)
            .expect("events")
            .lines()
            .next()
            .expect("transport event"),
    )
    .expect("event JSON");
    assert_eq!(first["name"], "capture.transport");
    assert_eq!(first["attributes"]["selected"], "netns");
}

/// The transparent lane's in-trace capture-health contract: a gRPC-exported netns run records
/// one `capture.drain` event — with the auth-refresh accounting — so export degradation is
/// queryable from the run's trace instead of living only in stderr. The gateway here is
/// unreachable on purpose: the record must still land in the local JSONL sink.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_composer_records_the_capture_drain_health_event() {
    use hiloop_interceptor::{DrainRetryPolicy, GrpcExportOptions};

    let temp = tempfile::tempdir().expect("tempdir");
    let events = temp.path().join("events.jsonl");
    let blobs = temp.path().join("blobs");
    let (provisioner, _handle) = FakeNetworkProvisioner::passing(
        PreflightReport::passed(true),
        info(),
        SubstrateExit::Code(0),
    );
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        "/fixture/hiloop-interceptor",
    ));
    let report = runner.preflight().await;
    let capture = NetworkCapture::netns(NetCaptureMode::Netns, report, runner);
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec!["fixture-child".to_owned()],
        Some(events.clone()),
        None,
        Some(blobs),
        false,
        capture,
        None,
        Some(GrpcExportOptions {
            endpoint: "http://127.0.0.1:9".to_owned(),
            insecure: true,
            tenant_id: None,
            project_id: "default".to_owned(),
            bearer_refresh: None,
        }),
    )
    .with_blob_drain_retry(DrainRetryPolicy {
        attempts: 1,
        initial_backoff: Duration::from_millis(1),
    });

    run(&options).await.expect("composed fake run");

    let contents = std::fs::read_to_string(&events).expect("events");
    let drain = contents
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("event JSON"))
        .find(|event| event["name"] == "capture.drain")
        .expect("the transparent lane records its capture-health event");
    assert_eq!(drain["attributes"]["capture.auth.refreshes"], 0);
    // Spooled-but-undelivered (the unreachable gateway) is a backlog, never a loss.
    assert_eq!(drain["attributes"]["capture.events.rejected"], 0);
    assert_eq!(drain["attributes"]["capture.complete"], true);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_composer_preserves_close_first_fatal_order_and_durable_reason() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events = temp.path().join("fatal.jsonl");
    let destination =
        OriginalDestination::new("203.0.113.10".parse().expect("IP"), 443).expect("destination");
    let report =
        FatalReport::destination(CaptureFatalReason::SecretTransportUnsupported, destination);
    let (provisioner, handle) = FakeNetworkProvisioner::scripted(
        PreflightReport::passed(true),
        info(),
        FakeSessionOutcome::Fatal(report),
    );
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        PathBuf::from("/fixture/hiloop-interceptor"),
    ));
    let preflight = runner.preflight().await;
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec!["fixture-child".to_owned()],
        Some(events.clone()),
        None,
        Some(temp.path().join("blobs")),
        false,
        NetworkCapture::netns(NetCaptureMode::Netns, preflight, runner),
        None,
        None,
    );

    let error = run(&options).await.expect_err("fatal result");
    assert!(error.to_string().contains("secret_transport_unsupported"));
    assert_eq!(
        &handle.calls()[2..],
        [
            FakeProvisionerCall::Wait,
            FakeProvisionerCall::CloseDataplane,
            FakeProvisionerCall::TerminateNamespace,
            FakeProvisionerCall::ReapHelpers,
        ]
    );
    let last: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(events)
            .expect("events")
            .lines()
            .last()
            .expect("fatal event"),
    )
    .expect("event JSON");
    assert_eq!(last["name"], "capture.fatal");
    assert_eq!(last["attributes"]["reason"], "secret_transport_unsupported");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires unprivileged user/net/PID namespaces, nft TPROXY, /dev/net/tun, curl, and pinned pasta"]
async fn real_system_composer_captures_cleartext_http_without_proxy_environment() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let pasta = std::env::var_os("HILOOP_TEST_PASTA")
        .map(PathBuf::from)
        .expect("set HILOOP_TEST_PASTA to the pinned pasta binary");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    let provisioner = SystemNetworkProvisioner::new(&pasta)
        .expect("system provisioner")
        .with_helper_executable(&helper);
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        &helper,
    ));
    let preflight = runner.preflight().await;
    assert_eq!(
        preflight.result(),
        CapturePreflight::Passed,
        "{}",
        preflight.diagnostic().unwrap_or("preflight failed")
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("host HTTP fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("fixture accept");
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let length = stream.read(&mut buffer).await.expect("fixture read");
            request.extend_from_slice(&buffer[..length]);
            if length == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("fixture response");
    });

    let temp = tempfile::tempdir().expect("capture directory");
    let events = temp.path().join("events.jsonl");
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec![
            "curl".to_owned(),
            "--fail".to_owned(),
            "--silent".to_owned(),
            format!("http://169.254.2.2:{port}/"),
        ],
        Some(events.clone()),
        None,
        Some(temp.path().join("blobs")),
        false,
        NetworkCapture::netns(NetCaptureMode::Netns, preflight, runner),
        None,
        None,
    );
    let code = tokio::time::timeout(Duration::from_secs(90), run(&options))
        .await
        .expect("composed run timed out")
        .expect("composed run");
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    fixture.await.expect("fixture task");

    let event_names = std::fs::read_to_string(events)
        .expect("events")
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("event JSON")["name"].clone()
        })
        .collect::<Vec<_>>();
    assert!(event_names.contains(&serde_json::Value::String("http.request".to_owned())));
    assert!(event_names.contains(&serde_json::Value::String("http.response".to_owned())));
}

/// A claude/bun-shaped client aborts speculative connections (happy-eyeballs losers,
/// cancelled preconnects) with an RST before sending a byte. That is one flow's
/// lifecycle: the dataplane must keep serving and the run must still succeed.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires unprivileged user/net/PID namespaces, nft TPROXY, /dev/net/tun, curl, python3, and pinned pasta"]
async fn real_system_composer_survives_client_aborted_connections() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let pasta = std::env::var_os("HILOOP_TEST_PASTA")
        .map(PathBuf::from)
        .expect("set HILOOP_TEST_PASTA to the pinned pasta binary");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    let provisioner = SystemNetworkProvisioner::new(&pasta)
        .expect("system provisioner")
        .with_helper_executable(&helper);
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        &helper,
    ));
    let preflight = runner.preflight().await;
    assert_eq!(
        preflight.result(),
        CapturePreflight::Passed,
        "{}",
        preflight.diagnostic().unwrap_or("preflight failed")
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("host HTTP fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let fixture = tokio::spawn(async move {
        // Serve until one complete request arrives; aborted connections are expected.
        loop {
            let (mut stream, _) = listener.accept().await.expect("fixture accept");
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 1024];
                let Ok(length) = stream.read(&mut buffer).await else {
                    break;
                };
                if length == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..length]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .expect("fixture response");
                    return;
                }
            }
        }
    });

    let abort_then_fetch = format!(
        "python3 -c 'import socket, struct\n\
         s = socket.create_connection((\"169.254.2.2\", {port}))\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(\"ii\", 1, 0))\n\
         s.close()'\n\
         sleep 1\n\
         exec curl --fail --silent http://169.254.2.2:{port}/"
    );
    let temp = tempfile::tempdir().expect("capture directory");
    let events = temp.path().join("events.jsonl");
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec!["sh".to_owned(), "-c".to_owned(), abort_then_fetch],
        Some(events.clone()),
        None,
        Some(temp.path().join("blobs")),
        false,
        NetworkCapture::netns(NetCaptureMode::Netns, preflight, runner),
        None,
        None,
    );
    let code = tokio::time::timeout(Duration::from_secs(90), run(&options))
        .await
        .expect("composed run timed out")
        .expect("an aborted client connection must not fail the run");
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    fixture.await.expect("fixture task");

    let contents = std::fs::read_to_string(events).expect("events");
    let event_names = contents
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("event JSON")["name"].clone()
        })
        .collect::<Vec<_>>();
    assert!(
        !event_names.contains(&serde_json::Value::String("capture.fatal".to_owned())),
        "aborted client connections must not be dataplane-fatal: {event_names:?}"
    );
    assert!(event_names.contains(&serde_json::Value::String("http.request".to_owned())));
    assert!(event_names.contains(&serde_json::Value::String("http.response".to_owned())));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires unprivileged user/net/PID namespaces, nft TPROXY, /dev/net/tun, curl, internet access, and pinned pasta"]
async fn real_system_composer_reaches_dual_stack_https_with_forced_ipv4_only_egress() {
    let pasta = std::env::var_os("HILOOP_TEST_PASTA")
        .map(PathBuf::from)
        .expect("set HILOOP_TEST_PASTA to the pinned pasta binary");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    let provisioner = force_ipv4_only(
        SystemNetworkProvisioner::new(&pasta)
            .expect("system provisioner")
            .with_helper_executable(&helper),
    );
    let runner = Arc::new(SystemNetnsRun::with_provisioner(
        Arc::new(provisioner),
        &helper,
    ));
    let preflight = runner.preflight().await;
    assert_eq!(
        preflight.result(),
        CapturePreflight::Passed,
        "{}",
        preflight.diagnostic().unwrap_or("preflight failed")
    );
    assert!(preflight.ipv4_available());
    assert!(!preflight.ipv6_available());

    let temp = tempfile::tempdir().expect("capture directory");
    let options = RunOptions::new(
        RunContext::new_local_root(),
        vec![
            "curl".to_owned(),
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--connect-timeout".to_owned(),
            "10".to_owned(),
            "--max-time".to_owned(),
            "30".to_owned(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            "https://example.com".to_owned(),
        ],
        Some(temp.path().join("events.jsonl")),
        None,
        Some(temp.path().join("blobs")),
        false,
        NetworkCapture::netns(NetCaptureMode::Netns, preflight, runner),
        None,
        None,
    );
    let code = tokio::time::timeout(Duration::from_secs(90), run(&options))
        .await
        .expect("composed run timed out")
        .expect("composed run");
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}
