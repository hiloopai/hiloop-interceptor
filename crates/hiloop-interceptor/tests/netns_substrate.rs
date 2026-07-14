#![cfg(feature = "test-support")]

use std::{
    net::Ipv6Addr,
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::Duration,
};

use hiloop_core::capture::CaptureTransportDegradationReason;
use hiloop_interceptor::netns::{
    FragmentedUdpBehavior, NamespaceCommand, NetworkProvisioner, PreflightReport, ProvisionError,
    ProvisionRequest, StartupStage, SubstrateExit, SubstrateInfo,
    testing::{FakeNetworkProvisioner, FakeProvisionerCall},
};

const WORKER_PROBE_ROLE: &str = "__hiloop-netns-worker-probe";
const DATAPLANE_WORKER_ROLE: &str = "__hiloop-netns-dataplane-worker-probe";
const DATAPLANE_WORKLOAD_ROLE: &str = "__hiloop-netns-dataplane-workload-probe";
const CRASHING_WORKER_ROLE: &str = "__hiloop-netns-crashing-worker-probe";
const DETACHED_WORKLOAD_ROLE: &str = "__hiloop-netns-detached-workload-probe";
const REAL_TEST_TIMEOUT: Duration = Duration::from_secs(90);

fn fake_info() -> SubstrateInfo {
    SubstrateInfo::new(
        NonZeroU16::new(15_001).expect("test port is nonzero"),
        65_520,
        "169.254.254.1".parse().expect("test IPv4"),
        "fd00:6869:6c6f:6f70::1".parse().expect("test IPv6"),
        "169.254.2.2".parse().expect("test host IPv4"),
        "fd00:6869:6c6f:6f70:1::2"
            .parse::<Ipv6Addr>()
            .expect("test host IPv6"),
        FragmentedUdpBehavior::Drop,
    )
    .expect("valid fake substrate facts")
}

fn fake_request() -> ProvisionRequest {
    ProvisionRequest::new(
        NamespaceCommand::new("fixture-workload"),
        NamespaceCommand::new("fixture-worker"),
    )
}

#[tokio::test]
async fn fake_provisioner_exercises_the_public_production_port() {
    let (fake, handle) = FakeNetworkProvisioner::passing(
        PreflightReport::passed(true),
        fake_info(),
        SubstrateExit::Code(17),
    );
    let request = fake_request();

    assert_eq!(fake.preflight().await, PreflightReport::passed(true));
    let mut session = fake
        .provision(request.clone())
        .await
        .expect("fake provision");
    assert_eq!(
        session.info().fragmented_udp_behavior(),
        FragmentedUdpBehavior::Drop
    );
    assert_eq!(
        session.wait().await.expect("fake wait"),
        SubstrateExit::Code(17)
    );
    assert_eq!(
        handle.calls(),
        [
            FakeProvisionerCall::Preflight,
            FakeProvisionerCall::Provision(request),
            FakeProvisionerCall::Wait,
            FakeProvisionerCall::CloseDataplane,
            FakeProvisionerCall::TerminateNamespace,
            FakeProvisionerCall::ReapHelpers,
        ]
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires unprivileged user/net/PID namespaces, nft TPROXY, /dev/net/tun, and pasta 2026_06_11.a9c61ff"]
async fn real_rootless_substrate_preserves_dataplane_security_and_all_cleanup_paths() {
    tokio::time::timeout(REAL_TEST_TIMEOUT, real_rootless_substrate_contract())
        .await
        .expect("rootless substrate contract exceeded its outer timeout");
}

#[cfg(target_os = "linux")]
async fn real_rootless_substrate_contract() {
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::TcpListener,
        os::unix::fs::PermissionsExt as _,
        thread,
    };

    use hiloop_interceptor::netns::{PINNED_PASTA_VERSION, SystemNetworkProvisioner};

    let pasta = std::env::var_os("HILOOP_TEST_PASTA")
        .map(PathBuf::from)
        .expect("set HILOOP_TEST_PASTA to the pinned pasta binary");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    let provisioner = SystemNetworkProvisioner::new(&pasta)
        .expect("system provisioner")
        .with_helper_executable(&helper);

    let preflight = provisioner.preflight().await;
    wait_for_cleanup(&helper, &[&pasta]);
    assert_eq!(
        preflight,
        PreflightReport::passed(preflight.ipv6_available()),
        "pasta pin {PINNED_PASTA_VERSION}: {}",
        preflight.diagnostic().unwrap_or("no diagnostic")
    );

    let host_ipv4 = TcpListener::bind("127.0.0.1:0").expect("IPv4 host-loopback fixture");
    let host_ipv4_port = host_ipv4
        .local_addr()
        .expect("IPv4 host fixture address")
        .port();
    let host_ipv6 = TcpListener::bind("[::1]:0").expect("IPv6 host-loopback fixture");
    let host_ipv6_port = host_ipv6
        .local_addr()
        .expect("IPv6 host fixture address")
        .port();
    let fixture = thread::spawn(move || {
        for (host, family) in [(host_ipv4, "IPv4"), (host_ipv6, "IPv6")] {
            let (mut stream, _) = host.accept().expect("host fixture accept");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("host fixture read");
            assert_eq!(request, *b"ping", "{family} host request");
            stream.write_all(b"pong").expect("host fixture response");
        }
    });
    let evidence_dir = tempfile::tempdir().expect("evidence directory");
    let evidence = evidence_dir.path().join("destinations.txt");

    let worker = NamespaceCommand::new(&helper).args([
        DATAPLANE_WORKER_ROLE.into(),
        evidence.clone().into_os_string(),
        host_ipv4_port.to_string().into(),
        host_ipv6_port.to_string().into(),
    ]);
    let workload = NamespaceCommand::new(&helper).args([
        DATAPLANE_WORKLOAD_ROLE.to_owned(),
        host_ipv4_port.to_string(),
        host_ipv6_port.to_string(),
    ]);
    let mut session = provisioner
        .provision(ProvisionRequest::new(workload, worker))
        .await
        .expect("real rootless substrate provision");
    assert_eq!(session.info().mtu(), 65_520);
    assert_eq!(
        session.info().fragmented_udp_behavior(),
        FragmentedUdpBehavior::Drop
    );
    assert_eq!(
        session.wait().await.expect("real substrate wait"),
        SubstrateExit::Code(0)
    );
    fixture.join().expect("host fixture thread");
    wait_for_cleanup(&helper, &[&pasta]);

    let evidence = fs::read_to_string(evidence).expect("dataplane evidence");
    assert!(evidence.contains("ipv4=198.51.100.42:443"));
    assert!(evidence.contains("ipv6=[2001:db8::42]:443"));
    assert!(evidence.contains(&format!("host_ipv4=169.254.2.2:{host_ipv4_port}")));
    assert!(evidence.contains(&format!(
        "host_ipv6=[fd00:6869:6c6f:6f70:1::2]:{host_ipv6_port}"
    )));

    let missing_worker = evidence_dir.path().join("missing-worker");
    let error = provisioner
        .provision(ProvisionRequest::new(
            NamespaceCommand::new("/bin/true"),
            NamespaceCommand::new(&missing_worker),
        ))
        .await
        .err()
        .expect("missing gateway worker must fail startup");
    assert!(matches!(
        error,
        ProvisionError::Startup {
            stage: StartupStage::GatewayWorker,
            reason: CaptureTransportDegradationReason::NetnsStartupFailed,
            ..
        }
    ));
    wait_for_cleanup(&helper, &[&pasta]);

    let missing_workload = evidence_dir.path().join("missing-workload");
    let error = provisioner
        .provision(ProvisionRequest::new(
            NamespaceCommand::new(&missing_workload),
            NamespaceCommand::new(&helper).arg(WORKER_PROBE_ROLE),
        ))
        .await
        .err()
        .expect("missing workload must fail before readiness");
    assert!(matches!(
        error,
        ProvisionError::Startup {
            stage: StartupStage::Workload,
            reason: CaptureTransportDegradationReason::NetnsStartupFailed,
            ..
        }
    ));
    wait_for_cleanup(&helper, &[&pasta]);

    let mut crashed = provisioner
        .provision(ProvisionRequest::new(
            NamespaceCommand::new("/bin/sleep").arg("30"),
            NamespaceCommand::new(&helper).arg(CRASHING_WORKER_ROLE),
        ))
        .await
        .expect("crashing-worker substrate reaches readiness");
    assert!(matches!(
        crashed.wait().await,
        Err(ProvisionError::Dataplane {
            component: "gateway_worker",
            ..
        })
    ));
    wait_for_cleanup(&helper, &[&pasta]);

    let descendant_pid = evidence_dir.path().join("descendant.pid");
    let mut detached = provisioner
        .provision(ProvisionRequest::new(
            NamespaceCommand::new(&helper)
                .arg(DETACHED_WORKLOAD_ROLE)
                .arg(&descendant_pid),
            NamespaceCommand::new(&helper).arg(WORKER_PROBE_ROLE),
        ))
        .await
        .expect("detached-descendant substrate");
    wait_for_path(&descendant_pid);
    detached
        .shutdown()
        .await
        .expect("ordered explicit shutdown");
    wait_for_cleanup(&helper, &[&pasta]);

    fs::remove_file(&descendant_pid).expect("reset descendant fixture");
    let dropped = provisioner
        .provision(ProvisionRequest::new(
            NamespaceCommand::new(&helper)
                .arg(DETACHED_WORKLOAD_ROLE)
                .arg(&descendant_pid),
            NamespaceCommand::new(&helper).arg(WORKER_PROBE_ROLE),
        ))
        .await
        .expect("drop-cleanup substrate");
    wait_for_path(&descendant_pid);
    drop(dropped);
    wait_for_cleanup(&helper, &[&pasta]);

    let wrapper = evidence_dir.path().join("crashing-pasta");
    let quoted_pasta = shell_single_quote(&pasta);
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exec {quoted_pasta} \"$@\"; fi\n(sleep 2; kill -TERM \"$$\") &\nexec {quoted_pasta} \"$@\"\n"
        ),
    )
    .expect("write crashing pasta wrapper");
    let mut permissions = fs::metadata(&wrapper)
        .expect("wrapper metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&wrapper, permissions).expect("make wrapper executable");
    let crashing_pasta = SystemNetworkProvisioner::new(&wrapper)
        .expect("crashing pasta provisioner")
        .with_helper_executable(&helper);
    let mut session = crashing_pasta
        .provision(ProvisionRequest::new(
            NamespaceCommand::new("/bin/sleep").arg("30"),
            NamespaceCommand::new(&helper).arg(WORKER_PROBE_ROLE),
        ))
        .await
        .expect("pasta survives through initial readiness");
    assert!(matches!(
        session.wait().await,
        Err(ProvisionError::Dataplane {
            component: "pasta",
            ..
        })
    ));
    wait_for_cleanup(&helper, &[&pasta, &wrapper]);
}

#[cfg(target_os = "linux")]
fn wait_for_path(path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture path {} was not created",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn wait_for_cleanup(helper: &Path, pasta_paths: &[&Path]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let leaks = substrate_processes(helper, pasta_paths);
        if leaks.is_empty() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "substrate processes remained after teardown: {leaks:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn substrate_processes(helper: &Path, pasta_paths: &[&Path]) -> Vec<String> {
    let helper = std::fs::canonicalize(helper).expect("canonical helper path");
    let pasta_paths = pasta_paths
        .iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect::<Vec<_>>();
    let mut leaks = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("read proc") {
        let entry = entry.expect("proc entry");
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let command = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let has_role = command
            .split(|byte| *byte == 0)
            .any(|argument| argument.starts_with(b"__hiloop-netns-"));
        let executable = std::fs::read_link(entry.path().join("exe")).ok();
        if has_role
            || executable.as_ref() == Some(&helper)
                && command
                    .split(|byte| *byte == 0)
                    .any(|argument| argument.starts_with(b"__hiloop-netns-"))
            || executable
                .as_ref()
                .is_some_and(|path| pasta_paths.iter().any(|pasta| pasta == path))
        {
            leaks.push(format!("{pid}:{}", String::from_utf8_lossy(&command)));
        }
    }
    leaks
}

#[cfg(target_os = "linux")]
fn shell_single_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}
