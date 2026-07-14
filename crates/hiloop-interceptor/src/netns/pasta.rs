use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt as _},
    process::Command,
    task::JoinHandle,
    time,
};

use super::{PINNED_PASTA_VERSION, routing::LINK_MTU, security::PreExecDescriptorSanitizer};

pub(super) const PASTA_INTERFACE: &str = "hlhost0";
pub(super) const HOST_LOOPBACK_IPV4: &str = "169.254.2.2";
pub(super) const HOST_LOOPBACK_IPV6: &str = "fd00:6869:6c6f:6f70:1::2";

const EXPECTED_VERSION_LINE: &str = "pasta 2026_06_11.a9c61ff";
const VERSION_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PastaCommand {
    program: PathBuf,
    args: Vec<OsString>,
}

impl PastaCommand {
    pub(super) fn attach(program: impl Into<PathBuf>, target_pid: u32, pid_file: &Path) -> Self {
        Self {
            program: program.into(),
            args: [
                OsString::from("--foreground"),
                OsString::from("--quiet"),
                OsString::from("--config-net"),
                OsString::from("--pid"),
                pid_file.as_os_str().to_owned(),
                OsString::from("--mtu"),
                OsString::from(LINK_MTU.to_string()),
                OsString::from("--ns-ifname"),
                OsString::from(PASTA_INTERFACE),
                OsString::from("--tcp-ports"),
                OsString::from("none"),
                OsString::from("--udp-ports"),
                OsString::from("none"),
                OsString::from("--tcp-ns"),
                OsString::from("none"),
                OsString::from("--udp-ns"),
                OsString::from("none"),
                OsString::from("--map-host-loopback"),
                OsString::from(HOST_LOOPBACK_IPV4),
                OsString::from("--map-host-loopback"),
                OsString::from(HOST_LOOPBACK_IPV6),
                OsString::from(target_pid.to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[cfg(test)]
    pub(super) fn program(&self) -> &Path {
        &self.program
    }

    #[cfg(test)]
    pub(super) fn arguments(&self) -> &[OsString] {
        &self.args
    }

    pub(super) fn into_tokio_command(self) -> Command {
        let mut command = Command::new(self.program);
        command
            .args(self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}

pub(super) async fn verify_version(path: &Path, timeout: Duration) -> io::Result<()> {
    let mut command = Command::new(path);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let sanitizer = PreExecDescriptorSanitizer::prepare(&[])?;
    set_version_pre_exec(&mut command, sanitizer);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("pasta version stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("pasta version stderr was not piped"))?;
    let stdout_task = tokio::spawn(drain_bounded(stdout));
    let stderr_task = tokio::spawn(drain_bounded(stderr));

    let status = if let Ok(status) = time::timeout(timeout, child.wait()).await {
        status?
    } else {
        let _ = child.start_kill();
        let Ok(wait_result) = time::timeout(timeout, child.wait()).await else {
            stdout_task.abort();
            stderr_task.abort();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pasta --version timed out and could not be reaped",
            ));
        };
        let _ = join_output(stdout_task).await;
        let _ = join_output(stderr_task).await;
        wait_result?;
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pasta --version timed out",
        ));
    };
    let stdout = join_output(stdout_task).await?;
    let stderr = join_output(stderr_task).await?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "pasta --version exited with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    validate_version_output(&stdout)
}

#[expect(
    unsafe_code,
    reason = "pre_exec arms parent-death cleanup and applies a prepared descriptor-only plan; see SAFETY"
)]
fn set_version_pre_exec(command: &mut Command, sanitizer: PreExecDescriptorSanitizer) {
    // SAFETY: the closure captures scalar state and a plan fully prepared in the parent, then
    // performs only prctl/getppid and descriptor syscalls before exec.
    let expected_parent = unsafe { nix::libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) == -1 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::getppid() != expected_parent {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "network supervisor exited during pasta version probe",
                ));
            }
            sanitizer.apply_in_pre_exec()
        });
    }
}

async fn drain_bounded(mut reader: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(captured);
        }
        let remaining = VERSION_OUTPUT_LIMIT.saturating_sub(captured.len());
        captured.extend_from_slice(&chunk[..read.min(remaining)]);
    }
}

async fn join_output(task: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    task.await
        .map_err(|error| io::Error::other(format!("pasta output task failed: {error}")))?
}

pub(super) fn validate_version_output(stdout: &[u8]) -> io::Result<()> {
    let first_line = stdout
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if first_line == EXPECTED_VERSION_LINE.as_bytes() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "required pasta {PINNED_PASTA_VERSION}, found `{}`",
                String::from_utf8_lossy(first_line)
            ),
        ))
    }
}

pub(super) async fn wait_until_ready(
    pid_file: &Path,
    expected_pid: u32,
    timeout: Duration,
) -> io::Result<()> {
    time::timeout(timeout, async {
        loop {
            match fs::read_to_string(pid_file).await {
                Ok(value) if value.trim() == expected_pid.to_string() => return Ok(()),
                Ok(value) if !value.trim().is_empty() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "pasta pidfile contained `{}` instead of {expected_pid}",
                            value.trim()
                        ),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pasta readiness timed out"))?
}

pub(super) fn classify_startup_stderr(stderr: &str) -> PastaStartupFailure {
    if stderr.contains("user namespace") || stderr.contains("uid_map") || stderr.contains("gid_map")
    {
        PastaStartupFailure::UserNamespace
    } else if stderr.contains("/dev/net/tun")
        || stderr.contains("TUNSETIFF")
        || stderr.contains("tap device")
    {
        PastaStartupFailure::Tun
    } else if stderr.contains("IPv6") || stderr.contains("IPv6 route") {
        PastaStartupFailure::Ipv6
    } else {
        PastaStartupFailure::Other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PastaStartupFailure {
    UserNamespace,
    Tun,
    Ipv6,
    Other,
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt as _, time::Duration};

    use super::*;

    #[test]
    fn version_output_requires_the_exact_pinned_first_line() {
        validate_version_output(
            b"pasta 2026_06_11.a9c61ff\nCopyright Red Hat\nGNU General Public License\n",
        )
        .expect("exact pin");
        for invalid in [
            b"pasta 2026_06_10.deadbee\n".as_slice(),
            b"passt 2026_06_11.a9c61ff\n".as_slice(),
            b"pasta 2026_06_11.a9c61ff-dirty\n".as_slice(),
            b"".as_slice(),
        ] {
            assert!(validate_version_output(invalid).is_err());
        }
    }

    #[test]
    fn attach_arguments_pin_isolation_mtu_and_no_inbound_forwarding() {
        let command = PastaCommand::attach("/bundle/pasta", 42, Path::new("/tmp/pasta.pid"));
        assert_eq!(command.program(), Path::new("/bundle/pasta"));
        assert_eq!(
            command.arguments(),
            [
                "--foreground",
                "--quiet",
                "--config-net",
                "--pid",
                "/tmp/pasta.pid",
                "--mtu",
                "65520",
                "--ns-ifname",
                "hlhost0",
                "--tcp-ports",
                "none",
                "--udp-ports",
                "none",
                "--tcp-ns",
                "none",
                "--udp-ns",
                "none",
                "--map-host-loopback",
                "169.254.2.2",
                "--map-host-loopback",
                "fd00:6869:6c6f:6f70:1::2",
                "42",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn pinned_startup_diagnostics_map_to_closed_probe_classes() {
        assert_eq!(
            classify_startup_stderr("Couldn't create user namespace: Operation not permitted"),
            PastaStartupFailure::UserNamespace
        );
        assert_eq!(
            classify_startup_stderr("Couldn't open /dev/net/tun"),
            PastaStartupFailure::Tun
        );
        assert_eq!(
            classify_startup_stderr("couldn't set IPv6 route(s) in guest"),
            PastaStartupFailure::Ipv6
        );
        assert_eq!(
            classify_startup_stderr("unexpected failure"),
            PastaStartupFailure::Other
        );
    }

    #[tokio::test]
    async fn timed_out_version_probe_kills_and_reaps_the_helper() {
        let directory = tempfile::tempdir().expect("temporary version helper");
        let helper = directory.path().join("pasta");
        std::fs::write(
            &helper,
            b"#!/bin/sh\nprintf '%s' \"$$\" > \"$0.pid\"\nexec sleep 30\n",
        )
        .expect("write version helper");
        let mut permissions = std::fs::metadata(&helper)
            .expect("version helper metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&helper, permissions).expect("make version helper executable");

        let error = verify_version(&helper, Duration::from_millis(100))
            .await
            .expect_err("hung version helper must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pid_file = PathBuf::from(format!("{}.pid", helper.display()));
        let pid = std::fs::read_to_string(pid_file).expect("helper records its PID");
        assert!(
            !Path::new("/proc").join(pid.trim()).exists(),
            "timed-out version helper {pid} remained alive"
        );
    }
}
