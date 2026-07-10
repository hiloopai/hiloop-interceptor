use hiloop_interceptor::seams::provenance_keys;
use serde_json::Value;
use std::{collections::BTreeSet, path::PathBuf, process::Output, time::Duration};
use tokio::process::Command;

const RUN_ID: &str = "01J00000000000000000000001";
const LINEAGE_PATH: &str = "01J00000000000000000000000.01J00000000000000000000001";
const E2E_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn pass_through_injects_context_and_returns_child_exit_code() {
    let mut command = interceptor_command();
    append_mock_harness(&mut command, "context", &["23"]);

    let output = run(command).await;

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout"),
        concat!(
            "HILOOP_RUN_ID=01J00000000000000000000001\n",
            "HILOOP_LINEAGE_PATH=01J00000000000000000000000.01J00000000000000000000001\n",
            "OTEL_RESOURCE_ATTRIBUTES=hiloop.run.id=01J00000000000000000000001,",
            "hiloop.run.lineage_path=01J00000000000000000000000.01J00000000000000000000001\n",
        )
    );
    assert_eq!(output.stderr, b"context-stderr\n");
}

#[tokio::test]
async fn capture_tees_mixed_stdio_and_links_raw_observations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let raw_path = temp.path().join("raw.jsonl");
    let mut command = interceptor_command();
    command
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--raw-jsonl")
        .arg(&raw_path);
    append_mock_harness(&mut command, "mixed", &[]);

    let output = run(command).await;

    assert!(output.status.success());
    assert_eq!(output.stdout, b"out1\npartial");
    assert_eq!(output.stderr, b"err1\nerr-partial");

    let events = read_jsonl(&events_path);
    assert_eq!(events.len(), 6, "4 stdio lines + process.start/exit");
    for event in &events {
        assert_common_event_provenance(event, "preserve");
        assert!(
            event["attributes"][provenance_keys::RAW_OBSERVATION_ID]
                .as_str()
                .expect("raw observation id")
                .starts_with("raw-jsonl-")
        );
    }
    let stdio_events = log_events(&events);
    assert_eq!(stdio_events.len(), 4);
    for event in &stdio_events {
        assert_stdio_event(event);
    }
    assert_process_lifecycle(&events, 0);

    let messages = stdio_events
        .iter()
        .map(|event| {
            (
                event["attributes"]["stream"]
                    .as_str()
                    .expect("stream")
                    .to_owned(),
                event["attributes"]["message"]
                    .as_str()
                    .expect("message")
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        messages,
        BTreeSet::from([
            ("stderr".to_owned(), "err-partial".to_owned()),
            ("stderr".to_owned(), "err1".to_owned()),
            ("stdout".to_owned(), "out1".to_owned()),
            ("stdout".to_owned(), "partial".to_owned()),
        ])
    );

    let raw_records = read_jsonl(&raw_path);
    assert_eq!(raw_records.len(), 6);
    let raw_ids = raw_records
        .iter()
        .map(|record| record["id"].as_str().expect("raw id"))
        .collect::<BTreeSet<_>>();
    let event_raw_ids = events
        .iter()
        .map(|event| {
            event["attributes"][provenance_keys::RAW_OBSERVATION_ID]
                .as_str()
                .expect("event raw id")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(raw_ids, event_raw_ids);

    let raw_bodies = raw_records
        .iter()
        .map(|record| record["body_base64"].as_str().expect("raw body"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        raw_bodies,
        // The two process lifecycle observations carry empty bodies.
        BTreeSet::from([
            "",
            "ZXJyLXBhcnRpYWw=",
            "ZXJyMQ==",
            "b3V0MQ==",
            "cGFydGlhbA=="
        ])
    );
}

#[tokio::test]
async fn captures_and_tees_stdin_to_the_child() {
    use tokio::io::AsyncWriteExt as _;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    // `cat` echoes its stdin to its stdout, so a successful tee shows up on the child's stdout.
    command
        .arg("--")
        .arg("cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn().expect("spawn interceptor");
    {
        let mut stdin = child.stdin.take().expect("interceptor stdin");
        stdin
            .write_all(b"hello from stdin\n")
            .await
            .expect("write stdin");
        // Dropping the handle closes the interceptor's stdin → EOF → the pump closes the child's
        // stdin → `cat` exits.
    }
    let output = tokio::time::timeout(E2E_TIMEOUT, child.wait_with_output())
        .await
        .expect("interceptor stdin scenario timed out")
        .expect("run interceptor");

    assert!(output.status.success(), "child exited non-zero: {output:?}");
    // The input was teed through the interceptor → cat → back out: child stdout echoes it verbatim.
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout"),
        "hello from stdin\n"
    );

    // …and it was captured as a fork-stamped process.stdin log event.
    let events = read_jsonl(&events_path);
    let stdin_events = events
        .iter()
        .filter(|event| event["name"] == "process.stdin")
        .collect::<Vec<_>>();
    assert_eq!(stdin_events.len(), 1, "exactly one stdin line captured");
    let event = stdin_events[0];
    assert_eq!(event["signal"], "log");
    assert_eq!(event["attributes"]["stream"], "stdin");
    assert_eq!(event["attributes"]["source"], "stdio");
    assert_eq!(event["attributes"]["message"], "hello from stdin");
    assert_eq!(event["run_id"], RUN_ID);
}

#[tokio::test]
async fn wrapper_exits_after_the_child_even_when_its_stdin_never_closes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut command = interceptor_command();
    // An export target turns capture on — without one the wrapper is a pass-through with no
    // stdin pump, and this scenario would trivially pass.
    command
        .arg("--events-jsonl")
        .arg(temp.path().join("events.jsonl"));
    // The child must outlive the pump's first poll so a stdin read is in flight when the
    // child exits — an instant child made the historical hang racy instead of deterministic.
    command.arg("--").arg("sh").arg("-c").arg("sleep 0.3");
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn().expect("spawn interceptor");
    // Hold the wrapper's stdin open across the child's exit: an interactive parent (terminal,
    // agent-harness pipe) never EOFs, and the wrapper must still exit on its own.
    let held_open_stdin = child.stdin.take().expect("interceptor stdin");
    let status = tokio::time::timeout(E2E_TIMEOUT, child.wait())
        .await
        .expect("wrapper must exit after the child even though its stdin never closed")
        .expect("wait for interceptor");
    drop(held_open_stdin);

    assert!(status.success(), "wrapper exited non-zero: {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn capture_preserves_tty_stdio_for_interactive_children() {
    use nix::fcntl::OFlag;
    use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};
    use std::os::unix::fs::OpenOptionsExt as _;
    use tokio::io::AsyncReadExt as _;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    // openpty would hand out inheritable descriptors with no atomic way to fix that after the
    // fact: a child forked by a concurrently running test inside the gap would keep the slave
    // open past this test's child and hold the master read short of EOF below. Open both ends
    // close-on-exec from birth instead (std's open sets O_CLOEXEC by default).
    let master =
        posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).expect("open pty master");
    grantpt(&master).expect("grant pty slave");
    unlockpt(&master).expect("unlock pty slave");
    let slave_path = ptsname_r(&master).expect("pty slave path");
    let master = std::fs::File::from(std::os::fd::OwnedFd::from(master));
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOCTTY)
        .open(&slave_path)
        .expect("open pty slave");

    let mut command = interceptor_command();
    command
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(
            "if [ -t 0 ] && [ -t 1 ] && [ -t 2 ]; then \
                 printf 'tty-ok\\n'; \
             else \
                 printf 'not-a-tty\\n'; \
                 exit 42; \
             fi",
        )
        .stdin(std::process::Stdio::from(
            slave.try_clone().expect("clone pty slave for stdin"),
        ))
        .stdout(std::process::Stdio::from(
            slave.try_clone().expect("clone pty slave for stdout"),
        ))
        .stderr(std::process::Stdio::from(slave));

    let mut child = command.spawn().expect("spawn interceptor under pty");
    // The command still owns the parent-side slave handles; drop it so the wrapper process holds
    // the only remaining ones and the master reader reaches EOF (EIO on Linux) once it exits.
    drop(command);
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let reader_output = std::sync::Arc::clone(&output);
    let mut master = tokio::fs::File::from_std(master);
    let reader = tokio::spawn(async move {
        let mut buf = [0_u8; 1024];
        loop {
            match master.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => reader_output
                    .lock()
                    .expect("output buffer mutex")
                    .extend_from_slice(&buf[..n]),
                Err(err) if err.raw_os_error() == Some(nix::libc::EIO) => break,
                Err(err) => panic!("read pty output: {err}"),
            }
        }
    });

    let status = tokio::time::timeout(E2E_TIMEOUT, child.wait())
        .await
        .expect("pty capture scenario timed out")
        .expect("wait for interceptor");
    // The child's final burst can still be in flight between the PTY buffer and the reader when
    // `wait` returns; await the reader's EOF instead of aborting it so no output is dropped.
    tokio::time::timeout(E2E_TIMEOUT, reader)
        .await
        .expect("pty reader should reach EOF once the child exits")
        .expect("pty reader task");
    let output = output.lock().expect("output buffer mutex").clone();

    assert!(
        status.success(),
        "child should see a tty; pty output: {}",
        String::from_utf8_lossy(&output)
    );
    assert!(
        String::from_utf8_lossy(&output).contains("tty-ok"),
        "pty output: {}",
        String::from_utf8_lossy(&output)
    );
    assert!(
        event_messages(&read_jsonl(&events_path), "stdout")
            .iter()
            .any(|message| message == "tty-ok"),
        "tty output should be captured as stdout telemetry"
    );
}

#[tokio::test]
async fn capture_is_lossless_and_ordered_per_stream_under_load() {
    const LINE_COUNT: usize = 512;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let line_count = LINE_COUNT.to_string();
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(&mut command, "lines", &[&line_count]);

    let output = run(command).await;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("stdout")
            .lines()
            .collect::<Vec<_>>(),
        expected_lines("stdout", LINE_COUNT)
    );
    assert_eq!(
        String::from_utf8(output.stderr)
            .expect("stderr")
            .lines()
            .collect::<Vec<_>>(),
        expected_lines("stderr", LINE_COUNT)
    );

    let events = read_jsonl(&events_path);
    assert_eq!(
        events.len(),
        LINE_COUNT * 2 + 2,
        "stdio + process.start/exit"
    );
    assert_eq!(
        event_messages(&events, "stdout"),
        expected_lines("stdout", LINE_COUNT)
    );
    assert_eq!(
        event_messages(&events, "stderr"),
        expected_lines("stderr", LINE_COUNT)
    );
    for event in &events {
        assert_common_event_provenance(event, "discard_after_normalize");
        assert!(
            event["attributes"]
                .get(provenance_keys::RAW_OBSERVATION_ID)
                .is_none()
        );
    }
    for event in log_events(&events) {
        assert_stdio_event(event);
    }
    assert_process_lifecycle(&events, 0);
}

#[tokio::test]
async fn capture_preserves_non_utf8_and_empty_lines() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(&mut command, "binary", &[]);

    let output = run(command).await;

    assert!(output.status.success());
    assert_eq!(output.stdout, [0xff, 0x00, b'A', b'\n', b'\n']);
    assert!(output.stderr.is_empty());

    let events = read_jsonl(&events_path);
    assert_eq!(events.len(), 4, "2 stdio lines + process.start/exit");
    let stdio = log_events(&events);
    assert_eq!(stdio.len(), 2);
    assert_eq!(stdio[0]["attributes"]["message_base64"], "/wBB");
    assert_eq!(stdio[0]["attributes"]["message_encoding"], "base64");
    assert!(stdio[0]["attributes"].get("message").is_none());
    assert_eq!(stdio[1]["attributes"]["message"], "");
}

#[tokio::test]
async fn capture_normalizes_line_boundaries_and_final_partial_line() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(&mut command, "line-boundaries", &[]);

    let output = run(command).await;

    assert!(output.status.success());
    assert_eq!(output.stdout, b"lf\ncrlf\r\n\npartial");
    assert!(output.stderr.is_empty());
    assert_eq!(
        event_messages(&read_jsonl(&events_path), "stdout"),
        ["lf", "crlf", "", "partial"]
    );
}

#[tokio::test]
async fn capture_flushes_telemetry_before_returning_nonzero_child_exit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(&mut command, "exit", &["23"]);

    let output = run(command).await;

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"stdout-before-exit\n");
    assert_eq!(output.stderr, b"stderr-before-exit\n");
    let events = read_jsonl(&events_path);
    assert_eq!(events.len(), 4, "2 stdio lines + process.start/exit");
    assert_eq!(
        events
            .iter()
            .map(|event| event["name"].as_str().expect("event name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "process.exit",
            "process.start",
            "process.stderr",
            "process.stdout",
        ])
    );
    assert_process_lifecycle(&events, 23);
}

#[tokio::test]
async fn process_start_leads_the_stream_and_records_the_env_allowlist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--env-allowlist")
        .arg("PATH,HOME");
    append_mock_harness(&mut command, "mixed", &[]);

    let output = run(command).await;

    assert!(output.status.success());
    let events = read_jsonl(&events_path);
    assert_process_lifecycle(&events, 0);
    assert_eq!(
        events[0]["name"], "process.start",
        "process.start opens the run's event stream"
    );

    let start = &events[0];
    assert_eq!(start["attributes"]["process.env_allowlist"], "PATH,HOME");
    // Process identity arrives via the shared provenance pass.
    assert!(
        start["attributes"][provenance_keys::PROCESS_PID]
            .as_i64()
            .expect("process pid")
            > 0
    );
    let argv = serde_json::from_str::<Vec<String>>(
        start["attributes"][provenance_keys::PROCESS_COMMAND_ARGS]
            .as_str()
            .expect("process argv"),
    )
    .expect("process argv json");
    assert_eq!(argv[0], "sh");
    assert!(start["attributes"][provenance_keys::PROCESS_CWD].is_string());

    // Without the flag the attribute is omitted (capture is opt-in per name).
    let bare_events_path = temp.path().join("bare-events.jsonl");
    let mut bare = interceptor_command();
    bare.arg("--events-jsonl").arg(&bare_events_path);
    append_mock_harness(&mut bare, "mixed", &[]);
    assert!(run(bare).await.status.success());
    let bare_start = read_jsonl(&bare_events_path)
        .into_iter()
        .find(|event| event["name"] == "process.start")
        .expect("process.start event");
    assert!(
        bare_start["attributes"]
            .get("process.env_allowlist")
            .is_none()
    );
}

#[tokio::test]
async fn process_start_captures_allowlisted_env_values_redacted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--env-allowlist")
        .arg("HILOOP_E2E_RATE,HILOOP_E2E_KEY,HILOOP_E2E_UNSET")
        .env("HILOOP_E2E_RATE", "0.001")
        .env("HILOOP_E2E_KEY", "sk-e2e-secret-123")
        .env("HILOOP_E2E_OFFLIST", "must-not-appear")
        .env_remove("HILOOP_E2E_UNSET");
    append_mock_harness(&mut command, "mixed", &[]);

    let output = run(command).await;

    assert!(output.status.success());
    let events = read_jsonl(&events_path);
    let start = &events[0];
    assert_eq!(start["name"], "process.start");
    let attributes = &start["attributes"];
    assert_eq!(
        attributes["process.env_allowlist"], "HILOOP_E2E_RATE,HILOOP_E2E_KEY,HILOOP_E2E_UNSET",
        "the allowlist names every configured variable, set or not"
    );
    assert_eq!(attributes["process.env.HILOOP_E2E_RATE"], "0.001");
    assert_eq!(
        attributes["process.env.HILOOP_E2E_KEY"], "[REDACTED]",
        "a secret-shaped value is scrubbed by the capture-side redaction"
    );
    assert!(
        attributes.get("process.env.HILOOP_E2E_UNSET").is_none(),
        "an unset allowlisted variable yields no value attribute"
    );
    assert!(
        attributes.get("process.env.HILOOP_E2E_OFFLIST").is_none(),
        "a variable outside the allowlist is never captured"
    );

    // --no-redact captures allowlisted values verbatim, matching body behavior.
    let verbatim_events_path = temp.path().join("verbatim-events.jsonl");
    let mut verbatim = interceptor_command();
    verbatim
        .arg("--events-jsonl")
        .arg(&verbatim_events_path)
        .arg("--no-redact")
        .arg("--env-allowlist")
        .arg("HILOOP_E2E_KEY")
        .env("HILOOP_E2E_KEY", "sk-e2e-secret-123");
    append_mock_harness(&mut verbatim, "mixed", &[]);
    assert!(run(verbatim).await.status.success());
    let verbatim_start = read_jsonl(&verbatim_events_path)
        .into_iter()
        .find(|event| event["name"] == "process.start")
        .expect("process.start event");
    assert_eq!(
        verbatim_start["attributes"]["process.env.HILOOP_E2E_KEY"],
        "sk-e2e-secret-123"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn captures_forwarded_signal_as_a_process_signal_event() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let started = temp.path().join("started");
    let terminated = temp.path().join("terminated");
    let _harness_reaper = HarnessGroupReaper {
        pid_file: started.clone(),
    };

    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(
        &mut command,
        "trap",
        &[
            started.to_str().expect("started path"),
            terminated.to_str().expect("terminated path"),
        ],
    );
    let mut child = command.spawn().expect("spawn interceptor");
    wait_for_path(&started).await;

    let pid =
        i32::try_from(child.id().expect("interceptor pid")).expect("interceptor pid fits i32");
    kill(Pid::from_raw(pid), Signal::SIGTERM).expect("send SIGTERM to interceptor");

    let status = tokio::time::timeout(E2E_TIMEOUT, child.wait())
        .await
        .expect("interceptor should exit after SIGTERM")
        .expect("wait interceptor");
    assert_eq!(status.code(), Some(143));

    let events = read_jsonl(&events_path);
    let signal_event = events
        .iter()
        .find(|event| event["name"] == "process.signal")
        .expect("process.signal event");
    assert_eq!(signal_event["signal"], "exec");
    assert_eq!(signal_event["attributes"]["signal"], "SIGTERM");
    // The harness's trap handler exits 143 itself, so this is a normal
    // (non-signal) child exit carrying the conventional 128 + SIGTERM code.
    assert_process_lifecycle(&events, 143);
}

#[tokio::test]
async fn spawn_failure_is_captured_as_a_process_spawn_failed_event() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let missing = temp.path().join("no-such-harness");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    command.arg("--").arg(&missing).arg("--flag");

    let output = run(command).await;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(
        stderr.contains("failed to spawn child command"),
        "stderr: {stderr}"
    );

    // Full capture includes the failed attempt: exactly one exec-signal record
    // stating what was attempted and why no process ever started.
    let events = read_jsonl(&events_path);
    let [event] = events.as_slice() else {
        panic!("expected exactly the spawn-failure event, got {events:?}");
    };
    assert_eq!(event["name"], "process.spawn_failed");
    assert_eq!(event["signal"], "exec");
    assert_eq!(event["run_id"], RUN_ID);
    assert_eq!(event["lineage_path"], LINEAGE_PATH);
    let argv = serde_json::from_str::<Vec<String>>(
        event["attributes"][provenance_keys::PROCESS_COMMAND_ARGS]
            .as_str()
            .expect("process argv"),
    )
    .expect("process argv json");
    assert_eq!(
        argv,
        vec![
            missing.to_str().expect("missing path").to_owned(),
            "--flag".to_owned()
        ]
    );
    let error = event["attributes"]["process.error"]
        .as_str()
        .expect("process error");
    assert!(error.contains("os error 2"), "error: {error}");
    assert!(event["attributes"][provenance_keys::WRAPPER_NAME].is_string());
    // The spawn-failure record is built outside the pipeline yet still carries
    // the wrap's minted invocation identity.
    let invocation_id = event["attributes"][provenance_keys::WRAPPER_INVOCATION_ID]
        .as_str()
        .expect("wrapper.invocation_id on the spawn-failure event");
    ulid::Ulid::from_string(invocation_id).expect("wrapper.invocation_id is a valid ULID");
}

#[tokio::test]
async fn raw_output_without_event_output_fails_before_starting_child() {
    let temp = tempfile::tempdir().expect("tempdir");
    let raw_path = temp.path().join("raw.jsonl");
    let marker_path = temp.path().join("child-started");
    let mut command = interceptor_command();
    command.arg("--raw-jsonl").arg(&raw_path);
    append_mock_harness(
        &mut command,
        "marker",
        &[marker_path.to_str().expect("marker path")],
    );

    let output = run(command).await;

    assert!(!output.status.success());
    assert!(!marker_path.exists());
    assert!(!raw_path.exists());
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr")
            .contains("--raw-jsonl requires an export target")
    );
}

#[tokio::test]
async fn invalid_output_configuration_fails_before_starting_child() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let marker_path = temp.path().join("child-started");
    std::fs::write(&events_path, "existing").expect("seed events file");
    let mut command = interceptor_command();
    command.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(
        &mut command,
        "marker",
        &[marker_path.to_str().expect("marker path")],
    );

    let output = run(command).await;

    assert!(!output.status.success());
    assert!(!marker_path.exists());
    assert_eq!(
        std::fs::read_to_string(events_path).expect("events file"),
        "existing"
    );
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr")
            .contains("failed to create JSONL event exporter")
    );
}

#[tokio::test]
async fn inspect_summarizes_captured_events() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");

    let mut capture = interceptor_command();
    capture.arg("--events-jsonl").arg(&events_path);
    append_mock_harness(&mut capture, "mixed", &[]);
    let captured = run(capture).await;
    assert!(captured.status.success());

    let mut inspect = Command::new(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    inspect.kill_on_drop(true);
    inspect.arg("inspect").arg(&events_path);
    let output = run(inspect).await;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(
        stdout.contains("6 events across 1 run lineage path(s)"),
        "summary header missing: {stdout}"
    );
    assert!(
        stdout.contains("process.stdout: 2"),
        "stdout count: {stdout}"
    );
    assert!(
        stdout.contains("process.stderr: 2"),
        "stderr count: {stdout}"
    );
    assert!(
        stdout.contains("process.start: 1"),
        "process.start count: {stdout}"
    );
    assert!(
        stdout.contains("process.exit: 1"),
        "process.exit count: {stdout}"
    );
}

#[tokio::test]
async fn captures_otlp_traces_from_child_export() {
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let fixture_path = temp.path().join("trace.pb");
    std::fs::write(&fixture_path, otlp_trace_fixture()).expect("write fixture");

    let mut command = interceptor_command();
    command
        .arg("--otlp")
        .arg("--events-jsonl")
        .arg(&events_path);
    append_mock_harness(
        &mut command,
        "otlp",
        &[fixture_path.to_str().expect("fixture path")],
    );

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let llm = events
        .iter()
        .find(|event| event["signal"] == "llm")
        .expect("an llm event from the OTLP export");
    assert_eq!(llm["name"], "chat");
    assert_eq!(llm["lineage_path"], LINEAGE_PATH);
    assert_eq!(llm["attributes"]["gen_ai.system"], "anthropic");
    assert_eq!(
        llm["attributes"][provenance_keys::NORMALIZER_NAME],
        "otlp-trace"
    );
}

fn otlp_trace_fixture() -> Vec<u8> {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message as _;

    let span = Span {
        name: "chat".to_owned(),
        start_time_unix_nano: 7,
        attributes: vec![KeyValue {
            key: "gen_ai.system".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("anthropic".to_owned())),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![span],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}

#[tokio::test]
async fn proxy_mitm_captures_decrypted_https_request() {
    // A local TCP sink the proxy reaches upstream: it accepts then drops, so the
    // proxy's upstream TLS fails (502) — but the decrypted request is captured
    // first, which is exactly what proves the MITM + injected CA worked.
    let sink = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind sink");
    let sink_port = sink.local_addr().expect("sink addr").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = sink.accept().await {
            drop(stream);
        }
    });

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir);
    let url = format!("https://localhost:{sink_port}/v1/thing");
    append_mock_harness(&mut command, "proxy", &[&url]);

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let request = events
        .iter()
        .find(|event| {
            event["name"] == "http.request"
                && event["attributes"]["http.target"]
                    .as_str()
                    .is_some_and(|target| target.ends_with("/v1/thing"))
        })
        .expect("a captured https request proves TLS interception");
    assert_eq!(request["signal"], "net");
    assert_eq!(request["lineage_path"], LINEAGE_PATH);
    assert!(
        request["attributes"]["http.host"]
            .as_str()
            .is_some_and(|host| host.starts_with("localhost")),
        "captured host: {}",
        request["attributes"]["http.host"]
    );
    // Body streamed to the content-addressed blob store, referenced from the event.
    let digest = request["payload_ref"]["digest"]
        .as_str()
        .expect("request payload_ref digest");
    assert!(
        digest.starts_with("blake3:"),
        "payload digest should be blake3: {digest}"
    );
    let hex = digest.strip_prefix("blake3:").expect("blake3 prefix");
    assert!(
        blob_dir.join(format!("blake3-{hex}")).exists(),
        "the request body blob should exist in the blob dir"
    );
}

/// Mint a deployment-style egress interception CA: the CA PEM is what a deployment
/// provisions at `HILOOP_EGRESS_INTERCEPTION_CA`, the issuer signs the leaves its
/// host-side egress proxy would terminate bound routes with.
fn mint_interception_ca() -> (
    String,
    hudsucker::rcgen::Issuer<'static, hudsucker::rcgen::KeyPair>,
) {
    use hudsucker::rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "test egress interception CA");
    ca_params.distinguished_name = distinguished_name;
    let ca_pem = ca_params.self_signed(&ca_key).expect("ca cert").pem();

    let issuer_key = KeyPair::from_pem(&ca_key.serialize_pem()).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, issuer_key).expect("issuer");
    (ca_pem, issuer)
}

/// A TLS upstream whose `localhost` leaf chains to `issuer` — the exact upstream the
/// proxy's forward hop sees on a bound route a host-side egress proxy terminated.
/// Serves one canned HTTP/1.1 200 per connection. Also returns the leaf's PEM, for
/// the mis-provisioning test that plants a leaf where the CA belongs.
async fn interception_terminated_upstream(
    issuer: &hudsucker::rcgen::Issuer<'static, hudsucker::rcgen::KeyPair>,
    body: &'static str,
) -> (u16, String) {
    use hudsucker::rcgen::{CertificateParams, KeyPair};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ServerConfig, crypto::aws_lc_rs};

    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("leaf params")
        .signed_by(&leaf_key, issuer)
        .expect("signed leaf");
    let leaf_pem = leaf.pem();

    let server_cfg = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server cert");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let port = listener.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0_u8; 4096];
                let _ = tls.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, leaf_pem)
}

#[tokio::test]
async fn proxy_upstream_trusts_the_provisioned_interception_ca_on_bound_routes() {
    // Bound routes reach the proxy's upstream hop TLS-terminated by the deployment's
    // egress proxy: the leaf chains to the deployment's interception CA, which no
    // public root anchors. With `HILOOP_EGRESS_INTERCEPTION_CA` provisioned, the
    // upstream client unions that CA with the public roots and the exchange completes.
    let (ca_pem, issuer) = mint_interception_ca();
    let (port, _leaf_pem) = interception_terminated_upstream(&issuer, "bound-ok").await;

    let temp = tempfile::tempdir().expect("tempdir");
    let ca_path = temp.path().join("egress-interception-ca.pem");
    std::fs::write(&ca_path, &ca_pem).expect("write ca");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir)
        .env("HILOOP_EGRESS_INTERCEPTION_CA", &ca_path);
    let url = format!("https://localhost:{port}/v1/bound");
    append_mock_harness(&mut command, "proxy", &[&url]);

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let response = events
        .iter()
        .find(|event| event["name"] == "http.response")
        .expect("the bound-route exchange completes against the interception-CA leaf");
    assert_eq!(response["attributes"]["http.status_code"], "200");
    assert!(
        !events.iter().any(|event| event["name"] == "http.abort"),
        "no exchange aborts: {events:?}"
    );
}

#[tokio::test]
async fn proxy_upstream_still_rejects_leaves_from_an_unprovisioned_ca() {
    // The upstream's CA is NOT the provisioned one. Extra upstream trust is strictly
    // the CA `HILOOP_EGRESS_INTERCEPTION_CA` names, so this handshake must fail
    // closed exactly as with public roots only — the union never relaxes verification.
    let (_upstream_ca_pem, upstream_issuer) = mint_interception_ca();
    let (port, _leaf_pem) =
        interception_terminated_upstream(&upstream_issuer, "must-not-arrive").await;
    let (provisioned_ca_pem, _provisioned_issuer) = mint_interception_ca();

    let temp = tempfile::tempdir().expect("tempdir");
    let ca_path = temp.path().join("egress-interception-ca.pem");
    std::fs::write(&ca_path, &provisioned_ca_pem).expect("write ca");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir)
        .env("HILOOP_EGRESS_INTERCEPTION_CA", &ca_path);
    let url = format!("https://localhost:{port}/v1/unknown-ca");
    append_mock_harness(&mut command, "proxy", &[&url]);

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let abort = events
        .iter()
        .find(|event| event["name"] == "http.abort")
        .expect("the unknown-CA handshake fails closed with a terminal abort");
    assert_eq!(
        abort["attributes"]["http.abort.reason"],
        "upstream_connect_error"
    );
    assert!(
        !events.iter().any(|event| event["name"] == "http.response"),
        "no response can complete against an untrusted upstream: {events:?}"
    );
}

#[tokio::test]
async fn proxy_rejects_a_mis_provisioned_leaf_as_interception_ca_and_fails_closed() {
    // `HILOOP_EGRESS_INTERCEPTION_CA` points at the upstream's own END-ENTITY leaf
    // instead of a CA. A leaf must never become a trust anchor (that would WIDEN
    // trust on mis-provisioning): the proxy warns loudly, degrades to public roots
    // only, and the bound route fails closed.
    let (_ca_pem, issuer) = mint_interception_ca();
    let (port, leaf_pem) = interception_terminated_upstream(&issuer, "must-not-arrive").await;

    let temp = tempfile::tempdir().expect("tempdir");
    let ca_path = temp.path().join("egress-interception-ca.pem");
    std::fs::write(&ca_path, &leaf_pem).expect("write mis-provisioned leaf");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir)
        .env("HILOOP_EGRESS_INTERCEPTION_CA", &ca_path);
    let url = format!("https://localhost:{port}/v1/leaf-as-ca");
    append_mock_harness(&mut command, "proxy", &[&url]);

    let output = run(command).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("not a CA certificate"),
        "the mis-provisioned leaf must warn loudly, stderr: {stderr}"
    );

    let events = read_jsonl(&events_path);
    let abort = events
        .iter()
        .find(|event| event["name"] == "http.abort")
        .expect("the exchange fails closed instead of trusting the leaf");
    assert_eq!(
        abort["attributes"]["http.abort.reason"],
        "upstream_connect_error"
    );
    assert!(
        !events.iter().any(|event| event["name"] == "http.response"),
        "a mis-provisioned leaf must not verify its own upstream: {events:?}"
    );
}

#[tokio::test]
async fn proxy_survives_a_dangling_interception_ca_pointer_and_keeps_capturing() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // A plain-HTTP upstream: the publicly-reachable capture path that must survive a
    // broken CA provisioning. The dangling pointer warns loudly and degrades to
    // public-roots-only; it never fails the proxy or the run.
    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir)
        .env(
            "HILOOP_EGRESS_INTERCEPTION_CA",
            temp.path().join("no-such-ca.pem"),
        );
    let url = format!("http://127.0.0.1:{upstream_port}/v1/ok");
    append_mock_harness(&mut command, "proxy-http", &[&url]);

    let output = run(command).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("egress interception CA"),
        "the dangling CA pointer must warn loudly, stderr: {stderr}"
    );

    let events = read_jsonl(&events_path);
    let response = events
        .iter()
        .find(|event| event["name"] == "http.response")
        .expect("capture must survive a broken CA provisioning");
    assert_eq!(response["attributes"]["http.status_code"], "200");
}

#[tokio::test]
async fn proxy_correlates_request_and_response_over_chunked_upstream() {
    // A plain-HTTP upstream the proxy forwards to: it returns a chunked body so
    // the capture exercises the streaming tee, and because a real response comes
    // back, both the request and its response are captured — letting us assert
    // they share an http.exchange_id and that the de-chunked body was retained.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "7\r\nchunk-1\r\n",
                "7\r\nchunk-2\r\n",
                "0\r\n\r\n",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let blob_dir = temp.path().join("blobs");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--blob-dir")
        .arg(&blob_dir);
    let url = format!("http://127.0.0.1:{upstream_port}/v1/stream");
    append_mock_harness(&mut command, "proxy-http", &[&url]);

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let request = events
        .iter()
        .find(|event| {
            event["name"] == "http.request"
                && event["attributes"]["http.target"]
                    .as_str()
                    .is_some_and(|target| target.ends_with("/v1/stream"))
        })
        .expect("a captured http request");
    let response = events
        .iter()
        .find(|event| event["name"] == "http.response")
        .expect("a captured http response");

    let request_id = request["attributes"]["http.exchange_id"]
        .as_str()
        .expect("request exchange id");
    let response_id = response["attributes"]["http.exchange_id"]
        .as_str()
        .expect("response exchange id");
    assert_eq!(
        request_id, response_id,
        "request and response must share an exchange id"
    );

    // The chunked response body was reassembled and streamed to the blob store;
    // the blob's bytes are "chunk-1chunk-2", proving frame boundaries did not
    // corrupt capture.
    let digest = response["payload_ref"]["digest"]
        .as_str()
        .expect("response payload_ref digest");
    let hex = digest.strip_prefix("blake3:").expect("blake3 prefix");
    let blob = std::fs::read(blob_dir.join(format!("blake3-{hex}"))).expect("read response blob");
    assert_eq!(blob, b"chunk-1chunk-2");
}

#[tokio::test]
async fn proxy_capture_without_blob_dir_uploads_bodies_to_the_gateway() {
    // Same plain-HTTP upstream as the chunked-capture test: a response body worth shipping.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "7\r\nchunk-1\r\n",
                "7\r\nchunk-2\r\n",
                "0\r\n\r\n",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let gateway = fake_gateway::serve().await;

    // No --blob-dir: with a gRPC export, bodies stage in a per-run scratch store and are
    // uploaded to the same gateway the events go to at run end.
    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--export-grpc")
        .arg(&gateway.endpoint)
        .arg("--insecure-grpc");
    let url = format!("http://127.0.0.1:{upstream_port}/v1/stream");
    append_mock_harness(&mut command, "proxy-http", &[&url]);

    let output = run(command).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        !stderr.contains("telemetry capture incomplete"),
        "the blob drain must complete cleanly, stderr: {stderr}"
    );

    // The de-chunked response body reached the gateway CAS…
    let uploads = gateway.uploads.lock().expect("lock");
    let response_upload = uploads
        .iter()
        .find(|(_, bytes)| bytes == b"chunk-1chunk-2")
        .expect("the captured response body should have been uploaded");

    // …under exactly the digest the exported response event references.
    let events = gateway.events.lock().expect("lock");
    let response_event = events
        .iter()
        .find(|event| event.name == "http.response")
        .expect("a captured http response event");
    let digest = &response_event
        .payload_ref
        .as_ref()
        .expect("response payload_ref")
        .digest;
    assert_eq!(digest, &response_upload.0);

    // The run-end capture-health record states the drain landed everything.
    let drain_event = find_capture_drain_event(&events);
    assert_eq!(drain_event.signal, "log");
    assert_eq!(
        proto_attr_bool(drain_event, "capture.complete"),
        Some(true),
        "attributes: {:?}",
        drain_event.attributes
    );
    assert_eq!(
        proto_attr_i64(drain_event, "capture.blobs.missing"),
        Some(0)
    );
    assert!(
        proto_attr_i64(drain_event, "capture.blobs.found").is_some_and(|found| found >= 1),
        "the drain must account for the captured body"
    );
    assert_eq!(
        proto_attr_i64(drain_event, "capture.blobs.found"),
        proto_attr_i64(drain_event, "capture.blobs.landed"),
    );
}

#[tokio::test]
async fn every_exported_event_carries_the_wrap_invocation_identity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A plain-HTTP upstream that answers, so the wrap captures a full exchange.
    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Length: 2\r\n\r\n",
                "ok",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let gateway = fake_gateway::serve().await;
    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let fixture_path = temp.path().join("trace.pb");
    std::fs::write(&fixture_path, otlp_trace_fixture()).expect("write fixture");

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--otlp")
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--export-grpc")
        .arg(&gateway.endpoint)
        .arg("--insecure-grpc")
        .arg("--egress-mode")
        .arg("allow")
        .arg("--egress-domain")
        .arg("denied.test");
    let url = format!("http://127.0.0.1:{upstream_port}/v1/ok");
    append_mock_harness(
        &mut command,
        "full",
        &[
            fixture_path.to_str().expect("fixture path"),
            &url,
            "http://denied.test/",
        ],
    );

    let output = run(command).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = read_jsonl(&events_path);
    let names = events
        .iter()
        .map(|event| event["name"].as_str().expect("event name").to_owned())
        .collect::<BTreeSet<_>>();
    for required in [
        "process.start",
        "process.exit",
        "process.stdout",
        "process.stderr",
        "http.request",
        "http.response",
        "egress.denied",
        "chat",
        "capture.drain",
    ] {
        assert!(
            names.contains(required),
            "expected a {required} event, got {names:?}"
        );
    }

    // One invocation identity across every exported event — pipeline-normalized
    // and out-of-band alike — and it is a minted ULID.
    let invocation_id = events[0]["attributes"][provenance_keys::WRAPPER_INVOCATION_ID]
        .as_str()
        .expect("wrapper.invocation_id on the first event")
        .to_owned();
    ulid::Ulid::from_string(&invocation_id).expect("wrapper.invocation_id is a valid ULID");
    for event in &events {
        assert_eq!(
            event["attributes"][provenance_keys::WRAPPER_INVOCATION_ID].as_str(),
            Some(invocation_id.as_str()),
            "every exported event carries the run's invocation id: {event}"
        );
    }

    // The capture-health record is built outside the pipeline; the shared
    // provenance seam must still stamp process identity onto it.
    let drain = events
        .iter()
        .find(|event| event["name"] == "capture.drain")
        .expect("capture.drain event");
    assert!(
        drain["attributes"][provenance_keys::PROCESS_PID]
            .as_i64()
            .expect("capture.drain carries process.pid")
            > 0
    );
}

#[tokio::test]
async fn exchange_ids_do_not_collide_across_wrapper_invocations_in_one_run() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Length: 2\r\n\r\n",
                "ok",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    // Two sequential wrapper invocations stamped with the SAME run identity —
    // the shape of sibling execs inside one sandbox run.
    let temp = tempfile::tempdir().expect("tempdir");
    let url = format!("http://127.0.0.1:{upstream_port}/v1/ok");
    let mut exchange_ids = Vec::new();
    for events_file in ["first.jsonl", "second.jsonl"] {
        let events_path = temp.path().join(events_file);
        let blob_dir = temp.path().join(format!("{events_file}-blobs"));
        let mut command = interceptor_command();
        command
            .arg("--proxy")
            .arg("--events-jsonl")
            .arg(&events_path)
            .arg("--blob-dir")
            .arg(&blob_dir);
        append_mock_harness(&mut command, "proxy-http", &[&url]);

        let output = run(command).await;
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let events = read_jsonl(&events_path);
        let request = events
            .iter()
            .find(|event| event["name"] == "http.request")
            .expect("a captured http request");
        exchange_ids.push(
            request["attributes"]["http.exchange_id"]
                .as_str()
                .expect("request exchange id")
                .to_owned(),
        );
    }

    let [first, second] = exchange_ids.as_slice() else {
        panic!("expected two exchange ids, got {exchange_ids:?}");
    };
    assert_ne!(
        first, second,
        "invocations sharing one run must never mint the same exchange id"
    );
    for id in [first, second] {
        ulid::Ulid::from_string(id).expect("http.exchange_id is a minted ULID");
    }
}

/// The single `capture.drain` health record in `events` — exactly one per captured run.
fn find_capture_drain_event(
    events: &[hiloop_interceptor::grpc_client::proto::Event],
) -> &hiloop_interceptor::grpc_client::proto::Event {
    let drains: Vec<_> = events
        .iter()
        .filter(|event| event.name == "capture.drain")
        .collect();
    assert_eq!(
        drains.len(),
        1,
        "expected exactly one capture.drain event, got {}",
        drains.len()
    );
    drains[0]
}

fn proto_attr_i64(event: &hiloop_interceptor::grpc_client::proto::Event, key: &str) -> Option<i64> {
    use hiloop_interceptor::grpc_client::proto::attribute_value::Value;
    match event.attributes.get(key)?.value.as_ref()? {
        Value::IntValue(value) => Some(*value),
        _ => None,
    }
}

fn proto_attr_bool(
    event: &hiloop_interceptor::grpc_client::proto::Event,
    key: &str,
) -> Option<bool> {
    use hiloop_interceptor::grpc_client::proto::attribute_value::Value;
    match event.attributes.get(key)?.value.as_ref()? {
        Value::BoolValue(value) => Some(*value),
        _ => None,
    }
}

#[tokio::test]
async fn failed_blob_drain_keeps_the_scratch_store_for_recovery() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Length: 9\r\n\r\n",
                "body-kept",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    // Ingest-only gateway: the run-end blob drain fails, so the scratch store must survive.
    let gateway = fake_gateway::serve_ingest_only().await;

    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--export-grpc")
        .arg(&gateway.endpoint)
        .arg("--insecure-grpc");
    let url = format!("http://127.0.0.1:{upstream_port}/v1/body");
    append_mock_harness(&mut command, "proxy-http", &[&url]);

    let output = run(command).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");

    let kept_marker = "captured payload blobs kept at `";
    let start = stderr
        .find(kept_marker)
        .unwrap_or_else(|| panic!("warning should name the kept scratch dir, stderr: {stderr}"))
        + kept_marker.len();
    let kept_path = std::path::PathBuf::from(
        &stderr[start..start + stderr[start..].find('`').expect("closing backtick")],
    );

    let kept_blobs: Vec<_> = std::fs::read_dir(&kept_path)
        .expect("kept scratch dir should still exist")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("blake3-"))
        })
        .collect();
    assert!(
        kept_blobs
            .iter()
            .any(|path| std::fs::read(path).expect("read kept blob") == b"body-kept"),
        "the captured response body should survive in the kept scratch dir"
    );

    // The audit scenario: blob transport broken, event ingest healthy. The loss must be
    // queryable, not silent — the capture-health record lands over ingest and says how many
    // bodies never made it.
    let events = gateway.events.lock().expect("lock");
    let drain_event = find_capture_drain_event(&events);
    assert_eq!(
        proto_attr_bool(drain_event, "capture.complete"),
        Some(false),
        "attributes: {:?}",
        drain_event.attributes
    );
    assert!(
        proto_attr_i64(drain_event, "capture.blobs.missing").is_some_and(|missing| missing >= 1),
        "the missing body count must be reported"
    );
    assert!(
        drain_event.attributes.contains_key("capture.error"),
        "the drain failure must be recorded on the event"
    );

    std::fs::remove_dir_all(&kept_path).expect("cleanup kept scratch dir");
}

/// A gateway outage for the whole run must not abort capture: every event still
/// lands in the local JSONL sink, the child's exit code passes through, and the
/// undelivered backlog is reported with counts — not dropped silently.
#[tokio::test]
async fn gateway_outage_keeps_local_capture_complete_and_reports_undelivered_counts() {
    // A dead endpoint: bind a port, then drop the listener so every connect is refused.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let dead_endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let mut command = interceptor_command();
    command
        .arg("--events-jsonl")
        .arg(&events_path)
        .arg("--export-grpc")
        .arg(&dead_endpoint)
        .arg("--insecure-grpc")
        // Small batches so the outage is hit across several export calls, not one
        // final flush — the regression this guards is the pipeline dying on the
        // first failed batch and losing the rest of the local capture too.
        .arg("--export-batch-size")
        .arg("4");
    append_mock_harness(&mut command, "lines", &["10"]);

    let output = run(command).await;

    assert!(output.status.success(), "the outage must not fail the run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("telemetry capture incomplete"),
        "the undelivered backlog must be reported, stderr: {stderr}"
    );
    assert!(
        stderr.contains("never reached the telemetry gateway"),
        "the report names the loss class with a count, stderr: {stderr}"
    );

    // The local JSONL capture is untouched by the gateway outage.
    let events = read_jsonl(&events_path);
    let stdio_messages = events
        .iter()
        .filter(|event| event["name"] == "process.stdout" || event["name"] == "process.stderr")
        .count();
    assert_eq!(
        stdio_messages, 20,
        "all 10 stdout + 10 stderr lines are captured locally despite the outage"
    );
    assert_process_lifecycle(&events, 0);

    // The capture-health record is minted and captured locally; it accounts for the
    // backlog without claiming loss (the spool drops nothing under its caps here).
    let drain = events
        .iter()
        .find(|event| event["name"] == "capture.drain")
        .expect("capture.drain event in the local capture");
    assert_eq!(drain["attributes"]["capture.events.dropped"], 0);
    assert_eq!(drain["attributes"]["capture.events.rejected"], 0);
    assert!(
        drain["attributes"]["capture.events.pending"]
            .as_i64()
            .expect("pending count")
            > 0,
        "the backlog at mint time is recorded: {drain}"
    );
    assert_eq!(
        drain["attributes"]["capture.complete"], true,
        "spooled-but-undelivered is a backlog, not a loss: {drain}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn incremental_drain_lands_bodies_before_a_sigkill_teardown() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Length: 13\r\n\r\n",
                "survives-kill",
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let gateway = fake_gateway::serve().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let fetched = temp.path().join("fetched");
    let mut command = interceptor_command();
    command
        .arg("--proxy")
        .arg("--export-grpc")
        .arg(&gateway.endpoint)
        .arg("--insecure-grpc");
    let url = format!("http://127.0.0.1:{upstream_port}/v1/body");
    append_mock_harness(
        &mut command,
        "proxy-http-hang",
        &[&url, fetched.to_str().expect("marker path")],
    );
    let mut child = command.spawn().expect("spawn interceptor");

    // The harness has fetched the body; the run is still alive. The incremental drain must
    // ship the captured bytes without waiting for run end — that is the durability contract
    // for a teardown that never delivers SIGTERM.
    wait_for_path(&fetched).await;
    tokio::time::timeout(E2E_TIMEOUT, async {
        loop {
            let landed = gateway
                .uploads
                .lock()
                .expect("lock")
                .iter()
                .any(|(_, bytes)| bytes == b"survives-kill");
            if landed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the captured body should land at the gateway while the run is still alive");

    // Hard-kill the wrapper: SIGKILL cannot be caught, so no run-end drain happens at all.
    let pid =
        i32::try_from(child.id().expect("interceptor pid")).expect("interceptor pid fits i32");
    kill(Pid::from_raw(pid), Signal::SIGKILL).expect("send SIGKILL to interceptor");
    let status = tokio::time::timeout(E2E_TIMEOUT, child.wait())
        .await
        .expect("interceptor should exit after SIGKILL")
        .expect("wait interceptor");
    assert!(!status.success());

    // The bytes shipped before the kill are safe; and a hard-killed run leaves no
    // capture.drain record — its absence is the queryable "capture died mid-run" signal.
    assert!(
        gateway
            .uploads
            .lock()
            .expect("lock")
            .iter()
            .any(|(_, bytes)| bytes == b"survives-kill"),
        "the body uploaded before SIGKILL must remain at the gateway"
    );
    assert!(
        gateway
            .events
            .lock()
            .expect("lock")
            .iter()
            .all(|event| event.name != "capture.drain"),
        "a SIGKILLed wrapper cannot have drained at run end"
    );
}

/// In-process telemetry gateway hosting both services the interceptor speaks — event ingest and
/// the digest-first blob transport — on one endpoint, mirroring the hosted gateway's shape.
mod fake_gateway {
    use std::sync::{Arc, Mutex};

    use hiloop_interceptor::grpc_client::proto::telemetry_blob_service_server::{
        TelemetryBlobService, TelemetryBlobServiceServer,
    };
    use hiloop_interceptor::grpc_client::proto::telemetry_ingest_service_server::{
        TelemetryIngestService, TelemetryIngestServiceServer,
    };
    use hiloop_interceptor::grpc_client::proto::{
        Event, HasBlobsRequest, HasBlobsResponse, IngestRequest, IngestResponse,
        IngestStreamRequest, IngestStreamResponse, UploadBlobRequest, UploadBlobResponse,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status, Streaming};

    /// Completed uploads as `(declared digest, assembled bytes)`.
    type RecordedUploads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    pub(crate) struct FakeGateway {
        pub(crate) endpoint: String,
        pub(crate) events: Arc<Mutex<Vec<Event>>>,
        pub(crate) uploads: RecordedUploads,
    }

    #[derive(Clone, Default)]
    struct Ingest {
        events: Arc<Mutex<Vec<Event>>>,
    }

    #[tonic::async_trait]
    impl TelemetryIngestService for Ingest {
        async fn ingest(
            &self,
            request: Request<IngestRequest>,
        ) -> Result<Response<IngestResponse>, Status> {
            let req = request.into_inner();
            let accepted = req.events.len() as u64;
            self.events.lock().expect("lock").extend(req.events);
            Ok(Response::new(IngestResponse { accepted }))
        }

        async fn ingest_stream(
            &self,
            request: Request<Streaming<IngestStreamRequest>>,
        ) -> Result<Response<IngestStreamResponse>, Status> {
            let mut stream = request.into_inner();
            let mut accepted = 0;
            while let Some(batch) = stream.message().await? {
                accepted += batch.events.len() as u64;
                self.events.lock().expect("lock").extend(batch.events);
            }
            Ok(Response::new(IngestStreamResponse { accepted }))
        }
    }

    #[derive(Clone, Default)]
    struct Blobs {
        uploads: RecordedUploads,
    }

    #[tonic::async_trait]
    impl TelemetryBlobService for Blobs {
        async fn has_blobs(
            &self,
            request: Request<HasBlobsRequest>,
        ) -> Result<Response<HasBlobsResponse>, Status> {
            // An empty store: everything the client offers is missing.
            Ok(Response::new(HasBlobsResponse {
                missing_digests: request.into_inner().digests,
            }))
        }

        async fn upload_blob(
            &self,
            request: Request<Streaming<UploadBlobRequest>>,
        ) -> Result<Response<UploadBlobResponse>, Status> {
            let mut stream = request.into_inner();
            let mut digest = String::new();
            let mut bytes = Vec::new();
            while let Some(frame) = stream.message().await? {
                bytes.extend_from_slice(&frame.data);
                if digest.is_empty() {
                    digest = frame.digest;
                }
            }
            let size_bytes = bytes.len() as u64;
            self.uploads.lock().expect("lock").push((digest, bytes));
            Ok(Response::new(UploadBlobResponse { size_bytes }))
        }
    }

    pub(crate) async fn serve() -> FakeGateway {
        serve_with_blob_service(true).await
    }

    /// A gateway that ingests events but hosts no blob service, so blob uploads fail
    /// (`unimplemented`) while the event export succeeds.
    pub(crate) async fn serve_ingest_only() -> FakeGateway {
        serve_with_blob_service(false).await
    }

    async fn serve_with_blob_service(with_blobs: bool) -> FakeGateway {
        let ingest = Ingest::default();
        let blobs = Blobs::default();
        let events = Arc::clone(&ingest.events);
        let uploads = Arc::clone(&blobs.uploads);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let addr = listener.local_addr().expect("gateway addr");
        tokio::spawn(async move {
            let mut router = tonic::transport::Server::builder()
                .add_service(TelemetryIngestServiceServer::new(ingest));
            if with_blobs {
                router = router.add_service(TelemetryBlobServiceServer::new(blobs));
            }
            router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("serve gateway");
        });
        FakeGateway {
            endpoint: format!("http://{addr}"),
            events,
            uploads,
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn forwards_sigterm_to_child_and_reports_signal_exit() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let temp = tempfile::tempdir().expect("tempdir");
    let started = temp.path().join("started");
    let terminated = temp.path().join("terminated");
    let _harness_reaper = HarnessGroupReaper {
        pid_file: started.clone(),
    };

    let mut command = interceptor_command();
    append_mock_harness(
        &mut command,
        "trap",
        &[
            started.to_str().expect("started path"),
            terminated.to_str().expect("terminated path"),
        ],
    );
    let mut child = command.spawn().expect("spawn interceptor");

    // The harness writes `started` only after installing its SIGTERM trap, and
    // the wrapper installs its forwarding handlers before spawning the child,
    // so once `started` exists both ends are ready for the signal.
    wait_for_path(&started).await;

    let pid =
        i32::try_from(child.id().expect("interceptor pid")).expect("interceptor pid fits i32");
    kill(Pid::from_raw(pid), Signal::SIGTERM).expect("send SIGTERM to interceptor");

    let status = tokio::time::timeout(E2E_TIMEOUT, child.wait())
        .await
        .expect("interceptor should exit after SIGTERM")
        .expect("wait interceptor");

    assert!(
        terminated.exists(),
        "the harness should have received the forwarded SIGTERM"
    );
    assert_eq!(
        status.code(),
        Some(143),
        "wrapper should report the child's 128 + SIGTERM exit code"
    );
}

/// Kills the mock harness's process group on drop, so no exit path — panic,
/// timeout, or a wrapper bug that skips forwarding — can leak the `trap`-mode
/// harness past the test.
///
/// The harness records its pid in the started marker, and the wrapper starts
/// it at the head of its own process group (pgid == pid); when the harness
/// already exited the kill is a no-op.
#[cfg(unix)]
struct HarnessGroupReaper {
    pid_file: PathBuf,
}

#[cfg(unix)]
impl Drop for HarnessGroupReaper {
    fn drop(&mut self) {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let Ok(contents) = std::fs::read_to_string(&self.pid_file) else {
            return;
        };
        let Ok(pid) = contents.trim().parse::<i32>() else {
            return;
        };
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

#[cfg(unix)]
async fn wait_for_path(path: &std::path::Path) {
    tokio::time::timeout(E2E_TIMEOUT, async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("path should appear before timeout");
}

fn interceptor_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hiloop-interceptor"));
    command.kill_on_drop(true);
    command.args(["run", "--run-id", RUN_ID, "--lineage-path", LINEAGE_PATH]);
    command
}

fn append_mock_harness(command: &mut Command, mode: &str, args: &[&str]) {
    command
        .arg("--")
        .arg("sh")
        .arg(mock_harness_path())
        .arg(mode)
        .args(args);
}

fn mock_harness_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock_harness.sh")
}

async fn run(mut command: Command) -> Output {
    tokio::time::timeout(E2E_TIMEOUT, command.output())
        .await
        .expect("interceptor e2e scenario timed out")
        .expect("run interceptor")
}

fn read_jsonl(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read jsonl")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("json record"))
        .collect()
}

/// The stdio (`signal == "log"`) subset of `events`, in file order.
fn log_events(events: &[Value]) -> Vec<&Value> {
    events
        .iter()
        .filter(|event| event["signal"] == "log")
        .collect()
}

fn assert_stdio_event(event: &Value) {
    assert_eq!(event["signal"], "log");
    assert_eq!(event["attributes"]["source"], "stdio");
}

/// Assert exactly one `process.start` and one `process.exit` event, the latter
/// carrying `exit_code` and a non-negative duration.
fn assert_process_lifecycle(events: &[Value], exit_code: i64) {
    let starts = events
        .iter()
        .filter(|event| event["name"] == "process.start")
        .collect::<Vec<_>>();
    let [start] = starts.as_slice() else {
        panic!("expected exactly one process.start, got {starts:?}");
    };
    assert_eq!(start["signal"], "exec");

    let exits = events
        .iter()
        .filter(|event| event["name"] == "process.exit")
        .collect::<Vec<_>>();
    let [exit] = exits.as_slice() else {
        panic!("expected exactly one process.exit, got {exits:?}");
    };
    assert_eq!(exit["signal"], "exec");
    assert_eq!(
        exit["attributes"]["process.exit_code"].as_i64(),
        Some(exit_code)
    );
    assert!(
        exit["attributes"]["process.duration_ms"]
            .as_i64()
            .expect("process.duration_ms")
            >= 0
    );
}

fn assert_common_event_provenance(event: &Value, raw_retention: &str) {
    assert_eq!(event["run_id"], RUN_ID);
    assert_eq!(event["lineage_path"], LINEAGE_PATH);
    assert_eq!(
        event["attributes"][provenance_keys::RAW_RETENTION],
        raw_retention
    );
    assert_eq!(event["attributes"][provenance_keys::PROCESS_COMMAND], "sh");
    assert_eq!(
        event["attributes"][provenance_keys::PROCESS_CWD],
        std::env::current_dir()
            .expect("current dir")
            .display()
            .to_string()
    );
    assert!(
        event["attributes"][provenance_keys::PROCESS_PID]
            .as_i64()
            .expect("process pid")
            > 0
    );
    assert_eq!(
        event["attributes"][provenance_keys::WRAPPER_NAME],
        "hiloop-interceptor"
    );
    assert_eq!(
        event["attributes"][provenance_keys::WRAPPER_VERSION],
        env!("CARGO_PKG_VERSION")
    );

    let argv = serde_json::from_str::<Vec<String>>(
        event["attributes"][provenance_keys::PROCESS_COMMAND_ARGS]
            .as_str()
            .expect("process argv"),
    )
    .expect("process argv json");
    assert_eq!(argv[0], "sh");
    assert_eq!(
        PathBuf::from(&argv[1]),
        mock_harness_path(),
        "argv should identify the mock harness"
    );
}

fn expected_lines(stream: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{stream}-{index:04}"))
        .collect()
}

fn event_messages(events: &[Value], stream: &str) -> Vec<String> {
    events
        .iter()
        .filter(|event| event["attributes"]["stream"] == stream)
        .map(|event| {
            event["attributes"]["message"]
                .as_str()
                .expect("message")
                .to_owned()
        })
        .collect()
}
