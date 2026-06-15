use hiloop_interceptor::seams::provenance_keys;
use serde_json::Value;
use std::{collections::BTreeSet, path::PathBuf, process::Output, time::Duration};
use tokio::process::Command;

const RUN_ID: &str = "01J00000000000000000000000";
const FORK_NODE_ID: &str = "01J00000000000000000000001";
const FORK_PATH: &str = "/0/3";
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
            "HILOOP_RUN_ID=01J00000000000000000000000\n",
            "HILOOP_FORK_NODE_ID=01J00000000000000000000001\n",
            "HILOOP_FORK_PATH=/0/3\n",
            "OTEL_RESOURCE_ATTRIBUTES=hiloop.run.id=01J00000000000000000000000,",
            "hiloop.fork.node_id=01J00000000000000000000001,",
            "hiloop.fork.path=/0/3\n",
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
    assert_eq!(events.len(), 4);
    for event in &events {
        assert_common_event_provenance(event, "preserve");
        assert!(
            event["attributes"][provenance_keys::RAW_OBSERVATION_ID]
                .as_str()
                .expect("raw observation id")
                .starts_with("raw-jsonl-")
        );
    }

    let messages = events
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
    assert_eq!(raw_records.len(), 4);
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
        BTreeSet::from(["ZXJyLXBhcnRpYWw=", "ZXJyMQ==", "b3V0MQ==", "cGFydGlhbA=="])
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
    assert_eq!(events.len(), LINE_COUNT * 2);
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
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["attributes"]["message_base64"], "/wBB");
    assert_eq!(events[0]["attributes"]["message_encoding"], "base64");
    assert!(events[0]["attributes"].get("message").is_none());
    assert_eq!(events[1]["attributes"]["message"], "");
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
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|event| event["name"].as_str().expect("event name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["process.stderr", "process.stdout"])
    );
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
            .contains("--raw-jsonl requires --events-jsonl")
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
        stdout.contains("4 events across 1 fork path(s)"),
        "summary header missing: {stdout}"
    );
    assert!(stdout.contains("process.stdout: 2"), "stdout count: {stdout}");
    assert!(stdout.contains("process.stderr: 2"), "stderr count: {stdout}");
}

#[cfg(unix)]
#[tokio::test]
async fn forwards_sigterm_to_child_and_reports_signal_exit() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let temp = tempfile::tempdir().expect("tempdir");
    let started = temp.path().join("started");
    let terminated = temp.path().join("terminated");

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
    // the wrapper installs its own handlers before the child can run, so once
    // `started` exists both ends are ready for the signal.
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
    command.args([
        "run",
        "--run-id",
        RUN_ID,
        "--node",
        FORK_NODE_ID,
        "--fork-path",
        FORK_PATH,
    ]);
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

fn assert_common_event_provenance(event: &Value, raw_retention: &str) {
    assert_eq!(event["run_id"], RUN_ID);
    assert_eq!(event["fork_node_id"], FORK_NODE_ID);
    assert_eq!(event["fork_path"], FORK_PATH);
    assert_eq!(event["signal"], "log");
    assert_eq!(event["attributes"]["source"], "stdio");
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
        event["attributes"][provenance_keys::PROCESS_ARGV]
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
