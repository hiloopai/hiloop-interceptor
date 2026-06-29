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

#[cfg(unix)]
#[tokio::test]
async fn capture_preserves_tty_stdio_for_interactive_children() {
    use nix::pty::openpty;
    use tokio::io::AsyncReadExt as _;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let pty = openpty(None, None).expect("open pty");
    let master = std::fs::File::from(pty.master);
    let slave = std::fs::File::from(pty.slave);

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
    reader.abort();
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
        stdout.contains("4 events across 1 fork path(s)"),
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
    assert_eq!(llm["fork_path"], FORK_PATH);
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
    assert_eq!(request["fork_path"], FORK_PATH);
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
