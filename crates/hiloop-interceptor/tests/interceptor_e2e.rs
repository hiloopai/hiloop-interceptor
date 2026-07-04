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
        start["attributes"][provenance_keys::PROCESS_ARGV]
            .as_str()
            .expect("process argv"),
    )
    .expect("process argv json");
    assert_eq!(argv[0], "sh");
    assert!(start["attributes"][provenance_keys::PROCESS_CWD].is_string());

    // Without the flag the attribute is omitted (names are opt-in; values never captured).
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

#[cfg(unix)]
#[tokio::test]
async fn captures_forwarded_signal_as_a_process_signal_event() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let temp = tempfile::tempdir().expect("tempdir");
    let events_path = temp.path().join("events.jsonl");
    let started = temp.path().join("started");
    let terminated = temp.path().join("terminated");

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

    std::fs::remove_dir_all(&kept_path).expect("cleanup kept scratch dir");
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
