use serde_json::Value;
use std::process::Command;

#[test]
fn captures_stdio_to_jsonl_while_teeing_child_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let jsonl = temp.path().join("events.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_hiloop-interceptor"))
        .args([
            "run",
            "--run-id",
            "01J00000000000000000000000",
            "--node",
            "01J00000000000000000000001",
            "--fork-path",
            "/0/3",
            "--events-jsonl",
            jsonl.to_str().expect("jsonl path"),
            "--",
            "sh",
            "-c",
            "printf 'out1\npartial'; printf 'err1\n' >&2",
        ])
        .output()
        .expect("run interceptor");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout"),
        "out1\npartial"
    );
    assert_eq!(String::from_utf8(output.stderr).expect("stderr"), "err1\n");

    let contents = std::fs::read_to_string(jsonl).expect("read jsonl");
    let events = contents
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("json event"))
        .collect::<Vec<_>>();

    for event in &events {
        assert_eq!(event["run_id"], "01J00000000000000000000000");
        assert_eq!(event["fork_node_id"], "01J00000000000000000000001");
        assert_eq!(event["fork_path"], "/0/3");
        assert_eq!(event["signal"], "log");
        assert_eq!(event["attributes"]["source"], "stdio");
    }

    let mut messages = events
        .iter()
        .map(|event| {
            (
                event["name"].as_str().expect("event name"),
                event["attributes"]["stream"]
                    .as_str()
                    .expect("stream attribute"),
                event["attributes"]["message"]
                    .as_str()
                    .expect("message attribute"),
            )
        })
        .collect::<Vec<_>>();
    messages.sort_unstable();

    assert_eq!(
        messages,
        [
            ("process.stderr", "stderr", "err1"),
            ("process.stdout", "stdout", "out1"),
            ("process.stdout", "stdout", "partial"),
        ]
    );
}
