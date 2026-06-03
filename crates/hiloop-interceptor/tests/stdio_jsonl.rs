use hiloop_interceptor::seams::provenance_keys;
use serde_json::Value;
use std::process::Command;

#[test]
fn captures_stdio_to_jsonl_while_teeing_child_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let jsonl = temp.path().join("events.jsonl");
    let raw_jsonl = temp.path().join("raw.jsonl");

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
            "--raw-jsonl",
            raw_jsonl.to_str().expect("raw jsonl path"),
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
        assert_eq!(
            event["attributes"][provenance_keys::RAW_RETENTION],
            "preserve"
        );
        assert!(
            event["attributes"][provenance_keys::RAW_OBSERVATION_ID]
                .as_str()
                .expect("raw observation id")
                .starts_with("raw-jsonl-")
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
        assert_eq!(argv[1], "-c");
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

    let raw_contents = std::fs::read_to_string(raw_jsonl).expect("read raw jsonl");
    let raw_records = raw_contents
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("raw json event"))
        .collect::<Vec<_>>();
    assert_eq!(raw_records.len(), 3);

    let raw_ids = raw_records
        .iter()
        .map(|record| record["id"].as_str().expect("raw id"))
        .collect::<std::collections::BTreeSet<_>>();
    let event_raw_ids = events
        .iter()
        .map(|event| {
            event["attributes"][provenance_keys::RAW_OBSERVATION_ID]
                .as_str()
                .expect("event raw id")
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(raw_ids, event_raw_ids);

    let mut raw_bodies = raw_records
        .iter()
        .map(|record| record["body_base64"].as_str().expect("raw body"))
        .collect::<Vec<_>>();
    raw_bodies.sort_unstable();
    assert_eq!(raw_bodies, ["ZXJyMQ==", "b3V0MQ==", "cGFydGlhbA=="]);
}
