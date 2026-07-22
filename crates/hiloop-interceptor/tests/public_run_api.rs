//! The embeddable `run` library surface: a downstream crate
//! like the product CLI builds a `RunContext`, optional `GrpcExportOptions`, and a
//! `RunOptions`, then awaits `hiloop_interceptor::run`. These tests pin that surface
//! through the crate-root re-exports and assert the child's exit code passes through.

use std::process::ExitCode;
use std::time::Duration;

use hiloop_core::identity::RunContext;
use hiloop_interceptor::{DrainRetryPolicy, GrpcExportOptions, NetworkCapture, RunOptions, run};

fn options_for(command: Vec<String>, export_grpc: Option<GrpcExportOptions>) -> RunOptions {
    RunOptions::new(
        RunContext::new_local_root(),
        command,
        None,
        None,
        None,
        false,
        NetworkCapture::off(),
        None,
        export_grpc,
    )
}

#[tokio::test]
async fn run_passes_through_child_exit_code() {
    let options = options_for(
        vec!["sh".to_owned(), "-c".to_owned(), "exit 7".to_owned()],
        None,
    );

    let code = run(&options).await.expect("run should complete");

    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(7)));
}

#[tokio::test]
async fn sequential_runs_in_one_process_mint_distinct_invocation_ids() {
    // The invocation id is minted per constructed run, never from process-wide
    // static state, so an embedder running several wraps in one process gets a
    // distinct identity for each.
    let temp = tempfile::tempdir().expect("tempdir");
    let mut invocation_ids = Vec::new();
    for events_file in ["first.jsonl", "second.jsonl"] {
        let events_path = temp.path().join(events_file);
        let options = RunOptions::new(
            RunContext::new_local_root(),
            vec!["true".to_owned()],
            Some(events_path.clone()),
            None,
            None,
            false,
            NetworkCapture::off(),
            None,
            None,
        );

        run(&options).await.expect("run should complete");

        let contents = std::fs::read_to_string(&events_path).expect("events file");
        let event: serde_json::Value =
            serde_json::from_str(contents.lines().next().expect("an exported event"))
                .expect("event json");
        let invocation_id = event["attributes"]["wrapper.invocation_id"]
            .as_str()
            .expect("wrapper.invocation_id attribute")
            .to_owned();
        ulid::Ulid::from_string(&invocation_id).expect("wrapper.invocation_id is a valid ULID");
        invocation_ids.push(invocation_id);
    }

    assert_ne!(
        invocation_ids[0], invocation_ids[1],
        "each wrap invocation mints its own identity"
    );
}

#[tokio::test]
async fn grpc_export_options_are_part_of_the_public_surface() {
    // A downstream embedder constructs the gRPC target alongside the run options.
    let export = GrpcExportOptions {
        endpoint: "http://127.0.0.1:50051".to_owned(),
        insecure: true,
        tenant_id: Some("dev".to_owned()),
        project_id: "local".to_owned(),
        bearer_refresh: None,
    };
    let options = options_for(vec!["true".to_owned()], Some(export));

    // The export connects lazily, so a missing local gateway doesn't fail the run.
    let code = run(&options).await.expect("run should complete");

    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
}

#[tokio::test]
async fn export_cadence_builders_are_part_of_the_public_surface() {
    // A downstream embedder can tune the size and age flush triggers on the run options.
    let options = options_for(vec!["true".to_owned()], None)
        .with_export_batch_size(32)
        .with_export_flush_interval(Some(Duration::from_millis(250)));

    let code = run(&options).await.expect("run should complete");

    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
}

#[tokio::test]
async fn blob_drain_builders_are_part_of_the_public_surface() {
    // A downstream embedder can tune the incremental drain cadence and the run-end
    // drain's bounded retry schedule.
    let options = options_for(vec!["true".to_owned()], None)
        .with_blob_drain_interval(Duration::from_millis(250))
        .with_blob_drain_retry(DrainRetryPolicy {
            attempts: 2,
            initial_backoff: Duration::from_millis(10),
        });

    let code = run(&options).await.expect("run should complete");

    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
}
