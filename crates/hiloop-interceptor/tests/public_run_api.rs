//! The embeddable `run` library surface: a downstream crate
//! like the product CLI builds a `ForkContext`, optional `GrpcExportOptions`, and a
//! `RunOptions`, then awaits `hiloop_interceptor::run`. These tests pin that surface
//! through the crate-root re-exports and assert the child's exit code passes through.

use std::process::ExitCode;
use std::time::Duration;

use hiloop_core::identity::ForkContext;
use hiloop_interceptor::{GrpcExportOptions, RunOptions, run};

fn options_for(command: Vec<String>, export_grpc: Option<GrpcExportOptions>) -> RunOptions {
    RunOptions::new(
        ForkContext::new_local_root(),
        command,
        None,
        None,
        None,
        false,
        false,
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
async fn grpc_export_options_are_part_of_the_public_surface() {
    // A downstream embedder constructs the gRPC target alongside the run options.
    let export = GrpcExportOptions {
        endpoint: "http://127.0.0.1:50051".to_owned(),
        insecure: true,
        tenant_id: Some("dev".to_owned()),
        project_id: "local".to_owned(),
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
