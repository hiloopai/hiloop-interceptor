//! Generates the `TelemetryIngestService` gRPC client from the vendored ingest proto
//! (`proto/hiloop/telemetry/v1/telemetry.proto`) — the public wire contract the gateway exposes.
//! Client only: the interceptor exports telemetry, it never serves the ingest API.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/hiloop/telemetry/v1/telemetry.proto";
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=proto");

    // Bundle protoc so the build is self-contained (no system protobuf install required).
    if std::env::var_os("PROTOC").is_none() {
        // SAFETY: a build script runs single-threaded before it spawns protoc, so there is no
        // concurrent reader of the environment when this set_var executes.
        #[allow(
            unsafe_code,
            reason = "set_var is unsafe in edition 2024; safe here — single-threaded build script, set before protoc runs"
        )]
        unsafe {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir(&out_dir)
        .compile_protos(&[proto], &["proto"])?;
    Ok(())
}
