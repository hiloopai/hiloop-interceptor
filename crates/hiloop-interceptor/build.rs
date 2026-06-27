//! Generate the `TelemetryIngestService` gRPC client (+ a server for tests) from the vendored
//! `proto/` tree using protox (pure-Rust protobuf compiler — no system `protoc`) + tonic-prost-build.
//!
//! `proto/hiloop/telemetry/v1/telemetry.proto` is the vendored copy of the gateway's published wire
//! contract; update it when that contract changes.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest.join("proto");
    let proto = proto_root.join("hiloop/telemetry/v1/telemetry.proto");

    println!("cargo:rerun-if-changed={}", proto.display());

    let fds = protox::compile([&proto], [&proto_root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)?;
    Ok(())
}
