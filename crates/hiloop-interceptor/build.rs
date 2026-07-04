//! Generate the `TelemetryIngestService` and `TelemetryBlobService` gRPC clients (+ servers for
//! tests) from the vendored `proto/` tree using protox (pure-Rust protobuf compiler — no system
//! `protoc`) + tonic-prost-build.
//!
//! `proto/hiloop/telemetry/v1/` holds the vendored copies of the gateway's published wire
//! contracts; update them when those contracts change.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest.join("proto");
    let protos = [
        proto_root.join("hiloop/telemetry/v1/telemetry.proto"),
        proto_root.join("hiloop/telemetry/v1/blob.proto"),
    ];

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let fds = protox::compile(&protos, [&proto_root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)?;
    Ok(())
}
