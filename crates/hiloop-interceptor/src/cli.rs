//! Command-line interface for `hiloop-interceptor`.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use hiloop_core::identity::{ForkContext, ForkNodeId, ForkPath, RunId};
use hiloop_interceptor::pipeline::{DEFAULT_EXPORT_BATCH_SIZE, DEFAULT_EXPORT_FLUSH_INTERVAL_MS};
use hiloop_interceptor::proxy::DEFAULT_MAX_CAPTURE_BYTES;
use hiloop_interceptor::{GrpcExportOptions, RedactionPolicy, RunOptions, run};
use std::{path::PathBuf, process::ExitCode, time::Duration};

pub(crate) async fn run_from_args() -> Result<ExitCode> {
    Box::pin(Cli::parse().execute()).await
}

#[derive(Debug, Parser)]
#[command(name = "hiloop-interceptor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    async fn execute(self) -> Result<ExitCode> {
        match self.command {
            Command::Run(args) => {
                let options = args.into_run_options();
                Box::pin(run(&options)).await
            }
            Command::Inspect(args) => {
                let diff = args
                    .diff
                    .as_ref()
                    .map(|paths| (paths[0].as_str(), paths[1].as_str()));
                crate::inspect_cli::run(&args.events_jsonl, diff)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "clap flattens each variant's Args struct into the subcommand; the size spread between run and inspect is inherent and not worth boxing through clap's derive"
)]
enum Command {
    /// Run a command under the interceptor supervisor.
    Run(RunArgs),
    /// Summarize a captured events JSONL file, grouped by fork path.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// Newline-delimited JSON events file produced by `run --events-jsonl`.
    events_jsonl: PathBuf,

    /// Compare two fork paths' event-name distributions, e.g. `--diff "" /0`.
    #[arg(long, num_args = 2, value_names = ["PATH_A", "PATH_B"])]
    diff: Option<Vec<String>>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Run id to stamp on telemetry. Generated locally when omitted.
    #[arg(long, env = "HILOOP_RUN_ID")]
    run_id: Option<RunId>,

    /// Fork-tree node id to stamp on telemetry. Generated locally when omitted.
    #[arg(
        long = "node",
        visible_alias = "fork-node-id",
        env = "HILOOP_FORK_NODE_ID"
    )]
    fork_node_id: Option<ForkNodeId>,

    /// Materialized fork path. Defaults to the root path.
    #[arg(long, env = "HILOOP_FORK_PATH")]
    fork_path: Option<ForkPath>,

    /// Create a newline-delimited JSON event file. Fails if the path exists.
    #[arg(long = "events-jsonl", env = "HILOOP_EVENTS_JSONL")]
    events_jsonl: Option<PathBuf>,

    /// Create a newline-delimited raw observation file. Requires `--events-jsonl`.
    #[arg(long = "raw-jsonl", env = "HILOOP_RAW_JSONL")]
    raw_jsonl: Option<PathBuf>,

    /// Directory for the content-addressed blob store the proxy streams bodies to.
    /// Created if absent. Required by `--proxy`.
    #[arg(long = "blob-dir", env = "HILOOP_BLOB_DIR")]
    blob_dir: Option<PathBuf>,

    /// Run an embedded OTLP receiver and capture the child's OpenTelemetry
    /// export. Requires `--events-jsonl`.
    #[arg(long = "otlp")]
    otlp: bool,

    /// Run an embedded MITM proxy and capture the child's HTTP(S) traffic.
    /// Requires `--events-jsonl` and `--blob-dir`.
    #[arg(long = "proxy")]
    proxy: bool,

    /// Cap how many body bytes the proxy captures (blob + reported size) per
    /// request/response. Defaults to 8 MiB when omitted (the captured copy is buffered
    /// in memory, so a finite cap bounds interceptor memory). Set to `0` for unlimited.
    /// Never affects what the client or upstream receives.
    #[arg(long = "max-capture-bytes", env = "HILOOP_MAX_CAPTURE_BYTES")]
    max_capture_bytes: Option<u64>,

    /// Persist captured request/response bodies verbatim, without scrubbing
    /// credentials. Redaction is on by default and only affects the captured copy,
    /// never the traffic forwarded to the origin.
    #[arg(long = "no-redact", env = "HILOOP_NO_REDACT")]
    no_redact: bool,

    /// Stream captured events to a telemetry gateway over gRPC, e.g.
    /// `https://telemetry.example.com:443`. Composes with `--events-jsonl`. The API token is read
    /// from the `HILOOP_API_KEY` environment variable (never a flag, to keep it out of argv).
    #[arg(long = "export-grpc", env = "HILOOP_TELEMETRY_ENDPOINT")]
    export_grpc: Option<String>,

    /// Use cleartext h2c instead of TLS for `--export-grpc` (local dev gateways only).
    #[arg(long = "insecure-grpc")]
    insecure_grpc: bool,

    /// Project to record events under when exporting over gRPC.
    #[arg(
        long = "project-id",
        env = "HILOOP_PROJECT_ID",
        default_value = "default"
    )]
    project_id: String,

    /// Tenant to record under when exporting over gRPC. Omit against an authenticated gateway
    /// (it derives the tenant from the API token); set only for a no-auth local gateway.
    #[arg(long = "tenant-id", env = "HILOOP_TENANT_ID")]
    tenant_id: Option<String>,

    /// Ship a partial batch once this many captured events accumulate (the size trigger).
    #[arg(
        long = "export-batch-size",
        env = "HILOOP_EXPORT_BATCH_SIZE",
        default_value_t = DEFAULT_EXPORT_BATCH_SIZE,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..),
    )]
    export_batch_size: usize,

    /// Ship a partial batch after it has waited this many milliseconds, even before it reaches
    /// `--export-batch-size` (the age trigger). This bounds how long an event waits before it
    /// reaches the exporter, so a live tail sees a long-running command's events progressively
    /// rather than all at once when it exits. Set to 0 to disable and flush only on size or exit.
    #[arg(
        long = "export-flush-interval-ms",
        env = "HILOOP_EXPORT_FLUSH_INTERVAL_MS",
        default_value_t = DEFAULT_EXPORT_FLUSH_INTERVAL_MS,
    )]
    export_flush_interval_ms: u64,

    /// Command to wrap. Everything after `--` is passed to the child.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

impl RunArgs {
    fn into_run_options(self) -> RunOptions {
        let context = ForkContext::new(
            self.run_id.unwrap_or_default(),
            self.fork_node_id.unwrap_or_default(),
            self.fork_path.unwrap_or_default(),
        );

        let export_grpc = self.export_grpc.map(|endpoint| GrpcExportOptions {
            endpoint,
            insecure: self.insecure_grpc,
            tenant_id: self.tenant_id.filter(|t| !t.is_empty()),
            project_id: self.project_id,
        });

        let export_flush_interval = (self.export_flush_interval_ms > 0)
            .then(|| Duration::from_millis(self.export_flush_interval_ms));

        let redaction = if self.no_redact {
            RedactionPolicy::disabled()
        } else {
            RedactionPolicy::enabled()
        };

        let max_capture_bytes = resolve_max_capture_bytes(self.max_capture_bytes);

        RunOptions::new(
            context,
            self.command,
            self.events_jsonl,
            self.raw_jsonl,
            self.blob_dir,
            self.otlp,
            self.proxy,
            max_capture_bytes,
            export_grpc,
        )
        .with_export_batch_size(self.export_batch_size)
        .with_export_flush_interval(export_flush_interval)
        .with_redaction(redaction)
    }
}

/// Map the `--max-capture-bytes` CLI surface onto the internal representation, where
/// `None` means unlimited: omitted → the finite default (bounds interceptor memory),
/// `0` → unlimited, `N` → exactly `N`.
fn resolve_max_capture_bytes(flag: Option<u64>) -> Option<u64> {
    match flag {
        None => Some(DEFAULT_MAX_CAPTURE_BYTES),
        Some(0) => None,
        Some(n) => Some(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_cap_uses_finite_default() {
        assert_eq!(
            resolve_max_capture_bytes(None),
            Some(DEFAULT_MAX_CAPTURE_BYTES)
        );
    }

    #[test]
    fn zero_cap_means_unlimited() {
        assert_eq!(resolve_max_capture_bytes(Some(0)), None);
    }

    #[test]
    fn explicit_cap_is_passed_through() {
        assert_eq!(resolve_max_capture_bytes(Some(4096)), Some(4096));
    }

    #[test]
    fn parsed_run_args_apply_the_default_cap_when_omitted() {
        let cli = Cli::try_parse_from(["hiloop-interceptor", "run", "--", "echo", "hi"])
            .expect("parse run args");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        assert_eq!(
            resolve_max_capture_bytes(args.max_capture_bytes),
            Some(DEFAULT_MAX_CAPTURE_BYTES)
        );
    }

    #[test]
    fn parsed_zero_flag_maps_to_unlimited() {
        let cli = Cli::try_parse_from([
            "hiloop-interceptor",
            "run",
            "--max-capture-bytes",
            "0",
            "--",
            "echo",
            "hi",
        ])
        .expect("parse run args");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        assert_eq!(resolve_max_capture_bytes(args.max_capture_bytes), None);
    }
}
