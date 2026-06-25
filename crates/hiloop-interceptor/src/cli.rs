//! Command-line interface for `hiloop-interceptor`.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use hiloop_core::identity::{ForkContext, ForkNodeId, ForkPath, RunId};
use hiloop_interceptor::{GrpcExportOptions, RunOptions, run};
use std::{path::PathBuf, process::ExitCode};

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
    /// request/response. Unlimited when omitted; never affects what the client
    /// or upstream receives.
    #[arg(long = "max-capture-bytes", env = "HILOOP_MAX_CAPTURE_BYTES")]
    max_capture_bytes: Option<u64>,

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

    /// Tenant to record under when exporting over gRPC. Leave empty against an authenticated
    /// gateway (it derives the tenant from the API token); set only for a no-auth local gateway.
    #[arg(long = "tenant-id", env = "HILOOP_TENANT_ID", default_value = "")]
    tenant_id: String,

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
            tenant_id: self.tenant_id,
            project_id: self.project_id,
        });

        RunOptions::new(
            context,
            self.command,
            self.events_jsonl,
            self.raw_jsonl,
            self.blob_dir,
            self.otlp,
            self.proxy,
            self.max_capture_bytes,
            export_grpc,
        )
    }
}
