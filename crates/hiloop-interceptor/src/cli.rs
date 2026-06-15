//! Command-line interface for `hiloop-interceptor`.

use crate::supervisor::{RunOptions, run};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use hiloop_core::identity::{ForkContext, ForkNodeId, ForkPath, RunId};
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

    /// Run an embedded OTLP receiver and capture the child's OpenTelemetry
    /// export. Requires `--events-jsonl`.
    #[arg(long = "otlp")]
    otlp: bool,

    /// Run an embedded MITM proxy and capture the child's HTTP(S) traffic.
    /// Requires `--events-jsonl` and `--raw-jsonl`.
    #[arg(long = "proxy")]
    proxy: bool,

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

        RunOptions::new(
            context,
            self.command,
            self.events_jsonl,
            self.raw_jsonl,
            self.otlp,
            self.proxy,
        )
    }
}
