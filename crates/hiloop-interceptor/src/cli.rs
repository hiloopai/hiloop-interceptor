//! Command-line interface for `hiloop-interceptor`.

use crate::supervisor::{RunOptions, run};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use hiloop_core::identity::{ForkContext, ForkNodeId, ForkPath, RunId};
use std::process::ExitCode;

pub(crate) fn run_from_args() -> Result<ExitCode> {
    Cli::parse().execute()
}

#[derive(Debug, Parser)]
#[command(name = "hiloop-interceptor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn execute(self) -> Result<ExitCode> {
        match self.command {
            Command::Run(args) => {
                let options = args.into_run_options();
                run(&options)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a command under the interceptor supervisor.
    Run(RunArgs),
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

        RunOptions::new(context, self.command)
    }
}
