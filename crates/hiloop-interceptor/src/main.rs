mod cli;
mod supervisor;

use std::process::ExitCode;

fn main() -> anyhow::Result<ExitCode> {
    cli::run_from_args()
}
