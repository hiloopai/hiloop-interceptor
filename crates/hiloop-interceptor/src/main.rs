mod cli;
mod supervisor;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    Box::pin(cli::run_from_args()).await
}
