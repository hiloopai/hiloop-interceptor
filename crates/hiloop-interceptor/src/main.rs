mod cli;
mod inspect_cli;

use std::process::ExitCode;

fn main() -> anyhow::Result<ExitCode> {
    if let Some(result) = hiloop_interceptor::netns::dispatch_internal_helper() {
        return result.map_err(Into::into);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(cli::run_from_args()))
}
