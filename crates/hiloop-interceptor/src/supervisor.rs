//! Process supervision for wrapped harness commands.

use anyhow::{Context, Result, bail};
use hiloop_core::identity::ForkContext;
use std::{
    ffi::OsString,
    process::{Command, ExitCode, ExitStatus},
};

#[derive(Debug, Clone)]
pub(crate) struct RunOptions {
    context: ForkContext,
    command: Vec<String>,
}

impl RunOptions {
    pub(crate) fn new(context: ForkContext, command: Vec<String>) -> Self {
        Self { context, command }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildEnv {
    vars: Vec<(OsString, OsString)>,
}

impl ChildEnv {
    fn for_context(context: &ForkContext) -> Self {
        let resource_attributes = format!(
            "run.id={},fork.node_id={},fork.path={}",
            context.run_id, context.fork_node_id, context.fork_path
        );

        Self {
            vars: vec![
                ("HILOOP_RUN_ID".into(), context.run_id.to_string().into()),
                (
                    "HILOOP_FORK_NODE_ID".into(),
                    context.fork_node_id.to_string().into(),
                ),
                (
                    "HILOOP_FORK_PATH".into(),
                    context.fork_path.to_string().into(),
                ),
                (
                    "OTEL_RESOURCE_ATTRIBUTES".into(),
                    resource_attributes.into(),
                ),
            ],
        }
    }

    #[cfg(test)]
    fn vars(&self) -> &[(OsString, OsString)] {
        &self.vars
    }

    fn apply_to(&self, command: &mut Command) {
        command.envs(self.vars.iter().cloned());
    }
}

pub(crate) fn run(options: &RunOptions) -> Result<ExitCode> {
    if options.command.is_empty() {
        bail!("no command given; usage: hiloop-interceptor run -- <cmd> [args...]");
    }

    let mut child = Command::new(&options.command[0]);
    child.args(&options.command[1..]);
    ChildEnv::for_context(&options.context).apply_to(&mut child);

    let status = child
        .status()
        .with_context(|| format!("failed to run child command `{}`", options.command[0]))?;
    Ok(exit_code_from_status(status))
}

fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::identity::{ForkNodeId, ForkPath, RunId};
    use std::str::FromStr;

    #[test]
    fn child_env_stamps_the_fork_context() {
        let run_id = RunId::from_str("01J00000000000000000000000").expect("run id");
        let fork_node_id = ForkNodeId::from_str("01J00000000000000000000001").expect("node id");
        let fork_path = ForkPath::parse("/0/3").expect("fork path");
        let context = ForkContext::new(run_id, fork_node_id, fork_path);

        let env = ChildEnv::for_context(&context);
        let vars = env
            .vars()
            .iter()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(
            vars.get("HILOOP_RUN_ID").map(String::as_str),
            Some("01J00000000000000000000000")
        );
        assert_eq!(
            vars.get("HILOOP_FORK_NODE_ID").map(String::as_str),
            Some("01J00000000000000000000001")
        );
        assert_eq!(
            vars.get("HILOOP_FORK_PATH").map(String::as_str),
            Some("/0/3")
        );
        assert_eq!(
            vars.get("OTEL_RESOURCE_ATTRIBUTES").map(String::as_str),
            Some(
                "run.id=01J00000000000000000000000,fork.node_id=01J00000000000000000000001,fork.path=/0/3"
            )
        );
    }
}
