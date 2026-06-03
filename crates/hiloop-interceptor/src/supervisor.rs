//! Process supervision for wrapped harness commands.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hiloop_core::identity::ForkContext;
use hiloop_interceptor::{
    exporters::JsonlExporter,
    pipeline::{PipelineOptions, run_stream_with_router_and_raw_store},
    raw::JsonlRawStore,
    seams::{
        Exporter, NormalizationContext, NormalizerRouter, ProcessContext, RawRetentionPolicy,
        RawSignal, RawStore, SourceError,
    },
    stdio::StdioLogNormalizer,
};
use std::{
    ffi::OsString,
    path::PathBuf,
    process::{ExitCode, ExitStatus, Stdio},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    sync::mpsc,
};

const MAX_STDIO_LINE_BYTES: usize = 64 * 1024;
const OTEL_RUN_ID: &str = "hiloop.run.id";
const OTEL_FORK_NODE_ID: &str = "hiloop.fork.node_id";
const OTEL_FORK_PATH: &str = "hiloop.fork.path";

#[derive(Debug, Clone)]
pub(crate) struct RunOptions {
    context: ForkContext,
    command: Vec<String>,
    events_jsonl: Option<PathBuf>,
    raw_jsonl: Option<PathBuf>,
}

impl RunOptions {
    pub(crate) fn new(
        context: ForkContext,
        command: Vec<String>,
        events_jsonl: Option<PathBuf>,
        raw_jsonl: Option<PathBuf>,
    ) -> Self {
        Self {
            context,
            command,
            events_jsonl,
            raw_jsonl,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildEnv {
    vars: Vec<(OsString, OsString)>,
}

impl ChildEnv {
    fn for_context(context: &ForkContext) -> Self {
        let resource_attributes = format!(
            "{OTEL_RUN_ID}={},{OTEL_FORK_NODE_ID}={},{OTEL_FORK_PATH}={}",
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

pub(crate) async fn run(options: &RunOptions) -> Result<ExitCode> {
    if options.command.is_empty() {
        bail!("no command given; usage: hiloop-interceptor run -- <cmd> [args...]");
    }

    if options.raw_jsonl.is_some() && options.events_jsonl.is_none() {
        bail!("--raw-jsonl requires --events-jsonl so raw capture and normalization run together");
    }

    if let Some(path) = &options.events_jsonl {
        let exporter = JsonlExporter::create(path).await.with_context(|| {
            format!(
                "failed to create JSONL event exporter at `{}`",
                path.display()
            )
        })?;
        if let Some(raw_path) = &options.raw_jsonl {
            let raw_store = JsonlRawStore::create(raw_path).await.with_context(|| {
                format!(
                    "failed to create JSONL raw observation store at `{}`",
                    raw_path.display()
                )
            })?;
            return Box::pin(run_captured(options, &exporter, Some(&raw_store))).await;
        }
        return Box::pin(run_captured(options, &exporter, None)).await;
    }

    let mut child = Command::new(&options.command[0]);
    child.args(&options.command[1..]);
    ChildEnv::for_context(&options.context).apply_to(&mut child);

    let status = child
        .status()
        .await
        .with_context(|| format!("failed to run child command `{}`", options.command[0]))?;
    Ok(exit_code_from_status(status))
}

async fn run_captured<E>(
    options: &RunOptions,
    exporter: &E,
    raw_store: Option<&dyn RawStore>,
) -> Result<ExitCode>
where
    E: Exporter,
{
    let mut child = Command::new(&options.command[0]);
    child
        .args(&options.command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    ChildEnv::for_context(&options.context).apply_to(&mut child);

    let mut child = child
        .spawn()
        .with_context(|| format!("failed to spawn child command `{}`", options.command[0]))?;
    let process = child_process_context(options, child.id());
    let stdout = child
        .stdout
        .take()
        .context("child stdout was not available for capture")?;
    let stderr = child
        .stderr
        .take()
        .context("child stderr was not available for capture")?;

    let mut options_pipeline = PipelineOptions::default();
    if raw_store.is_some() {
        options_pipeline =
            options_pipeline.with_raw_retention_override(RawRetentionPolicy::Preserve);
    }
    let (signal_tx, signal_rx) = mpsc::channel(options_pipeline.raw_queue_capacity());
    let clock = Arc::new(hiloop_core::identity::HlcClock::new());

    let stdout_capture = capture_stream(
        stdout,
        tokio::io::stdout(),
        "stdout",
        signal_tx.clone(),
        Arc::clone(&clock),
    );
    let stderr_capture = capture_stream(
        stderr,
        tokio::io::stderr(),
        "stderr",
        signal_tx.clone(),
        Arc::clone(&clock),
    );
    drop(signal_tx);

    let normalizer = StdioLogNormalizer;
    let router = NormalizerRouter::single(&normalizer);
    let normalization_context =
        NormalizationContext::new(options.context.clone()).with_process(process);
    let stream = tokio_stream::wrappers::ReceiverStream::new(signal_rx);
    let pipeline = run_stream_with_router_and_raw_store(
        &normalization_context,
        stream,
        &router,
        exporter,
        raw_store,
        options_pipeline,
    );

    let (status_result, stdout_result, stderr_result, pipeline_result) = tokio::join!(
        async {
            child.wait().await.with_context(|| {
                format!("failed to wait for child command `{}`", options.command[0])
            })
        },
        stdout_capture,
        stderr_capture,
        async { pipeline.await.context("stdio event pipeline failed") },
    );

    let status = status_result?;
    pipeline_result?;
    stdout_result.context("failed to capture child stdout")?;
    stderr_result.context("failed to capture child stderr")?;

    Ok(exit_code_from_status(status))
}

fn child_process_context(options: &RunOptions, pid: Option<u32>) -> ProcessContext {
    ProcessContext {
        pid,
        command: options.command.first().map(PathBuf::from),
        argv: options.command.clone(),
        cwd: std::env::current_dir().ok(),
    }
}

async fn capture_stream<R, W>(
    mut reader: R,
    mut writer: W,
    stream_name: &'static str,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut pending = Vec::new();
    let mut buffer = [0; 8192];
    let mut signal_tx = Some(signal_tx);

    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .with_context(|| format!("failed to read child {stream_name}"))?;
        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];
        writer
            .write_all(chunk)
            .await
            .with_context(|| format!("failed to tee child {stream_name}"))?;
        writer
            .flush()
            .await
            .with_context(|| format!("failed to flush tee for child {stream_name}"))?;

        pending.extend_from_slice(chunk);
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let mut line = pending.drain(..=newline).collect::<Vec<_>>();
            trim_line_ending(&mut line);
            send_stdio_signal(&mut signal_tx, stream_name, &clock, line).await;
        }
        while pending.len() > MAX_STDIO_LINE_BYTES {
            let chunk = pending.drain(..MAX_STDIO_LINE_BYTES).collect::<Vec<_>>();
            send_stdio_signal(&mut signal_tx, stream_name, &clock, chunk).await;
        }
    }

    if !pending.is_empty() {
        send_stdio_signal(&mut signal_tx, stream_name, &clock, pending).await;
    }

    if signal_tx.is_none() {
        bail!("stdio event pipeline stopped before {stream_name} capture finished");
    }

    Ok(())
}

async fn send_stdio_signal(
    signal_tx: &mut Option<mpsc::Sender<Result<RawSignal, SourceError>>>,
    stream_name: &'static str,
    clock: &hiloop_core::identity::HlcClock,
    line: Vec<u8>,
) {
    let Some(tx) = signal_tx else {
        return;
    };

    let raw = RawSignal::new("stdio", stream_name, clock.tick(), Bytes::from(line));
    if tx.send(Ok(raw)).await.is_err() {
        *signal_tx = None;
    }
}

fn trim_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
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
    use async_trait::async_trait;
    use hiloop_core::identity::{ForkNodeId, ForkPath, RunId};
    use std::str::FromStr;
    use tokio::io::AsyncWriteExt;

    #[derive(Debug)]
    struct FailingExporter;

    #[async_trait]
    impl Exporter for FailingExporter {
        async fn export(
            &self,
            _events: &[hiloop_core::event::Event],
        ) -> std::result::Result<(), hiloop_interceptor::seams::ExportError> {
            Err(hiloop_interceptor::seams::ExportError::other(
                "failing",
                "intentional test failure",
            ))
        }
    }

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
                "hiloop.run.id=01J00000000000000000000000,hiloop.fork.node_id=01J00000000000000000000001,hiloop.fork.path=/0/3"
            )
        );
    }

    #[tokio::test]
    async fn capture_stream_chunks_long_lines() {
        let line = vec![b'a'; MAX_STDIO_LINE_BYTES + 1];
        let (mut input, output) = tokio::io::duplex(MAX_STDIO_LINE_BYTES + 1);
        input.write_all(&line).await.expect("write test input");
        drop(input);

        let (signal_tx, mut signal_rx) = mpsc::channel(4);
        capture_stream(
            output,
            tokio::io::sink(),
            "stdout",
            signal_tx,
            Arc::new(hiloop_core::identity::HlcClock::new()),
        )
        .await
        .expect("capture stream");

        let first = signal_rx
            .recv()
            .await
            .expect("first signal")
            .expect("first raw signal");
        let second = signal_rx
            .recv()
            .await
            .expect("second signal")
            .expect("second raw signal");

        assert_eq!(first.body.len(), MAX_STDIO_LINE_BYTES);
        assert_eq!(second.body.len(), 1);
        assert!(signal_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn capture_stream_does_not_emit_empty_signal_for_boundary_newline() {
        let mut line = vec![b'a'; MAX_STDIO_LINE_BYTES];
        line.push(b'\n');
        let (mut input, output) = tokio::io::duplex(MAX_STDIO_LINE_BYTES + 1);
        input.write_all(&line).await.expect("write test input");
        drop(input);

        let (signal_tx, mut signal_rx) = mpsc::channel(4);
        capture_stream(
            output,
            tokio::io::sink(),
            "stdout",
            signal_tx,
            Arc::new(hiloop_core::identity::HlcClock::new()),
        )
        .await
        .expect("capture stream");

        let signal = signal_rx.recv().await.expect("signal").expect("raw signal");

        assert_eq!(signal.body.len(), MAX_STDIO_LINE_BYTES);
        assert!(signal_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn capture_stream_drains_after_event_pipeline_closes() {
        let (mut input, output) = tokio::io::duplex(64);
        input.write_all(b"hello\n").await.expect("write test input");
        drop(input);

        let (signal_tx, signal_rx) = mpsc::channel(1);
        drop(signal_rx);

        let error = capture_stream(
            output,
            tokio::io::sink(),
            "stdout",
            signal_tx,
            Arc::new(hiloop_core::identity::HlcClock::new()),
        )
        .await
        .expect_err("closed pipeline should be reported after drain");

        assert!(
            error
                .to_string()
                .contains("stdio event pipeline stopped before stdout capture finished")
        );
    }

    #[tokio::test]
    async fn telemetry_export_failure_does_not_kill_child() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("child-finished");
        let marker_arg = marker.to_string_lossy().into_owned();
        let options = RunOptions::new(
            ForkContext::new_local_root(),
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "printf 'hello\\n'; sleep 0.1; touch \"$0\"".to_owned(),
                marker_arg,
            ],
            None,
            None,
        );

        let error = Box::pin(run_captured(&options, &FailingExporter, None))
            .await
            .expect_err("export should fail");

        assert!(error.to_string().contains("stdio event pipeline failed"));
        assert!(
            marker.exists(),
            "child should finish despite export failure"
        );
    }
}
