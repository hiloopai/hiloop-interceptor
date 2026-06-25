//! Process supervision for wrapped harness commands.
//!
//! This is the embeddable entrypoint: build a [`RunOptions`] and call [`run`] to
//! supervise a child command, capturing its telemetry into the configured sinks.
//! The product CLI embeds this crate to provide `hiloop run -- <agent>` (ADR 0033).

use crate::{
    blob::DirBlobStore,
    exporters::{FanOutExporter, JsonlExporter},
    framing::LineFramer,
    grpc_export::GrpcIngestExporter,
    otlp::{OtlpReceiver, OtlpTraceNormalizer},
    pipeline::{Pipeline, PipelineOptions},
    proxy::{ProxyCa, ProxyNormalizer, ProxyServer},
    raw::JsonlRawStore,
    seams::{
        Exporter, NormalizationContext, Normalizer, NormalizerRouter, ProcessContext,
        RawRetentionPolicy, RawSignal, RawStore, SourceError,
    },
    stdio::StdioLogNormalizer,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hiloop_core::identity::ForkContext;
use std::{
    ffi::OsString,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
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

/// gRPC export target for captured events.
#[derive(Debug, Clone)]
pub struct GrpcExportOptions {
    /// Gateway endpoint, e.g. `https://telemetry.example.com:443`.
    pub endpoint: String,
    /// Use cleartext h2c instead of TLS (local dev gateways only).
    pub insecure: bool,
    /// Tenant to record under, or `None` against an authenticated gateway (it derives the tenant
    /// from the API token). Set only against a no-auth local gateway.
    pub tenant_id: Option<String>,
    /// Project to record events under.
    pub project_id: String,
}

/// Configuration for a single supervised run.
///
/// Construct with [`RunOptions::new`] and pass to [`run`]. The supervisor captures
/// the child's telemetry into whichever sinks are configured: a JSONL events file
/// ([`events_jsonl`](RunOptions::new)), a raw observation log, a content-addressed
/// blob store, an embedded OTLP receiver, an embedded MITM proxy, and/or a gRPC
/// export to a telemetry gateway. With no sink configured the child runs uncaptured.
#[derive(Debug, Clone)]
pub struct RunOptions {
    context: ForkContext,
    command: Vec<String>,
    events_jsonl: Option<PathBuf>,
    raw_jsonl: Option<PathBuf>,
    blob_dir: Option<PathBuf>,
    otlp: bool,
    proxy: bool,
    max_capture_bytes: Option<u64>,
    export_grpc: Option<GrpcExportOptions>,
}

impl RunOptions {
    /// Build run options for `command` (argv, where `command[0]` is the executable)
    /// stamped with the fork `context`.
    ///
    /// Each sink is optional and composes with the others: `events_jsonl` writes a
    /// newline-delimited JSON event log, `raw_jsonl` a raw observation log (requires
    /// an export target), `blob_dir` the proxy's blob store, `otlp` an embedded OTLP
    /// receiver, `proxy` an embedded MITM proxy (requires an export target and
    /// `blob_dir`), `max_capture_bytes` caps proxy body capture, and `export_grpc`
    /// streams events to a telemetry gateway. Invariants between these are validated
    /// by [`run`], not here.
    #[expect(
        clippy::too_many_arguments,
        reason = "public, embeddable run config; the flat constructor mirrors the CLI's RunArgs 1:1 — a builder is deferred while there is a single in-tree caller"
    )]
    pub fn new(
        context: ForkContext,
        command: Vec<String>,
        events_jsonl: Option<PathBuf>,
        raw_jsonl: Option<PathBuf>,
        blob_dir: Option<PathBuf>,
        otlp: bool,
        proxy: bool,
        max_capture_bytes: Option<u64>,
        export_grpc: Option<GrpcExportOptions>,
    ) -> Self {
        Self {
            context,
            command,
            events_jsonl,
            raw_jsonl,
            blob_dir,
            otlp,
            proxy,
            max_capture_bytes,
            export_grpc,
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

    fn set_otlp_endpoint(&mut self, addr: SocketAddr) {
        self.vars.push((
            "OTEL_EXPORTER_OTLP_ENDPOINT".into(),
            format!("http://{addr}").into(),
        ));
        self.vars
            .push(("OTEL_EXPORTER_OTLP_PROTOCOL".into(), "http/protobuf".into()));
    }

    fn set_proxy(&mut self, addr: SocketAddr, ca_path: &Path) {
        let proxy_url: OsString = format!("http://{addr}").into();
        // Both cases: tools split on which they read (curl uses lowercase).
        for var in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
            self.vars.push((var.into(), proxy_url.clone()));
        }
        // Child-scoped trust for the proxy CA across common runtimes; never the
        // system trust store.
        let ca = ca_path.as_os_str().to_owned();
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
        ] {
            self.vars.push((var.into(), ca.clone()));
        }
    }

    fn apply_to(&self, command: &mut Command) {
        command.envs(self.vars.iter().cloned());
    }
}

/// Supervise the child command described by `options`, returning its exit code.
///
/// Validates the sink invariants (e.g. `--proxy` needs a blob dir and an export
/// target), wires up the configured capture sinks, spawns the child in its own
/// process group with the fork context stamped into its environment, forwards
/// terminating signals, and drains telemetry until the child exits. Telemetry
/// export is best effort and never kills the child; a missing/failed-to-spawn
/// child or a misconfiguration returns `Err`.
pub async fn run(options: &RunOptions) -> Result<ExitCode> {
    if options.command.is_empty() {
        bail!("no command given; usage: hiloop-interceptor run -- <cmd> [args...]");
    }

    // Capture runs whenever there is somewhere to send events: a JSONL file and/or a gRPC export.
    let has_exporter = options.events_jsonl.is_some() || options.export_grpc.is_some();

    if options.raw_jsonl.is_some() && !has_exporter {
        bail!(
            "--raw-jsonl requires an export target (--events-jsonl or --export-grpc) so raw capture and normalization run together"
        );
    }

    if options.otlp && !has_exporter {
        bail!(
            "--otlp requires --events-jsonl or --export-grpc so received telemetry has an exporter"
        );
    }

    if options.proxy && (!has_exporter || options.blob_dir.is_none()) {
        bail!(
            "--proxy requires an export target (--events-jsonl or --export-grpc) and --blob-dir so captured bodies are streamed to the blob store"
        );
    }

    if has_exporter {
        // List durable sinks first (JSONL persists before the fallible network export is tried).
        let mut exporters: Vec<Box<dyn Exporter>> = Vec::new();
        if let Some(path) = &options.events_jsonl {
            exporters.push(Box::new(JsonlExporter::create(path).await.with_context(
                || {
                    format!(
                        "failed to create JSONL event exporter at `{}`",
                        path.display()
                    )
                },
            )?));
        }
        if let Some(grpc) = &options.export_grpc {
            exporters.push(Box::new(
                GrpcIngestExporter::connect(
                    &grpc.endpoint,
                    grpc.tenant_id.clone(),
                    &grpc.project_id,
                    grpc.insecure,
                )
                .with_context(|| {
                    format!("failed to build gRPC exporter for `{}`", grpc.endpoint)
                })?,
            ));
        }
        let exporter = FanOutExporter::new(exporters);
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

    let mut command = Command::new(&options.command[0]);
    command.args(&options.command[1..]);
    ChildEnv::for_context(&options.context).apply_to(&mut command);
    set_child_process_group(&mut command);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn child command `{}`", options.command[0]))?;
    let status = with_signal_forwarding(child.id(), child.wait())
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
    let clock = Arc::new(hiloop_core::identity::HlcClock::new());

    // Bind capture servers before spawning so the child env can point at them.
    let otlp_receiver = if options.otlp {
        Some(
            OtlpReceiver::bind(Arc::clone(&clock))
                .await
                .context("failed to bind OTLP receiver")?,
        )
    } else {
        None
    };

    let proxy_ca = if options.proxy {
        Some(ProxyCa::generate().context("failed to generate proxy CA")?)
    } else {
        None
    };
    // The child-scoped CA bundle file must outlive the child, so keep the handle.
    let proxy_ca_file = match &proxy_ca {
        Some(ca) => {
            let mut file =
                tempfile::NamedTempFile::new().context("failed to create proxy CA bundle file")?;
            file.write_all(ca.cert_pem().as_bytes())
                .context("failed to write proxy CA bundle")?;
            Some(file)
        }
        None => None,
    };
    let proxy_server = if options.proxy {
        Some(
            ProxyServer::bind(Arc::clone(&clock))
                .await
                .context("failed to bind proxy server")?,
        )
    } else {
        None
    };
    let blob_store = match (options.proxy, &options.blob_dir) {
        (true, Some(dir)) => {
            Some(Arc::new(DirBlobStore::create(dir).await.with_context(
                || format!("failed to create blob store at `{}`", dir.display()),
            )?))
        }
        _ => None,
    };

    let mut child = Command::new(&options.command[0]);
    child
        .args(&options.command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child_env = ChildEnv::for_context(&options.context);
    if let Some(receiver) = &otlp_receiver {
        let addr = receiver
            .local_addr()
            .context("failed to read OTLP receiver address")?;
        child_env.set_otlp_endpoint(addr);
    }
    if let (Some(server), Some(file)) = (&proxy_server, &proxy_ca_file) {
        let addr = server
            .local_addr()
            .context("failed to read proxy server address")?;
        child_env.set_proxy(addr, file.path());
    }
    child_env.apply_to(&mut child);
    set_child_process_group(&mut child);

    let mut child = child
        .spawn()
        .with_context(|| format!("failed to spawn child command `{}`", options.command[0]))?;
    let child_pid = child.id();
    let process = child_process_context(options, child_pid);
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

    let (otlp_shutdown_tx, otlp_server) = match otlp_receiver {
        Some(receiver) => {
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let server = receiver.serve(signal_tx.clone(), async move {
                let _ = shutdown_rx.await;
            });
            (Some(shutdown_tx), Some(server))
        }
        None => (None, None),
    };
    let (proxy_shutdown_tx, proxy_server_task) = match (proxy_server, proxy_ca, blob_store) {
        (Some(server), Some(ca), Some(blob_store)) => {
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let task = server.serve(
                ca,
                signal_tx.clone(),
                blob_store,
                options.max_capture_bytes,
                async move {
                    let _ = shutdown_rx.await;
                },
            );
            (Some(shutdown_tx), Some(task))
        }
        _ => (None, None),
    };
    drop(signal_tx);

    let stdio_normalizer = StdioLogNormalizer;
    let otlp_normalizer = OtlpTraceNormalizer;
    let proxy_normalizer = ProxyNormalizer;
    let mut normalizers: Vec<&dyn Normalizer> = vec![&stdio_normalizer];
    if options.otlp {
        normalizers.push(&otlp_normalizer);
    }
    if options.proxy {
        normalizers.push(&proxy_normalizer);
    }
    let router = NormalizerRouter::new(normalizers).expect("router has at least one normalizer");

    let normalization_context =
        NormalizationContext::new(options.context.clone()).with_process(process);
    let stream = tokio_stream::wrappers::ReceiverStream::new(signal_rx);
    let mut pipeline_builder =
        Pipeline::with_router(normalization_context, router, exporter).options(options_pipeline);
    if let Some(raw_store) = raw_store {
        pipeline_builder = pipeline_builder.raw_store(raw_store);
    }
    let pipeline = pipeline_builder.run(stream);

    // The child exiting is the cue to stop the capture servers: dropping their
    // senders lets the pipeline drain and finish.
    let child_and_shutdown = async {
        let status = with_signal_forwarding(child_pid, child.wait())
            .await
            .with_context(|| format!("failed to wait for child command `{}`", options.command[0]));
        for shutdown_tx in [otlp_shutdown_tx, proxy_shutdown_tx].into_iter().flatten() {
            let _ = shutdown_tx.send(());
        }
        status
    };
    let otlp_task = async {
        if let Some(server) = otlp_server {
            server.await;
        }
    };
    let proxy_task = async {
        // Capture is best effort: a proxy failure is reported, not fatal to the child.
        if let Some(task) = proxy_server_task
            && let Err(error) = task.await
        {
            eprintln!("hiloop-interceptor: proxy capture failed: {error}");
        }
    };

    let (status_result, stdout_result, stderr_result, (), (), pipeline_result) = Box::pin(async {
        tokio::join!(
            child_and_shutdown,
            stdout_capture,
            stderr_capture,
            otlp_task,
            proxy_task,
            async { pipeline.await.context("stdio event pipeline failed") },
        )
    })
    .await;

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

// TODO(source-seam): migrate this inline capture to `stdio::StdioSource`, which
// already composes the same `LineFramer` + verbatim-tee logic behind the
// `Source` trait. The blocker is a deliberate behavior difference, not the
// framing: this loop treats "the event pipeline closed before stdout/stderr
// finished" as a hard error (see `capture_stream_drains_after_event_pipeline_closes`
// and the `stdout_result`/`stderr_result` propagation in `run_captured`), whereas
// `StdioSource::run` returns `Ok(())` when its `RawSignalSink` reports
// `SinkSend::Closed` (a source must not assume *why* the pipeline went away).
// `run_captured` also fans stdout, stderr, OTLP, and proxy into ONE shared
// channel, so it cannot use `Pipeline::run_source` (which owns its channel);
// the migration must instead drive two `StdioSource`s against a shared
// `RawSignalSink` and decide how to preserve the closed-pipeline-is-fatal
// contract (e.g. a sink-closed callback or a supervisor-side check). Until that
// is designed, keep this path byte-for-byte to protect TESTING.md B1-B16.
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
    let mut framer = LineFramer::new(MAX_STDIO_LINE_BYTES);
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

        for record in framer.push(chunk) {
            send_stdio_signal(&mut signal_tx, stream_name, &clock, record).await;
        }
    }

    if let Some(record) = framer.flush() {
        send_stdio_signal(&mut signal_tx, stream_name, &clock, record).await;
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

fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    ExitCode::from(exit_u8_from_status(status))
}

/// Map a child exit status to a process exit byte.
///
/// Normal exits pass their code through. On Unix a child terminated by a signal
/// maps to the conventional `128 + signo`, so callers (and shells) can tell a
/// signal kill from a clean nonzero exit.
fn exit_u8_from_status(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128u8.saturating_add(u8::try_from(signal).unwrap_or(0));
        }
    }
    1
}

/// Put the child at the head of its own process group.
///
/// This lets the wrapper signal the whole harness subtree at once, and means
/// terminal job-control signals reach the child only through the wrapper's
/// deliberate forwarding rather than being delivered twice.
fn set_child_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

/// Run `work` to completion while forwarding terminating signals to the child.
///
/// On Unix the wrapper installs SIGINT/SIGTERM handlers and re-sends the signal
/// to the child's process group, so Ctrl-C and `kill` tear down the harness
/// subtree once instead of racing the wrapper, while the wrapper still drains
/// the child and reports its exit status. If handler installation fails, or off
/// Unix, `work` runs without forwarding.
#[cfg(unix)]
async fn with_signal_forwarding<F, T>(child_pid: Option<u32>, work: F) -> T
where
    F: std::future::Future<Output = T>,
{
    use tokio::signal::unix::{SignalKind, signal};

    let (Ok(mut sigint), Ok(mut sigterm)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        return work.await;
    };

    tokio::pin!(work);
    loop {
        tokio::select! {
            output = &mut work => return output,
            _ = sigint.recv() => forward_signal(child_pid, nix::sys::signal::Signal::SIGINT),
            _ = sigterm.recv() => forward_signal(child_pid, nix::sys::signal::Signal::SIGTERM),
        }
    }
}

#[cfg(not(unix))]
async fn with_signal_forwarding<F, T>(_child_pid: Option<u32>, work: F) -> T
where
    F: std::future::Future<Output = T>,
{
    work.await
}

/// Best-effort forward of `signal` to the child's process group.
#[cfg(unix)]
fn forward_signal(child_pid: Option<u32>, signal: nix::sys::signal::Signal) {
    let Some(pid) = child_pid else {
        return;
    };
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    // The child leads its own process group (process_group(0)), so its pgid is
    // its pid. The group may already be gone if the child just exited, so this
    // is best effort.
    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal);
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
        ) -> std::result::Result<(), crate::seams::ExportError> {
            Err(crate::seams::ExportError::other(
                "failing",
                "intentional test failure",
            ))
        }
    }

    #[test]
    fn child_env_sets_otlp_endpoint_and_protocol() {
        let mut env = ChildEnv::for_context(&ForkContext::new_local_root());
        env.set_otlp_endpoint("127.0.0.1:4317".parse().expect("addr"));

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
            vars.get("OTEL_EXPORTER_OTLP_ENDPOINT").map(String::as_str),
            Some("http://127.0.0.1:4317")
        );
        assert_eq!(
            vars.get("OTEL_EXPORTER_OTLP_PROTOCOL").map(String::as_str),
            Some("http/protobuf")
        );
    }

    #[cfg(unix)]
    #[test]
    fn exit_u8_maps_normal_and_signal_termination() {
        use std::os::unix::process::ExitStatusExt;

        // Normal exits pass their code through.
        assert_eq!(exit_u8_from_status(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_u8_from_status(ExitStatus::from_raw(3 << 8)), 3);
        // Signal termination uses the conventional 128 + signo encoding.
        assert_eq!(exit_u8_from_status(ExitStatus::from_raw(15)), 143); // SIGTERM
        assert_eq!(exit_u8_from_status(ExitStatus::from_raw(2)), 130); // SIGINT
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
            None,
            false,
            false,
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
