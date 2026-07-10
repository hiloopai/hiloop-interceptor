//! Process supervision for wrapped harness commands.
//!
//! This is the embeddable entrypoint: build a [`RunOptions`] and call [`run`] to
//! supervise a child command, capturing its telemetry into the configured sinks.
//! A downstream CLI can embed this crate to provide a `run -- <agent>` command.

use crate::{
    anomaly::AnomalyConfig,
    blob::{BlobUploader, DirBlobStore, UnavailableUploader},
    blob_drain::{BlobDrainOutcome, BlobDrainer, DrainRetryPolicy},
    blob_upload::GrpcBlobUploader,
    egress::EgressPolicy,
    exec_events::{ExecLifecycleEmitter, ExecLifecycleNormalizer, captured_env_values},
    exporters::{FanOutExporter, JsonlExporter},
    framing::LineFramer,
    grpc_export::GrpcIngestExporter,
    otlp::{OtlpReceiver, OtlpTraceNormalizer},
    pipeline::{
        DEFAULT_EXPORT_BATCH_SIZE, DEFAULT_EXPORT_FLUSH_INTERVAL, Pipeline, PipelineOptions,
    },
    proxy::{ProxyCa, ProxyNormalizer, ProxyServer},
    raw::JsonlRawStore,
    redact::RedactionPolicy,
    seams::{
        Exporter, NormalizationContext, Normalizer, NormalizerRouter, ProcessContext,
        RawRetentionPolicy, RawSignal, RawStore, SourceError, provenance_keys,
    },
    secret::{BrokerConfig, SecretBinding, SecretInjector},
    spool::{SpoolPolicy, SpoolReport, SpoolingExporter},
    stdio::StdioLogNormalizer,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hiloop_core::{
    event::{AttributeKey, AttributeValue, Attributes, Event, EventName, SignalType},
    identity::{Hlc, RunContext},
};
use hudsucker::rustls::pki_types::{CertificateDer, pem::PemObject as _};
use std::{
    ffi::OsString,
    future::Future,
    io::{self, IsTerminal, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitCode, ExitStatus, Stdio},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::mpsc,
};

const MAX_STDIO_LINE_BYTES: usize = 64 * 1024;
const OTEL_RUN_ID: &str = "hiloop.run.id";
const OTEL_LINEAGE_PATH: &str = "hiloop.run.lineage_path";
const OTEL_EXECUTION_ID: &str = "hiloop.execution.id";

/// Default cadence of the incremental blob drain — the event pipeline's flush default, so
/// captured bodies are roughly as durable as the events referencing them: a run killed
/// without grace loses at most the last interval's blobs.
const DEFAULT_BLOB_DRAIN_INTERVAL: Duration = DEFAULT_EXPORT_FLUSH_INTERVAL;

/// Bound on exporting the run-end capture-health record: it shares the drain's best-effort
/// contract and must never hang the wrapper's exit. By run end the export channel is warm, so
/// this stays tight.
const CAPTURE_HEALTH_EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on exporting the spawn-failure record. This is the process's FIRST network use — on
/// guests with a degraded resolver the cold lookup alone can exceed 10s while later exports on a
/// warm channel are instant — and the child never ran, so trading extra seconds on the failure
/// path for the record actually landing is the right side of the budget.
const SPAWN_FAILURE_EXPORT_TIMEOUT: Duration = Duration::from_secs(45);

/// Event name of the run-end capture-health record.
const CAPTURE_DRAIN_EVENT: &str = "capture.drain";

/// Attribute keys of the `capture.drain` health record.
mod capture_keys {
    pub(super) const FOUND: &str = "capture.blobs.found";
    pub(super) const LANDED: &str = "capture.blobs.landed";
    pub(super) const MISSING: &str = "capture.blobs.missing";
    pub(super) const OVERSIZE: &str = "capture.blobs.oversize";
    pub(super) const MISSING_BYTES: &str = "capture.blobs.missing_bytes";
    pub(super) const EVENTS_DROPPED: &str = "capture.events.dropped";
    pub(super) const EVENTS_REJECTED: &str = "capture.events.rejected";
    pub(super) const EVENTS_PENDING: &str = "capture.events.pending";
    pub(super) const COMPLETE: &str = "capture.complete";
    pub(super) const ERROR: &str = "capture.error";
}

/// Locations of the OS public-root CA bundle, most-common first. The wrapped child
/// would normally trust these; the interception bundle must *preserve* that trust,
/// not replace it — pointing a CA env at a MITM-only file strips public-root trust
/// for any tool that honors `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`.
const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/distroless
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora/CentOS
    "/etc/ssl/cert.pem",                  // Alpine/macOS/OpenBSD
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

/// Read the OS public-root CA bundle the wrapped child would otherwise trust, honoring
/// an explicit `SSL_CERT_FILE` first, then the well-known paths. `None` if none exist.
fn read_system_ca_roots() -> Option<Vec<u8>> {
    if let Some(path) = std::env::var_os("SSL_CERT_FILE")
        && let Ok(bytes) = std::fs::read(&path)
        && !bytes.is_empty()
    {
        return Some(bytes);
    }
    for candidate in SYSTEM_CA_BUNDLE_CANDIDATES {
        if let Ok(bytes) = std::fs::read(candidate)
            && !bytes.is_empty()
        {
            return Some(bytes);
        }
    }
    None
}

/// Build the child-scoped trust bundle: the OS public roots unioned with the interception
/// CA, so the child validates both public hosts and the TLS-terminating proxy. The public
/// roots come first, newline-separated from the appended interception CA.
fn union_ca_bundle(system_roots: Option<&[u8]>, interception_ca_pem: &str) -> Vec<u8> {
    let mut bundle = Vec::new();
    if let Some(roots) = system_roots {
        bundle.extend_from_slice(roots);
        if !roots.ends_with(b"\n") {
            bundle.push(b'\n');
        }
    }
    bundle.extend_from_slice(interception_ca_pem.as_bytes());
    bundle
}

/// Names the PEM file of a deployment's egress interception CA, when the wrapper runs
/// behind a host-side egress proxy that terminates TLS for bound (credential-injecting)
/// destinations. Deployments that provision such a proxy also provision this variable
/// and file into the sandbox; both are absent everywhere else.
///
/// The proxy's *upstream* TLS client must trust that CA explicitly: rustls has no
/// `SSL_CERT_FILE` behavior, so the union bundle exported to the child does not reach
/// this hop. See [`load_extra_upstream_trust_anchors`].
const EGRESS_INTERCEPTION_CA_ENV: &str = "HILOOP_EGRESS_INTERCEPTION_CA";

/// Load the deployment egress interception CA named by [`EGRESS_INTERCEPTION_CA_ENV`]
/// for the proxy's upstream trust union.
///
/// Fail-safe by contract: an unset/empty variable means no deployment CA is
/// provisioned (the common case outside managed sandboxes) and contributes nothing,
/// silently; a set variable whose file is unreadable, empty, or not certificate PEM
/// warns loudly and contributes nothing — capture of publicly-anchored traffic must
/// survive a broken CA provisioning, while deployment-terminated routes then fail
/// closed at the upstream handshake exactly as if the CA had never been provisioned.
fn load_extra_upstream_trust_anchors() -> Vec<CertificateDer<'static>> {
    match std::env::var_os(EGRESS_INTERCEPTION_CA_ENV) {
        Some(path) if !path.is_empty() => interception_ca_anchors(Path::new(&path)),
        _ => Vec::new(),
    }
}

/// Parse the interception CA file into upstream trust anchors, warning loudly (and
/// returning no anchors) on any failure. See [`load_extra_upstream_trust_anchors`]
/// for the fail-safe contract.
fn interception_ca_anchors(path: &Path) -> Vec<CertificateDer<'static>> {
    let pem = match std::fs::read(path) {
        Ok(pem) => pem,
        Err(error) => {
            eprintln!(
                "hiloop-interceptor: warning: egress interception CA {} is unreadable; \
                 continuing with public roots only, so TLS the egress proxy terminates for \
                 bound routes will fail upstream verification: {error}",
                path.display()
            );
            return Vec::new();
        }
    };
    match CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>() {
        Ok(anchors) if anchors.is_empty() => {
            eprintln!(
                "hiloop-interceptor: warning: egress interception CA {} contains no \
                 certificates; continuing with public roots only, so TLS the egress proxy \
                 terminates for bound routes will fail upstream verification",
                path.display()
            );
            Vec::new()
        }
        Ok(anchors) => anchors,
        Err(error) => {
            eprintln!(
                "hiloop-interceptor: warning: egress interception CA {} is not certificate \
                 PEM; continuing with public roots only, so TLS the egress proxy terminates \
                 for bound routes will fail upstream verification: {error}",
                path.display()
            );
            Vec::new()
        }
    }
}

type CaptureFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

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
    context: RunContext,
    execution_id: Option<String>,
    command: Vec<String>,
    events_jsonl: Option<PathBuf>,
    raw_jsonl: Option<PathBuf>,
    blob_dir: Option<PathBuf>,
    otlp: bool,
    proxy: bool,
    max_capture_bytes: Option<u64>,
    export_grpc: Option<GrpcExportOptions>,
    export_batch_size: usize,
    export_flush_interval: Option<Duration>,
    blob_drain_interval: Duration,
    blob_drain_retry: DrainRetryPolicy,
    attributes: Attributes,
    redaction: RedactionPolicy,
    egress: EgressPolicy,
    anomaly: AnomalyConfig,
    secret_bindings: Vec<SecretBinding>,
    secret_broker: Option<BrokerConfig>,
    verbose_diagnostics: bool,
    env_allowlist: Vec<String>,
}

impl RunOptions {
    /// Build run options for `command` (argv, where `command[0]` is the executable)
    /// stamped with the run `context`.
    ///
    /// Construction mints the wrap's invocation identity: a ULID stamped as
    /// `wrapper.invocation_id` onto every event the run emits — including
    /// out-of-band records such as `capture.drain` and `process.spawn_failed` —
    /// so one `RunOptions` value describes exactly one wrap invocation and its
    /// events stay correlatable even when several invocations share a run.
    ///
    /// Each sink is optional and composes with the others: `events_jsonl` writes a
    /// newline-delimited JSON event log, `raw_jsonl` a raw observation log (requires
    /// an export target), `blob_dir` the proxy's durable local blob store, `otlp` an
    /// embedded OTLP receiver, `proxy` an embedded MITM proxy (requires an export
    /// target, plus somewhere for captured bodies: `blob_dir`, or `export_grpc` — which
    /// stages them in a per-run scratch store), `max_capture_bytes` caps the captured
    /// copy of proxy bodies in memory (`Some(n)` bounds it to `n` bytes; `None` is
    /// unlimited — prefer a finite cap such as [`crate::proxy::DEFAULT_MAX_CAPTURE_BYTES`]
    /// so a large body can't OOM the wrapper; forwarding to the origin is never capped),
    /// and `export_grpc` streams events to a telemetry gateway and, when the proxy is
    /// capturing, uploads the captured payload blobs there both during the run and in a
    /// retried run-end drain (digest-first dedup), reporting the outcome as a
    /// `capture.drain` event. Invariants between these are validated by [`run`], not here.
    #[expect(
        clippy::too_many_arguments,
        reason = "public, embeddable run config; the flat constructor mirrors the CLI's RunArgs 1:1 — a builder is deferred while there is a single in-tree caller"
    )]
    pub fn new(
        context: RunContext,
        command: Vec<String>,
        events_jsonl: Option<PathBuf>,
        raw_jsonl: Option<PathBuf>,
        blob_dir: Option<PathBuf>,
        otlp: bool,
        proxy: bool,
        max_capture_bytes: Option<u64>,
        export_grpc: Option<GrpcExportOptions>,
    ) -> Self {
        let mut attributes = Attributes::new();
        attributes.insert(
            AttributeKey::from_static(provenance_keys::WRAPPER_INVOCATION_ID),
            ulid::Ulid::new().to_string().into(),
        );
        Self {
            context,
            execution_id: None,
            command,
            events_jsonl,
            raw_jsonl,
            blob_dir,
            otlp,
            proxy,
            max_capture_bytes,
            export_grpc,
            export_batch_size: DEFAULT_EXPORT_BATCH_SIZE,
            export_flush_interval: Some(DEFAULT_EXPORT_FLUSH_INTERVAL),
            blob_drain_interval: DEFAULT_BLOB_DRAIN_INTERVAL,
            blob_drain_retry: DrainRetryPolicy::default(),
            attributes,
            redaction: RedactionPolicy::default(),
            egress: EgressPolicy::default(),
            anomaly: AnomalyConfig::default(),
            secret_bindings: Vec::new(),
            secret_broker: None,
            verbose_diagnostics: false,
            env_allowlist: Vec::new(),
        }
    }

    /// Override capture-side secret redaction. On by default; pass
    /// [`RedactionPolicy::disabled`] to persist captured bodies verbatim.
    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionPolicy) -> Self {
        self.redaction = redaction;
        self
    }

    /// Set the egress policy the proxy enforces. The default
    /// ([`EgressPolicy::default`]) allows all egress (a no-op). The policy applies
    /// only to traffic that flows through the proxy (`proxy` must be enabled) and is a
    /// cooperative control — the un-bypassable boundary is host-side.
    #[must_use]
    pub fn with_egress(mut self, egress: EgressPolicy) -> Self {
        self.egress = egress;
        self
    }

    /// The configured egress policy (default allow-all).
    pub fn egress_policy(&self) -> &EgressPolicy {
        &self.egress
    }

    /// Set the request-body anomaly-detection policy the proxy applies. The default
    /// ([`AnomalyConfig::default`]) is disabled (a no-op). Detection runs only on
    /// traffic that flows through the proxy (`proxy` must be enabled) and is a
    /// cooperative detection layer — the un-bypassable boundary is host-side.
    #[must_use]
    pub fn with_anomaly_detection(mut self, anomaly: AnomalyConfig) -> Self {
        self.anomaly = anomaly;
        self
    }

    /// The configured anomaly-detection policy (default disabled).
    pub fn anomaly_config(&self) -> &AnomalyConfig {
        &self.anomaly
    }

    /// Bind named secrets to destination hosts and configure the credential broker the
    /// proxy resolves them from. Injection applies only when `proxy` is enabled; a
    /// binding with no broker configured is a configuration error caught by [`run`].
    #[must_use]
    pub fn with_secret_bindings(
        mut self,
        bindings: Vec<SecretBinding>,
        broker: BrokerConfig,
    ) -> Self {
        self.secret_bindings = bindings;
        self.secret_broker = Some(broker);
        self
    }

    /// Override the export batch size: a partial batch is shipped once this many events accumulate.
    /// Values below 1 are clamped to 1.
    #[must_use]
    pub fn with_export_batch_size(mut self, size: usize) -> Self {
        self.export_batch_size = size.max(1);
        self
    }

    /// Override the incremental blob drain cadence. Captured payload blobs are shipped to
    /// the gateway on this interval while the run is alive (idle intervals cost no RPC), so
    /// a run killed without grace loses at most the last interval's blobs. A zero duration
    /// disables the incremental drain; the run-end drain still runs.
    #[must_use]
    pub fn with_blob_drain_interval(mut self, interval: Duration) -> Self {
        self.blob_drain_interval = interval;
        self
    }

    /// Override the run-end drain's bounded retry schedule. One budget bounds both
    /// final drains — captured payload blobs and the spooled event backlog — so it
    /// caps the wrapper's exit latency when the gateway is unreachable.
    #[must_use]
    pub fn with_blob_drain_retry(mut self, policy: DrainRetryPolicy) -> Self {
        self.blob_drain_retry = policy;
        self
    }

    /// Override the export age trigger: a partial batch waiting this long is shipped even before it
    /// reaches the batch size, so a live tail sees events progressively rather than only at run end.
    /// `None` (or a zero duration) disables the timer, restoring size-or-EOF-only flushing.
    #[must_use]
    pub fn with_export_flush_interval(mut self, interval: Option<Duration>) -> Self {
        self.export_flush_interval = interval.filter(|d| !d.is_zero());
        self
    }

    /// Stamp one static attribute onto every normalized event produced by this run.
    #[must_use]
    pub fn with_attribute(mut self, key: AttributeKey, value: impl Into<AttributeValue>) -> Self {
        self.attributes.insert(key, value.into());
        self
    }

    /// Stamp a control-plane execution id onto emitted events and child telemetry resources.
    #[must_use]
    pub fn with_execution_id(mut self, execution_id: impl Into<String>) -> Self {
        let execution_id = execution_id.into();
        if !execution_id.trim().is_empty() {
            self.attributes.insert(
                AttributeKey::from_static(provenance_keys::EXECUTION_ID),
                execution_id.clone().into(),
            );
            self.execution_id = Some(execution_id);
        }
        self
    }

    /// Print wrapper diagnostics to stderr. Disabled by default so `run` stays transparent.
    #[must_use]
    pub fn with_verbose_diagnostics(mut self, verbose: bool) -> Self {
        self.verbose_diagnostics = verbose;
        self
    }

    /// Record these environment variables on the run's `process.start` event:
    /// the names as `process.env_allowlist`, and each listed variable that is
    /// set in the child's environment as a `process.env.<NAME>` attribute whose
    /// value is scrubbed by the run's capture-side redaction (the same pattern
    /// and known-secret-literal passes applied to captured bodies) before it is
    /// recorded. Variables not listed here are never captured — the environment
    /// is a known secret carrier, so value capture stays strictly opt-in. Empty
    /// (the default) captures nothing and omits both attributes.
    #[must_use]
    pub fn with_env_allowlist(mut self, env_allowlist: Vec<String>) -> Self {
        self.env_allowlist = env_allowlist;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildEnv {
    vars: Vec<(OsString, OsString)>,
}

impl ChildEnv {
    fn for_run(context: &RunContext, execution_id: Option<&str>) -> Self {
        let execution_id = execution_id.filter(|value| !value.trim().is_empty());
        let mut resource_attributes = vec![
            format!("{OTEL_RUN_ID}={}", context.run_id),
            format!("{OTEL_LINEAGE_PATH}={}", context.lineage_path),
        ];
        if let Some(execution_id) = execution_id {
            resource_attributes.push(format!(
                "{OTEL_EXECUTION_ID}={}",
                encode_otel_resource_value(execution_id)
            ));
        }

        let mut vars = vec![
            ("HILOOP_RUN_ID".into(), context.run_id.to_string().into()),
            (
                "HILOOP_LINEAGE_PATH".into(),
                context.lineage_path.to_string().into(),
            ),
            (
                "OTEL_RESOURCE_ATTRIBUTES".into(),
                resource_attributes.join(",").into(),
            ),
        ];
        if let Some(execution_id) = execution_id {
            vars.push(("HILOOP_EXECUTION_ID".into(), execution_id.into()));
        }

        Self { vars }
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
        // Child-scoped trust across common runtimes: point each CA env at the
        // interception bundle (OS public roots unioned with the proxy CA — see
        // `union_ca_bundle`), so the child trusts both public hosts and the proxy
        // without us mutating the on-disk system trust store.
        let ca = ca_path.as_os_str().to_owned();
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            self.vars.push((var.into(), ca.clone()));
        }
    }

    fn apply_to(&self, command: &mut Command) {
        command.envs(self.vars.iter().cloned());
    }

    /// The value `name` resolves to in the child's environment: the last
    /// supervisor-injected override when present, else the inherited value.
    fn child_value(&self, name: &str) -> Option<OsString> {
        self.vars
            .iter()
            .rev()
            .find(|(key, _)| key.as_os_str() == std::ffi::OsStr::new(name))
            .map(|(_, value)| value.clone())
            .or_else(|| std::env::var_os(name))
    }
}

fn encode_otel_resource_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
            }
        }
    }
    encoded
}

/// Supervise the child command described by `options`, returning its exit code.
///
/// Validates the sink invariants (e.g. `--proxy` needs a blob dir and an export
/// target), wires up the configured capture sinks, spawns the child in its own
/// process group with the run context stamped into its environment, forwards
/// terminating signals, and drains telemetry until the child exits. Telemetry
/// export is best effort: it never kills the child, and once the child has
/// exited a capture/export failure is reported on stderr as a warning rather
/// than overriding the child's exit code. Only a missing/failed-to-spawn
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

    if options.proxy {
        if !has_exporter {
            bail!(
                "--proxy requires an export target (--events-jsonl or --export-grpc) so captured exchanges have an exporter"
            );
        }
        // Captured bodies need a durable destination: an explicit local store, or the gateway
        // (staged in a per-run scratch store, uploaded at run end). Anything else would lose
        // them silently.
        if options.blob_dir.is_none() && options.export_grpc.is_none() {
            bail!(
                "--proxy requires --blob-dir so captured bodies are streamed to the blob store (with --export-grpc it may be omitted: bodies are staged in a scratch store and uploaded to the gateway)"
            );
        }
    }

    if !options.secret_bindings.is_empty() {
        if !options.proxy {
            bail!(
                "secret bindings require --proxy: credentials are injected into intercepted HTTP(S) requests"
            );
        }
        if options.secret_broker.is_none() {
            bail!("secret bindings require a configured credential broker");
        }
    }

    if !options.egress.is_allow_all() && !options.proxy {
        bail!(
            "an egress policy requires --proxy: egress is enforced on intercepted HTTP(S) traffic"
        );
    }

    if options.anomaly.is_enabled() && !options.proxy {
        bail!(
            "anomaly detection requires --proxy: request bodies are inspected on intercepted HTTP(S) traffic"
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
        // The gRPC exporter is wrapped in a bounded spool so a gateway outage degrades
        // capture measurably (spooled, redelivered in order on recovery) instead of
        // killing the pipeline; the supervisor keeps a handle for the run-end drain
        // and its loss accounting.
        let mut event_spool: Option<Arc<SpoolingExporter<GrpcIngestExporter>>> = None;
        if let Some(grpc) = &options.export_grpc {
            let ingest = GrpcIngestExporter::connect(
                &grpc.endpoint,
                grpc.tenant_id.clone(),
                &grpc.project_id,
                grpc.insecure,
            )
            .with_context(|| format!("failed to build gRPC exporter for `{}`", grpc.endpoint))?;
            let spool = Arc::new(SpoolingExporter::new(ingest, SpoolPolicy::default()));
            exporters.push(Box::new(Arc::clone(&spool)));
            event_spool = Some(spool);
        }
        let exporter = FanOutExporter::new(exporters);
        if let Some(raw_path) = &options.raw_jsonl {
            let raw_store = JsonlRawStore::create(raw_path).await.with_context(|| {
                format!(
                    "failed to create JSONL raw observation store at `{}`",
                    raw_path.display()
                )
            })?;
            return Box::pin(run_captured(
                options,
                &exporter,
                Some(&raw_store),
                event_spool.as_deref(),
            ))
            .await
            .map(CapturedRun::into_exit_code);
        }
        return Box::pin(run_captured(
            options,
            &exporter,
            None,
            event_spool.as_deref(),
        ))
        .await
        .map(CapturedRun::into_exit_code);
    }

    let mut command = Command::new(&options.command[0]);
    command.args(&options.command[1..]);
    ChildEnv::for_run(&options.context, options.execution_id.as_deref()).apply_to(&mut command);
    set_child_process_group(&mut command);

    let signals = ForwardedSignals::install();
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn child command `{}`", options.command[0]))?;
    let status = with_signal_forwarding(signals, child.id(), None, None, child.wait())
        .await
        .with_context(|| format!("failed to run child command `{}`", options.command[0]))?;
    Ok(exit_code_from_status(status))
}

/// Outcome of a supervised, captured run: the child's exit byte plus any telemetry
/// drain failures that happened after the child ran (best-effort capture — reported,
/// never allowed to override the child's exit code).
struct CapturedRun {
    exit_code: u8,
    drain_warnings: Vec<anyhow::Error>,
}

impl CapturedRun {
    /// Report drain warnings on stderr and yield the child's exit code.
    fn into_exit_code(self) -> ExitCode {
        for warning in &self.drain_warnings {
            eprintln!("hiloop-interceptor: warning: telemetry capture incomplete: {warning:#}");
        }
        ExitCode::from(self.exit_code)
    }
}

async fn run_captured<E>(
    options: &RunOptions,
    exporter: &E,
    raw_store: Option<&dyn RawStore>,
    event_spool: Option<&SpoolingExporter<GrpcIngestExporter>>,
) -> Result<CapturedRun>
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
            let bundle = union_ca_bundle(read_system_ca_roots().as_deref(), ca.cert_pem());
            file.write_all(&bundle)
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
    // With a gRPC export and no explicit blob dir, bodies are staged in a per-run scratch store;
    // the TempDir handle keeps it alive until the post-run blob upload below, then removes it on
    // drop — unless the drain left blobs behind, in which case it is kept (see the drain below).
    // An explicit blob dir is the durable local CAS and is never removed.
    let mut scratch_blob_dir = match (options.proxy, &options.blob_dir, &options.export_grpc) {
        (true, None, Some(_)) => {
            Some(tempfile::tempdir().context("failed to create scratch blob dir")?)
        }
        _ => None,
    };
    let blob_store = match (options.proxy, &options.blob_dir, &scratch_blob_dir) {
        (true, Some(dir), _) => {
            Some(Arc::new(DirBlobStore::create(dir).await.with_context(
                || format!("failed to create blob store at `{}`", dir.display()),
            )?))
        }
        (true, None, Some(scratch)) => Some(Arc::new(
            DirBlobStore::create(scratch.path())
                .await
                .with_context(|| {
                    format!(
                        "failed to create blob store at `{}`",
                        scratch.path().display()
                    )
                })?,
        )),
        _ => None,
    };

    let mut command = Command::new(&options.command[0]);
    command.args(&options.command[1..]).kill_on_drop(true);
    #[cfg(unix)]
    let pty_stdio = configure_interactive_pty_stdio(&mut command)?;
    #[cfg(unix)]
    let uses_pty = pty_stdio.is_some();
    #[cfg(not(unix))]
    let uses_pty = false;
    if !uses_pty {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        set_child_process_group(&mut command);
    }
    let mut child_env = ChildEnv::for_run(&options.context, options.execution_id.as_deref());
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
    child_env.apply_to(&mut command);

    let signals = ForwardedSignals::install();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let event = spawn_failure_event(options, clock.tick(), &error);
            if let Err(warning) = export_supervisor_record(
                exporter,
                event,
                "spawn-failure",
                SPAWN_FAILURE_EXPORT_TIMEOUT,
            )
            .await
            {
                eprintln!("hiloop-interceptor: warning: telemetry capture incomplete: {warning:#}");
            }
            // The record may have parked in the event spool (a gateway outage at spawn
            // time); this is the process's only exit path, so give it its bounded final
            // chance now and report what stays undelivered.
            if let Some(spool) = event_spool {
                let report = spool.drain(&options.blob_drain_retry).await;
                if let Some(warning) = spool_problem(&report, spool.last_failure().await) {
                    eprintln!(
                        "hiloop-interceptor: warning: telemetry capture incomplete: {warning:#}"
                    );
                }
            }
            return Err(anyhow::Error::new(error).context(format!(
                "failed to spawn child command `{}`",
                options.command[0]
            )));
        }
    };
    drop(command);
    let child_started = Instant::now();
    let spawn_ts = clock.tick();
    let child_pid = child.id();
    let process = child_process_context(options, child_pid);
    #[cfg(unix)]
    let stdio = match pty_stdio {
        Some(pty_stdio) => CaptureStdio::Pty(Box::new(pty_stdio)),
        None => take_piped_stdio(&mut child)?,
    };
    #[cfg(not(unix))]
    let stdio = take_piped_stdio(&mut child)?;

    let mut options_pipeline = PipelineOptions::default()
        .with_export_batch_size(options.export_batch_size)
        .with_export_flush_interval(options.export_flush_interval);
    if raw_store.is_some() {
        options_pipeline =
            options_pipeline.with_raw_retention_override(RawRetentionPolicy::Preserve);
    }
    let (signal_tx, signal_rx) = mpsc::channel(options_pipeline.raw_queue_capacity());

    // Process-boundary lifecycle capture: `process.start` now, `process.signal`
    // on each forwarded terminating signal, `process.exit` once the child exits.
    let exec_emitter = ExecLifecycleEmitter::new(signal_tx.clone(), Arc::clone(&clock));
    // The broker token is the one secret the supervisor itself holds at spawn;
    // scrub it as a literal so an allowlist mistake can't record it verbatim.
    let secret_literals: Vec<&[u8]> = options
        .secret_broker
        .as_ref()
        .map(|broker| broker.token.as_bytes())
        .into_iter()
        .collect();
    let env_values = captured_env_values(
        &options.env_allowlist,
        |name| child_env.child_value(name),
        options.redaction,
        &secret_literals,
    );
    exec_emitter
        .emit_start(spawn_ts, &options.env_allowlist, &env_values)
        .await;

    let (stdin_shutdown_tx, stdin_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    #[cfg(unix)]
    let pty_resize_fd = match &stdio {
        CaptureStdio::Pty(pty) => Some(
            pty.resize_fd
                .try_clone()
                .context("failed to clone PTY resize handle")?,
        ),
        CaptureStdio::Pipes { .. } => None,
    };
    #[cfg(not(unix))]
    let pty_resize_fd = ();
    let (stdin_capture, stdout_capture, stderr_capture): (
        CaptureFuture<'_>,
        CaptureFuture<'_>,
        CaptureFuture<'_>,
    ) = match stdio {
        CaptureStdio::Pipes {
            stdin,
            stdout,
            stderr,
        } => stdio_pipe_captures(
            stdin,
            stdout,
            stderr,
            stdin_shutdown_rx,
            signal_tx.clone(),
            Arc::clone(&clock),
        ),
        #[cfg(unix)]
        CaptureStdio::Pty(pty) => stdio_pty_captures(
            *pty,
            stdin_shutdown_rx,
            signal_tx.clone(),
            Arc::clone(&clock),
        ),
    };

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
    let egress = Arc::new(options.egress.clone());
    let anomaly = Arc::new(options.anomaly.clone());
    let injector = match (&options.secret_broker, options.secret_bindings.is_empty()) {
        (Some(broker), false) => Some(
            SecretInjector::new(options.secret_bindings.clone(), broker)
                .context("failed to build the credential injector from the secret bindings")?,
        ),
        _ => None,
    };
    // The proxy consumes the store handle; the drainer keeps its own clone for the
    // incremental and run-end uploads. A gateway client that cannot even be configured
    // still gets a drainer (over an always-failing uploader), so run-end accounting
    // reports the loss instead of skipping silently.
    let blob_drainer = match (&blob_store, &options.export_grpc) {
        (Some(store), Some(grpc)) => {
            let uploader: Arc<dyn BlobUploader> = match GrpcBlobUploader::connect(
                &grpc.endpoint,
                grpc.tenant_id.clone(),
                grpc.insecure,
            ) {
                Ok(uploader) => Arc::new(uploader),
                Err(error) => Arc::new(UnavailableUploader::new(format!(
                    "failed to build the blob uploader for `{}`: {:#}",
                    grpc.endpoint,
                    anyhow::Error::new(error)
                ))),
            };
            Some(BlobDrainer::new(store.as_ref().clone(), uploader))
        }
        _ => None,
    };
    let (proxy_shutdown_tx, proxy_server_task) = match (proxy_server, proxy_ca, blob_store) {
        (Some(server), Some(ca), Some(blob_store)) => {
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let task = server.serve(
                ca,
                signal_tx.clone(),
                blob_store,
                options.max_capture_bytes,
                options.redaction,
                Arc::clone(&egress),
                Arc::clone(&anomaly),
                injector,
                load_extra_upstream_trust_anchors(),
                async move {
                    let _ = shutdown_rx.await;
                },
            );
            (Some(shutdown_tx), Some(task))
        }
        _ => (None, None),
    };
    drop(signal_tx);

    // Incremental blob drain: ship captured bodies while the run is still alive, so a
    // process killed without grace loses at most the last interval's blobs. Pass errors are
    // expected while the gateway is unreachable — the next pass (or the authoritative
    // run-end drain below) retries. The task hands the drainer back so run-end accounting
    // continues from the same landed set.
    let (drain_stop_tx, mut drain_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let drain_task = blob_drainer.map(|mut drainer| {
        let interval = options.blob_drain_interval;
        let verbose = options.verbose_diagnostics;
        tokio::spawn(async move {
            // A zero interval disables the incremental drain (the run-end drain still
            // runs) — and `tokio::time::interval` panics on a zero period.
            if interval.is_zero() {
                let _ = (&mut drain_stop_rx).await;
                return drainer;
            }
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // An interval's first tick fires immediately; skip it so passes start one
            // interval in.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = &mut drain_stop_rx => break,
                    _ = ticker.tick() => {
                        let outcome = drainer.pass().await;
                        if verbose && let Some(error) = &outcome.error {
                            eprintln!(
                                "hiloop-interceptor: blob drain pass failed (will retry): {error}"
                            );
                        }
                    }
                }
            }
            drainer
        })
    });

    let stdio_normalizer = StdioLogNormalizer;
    let exec_normalizer = ExecLifecycleNormalizer;
    let otlp_normalizer = OtlpTraceNormalizer;
    let proxy_normalizer = ProxyNormalizer;
    let mut normalizers: Vec<&dyn Normalizer> = vec![&stdio_normalizer, &exec_normalizer];
    if options.otlp {
        normalizers.push(&otlp_normalizer);
    }
    if options.proxy {
        normalizers.push(&proxy_normalizer);
    }
    let router = NormalizerRouter::new(normalizers).expect("router has at least one normalizer");

    let normalization_context = NormalizationContext::new(options.context.clone())
        .with_attributes(options.attributes.clone())
        .with_process(process);
    // The pipeline consumes the context; the run-end capture-health event reuses a clone so
    // it carries the same run identity and static attributes as every captured event.
    let health_context = normalization_context.clone();
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
        let status = with_signal_forwarding(
            signals,
            child_pid,
            pty_resize_fd,
            Some(&exec_emitter),
            child.wait(),
        )
        .await
        .with_context(|| format!("failed to wait for child command `{}`", options.command[0]));
        if let Ok(status) = &status {
            exec_emitter
                .emit_exit(
                    exit_u8_from_status(*status),
                    term_signal_name(*status),
                    child_started.elapsed(),
                )
                .await;
        }
        // Release the lifecycle sender, then stop the stdin pump (its source may
        // never EOF), the incremental blob drain, and the capture servers; dropping
        // their senders lets the pipeline drain and finish.
        drop(exec_emitter);
        let _ = stdin_shutdown_tx.send(());
        let _ = drain_stop_tx.send(());
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
        // Capture is best effort: a proxy failure can be diagnosed with --verbose, but is not fatal
        // to the child.
        if let Some(task) = proxy_server_task
            && let Err(error) = task.await
            && options.verbose_diagnostics
        {
            eprintln!("hiloop-interceptor: proxy capture failed: {error}");
        }
    };

    let (status_result, stdin_result, stdout_result, stderr_result, (), (), pipeline_result) =
        Box::pin(async {
            tokio::join!(
                child_and_shutdown,
                stdin_capture,
                stdout_capture,
                stderr_capture,
                otlp_task,
                proxy_task,
                async { pipeline.await.context("stdio event pipeline failed") },
            )
        })
        .await;

    let status = status_result?;

    // The child has exited: capture/export is best effort from here, so drain failures
    // become warnings instead of clobbering the child's exit code (exit-code transparency).
    let mut drain_warnings: Vec<anyhow::Error> = [
        pipeline_result.map(|_| ()),
        stdin_result.context("failed to capture child stdin"),
        stdout_result.context("failed to capture child stdout"),
        stderr_result.context("failed to capture child stderr"),
    ]
    .into_iter()
    .filter_map(Result::err)
    .collect();

    // Run-end blob drain, best-effort like the rest of the drain. The authoritative
    // final pass re-probes every digest against the gateway and retries with bounded
    // backoff (the child has exited, so the budget caps exit latency, not capture). An
    // incomplete drain keeps the scratch store: deleting it would destroy the only
    // bytes behind already-exported payload_ref digests.
    let mut blob_outcome: Option<BlobDrainOutcome> = None;
    let mut blob_drain_failed = false;
    if let Some(task) = drain_task {
        match task.await {
            Ok(drainer) => {
                let outcome = drainer.finish(&options.blob_drain_retry).await;
                if options.verbose_diagnostics {
                    let report = outcome.report;
                    eprintln!(
                        "hiloop-interceptor: payload blob drain: {} found, {} landed ({} uploaded this run), {} missing, {} oversize",
                        report.found,
                        report.landed,
                        report.uploaded,
                        report.missing,
                        report.oversize_skipped
                    );
                }
                blob_outcome = Some(outcome);
            }
            Err(join_error) => {
                blob_drain_failed = true;
                drain_warnings
                    .push(anyhow::Error::new(join_error).context("blob drain task failed"));
            }
        }
    }

    // The capture-health record ships once per drained run so a run whose payload
    // bodies or events never landed is *queryably* incomplete — and a captured run
    // with no `capture.drain` event at all is one whose wrapper died before draining.
    // It ships BEFORE the final event-spool drain on purpose: spool redelivery is
    // strictly in arrival order, so a `capture.drain` event that reaches the gateway
    // certifies that everything spooled before it landed too.
    if !blob_drain_failed && (blob_outcome.is_some() || event_spool.is_some()) {
        let spool_report = match event_spool {
            Some(spool) => Some(spool.report().await),
            None => None,
        };
        let health_event = capture_drain_event(
            &health_context,
            clock.tick(),
            blob_outcome.as_ref(),
            spool_report,
        );
        if let Err(warning) = export_supervisor_record(
            exporter,
            health_event,
            "capture-health",
            CAPTURE_HEALTH_EXPORT_TIMEOUT,
        )
        .await
        {
            drain_warnings.push(warning);
        }
    }

    if let Some(outcome) = blob_outcome
        && let Some(warning) = drain_problem(outcome)
    {
        let warning = match scratch_blob_dir.take() {
            // `keep` disables the TempDir's deletion; the bytes survive for
            // recovery.
            Some(scratch) => warning.context(format!(
                "captured payload blobs kept at `{}`",
                scratch.keep().display()
            )),
            None => warning,
        };
        drain_warnings.push(warning);
    }

    // Run-end event drain: the spooled backlog gets its final chance within the same
    // bounded budget as the blob drain; whatever remains undelivered is reported with
    // counts instead of being dropped silently.
    if let Some(spool) = event_spool {
        let report = spool.drain(&options.blob_drain_retry).await;
        if let Some(warning) = spool_problem(&report, spool.last_failure().await) {
            drain_warnings.push(warning);
        }
    }
    drop(scratch_blob_dir);

    Ok(CapturedRun {
        exit_code: exit_u8_from_status(status),
        drain_warnings,
    })
}

/// Render an incomplete or lossy drain outcome as the run's drain warning, or `None` when
/// every uploadable blob landed and nothing stayed local.
fn drain_problem(outcome: BlobDrainOutcome) -> Option<anyhow::Error> {
    let complete = outcome.is_complete();
    let BlobDrainOutcome { report, error } = outcome;
    if !complete {
        let message = format!(
            "{} of {} captured payload blob(s) failed to land at the gateway",
            report.missing, report.found
        );
        return Some(match error {
            Some(error) => anyhow::Error::new(error).context(message),
            None => anyhow::anyhow!(message),
        });
    }
    if report.oversize_skipped > 0 {
        return Some(anyhow::anyhow!(
            "{} captured payload blob(s) exceed the upload cap and stayed local",
            report.oversize_skipped
        ));
    }
    None
}

/// Build the run-end capture-health event: one `log`-signal record per captured run
/// stating whether everything captured landed on the gateway — payload blobs (when a
/// blob drain ran) and exported events (when a gRPC export spool ran) — stamped
/// through the same provenance seam as the run's captured events (run identity,
/// static attributes, wrapper and process identity). `capture.complete` is the
/// conjunction: every uploadable blob landed AND no exported event was dropped. The
/// event-spool counters are loss counters — events still awaiting redelivery do not
/// count against completeness, because redelivery is strictly in order: this record
/// reaching the gateway certifies everything spooled before it landed too.
fn capture_drain_event(
    context: &NormalizationContext,
    ts: Hlc,
    blob_outcome: Option<&BlobDrainOutcome>,
    spool_report: Option<SpoolReport>,
) -> Event {
    let event = Event::new(
        context.run_context(),
        ts,
        SignalType::Log,
        EventName::from_static(CAPTURE_DRAIN_EVENT),
    );
    let mut event = context.stamp_provenance(event);
    let mut complete = true;
    if let Some(outcome) = blob_outcome {
        let report = outcome.report;
        complete &= outcome.is_complete();
        event = event
            .with_attribute(
                AttributeKey::from_static(capture_keys::FOUND),
                count_attr(report.found),
            )
            .with_attribute(
                AttributeKey::from_static(capture_keys::LANDED),
                count_attr(report.landed),
            )
            .with_attribute(
                AttributeKey::from_static(capture_keys::MISSING),
                count_attr(report.missing),
            )
            .with_attribute(
                AttributeKey::from_static(capture_keys::OVERSIZE),
                count_attr(report.oversize_skipped),
            )
            .with_attribute(
                AttributeKey::from_static(capture_keys::MISSING_BYTES),
                i64::try_from(report.missing_bytes).unwrap_or(i64::MAX),
            );
        if let Some(error) = &outcome.error {
            event = event.with_attribute(
                AttributeKey::from_static(capture_keys::ERROR),
                error.to_string(),
            );
        }
    }
    if let Some(report) = spool_report {
        complete &= report.is_lossless_so_far();
        event = event
            .with_attribute(
                AttributeKey::from_static(capture_keys::EVENTS_DROPPED),
                i64::try_from(report.dropped_events).unwrap_or(i64::MAX),
            )
            .with_attribute(
                AttributeKey::from_static(capture_keys::EVENTS_REJECTED),
                i64::try_from(report.rejected_events).unwrap_or(i64::MAX),
            )
            // The backlog at mint time, mainly for the local (JSONL) copy of this
            // record: on the gateway copy a non-zero value documents late delivery,
            // never loss — the record queues behind its backlog, so it can only
            // arrive after everything it counted.
            .with_attribute(
                AttributeKey::from_static(capture_keys::EVENTS_PENDING),
                count_attr(report.pending_events),
            );
    }
    event.with_attribute(AttributeKey::from_static(capture_keys::COMPLETE), complete)
}

fn count_attr(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Render event-spool loss/backlog as the run's export warning, or `None` when the
/// spool ended clean: everything delivered, nothing dropped.
fn spool_problem(report: &SpoolReport, last_failure: Option<String>) -> Option<anyhow::Error> {
    if report.is_clean() {
        return None;
    }
    let mut parts = Vec::new();
    if report.pending_events > 0 {
        parts.push(format!(
            "{} captured event(s) never reached the telemetry gateway",
            report.pending_events
        ));
    }
    if report.dropped_events > 0 {
        parts.push(format!(
            "{} oldest event(s) were dropped when the export spool filled",
            report.dropped_events
        ));
    }
    if report.rejected_events > 0 {
        parts.push(format!(
            "{} event(s) were dropped after the gateway permanently rejected their batch",
            report.rejected_events
        ));
    }
    let message = parts.join("; ");
    Some(match last_failure {
        Some(failure) => anyhow::anyhow!("last export failure: {failure}").context(message),
        None => anyhow::anyhow!(message),
    })
}

/// Build the spawn-failure record: a `process.spawn_failed` `exec` event carrying the attempted
/// argv, working directory, and the OS error that prevented the child from starting. It is
/// stamped through the same provenance seam as every captured event (run identity, static
/// attributes including `execution.id` when set, wrapper identity, the attempted process
/// context — no pid, since no process ever existed), so the failed attempt joins the run's
/// timeline.
fn spawn_failure_event(options: &RunOptions, ts: Hlc, error: &io::Error) -> Event {
    let context = NormalizationContext::new(options.context.clone())
        .with_attributes(options.attributes.clone())
        .with_process(child_process_context(options, None));
    let event = Event::new(
        context.run_context(),
        ts,
        SignalType::Exec,
        EventName::from_static(crate::exec_events::PROCESS_SPAWN_FAILED),
    );
    context.stamp_provenance(event).with_attribute(
        AttributeKey::from_static(crate::exec_events::keys::PROCESS_ERROR),
        error.to_string(),
    )
}

/// Export one supervisor-emitted record event (capture-health, spawn-failure) within a hard
/// per-record deadline: best-effort like every wind-down step, so it never hangs the wrapper's
/// exit.
async fn export_supervisor_record<E: Exporter>(
    exporter: &E,
    event: Event,
    what: &str,
    deadline: Duration,
) -> Result<()> {
    match tokio::time::timeout(deadline, async {
        exporter
            .export(std::slice::from_ref(&event))
            .await
            .with_context(|| format!("failed to export the {what} event"))?;
        exporter
            .flush()
            .await
            .with_context(|| format!("failed to flush the {what} event"))
    })
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => bail!("{what} export timed out after {}s", deadline.as_secs()),
    }
}

fn child_process_context(options: &RunOptions, pid: Option<u32>) -> ProcessContext {
    ProcessContext {
        pid,
        command: options.command.first().map(PathBuf::from),
        argv: options.command.clone(),
        cwd: std::env::current_dir().ok(),
    }
}

enum CaptureStdio {
    Pipes {
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
    },
    #[cfg(unix)]
    Pty(Box<PtyStdio>),
}

#[cfg(unix)]
struct PtyStdio {
    master_reader: tokio::fs::File,
    master_writer: tokio::fs::File,
    resize_fd: std::fs::File,
    raw_mode: RawTerminalMode,
}

fn take_piped_stdio(child: &mut Child) -> Result<CaptureStdio> {
    let stdin = child
        .stdin
        .take()
        .context("child stdin was not available for capture")?;
    let stdout = child
        .stdout
        .take()
        .context("child stdout was not available for capture")?;
    let stderr = child
        .stderr
        .take()
        .context("child stderr was not available for capture")?;
    Ok(CaptureStdio::Pipes {
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
fn configure_interactive_pty_stdio(command: &mut Command) -> Result<Option<PtyStdio>> {
    use std::os::fd::AsRawFd as _;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    if !(stdin.is_terminal() && stdout.is_terminal() && stderr.is_terminal()) {
        return Ok(None);
    }

    let raw_mode = RawTerminalMode::enable(&stdin).context("failed to enter raw terminal mode")?;
    let winsize = current_terminal_winsize();
    let pty = nix::pty::openpty(winsize.as_ref(), None).context("failed to allocate PTY")?;
    let master = std::fs::File::from(pty.master);
    set_cloexec(master.as_raw_fd()).context("failed to set PTY master close-on-exec")?;
    let resize_fd = master
        .try_clone()
        .context("failed to clone PTY master for resize forwarding")?;
    let master_reader = tokio::fs::File::from_std(
        master
            .try_clone()
            .context("failed to clone PTY master for output capture")?,
    );
    let master_writer = tokio::fs::File::from_std(master);
    let slave = std::fs::File::from(pty.slave);
    command
        .stdin(Stdio::from(
            slave
                .try_clone()
                .context("failed to clone PTY slave for stdin")?,
        ))
        .stdout(Stdio::from(
            slave
                .try_clone()
                .context("failed to clone PTY slave for stdout")?,
        ))
        .stderr(Stdio::from(slave));
    set_child_controlling_terminal(command);

    Ok(Some(PtyStdio {
        master_reader,
        master_writer,
        resize_fd,
        raw_mode,
    }))
}

#[cfg(unix)]
struct RawTerminalMode {
    original: nix::sys::termios::Termios,
}

#[cfg(unix)]
impl RawTerminalMode {
    fn enable(stdin: &io::Stdin) -> Result<Self> {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};

        let original = tcgetattr(stdin).context("failed to read terminal mode")?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(stdin, SetArg::TCSANOW, &raw).context("failed to set raw terminal mode")?;
        Ok(Self { original })
    }
}

#[cfg(unix)]
impl Drop for RawTerminalMode {
    fn drop(&mut self) {
        use nix::sys::termios::{SetArg, tcsetattr};

        let stdin = io::stdin();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &self.original);
    }
}

#[cfg(unix)]
fn current_terminal_winsize() -> Option<nix::pty::Winsize> {
    use std::os::fd::AsRawFd as _;

    let stdout = io::stdout();
    if stdout.is_terminal() {
        return read_winsize(stdout.as_raw_fd());
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return read_winsize(stdin.as_raw_fd());
    }
    None
}

#[cfg(unix)]
fn read_winsize(fd: std::os::fd::RawFd) -> Option<nix::pty::Winsize> {
    let mut winsize = std::mem::MaybeUninit::<nix::pty::Winsize>::uninit();
    // SAFETY: `ioctl(TIOCGWINSZ)` writes a `winsize` struct to the provided pointer when it returns
    // success. `fd` is borrowed from stdin/stdout and remains valid for the duration of the call.
    #[expect(
        unsafe_code,
        reason = "terminal size is only exposed through ioctl(TIOCGWINSZ); see SAFETY"
    )]
    let rc = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, winsize.as_mut_ptr()) };
    if rc == 0 {
        // SAFETY: a zero return from TIOCGWINSZ means the kernel initialized the struct.
        #[expect(
            unsafe_code,
            reason = "TIOCGWINSZ success initializes the winsize struct; see SAFETY"
        )]
        Some(unsafe { winsize.assume_init() })
    } else {
        None
    }
}

#[cfg(unix)]
fn set_pty_winsize(fd: std::os::fd::RawFd, winsize: &nix::pty::Winsize) -> io::Result<()> {
    // SAFETY: `ioctl(TIOCSWINSZ)` reads the provided winsize struct and applies it to a PTY fd.
    // Errors are reported via errno and do not affect Rust memory safety.
    #[expect(
        unsafe_code,
        reason = "terminal resize forwarding uses ioctl(TIOCSWINSZ); see SAFETY"
    )]
    let rc = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, std::ptr::from_ref(winsize)) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn set_child_controlling_terminal(command: &mut Command) {
    // SAFETY: this pre-exec closure runs after stdio has been remapped to the PTY slave and before
    // exec. It calls only async-signal-safe libc functions to make the child a session leader with
    // fd 0 as its controlling terminal.
    #[expect(
        unsafe_code,
        reason = "pre-exec PTY setup requires setsid + TIOCSCTTY in the child; see SAFETY"
    )]
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::ioctl(
                nix::libc::STDIN_FILENO,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn stdio_pipe_captures(
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
    stdin_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> (
    CaptureFuture<'static>,
    CaptureFuture<'static>,
    CaptureFuture<'static>,
) {
    let stdout_capture = Box::pin(capture_stream(
        stdout,
        tokio::io::stdout(),
        "stdout",
        signal_tx.clone(),
        Arc::clone(&clock),
    ));
    let stderr_capture = Box::pin(capture_stream(
        stderr,
        tokio::io::stderr(),
        "stderr",
        signal_tx.clone(),
        Arc::clone(&clock),
    ));
    let stdin_capture = Box::pin(stdin_capture(
        io::stdin(),
        stdin,
        stdin_shutdown_rx,
        signal_tx,
        clock,
    ));
    (stdin_capture, stdout_capture, stderr_capture)
}

#[cfg(unix)]
fn stdio_pty_captures(
    pty: PtyStdio,
    stdin_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> (
    CaptureFuture<'static>,
    CaptureFuture<'static>,
    CaptureFuture<'static>,
) {
    let PtyStdio {
        master_reader,
        master_writer,
        resize_fd: _,
        raw_mode,
    } = pty;
    let stdin_capture = Box::pin(pty_stdin_capture(
        master_writer,
        stdin_shutdown_rx,
        signal_tx.clone(),
        Arc::clone(&clock),
    ));
    let stdout_capture = Box::pin(async move {
        let _raw_mode = raw_mode;
        capture_pty_output(
            master_reader,
            tokio::io::stdout(),
            "stdout",
            signal_tx,
            clock,
        )
        .await
    });
    let stderr_capture = Box::pin(async { Ok(()) });
    (stdin_capture, stdout_capture, stderr_capture)
}

#[cfg(unix)]
async fn pty_stdin_capture<W>(
    child_stdin: W,
    stdin_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        result = capture_nonblocking_stdin(child_stdin, signal_tx, clock) => result,
        _ = stdin_shutdown_rx => Ok(()),
    }
}

#[cfg(unix)]
async fn capture_nonblocking_stdin<W>(
    mut writer: W,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    let (stdin, stdin_flags) = {
        // SAFETY: `dup(0)` returns a new owned descriptor on success. Its status flags are shared
        // with fd 0, so the restore guard resets the parent terminal flags when capture ends.
        #[expect(
            unsafe_code,
            reason = "dup(2) is needed to drive terminal stdin through AsyncFd; see SAFETY"
        )]
        let fd = unsafe { nix::libc::dup(nix::libc::STDIN_FILENO) };
        if fd == -1 {
            return Err(io::Error::last_os_error()).context("failed to duplicate stdin");
        }
        // SAFETY: `fd` is the successful return from `dup`, so this takes ownership exactly once.
        #[expect(
            unsafe_code,
            reason = "successful dup returns a fresh owned fd; see SAFETY"
        )]
        let stdin = unsafe { OwnedFd::from_raw_fd(fd) };
        let restore = set_nonblocking_with_restore(stdin.as_raw_fd(), nix::libc::STDIN_FILENO)
            .context("failed to set stdin duplicate nonblocking")?;
        (stdin, restore)
    };
    let stdin = tokio::io::unix::AsyncFd::new(stdin).context("failed to register stdin")?;
    let _stdin_flags = stdin_flags;
    let mut framer = LineFramer::new(MAX_STDIO_LINE_BYTES);
    let mut buffer = [0; 8192];
    let mut signal_tx = Some(signal_tx);

    loop {
        let mut guard = stdin
            .readable()
            .await
            .context("failed to wait for stdin readiness")?;
        let read = match guard.try_io(|inner| {
            // SAFETY: `buffer` is valid for writes up to its length, and `inner` owns a valid
            // nonblocking duplicate of stdin for the duration of the call.
            #[expect(
                unsafe_code,
                reason = "read(2) is used with AsyncFd for cancellable terminal input; see SAFETY"
            )]
            let rc = unsafe {
                nix::libc::read(
                    inner.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if rc >= 0 {
                usize::try_from(rc).map_err(|_| io::Error::other("stdin read count out of range"))
            } else {
                Err(io::Error::last_os_error())
            }
        }) {
            Ok(Ok(read)) => read,
            Ok(Err(error)) if is_pty_eio(&error) => 0,
            Ok(Err(error)) => return Err(error).context("failed to read stdin"),
            Err(_would_block) => continue,
        };
        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];
        if let Err(error) = writer.write_all(chunk).await {
            if is_pty_eio(&error) {
                break;
            }
            return Err(error).context("failed to write stdin to child PTY");
        }
        if let Err(error) = writer.flush().await {
            if is_pty_eio(&error) {
                break;
            }
            return Err(error).context("failed to flush child PTY stdin");
        }

        for record in framer.push(chunk) {
            send_stdio_signal(&mut signal_tx, "stdin", &clock, record).await;
        }
    }

    if let Some(record) = framer.flush() {
        send_stdio_signal(&mut signal_tx, "stdin", &clock, record).await;
    }

    if signal_tx.is_none() {
        bail!("stdio event pipeline stopped before stdin capture finished");
    }

    Ok(())
}

#[cfg(unix)]
struct FdStatusRestore {
    fd: std::os::fd::RawFd,
    flags: nix::libc::c_int,
}

#[cfg(unix)]
impl Drop for FdStatusRestore {
    fn drop(&mut self) {
        let _ = set_fd_status_flags(self.fd, self.flags);
    }
}

#[cfg(unix)]
fn set_nonblocking_with_restore(
    fd: std::os::fd::RawFd,
    restore_fd: std::os::fd::RawFd,
) -> io::Result<FdStatusRestore> {
    let flags = fd_status_flags(fd)?;
    set_fd_status_flags(fd, flags | nix::libc::O_NONBLOCK)?;
    Ok(FdStatusRestore {
        fd: restore_fd,
        flags,
    })
}

#[cfg(unix)]
fn fd_status_flags(fd: std::os::fd::RawFd) -> io::Result<nix::libc::c_int> {
    // SAFETY: `fcntl` operates on a valid descriptor; errors are reported via errno and do not
    // affect Rust memory safety.
    #[expect(
        unsafe_code,
        reason = "fcntl(F_GETFL) reads descriptor status flags; see SAFETY"
    )]
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

#[cfg(unix)]
fn set_fd_status_flags(fd: std::os::fd::RawFd, flags: nix::libc::c_int) -> io::Result<()> {
    // SAFETY: `fcntl` operates on a valid descriptor; errors are reported via errno and do not
    // affect Rust memory safety.
    #[expect(
        unsafe_code,
        reason = "fcntl(F_SETFL) writes descriptor status flags; see SAFETY"
    )]
    let rc = unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn set_cloexec(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: `fcntl` operates on a valid descriptor; errors are reported via errno and do not
    // affect Rust memory safety.
    #[expect(
        unsafe_code,
        reason = "fcntl(F_GETFD/F_SETFD) configures descriptor inheritance; see SAFETY"
    )]
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same descriptor as above; the flag value preserves existing flags and adds FD_CLOEXEC.
    #[expect(
        unsafe_code,
        reason = "fcntl(F_SETFD) configures descriptor inheritance; see SAFETY"
    )]
    let rc = unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Forwards a blocking reader (the parent's stdin) into async code from a dedicated,
/// deliberately detached OS thread.
///
/// `tokio::io::stdin()` would dispatch each `read(2)` to the runtime's blocking pool, where an
/// in-flight read cannot be cancelled: aborting the pump leaves the read parked, and runtime
/// shutdown then blocks until stdin delivers a byte or EOF (tokio's `io::stdin` docs warn about
/// exactly this). Reading on a detached thread keeps the pump — and the embedder's runtime —
/// genuinely cancellable: dropping this reader closes the channel, the runtime never waits on
/// the thread, and the thread retires on its next read return (or with the process). While the
/// reader is alive every chunk is delivered in order, so no input is lost mid-run.
struct DetachedStdinReader {
    chunks: mpsc::Receiver<io::Result<Bytes>>,
    pending: Bytes,
}

impl DetachedStdinReader {
    fn spawn(source: impl io::Read + Send + 'static) -> io::Result<Self> {
        // Capacity 1 keeps the thread from reading ahead of the pump: at most one chunk is in
        // flight, so a chunk can be dropped only once the pump (and the child it feeds) has
        // already gone away.
        let (chunk_tx, chunks) = mpsc::channel::<io::Result<Bytes>>(1);
        std::thread::Builder::new()
            .name("hiloop-stdin-reader".to_owned())
            .spawn(move || forward_blocking_reads(source, &chunk_tx))?;
        Ok(Self {
            chunks,
            pending: Bytes::new(),
        })
    }
}

fn forward_blocking_reads(mut source: impl io::Read, chunk_tx: &mpsc::Sender<io::Result<Bytes>>) {
    let mut buffer = [0; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if chunk_tx
                    .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                    .is_err()
                {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = chunk_tx.blocking_send(Err(error));
                break;
            }
        }
    }
}

impl AsyncRead for DetachedStdinReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            match this.chunks.poll_recv(cx) {
                Poll::Ready(Some(Ok(chunk))) => this.pending = chunk,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                // The reader thread saw EOF (an error chunk, if any, arrived before the close).
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let take = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending.split_to(take));
        Poll::Ready(Ok(()))
    }
}

async fn stdin_capture<R, W>(
    stdin_source: R,
    child_stdin: W,
    stdin_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    R: io::Read + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // stdin: pump the parent's stdin into the child while capturing it as `process.stdin` events.
    // Unlike stdout/stderr (which EOF when the child exits), the parent's stdin may never close (an
    // interactive TTY), so a child-exit shutdown signal cancels the pump instead of blocking
    // teardown — and the detached reader keeps that cancellation instant even mid-read.
    // When the pump ends — parent EOF or shutdown — `child_stdin` drops, closing the child's stdin.
    let reader =
        DetachedStdinReader::spawn(stdin_source).context("failed to start the stdin reader")?;
    tokio::select! {
        result = capture_stream(reader, child_stdin, "stdin", signal_tx, clock) => result,
        _ = stdin_shutdown_rx => Ok(()),
    }
}

#[cfg(unix)]
async fn capture_pty_output<R, W>(
    reader: R,
    writer: W,
    stream_name: &'static str,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    capture_stream_impl(reader, writer, stream_name, signal_tx, clock, true).await
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
// is designed, keep this behavior stable to protect TESTING.md B1-B16.
async fn capture_stream<R, W>(
    reader: R,
    writer: W,
    stream_name: &'static str,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    capture_stream_impl(reader, writer, stream_name, signal_tx, clock, false).await
}

async fn capture_stream_impl<R, W>(
    mut reader: R,
    mut writer: W,
    stream_name: &'static str,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<hiloop_core::identity::HlcClock>,
    pty_eio_is_eof: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framer = LineFramer::new(MAX_STDIO_LINE_BYTES);
    let mut buffer = [0; 8192];
    let mut signal_tx = Some(signal_tx);

    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(error) if pty_eio_is_eof && is_pty_eio(&error) => 0,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read child {stream_name}"));
            }
        };
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

fn is_pty_eio(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(nix::libc::EIO)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
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

/// The name of the signal that terminated the child (e.g. `SIGKILL`), when the
/// child was signal-killed rather than exiting on its own.
#[cfg(unix)]
fn term_signal_name(status: ExitStatus) -> Option<&'static str> {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .and_then(|signo| nix::sys::signal::Signal::try_from(signo).ok())
        .map(nix::sys::signal::Signal::as_str)
}

#[cfg(not(unix))]
fn term_signal_name(_status: ExitStatus) -> Option<&'static str> {
    None
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

/// The wrapper's installed SIGINT/SIGTERM handlers, ready to drive
/// [`with_signal_forwarding`].
#[cfg(unix)]
struct ForwardedSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ForwardedSignals {
    /// Install the wrapper's SIGINT/SIGTERM handlers, or `None` when
    /// installation fails (the run then proceeds without forwarding).
    ///
    /// Call this *before* spawning the child: handlers installed after the
    /// spawn race it — a signal sent as soon as the child observably runs can
    /// still hit the wrapper's default disposition, killing the wrapper
    /// without forwarding and orphaning the child's process group.
    fn install() -> Option<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        match (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) {
            (Ok(sigint), Ok(sigterm)) => Some(Self { sigint, sigterm }),
            _ => None,
        }
    }
}

#[cfg(not(unix))]
struct ForwardedSignals;

#[cfg(not(unix))]
impl ForwardedSignals {
    fn install() -> Option<Self> {
        None
    }
}

/// Run `work` to completion while forwarding terminating signals to the child.
///
/// On Unix the wrapper re-sends each SIGINT/SIGTERM received on `signals`
/// (installed by [`ForwardedSignals::install`] before the child was spawned)
/// to the child's process group, so Ctrl-C and `kill` tear down the harness
/// subtree once instead of racing the wrapper, while the wrapper still drains
/// the child and reports its exit status. Without installed handlers, or off
/// Unix, `work` runs without forwarding.
#[cfg(unix)]
async fn with_signal_forwarding<F, T>(
    signals: Option<ForwardedSignals>,
    child_pid: Option<u32>,
    pty_resize_fd: Option<std::fs::File>,
    emitter: Option<&ExecLifecycleEmitter>,
    work: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    use tokio::signal::unix::{SignalKind, signal};

    let Some(ForwardedSignals {
        mut sigint,
        mut sigterm,
    }) = signals
    else {
        return work.await;
    };
    let mut sigwinch = if pty_resize_fd.is_some() {
        signal(SignalKind::window_change()).ok()
    } else {
        None
    };

    tokio::pin!(work);
    loop {
        tokio::select! {
            output = &mut work => return output,
            _ = sigint.recv() => {
                forward_and_record(child_pid, nix::sys::signal::Signal::SIGINT, emitter).await;
            }
            _ = sigterm.recv() => {
                forward_and_record(child_pid, nix::sys::signal::Signal::SIGTERM, emitter).await;
            }
            () = async {
                match sigwinch.as_mut() {
                    Some(sigwinch) => {
                        if sigwinch.recv().await.is_none() {
                            std::future::pending::<()>().await;
                        }
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if let Some(pty) = &pty_resize_fd {
                    resize_pty_to_current_terminal(pty);
                }
            },
        }
    }
}

#[cfg(not(unix))]
async fn with_signal_forwarding<F, T>(
    _signals: Option<ForwardedSignals>,
    _child_pid: Option<u32>,
    _pty_resize_fd: (),
    _emitter: Option<&ExecLifecycleEmitter>,
    work: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    work.await
}

#[cfg(unix)]
fn resize_pty_to_current_terminal(pty: &std::fs::File) {
    use std::os::fd::AsRawFd as _;

    if let Some(winsize) = current_terminal_winsize() {
        let _ = set_pty_winsize(pty.as_raw_fd(), &winsize);
    }
}

/// Forward `signal` to the child's process group and, when capture is active,
/// record the steering fact as a `process.signal` event.
#[cfg(unix)]
async fn forward_and_record(
    child_pid: Option<u32>,
    signal: nix::sys::signal::Signal,
    emitter: Option<&ExecLifecycleEmitter>,
) {
    forward_signal(child_pid, signal);
    if let Some(emitter) = emitter {
        emitter.emit_signal(signal.as_str()).await;
    }
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
    use hiloop_core::identity::{LineagePath, RunId};
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
        let mut env = ChildEnv::for_run(&RunContext::new_local_root(), None);
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

    #[test]
    fn set_proxy_points_every_trust_store_env_at_the_bundle() {
        let mut env = ChildEnv::for_run(&RunContext::new_local_root(), None);
        env.set_proxy(
            "127.0.0.1:8080".parse().expect("addr"),
            Path::new("/tmp/hiloop-ca.pem"),
        );

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

        // git honors GIT_SSL_CAINFO, not the other CA envs, so it must be set too or
        // `git clone`/`pip install git+https` fail against the proxy.
        for key in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            assert_eq!(
                vars.get(key).map(String::as_str),
                Some("/tmp/hiloop-ca.pem"),
                "{key} must point at the interception bundle"
            );
        }
        assert_eq!(
            vars.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn union_ca_bundle_preserves_public_roots_and_appends_interception_ca() {
        let mitm = "-----BEGIN CERTIFICATE-----\nMITM\n-----END CERTIFICATE-----\n";

        // No system roots → the bundle is exactly the interception CA.
        assert_eq!(union_ca_bundle(None, mitm), mitm.as_bytes());

        // System roots without a trailing newline: a separator is inserted, and BOTH
        // the public root and the interception CA survive (no public-root loss — the
        // bug this fixes was a MITM-only bundle that stripped public trust).
        let roots = b"-----BEGIN CERTIFICATE-----\nPUBLICROOT\n-----END CERTIFICATE-----";
        let text = String::from_utf8(union_ca_bundle(Some(roots), mitm)).expect("utf8");
        assert!(text.contains("PUBLICROOT"), "public roots preserved");
        assert!(text.contains("MITM"), "interception CA appended");
        assert!(
            text.contains("-END CERTIFICATE-----\n-----BEGIN"),
            "a newline separates the two PEM blocks"
        );
    }

    #[test]
    fn interception_ca_anchors_loads_certificate_pem() {
        let ca = crate::proxy::ProxyCa::generate().expect("generate CA");
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), ca.cert_pem()).expect("write CA");

        let anchors = interception_ca_anchors(file.path());
        assert_eq!(anchors.len(), 1, "one certificate PEM block, one anchor");
    }

    #[test]
    fn interception_ca_anchors_is_empty_when_the_file_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchors = interception_ca_anchors(&dir.path().join("no-such-ca.pem"));
        assert!(
            anchors.is_empty(),
            "a dangling CA pointer degrades to public-roots-only, it never fails the proxy"
        );
    }

    #[test]
    fn interception_ca_anchors_is_empty_for_non_certificate_content() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), "not a pem certificate").expect("write junk");
        assert!(interception_ca_anchors(file.path()).is_empty());

        std::fs::write(
            file.path(),
            "-----BEGIN CERTIFICATE-----\n%%%not-base64%%%\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed pem");
        assert!(interception_ca_anchors(file.path()).is_empty());
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

    #[cfg(unix)]
    #[test]
    fn nonblocking_guard_restores_status_flags() {
        use std::os::fd::AsRawFd as _;

        let (reader, _writer) = nix::unistd::pipe().expect("pipe");
        let original = fd_status_flags(reader.as_raw_fd()).expect("initial flags");

        {
            let _restore = set_nonblocking_with_restore(reader.as_raw_fd(), reader.as_raw_fd())
                .expect("set nonblocking");
            let flags = fd_status_flags(reader.as_raw_fd()).expect("nonblocking flags");
            assert_ne!(flags & nix::libc::O_NONBLOCK, 0);
        }

        let restored = fd_status_flags(reader.as_raw_fd()).expect("restored flags");
        assert_eq!(restored, original);
    }

    #[test]
    fn child_env_stamps_the_run_context() {
        let root = RunId::from_str("01J00000000000000000000000").expect("root run id");
        let run_id = RunId::from_str("01J00000000000000000000001").expect("run id");
        let lineage_path = LineagePath::root(root).child(run_id).expect("lineage path");
        let context = RunContext::new(run_id, lineage_path).expect("run context");

        let env = ChildEnv::for_run(&context, None);
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
            Some("01J00000000000000000000001")
        );
        assert_eq!(
            vars.get("HILOOP_LINEAGE_PATH").map(String::as_str),
            Some("01J00000000000000000000000.01J00000000000000000000001")
        );
        assert_eq!(
            vars.get("OTEL_RESOURCE_ATTRIBUTES").map(String::as_str),
            Some(
                "hiloop.run.id=01J00000000000000000000001,hiloop.run.lineage_path=01J00000000000000000000000.01J00000000000000000000001"
            )
        );
    }

    #[test]
    fn child_env_stamps_execution_id_when_present() {
        let env = ChildEnv::for_run(&RunContext::new_local_root(), Some("execution-123"));
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
            vars.get("HILOOP_EXECUTION_ID").map(String::as_str),
            Some("execution-123")
        );
        assert!(
            vars.get("OTEL_RESOURCE_ATTRIBUTES")
                .is_some_and(|attrs| attrs.contains(&format!("{OTEL_EXECUTION_ID}=execution-123")))
        );
    }

    #[test]
    fn otel_resource_attribute_values_are_percent_encoded() {
        assert_eq!(
            encode_otel_resource_value("exec,= id/1"),
            "exec%2C%3D%20id%2F1"
        );
    }

    #[test]
    fn child_env_value_prefers_injected_override_then_inherited() {
        let context = RunContext::new_local_root();
        let env = ChildEnv::for_run(&context, None);

        assert_eq!(
            env.child_value("HILOOP_RUN_ID"),
            Some(OsString::from(context.run_id.to_string())),
            "a supervisor-injected variable resolves to the injected value"
        );
        assert_eq!(
            env.child_value("PATH"),
            std::env::var_os("PATH"),
            "a variable the supervisor does not set falls back to the inherited value"
        );
        assert_eq!(env.child_value("HILOOP_TEST_DEFINITELY_UNSET"), None);
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

    fn base_options(command: Vec<String>) -> RunOptions {
        RunOptions::new(
            RunContext::new_local_root(),
            command,
            Some(PathBuf::from("/tmp/never-created.jsonl")),
            None,
            None,
            false,
            false, // proxy disabled
            None,
            None,
        )
    }

    #[test]
    fn run_options_carry_static_attributes() {
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()])
            .with_attribute(AttributeKey::from_static("execution_id"), "exec-123");

        assert_eq!(
            options
                .attributes
                .get(&AttributeKey::from_static("execution_id")),
            Some(&AttributeValue::String("exec-123".to_owned()))
        );
    }

    #[test]
    fn run_options_mint_a_distinct_wrapper_invocation_id_per_construction() {
        let key = AttributeKey::from_static(provenance_keys::WRAPPER_INVOCATION_ID);
        let ids = [
            base_options(vec!["true".to_owned()]),
            base_options(vec!["true".to_owned()]),
        ]
        .map(|options| {
            let Some(AttributeValue::String(id)) = options.attributes.get(&key).cloned() else {
                panic!("run options must mint a wrapper.invocation_id string attribute");
            };
            ulid::Ulid::from_string(&id).expect("wrapper.invocation_id is a valid ULID");
            id
        });

        assert_ne!(ids[0], ids[1], "each construction mints its own identity");
    }

    #[test]
    fn capture_drain_event_carries_full_provenance_via_the_shared_seam() {
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()]);
        let context = NormalizationContext::new(options.context.clone())
            .with_attributes(options.attributes.clone())
            .with_process(child_process_context(&options, Some(1234)));

        let event = capture_drain_event(
            &context,
            Hlc {
                wall_ns: 7,
                logical: 0,
            },
            Some(&BlobDrainOutcome {
                report: crate::blob_drain::BlobDrainReport::default(),
                error: None,
            }),
            Some(SpoolReport::default()),
        );

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["attributes"][provenance_keys::PROCESS_PID], 1234);
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_COMMAND],
            "echo"
        );
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_ARGV],
            r#"["echo","hi"]"#
        );
        assert_eq!(
            value["attributes"][provenance_keys::WRAPPER_INVOCATION_ID],
            serde_json::to_value(
                options
                    .attributes
                    .get(&AttributeKey::from_static(
                        provenance_keys::WRAPPER_INVOCATION_ID
                    ))
                    .expect("minted invocation id")
            )
            .expect("serialize attribute"),
        );
        assert_eq!(value["attributes"]["capture.complete"], true);
    }

    #[test]
    fn capture_drain_event_without_a_blob_drain_reports_event_spool_health_only() {
        let options = base_options(vec!["true".to_owned()]);
        let context = NormalizationContext::new(options.context.clone())
            .with_attributes(options.attributes.clone());

        let event = capture_drain_event(
            &context,
            Hlc {
                wall_ns: 7,
                logical: 0,
            },
            None,
            Some(SpoolReport {
                pending_events: 3,
                pending_bytes: 512,
                dropped_events: 2,
                rejected_events: 1,
            }),
        );

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["attributes"]["capture.events.dropped"], 2);
        assert_eq!(value["attributes"]["capture.events.rejected"], 1);
        // Loss makes the capture incomplete; pending events do not (in-order
        // redelivery means this record landing certifies everything before it).
        assert_eq!(value["attributes"]["capture.complete"], false);
        assert_eq!(
            value["attributes"].get("capture.blobs.found"),
            None,
            "no blob drain ran, so no blob attributes are claimed"
        );
    }

    #[test]
    fn capture_drain_event_completeness_requires_blobs_and_events_clean() {
        let options = base_options(vec!["true".to_owned()]);
        let context = NormalizationContext::new(options.context.clone())
            .with_attributes(options.attributes.clone());
        let clean_blobs = BlobDrainOutcome {
            report: crate::blob_drain::BlobDrainReport::default(),
            error: None,
        };

        let event = capture_drain_event(
            &context,
            Hlc {
                wall_ns: 7,
                logical: 0,
            },
            Some(&clean_blobs),
            Some(SpoolReport {
                pending_events: 0,
                pending_bytes: 0,
                dropped_events: 1,
                rejected_events: 0,
            }),
        );

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["attributes"]["capture.blobs.found"], 0);
        assert_eq!(value["attributes"]["capture.events.dropped"], 1);
        assert_eq!(
            value["attributes"]["capture.complete"], false,
            "a dropped event makes the capture incomplete even when every blob landed"
        );
    }

    #[test]
    fn spool_problem_is_silent_for_a_clean_spool() {
        assert!(spool_problem(&SpoolReport::default(), None).is_none());
    }

    #[test]
    fn spool_problem_reports_every_loss_class_with_counts() {
        let report = SpoolReport {
            pending_events: 4,
            pending_bytes: 2048,
            dropped_events: 3,
            rejected_events: 2,
        };

        let warning =
            spool_problem(&report, Some("gateway down".to_owned())).expect("a lossy spool warns");
        let rendered = format!("{warning:#}");

        assert!(
            rendered.contains("4 captured event(s) never reached the telemetry gateway"),
            "rendered: {rendered}"
        );
        assert!(
            rendered.contains("3 oldest event(s) were dropped when the export spool filled"),
            "rendered: {rendered}"
        );
        assert!(
            rendered.contains("2 event(s) were dropped after the gateway permanently rejected"),
            "rendered: {rendered}"
        );
        assert!(
            rendered.contains("gateway down"),
            "the last failure is attributed: {rendered}"
        );
    }

    #[test]
    fn run_options_with_execution_id_stamps_attribute_and_child_env_id() {
        let options =
            base_options(vec!["echo".to_owned(), "hi".to_owned()]).with_execution_id("exec-123");

        assert_eq!(options.execution_id.as_deref(), Some("exec-123"));
        assert_eq!(
            options
                .attributes
                .get(&AttributeKey::from_static(provenance_keys::EXECUTION_ID)),
            Some(&AttributeValue::String("exec-123".to_owned()))
        );
    }

    #[test]
    fn spawn_failure_event_records_the_attempt_with_run_identity() {
        let options = base_options(vec!["/missing/harness".to_owned(), "--flag".to_owned()])
            .with_execution_id("exec-123");
        let error = io::Error::from_raw_os_error(2);

        let event = spawn_failure_event(
            &options,
            Hlc {
                wall_ns: 7,
                logical: 0,
            },
            &error,
        );

        assert_eq!(event.signal, SignalType::Exec);
        assert_eq!(
            event.name.as_str(),
            crate::exec_events::PROCESS_SPAWN_FAILED
        );
        assert_eq!(event.run_id, options.context.run_id);
        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(
            value["attributes"][provenance_keys::EXECUTION_ID],
            "exec-123"
        );
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_ARGV],
            r#"["/missing/harness","--flag"]"#
        );
        let recorded = value["attributes"][crate::exec_events::keys::PROCESS_ERROR]
            .as_str()
            .expect("process error");
        assert!(recorded.contains("os error 2"), "error: {recorded}");
        assert!(value["attributes"][provenance_keys::WRAPPER_NAME].is_string());
        let invocation_id = value["attributes"][provenance_keys::WRAPPER_INVOCATION_ID]
            .as_str()
            .expect("wrapper.invocation_id on the spawn-failure event");
        ulid::Ulid::from_string(invocation_id).expect("wrapper.invocation_id is a valid ULID");
        assert!(
            value["attributes"]
                .get(provenance_keys::PROCESS_PID)
                .is_none(),
            "a child that never spawned has no pid"
        );
    }

    #[test]
    fn run_options_suppress_verbose_diagnostics_by_default() {
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()]);

        assert!(!options.verbose_diagnostics);
        assert!(options.with_verbose_diagnostics(true).verbose_diagnostics);
    }

    #[tokio::test]
    async fn egress_policy_without_proxy_is_rejected() {
        let egress = EgressPolicy::new(
            crate::egress::EgressMode::Deny,
            ["api.openai.com".to_owned()],
            [],
        )
        .expect("policy");
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()]).with_egress(egress);
        let error = run(&options).await.expect_err("egress needs proxy");
        assert!(error.to_string().contains("egress policy requires --proxy"));
    }

    #[tokio::test]
    async fn anomaly_detection_without_proxy_is_rejected() {
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()])
            .with_anomaly_detection(AnomalyConfig::enabled());
        let error = run(&options)
            .await
            .expect_err("anomaly detection needs proxy");
        assert!(
            error
                .to_string()
                .contains("anomaly detection requires --proxy")
        );
    }

    #[tokio::test]
    async fn secret_bindings_without_proxy_are_rejected() {
        let options = base_options(vec!["echo".to_owned(), "hi".to_owned()]).with_secret_bindings(
            vec![SecretBinding {
                name: "k".to_owned(),
                env_placeholder: "hil-secret://k".to_owned(),
                host: "api.openai.com".to_owned(),
                header: "authorization".to_owned(),
                scheme: "Bearer".to_owned(),
            }],
            BrokerConfig {
                url: "http://localhost:9/resolve".to_owned(),
                token: "t".to_owned(),
            },
        );
        let error = run(&options).await.expect_err("secrets need proxy");
        assert!(
            error
                .to_string()
                .contains("secret bindings require --proxy")
        );
    }

    #[tokio::test]
    async fn proxy_without_blob_dir_or_grpc_export_is_rejected() {
        // An export target exists (events_jsonl) but captured bodies have nowhere durable to go.
        let options = RunOptions::new(
            RunContext::new_local_root(),
            vec!["echo".to_owned(), "hi".to_owned()],
            Some(PathBuf::from("/tmp/never-created.jsonl")),
            None,
            None,
            false,
            true,
            None,
            None,
        );
        let error = run(&options)
            .await
            .expect_err("proxy needs a body destination");
        assert!(error.to_string().contains("--proxy requires --blob-dir"));
    }

    #[tokio::test]
    async fn proxy_with_grpc_export_and_no_blob_dir_runs_with_a_scratch_store() {
        // A gRPC export satisfies the body-destination invariant: bodies stage in a per-run
        // scratch store. The unreachable gateway only degrades the drain to stderr warnings —
        // never the child's exit code.
        let options = RunOptions::new(
            RunContext::new_local_root(),
            vec!["true".to_owned()],
            None,
            None,
            None,
            false,
            true,
            None,
            Some(GrpcExportOptions {
                endpoint: "http://127.0.0.1:9".to_owned(),
                insecure: true,
                tenant_id: None,
                project_id: "default".to_owned(),
            }),
        )
        .with_blob_drain_retry(DrainRetryPolicy {
            attempts: 1,
            initial_backoff: Duration::from_millis(1),
        });

        let code = run(&options).await.expect("run should complete");

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
    }

    #[tokio::test]
    async fn zero_blob_drain_interval_disables_the_incremental_drain_without_panicking() {
        // `tokio::time::interval` panics on a zero period; a zero cadence must instead mean
        // "no incremental drain" while the run-end drain still executes.
        let options = RunOptions::new(
            RunContext::new_local_root(),
            vec!["true".to_owned()],
            None,
            None,
            None,
            false,
            true,
            None,
            Some(GrpcExportOptions {
                endpoint: "http://127.0.0.1:9".to_owned(),
                insecure: true,
                tenant_id: None,
                project_id: "default".to_owned(),
            }),
        )
        .with_blob_drain_interval(Duration::ZERO)
        .with_blob_drain_retry(DrainRetryPolicy {
            attempts: 1,
            initial_backoff: Duration::from_millis(1),
        });

        let code = run(&options).await.expect("run should complete");

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
    }

    #[tokio::test]
    async fn telemetry_export_failure_does_not_kill_child_or_clobber_exit_zero() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("child-finished");
        let marker_arg = marker.to_string_lossy().into_owned();
        let options = RunOptions::new(
            RunContext::new_local_root(),
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

        let captured = Box::pin(run_captured(&options, &FailingExporter, None, None))
            .await
            .expect("a successful child's exit code wins over an export failure");

        assert_eq!(captured.exit_code, 0);
        assert!(
            captured
                .drain_warnings
                .iter()
                .any(|warning| format!("{warning:#}").contains("stdio event pipeline failed")),
            "the export failure is surfaced as a drain warning"
        );
        assert!(
            marker.exists(),
            "child should finish despite export failure"
        );
    }

    #[tokio::test]
    async fn telemetry_export_failure_preserves_nonzero_child_exit() {
        let options = RunOptions::new(
            RunContext::new_local_root(),
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "printf 'hello\\n'; exit 7".to_owned(),
            ],
            None,
            None,
            None,
            false,
            false,
            None,
            None,
        );

        let captured = Box::pin(run_captured(&options, &FailingExporter, None, None))
            .await
            .expect("the child's own exit code wins over an export failure");

        assert_eq!(captured.exit_code, 7);
        assert!(
            !captured.drain_warnings.is_empty(),
            "the export failure is surfaced as a drain warning"
        );
    }

    #[tokio::test]
    async fn detached_stdin_reader_delivers_all_bytes_in_order_then_eofs() {
        let payload: Vec<u8> = (0..20_000u32).map(|index| (index % 251) as u8).collect();
        let mut reader = DetachedStdinReader::spawn(std::io::Cursor::new(payload.clone()))
            .expect("spawn reader");

        // A destination smaller than the reader's chunks forces splitting across poll_read calls.
        let mut collected = Vec::new();
        let mut buffer = [0_u8; 7];
        loop {
            let read = reader.read(&mut buffer).await.expect("read chunk");
            if read == 0 {
                break;
            }
            collected.extend_from_slice(&buffer[..read]);
        }

        assert_eq!(collected, payload);
    }

    /// Stands in for an interactive stdin that never delivers a byte: `read` reports that it is
    /// in flight, then parks until the test drops `park_until_dropped`, then reports EOF.
    struct NeverReadyStdin {
        read_in_flight: std::sync::mpsc::Sender<()>,
        park_until_dropped: std::sync::mpsc::Receiver<()>,
    }

    impl std::io::Read for NeverReadyStdin {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            let _ = self.read_in_flight.send(());
            let _ = self.park_until_dropped.recv();
            Ok(0)
        }
    }

    #[test]
    fn stdin_pump_shutdown_is_prompt_and_never_blocks_runtime_teardown() {
        let (read_in_flight_tx, read_in_flight) = std::sync::mpsc::channel::<()>();
        let (hold_read_open, park_until_dropped) = std::sync::mpsc::channel::<()>();
        let runtime = tokio::runtime::Runtime::new().expect("runtime");

        runtime.block_on(async {
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let (signal_tx, _signal_rx) = mpsc::channel(8);
            let pump = tokio::spawn(stdin_capture(
                NeverReadyStdin {
                    read_in_flight: read_in_flight_tx,
                    park_until_dropped,
                },
                tokio::io::sink(),
                shutdown_rx,
                signal_tx,
                Arc::new(hiloop_core::identity::HlcClock::new()),
            ));
            // Shut down only once a read is provably in flight — the uncancellable case.
            tokio::task::spawn_blocking(move || {
                read_in_flight
                    .recv_timeout(Duration::from_secs(5))
                    .expect("the pump must start a stdin read");
            })
            .await
            .expect("wait for the in-flight read");
            shutdown_tx.send(()).expect("pump listens for shutdown");
            tokio::time::timeout(Duration::from_secs(2), pump)
                .await
                .expect("pump must finish promptly after shutdown")
                .expect("pump task")
                .expect("pump result");
        });

        // The blocking read is still in flight on its detached thread; runtime teardown must not
        // wait for it (a pool-dispatched read here parked the embedder's runtime drop forever).
        let teardown_started = Instant::now();
        runtime.shutdown_timeout(Duration::from_secs(5));
        assert!(
            teardown_started.elapsed() < Duration::from_secs(2),
            "runtime teardown waited on the parked stdin read"
        );
        drop(hold_read_open);
    }
}
