//! Embeddable transparent-network run composition.

use std::{fmt, path::PathBuf, process::ExitCode, sync::Arc};

use async_trait::async_trait;
use hiloop_core::{
    capture::{CapturePolicy, CapturePreflight, NetCaptureMode, SelectedNetCaptureMode},
    event::Event,
    identity::{Hlc, RunContext},
};

use crate::supervisor::RunOptions;

use super::PreflightReport;

#[cfg(target_os = "linux")]
use crate::{
    blob::{BlobUploader, DirBlobStore, UnavailableUploader},
    blob_drain::BlobDrainer,
    blob_upload::GrpcBlobUploader,
    exporters::{FanOutExporter, JsonlExporter},
    grpc_export::GrpcIngestExporter,
    seams::{Exporter, NormalizationContext},
    spool::{SpoolPolicy, SpoolingExporter},
};

#[cfg(target_os = "linux")]
use super::{
    FatalRunSupervisor, NetworkProvisioner, ProvisionRequest, SubstrateExit,
    SystemNetworkProvisioner,
    event_relay::EventRelayServer,
    gateway::{GatewayConfig, WorkloadConfig},
};

/// Network transport selected by an embedding CLI after policy and preflight evaluation.
#[derive(Clone)]
pub enum NetworkCapture {
    /// Run without network capture.
    Off,
    /// Run the cooperative environment-proxy transport.
    Proxy {
        requested: NetCaptureMode,
        preflight: Option<PreflightReport>,
    },
    /// Run the production transparent-network composition.
    Netns {
        requested: NetCaptureMode,
        preflight: PreflightReport,
        runner: Arc<dyn NetnsRun>,
    },
}

impl fmt::Debug for NetworkCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => formatter.write_str("Off"),
            Self::Proxy {
                requested,
                preflight,
            } => formatter
                .debug_struct("Proxy")
                .field("requested", requested)
                .field("preflight", preflight)
                .finish(),
            Self::Netns {
                requested,
                preflight,
                ..
            } => formatter
                .debug_struct("Netns")
                .field("requested", requested)
                .field("preflight", preflight)
                .finish_non_exhaustive(),
        }
    }
}

impl NetworkCapture {
    /// Explicitly disable network capture.
    pub const fn off() -> Self {
        Self::Off
    }

    /// Select the cooperative proxy directly, without transparent preflight.
    pub const fn proxy() -> Self {
        Self::Proxy {
            requested: NetCaptureMode::Proxy,
            preflight: None,
        }
    }

    /// Select the cooperative proxy after an observation-only `auto` preflight failed.
    pub fn proxy_fallback(preflight: PreflightReport) -> Self {
        Self::Proxy {
            requested: NetCaptureMode::Auto,
            preflight: Some(preflight),
        }
    }

    /// Select transparent capture with the exact report used by the caller's decision.
    pub fn netns(
        requested: NetCaptureMode,
        preflight: PreflightReport,
        runner: Arc<dyn NetnsRun>,
    ) -> Self {
        Self::Netns {
            requested,
            preflight,
            runner,
        }
    }

    pub(crate) const fn uses_proxy(&self) -> bool {
        matches!(self, Self::Proxy { .. })
    }

    pub(crate) fn netns_runner(&self) -> Option<(&PreflightReport, &Arc<dyn NetnsRun>)> {
        match self {
            Self::Netns {
                preflight, runner, ..
            } => Some((preflight, runner)),
            Self::Off | Self::Proxy { .. } => None,
        }
    }

    /// Build the once-per-run transport event from the exact selection inputs.
    pub fn transport_event(
        &self,
        context: &RunContext,
        timestamp: Hlc,
        capture_policy: CapturePolicy,
    ) -> Event {
        let (requested, selected, report) = match self {
            Self::Off => (NetCaptureMode::Off, SelectedNetCaptureMode::Off, None),
            Self::Proxy {
                requested,
                preflight,
            } => (
                *requested,
                SelectedNetCaptureMode::Proxy,
                preflight.as_ref(),
            ),
            Self::Netns {
                requested,
                preflight,
                ..
            } => (
                *requested,
                if preflight.result() == CapturePreflight::Passed {
                    SelectedNetCaptureMode::Netns
                } else {
                    SelectedNetCaptureMode::None
                },
                Some(preflight),
            ),
        };
        Event::capture_transport(
            context,
            timestamp,
            requested,
            selected,
            capture_policy,
            report.map_or(CapturePreflight::NotApplicable, PreflightReport::result),
            report.is_none_or(PreflightReport::ipv4_available),
            report.is_some_and(PreflightReport::ipv6_available),
            report.and_then(PreflightReport::degradation_reason),
        )
    }
}

/// Production composition port shared by the host-backed runner and deterministic fake.
#[async_trait]
pub trait NetnsRun: Send + Sync {
    /// Exercise every host primitive without starting the requested workload.
    async fn preflight(&self) -> PreflightReport;

    /// Run the wrapped command through the transparent gateway and fatal supervisor.
    async fn run(&self, options: &RunOptions) -> anyhow::Result<ExitCode>;
}

/// Host-backed composition of the namespace substrate, gateway worker, and capture supervisor.
#[cfg(target_os = "linux")]
pub struct SystemNetnsRun {
    provisioner: Arc<dyn NetworkProvisioner>,
    helper_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SystemNetnsRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemNetnsRun")
            .field("helper_path", &self.helper_path)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl SystemNetnsRun {
    /// Compose the production runner around one explicit version-pinned pasta executable.
    pub fn new(pasta_path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let provisioner = SystemNetworkProvisioner::new(pasta_path)?;
        let helper_path = provisioner.helper_path().to_owned();
        Ok(Self {
            provisioner: Arc::new(provisioner),
            helper_path,
        })
    }

    /// Substitute the W2 provisioner at its production port while retaining the real composer.
    pub fn with_provisioner(
        provisioner: Arc<dyn NetworkProvisioner>,
        helper_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            provisioner,
            helper_path: helper_path.into(),
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl NetnsRun for SystemNetnsRun {
    async fn preflight(&self) -> PreflightReport {
        self.provisioner.preflight().await
    }

    async fn run(&self, options: &RunOptions) -> anyhow::Result<ExitCode> {
        run_system(self, options).await
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy)]
pub struct SystemNetnsRun;

#[cfg(not(target_os = "linux"))]
impl SystemNetnsRun {
    /// Transparent namespace composition is available only on Linux.
    pub fn new(_pasta_path: impl Into<PathBuf>) -> std::io::Result<Self> {
        Ok(Self)
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl NetnsRun for SystemNetnsRun {
    async fn preflight(&self) -> PreflightReport {
        PreflightReport::failed(
            hiloop_core::capture::CaptureTransportDegradationReason::UnsupportedPlatform,
            "transparent network namespaces are available only on Linux",
            false,
            false,
        )
    }

    async fn run(&self, _options: &RunOptions) -> anyhow::Result<ExitCode> {
        anyhow::bail!("transparent network namespaces are available only on Linux")
    }
}

#[cfg(target_os = "linux")]
async fn run_system(runner: &SystemNetnsRun, options: &RunOptions) -> anyhow::Result<ExitCode> {
    let Some((preflight, _)) = options.network_capture().netns_runner() else {
        anyhow::bail!("SystemNetnsRun requires NetworkCapture::Netns run options");
    };
    anyhow::ensure!(
        preflight.result() == CapturePreflight::Passed,
        "transparent network capture preflight did not pass"
    );
    anyhow::ensure!(
        options.raw_jsonl().is_none(),
        "transparent network capture does not yet support --raw-jsonl"
    );
    anyhow::ensure!(
        options.events_jsonl().is_some() || options.grpc_export().is_some(),
        "transparent network capture requires an export target (--events-jsonl or --export-grpc)"
    );
    anyhow::ensure!(
        options.blob_dir().is_some() || options.grpc_export().is_some(),
        "transparent network capture requires --blob-dir unless --export-grpc is configured"
    );

    let runtime = tempfile::tempdir().context("create transparent-run private directory")?;
    let event_socket = runtime.path().join("events.sock");
    let ca_bundle = runtime.path().join("capture-ca.pem");
    let scratch_blobs = if options.blob_dir().is_none() {
        Some(tempfile::tempdir().context("create transparent-run scratch blob directory")?)
    } else {
        None
    };
    let blob_dir = options.blob_dir().map_or_else(
        || {
            scratch_blobs
                .as_ref()
                .expect("scratch blob directory exists without --blob-dir")
                .path()
                .to_owned()
        },
        PathBuf::from,
    );
    let (exporter, spool) = build_exporter(options).await?;
    let relay = EventRelayServer::bind(&event_socket, Arc::clone(&exporter))
        .context("bind transparent-run event relay")?;
    let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::oneshot::channel();
    let relay_task = tokio::spawn(relay.serve(async move {
        let _ = relay_shutdown_rx.await;
    }));

    let gateway = GatewayConfig::from_options(
        options,
        event_socket.clone(),
        ca_bundle.clone(),
        blob_dir.clone(),
    );
    let workload = WorkloadConfig::from_options(options, event_socket, ca_bundle);
    let request = ProvisionRequest::new(
        workload.workload_command(&runner.helper_path, options.command())?,
        gateway.worker_command(&runner.helper_path, options.secret_broker())?,
    );

    let transport = NormalizationContext::new(options.context().clone())
        .with_attributes(options.attributes().clone())
        .stamp_provenance(options.network_capture().transport_event(
            options.context(),
            hiloop_core::identity::HlcClock::new().tick(),
            capture_policy(options),
        ));
    exporter
        .export(std::slice::from_ref(&transport))
        .await
        .context("export capture.transport")?;

    let mut session = runner.provisioner.provision(request).await?;
    let supervisor = FatalRunSupervisor::new(options.context().clone(), Arc::clone(&exporter));
    let result = supervisor.wait(session.as_mut()).await;

    let _ = relay_shutdown_tx.send(());
    relay_task
        .await
        .context("join transparent-run event relay")??;
    exporter
        .flush()
        .await
        .context("flush transparent-run events")?;

    if let Some(spool) = spool {
        let report = spool.drain(options.blob_drain_retry()).await;
        if report.pending_events > 0 || report.dropped_events > 0 || report.rejected_events > 0 {
            eprintln!(
                "hiloop-interceptor: warning: transparent capture event drain incomplete: {} pending, {} dropped, {} rejected",
                report.pending_events, report.dropped_events, report.rejected_events
            );
        }
    }
    let blobs_complete = drain_blobs(options, &blob_dir).await;
    if !blobs_complete && let Some(scratch) = scratch_blobs {
        eprintln!(
            "hiloop-interceptor: warning: captured payload blobs kept at `{}`",
            scratch.keep().display()
        );
    }

    match result? {
        SubstrateExit::Code(code) => Ok(ExitCode::from(exit_byte(code))),
        SubstrateExit::Signal(signal) => Ok(ExitCode::from(exit_byte(128 + signal.get()))),
    }
}

#[cfg(target_os = "linux")]
type NetnsSpool = SpoolingExporter<GrpcIngestExporter>;

#[cfg(target_os = "linux")]
async fn build_exporter(
    options: &RunOptions,
) -> anyhow::Result<(Arc<dyn Exporter>, Option<Arc<NetnsSpool>>)> {
    let mut exporters: Vec<Box<dyn Exporter>> = Vec::new();
    if let Some(path) = options.events_jsonl() {
        exporters.push(Box::new(JsonlExporter::create(path).await.with_context(
            || format!("create JSONL exporter at `{}`", path.display()),
        )?));
    }
    let mut spool = None;
    if let Some(grpc) = options.grpc_export() {
        let ingest = GrpcIngestExporter::connect(
            &grpc.endpoint,
            grpc.tenant_id.clone(),
            &grpc.project_id,
            grpc.insecure,
        )
        .with_context(|| format!("build gRPC exporter for `{}`", grpc.endpoint))?;
        let created = Arc::new(SpoolingExporter::new(ingest, SpoolPolicy::default()));
        exporters.push(Box::new(Arc::clone(&created)));
        spool = Some(created);
    }
    Ok((Arc::new(FanOutExporter::new(exporters)), spool))
}

#[cfg(target_os = "linux")]
async fn drain_blobs(options: &RunOptions, blob_dir: &std::path::Path) -> bool {
    let Some(grpc) = options.grpc_export() else {
        return true;
    };
    let store = match DirBlobStore::create(blob_dir).await {
        Ok(store) => store,
        Err(error) => {
            eprintln!("hiloop-interceptor: warning: open transparent blob store: {error:#}");
            return false;
        }
    };
    let uploader: Arc<dyn BlobUploader> =
        match GrpcBlobUploader::connect(&grpc.endpoint, grpc.tenant_id.clone(), grpc.insecure) {
            Ok(uploader) => Arc::new(uploader),
            Err(error) => Arc::new(UnavailableUploader::new(format!(
                "build transparent blob uploader: {error:#}"
            ))),
        };
    let outcome = BlobDrainer::new(store, uploader)
        .finish(options.blob_drain_retry())
        .await;
    let complete = outcome.is_complete();
    if !complete {
        eprintln!(
            "hiloop-interceptor: warning: transparent capture blob drain incomplete: {} of {} blob(s) missing",
            outcome.report.missing, outcome.report.found
        );
    }
    complete
}

#[cfg(target_os = "linux")]
fn capture_policy(options: &RunOptions) -> CapturePolicy {
    if !options.secret_bindings().is_empty() {
        CapturePolicy::SecretStrict
    } else if options.egress().is_allow_all() {
        CapturePolicy::Observe
    } else {
        CapturePolicy::PolicyStrict
    }
}

#[cfg(target_os = "linux")]
fn exit_byte(code: i32) -> u8 {
    u8::try_from(code.clamp(0, i32::from(u8::MAX))).unwrap_or(u8::MAX)
}

#[cfg(target_os = "linux")]
use anyhow::Context as _;
