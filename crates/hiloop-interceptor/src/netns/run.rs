//! Embeddable transparent-network run composition.

use std::{fmt, path::PathBuf, process::ExitCode, sync::Arc};

use async_trait::async_trait;
use hiloop_core::{
    capture::{
        CaptureBlobDelivery, CaptureCompletionReport, CaptureEventDelivery, CaptureEvidenceTrust,
        CapturePolicy, CapturePreflight, CaptureSourceDegradation, CaptureSourceReport,
        CaptureSourcesReport, NetCaptureMode, SelectedNetCaptureMode,
    },
    event::Event,
    identity::{Hlc, RunContext},
};

use crate::supervisor::RunOptions;

use super::PreflightReport;

#[cfg(target_os = "linux")]
use crate::{
    blob::{BlobUploader, DirBlobStore, UnavailableUploader},
    blob_drain::{BlobDrainOutcome, BlobDrainer},
    blob_upload::GrpcBlobUploader,
    exporters::{FanOutExporter, JsonlExporter},
    grpc_client::GatewayCredential,
    grpc_export::GrpcIngestExporter,
    seams::{Exporter, NormalizationContext},
    spool::{SpoolPolicy, SpoolingExporter},
    supervisor::{CAPTURE_HEALTH_EXPORT_TIMEOUT, capture_drain_event},
};

#[cfg(target_os = "linux")]
use super::{
    FatalRunSupervisor, NetworkProvisioner, ProvisionRequest, SubstrateExit, SupervisedRunError,
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

    /// Substitute the network provisioner at its production port while retaining the composer.
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
    // One shared credential for the event exporter and the blob uploader, so an auth refresh
    // triggered by either leg re-authenticates both.
    let gateway_credential = match options.grpc_export() {
        Some(grpc) => Some(
            GatewayCredential::from_env_with_refresher(grpc.bearer_refresh.clone())
                .context("build transparent-run gateway credential")?,
        ),
        None => None,
    };
    let (exporter, spool) = build_exporter(options, gateway_credential.as_ref()).await?;
    let gateway_token = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
    let workload_token = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
    let relay = EventRelayServer::bind(
        &event_socket,
        Arc::clone(&exporter),
        gateway_token.clone(),
        workload_token.clone(),
    )
    .context("bind transparent-run event relay")?;
    let relay_capture = relay.capture_report();
    let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::oneshot::channel();
    let relay_task = tokio::spawn(relay.serve(async move {
        let _ = relay_shutdown_rx.await;
    }));

    let gateway = GatewayConfig::from_options(
        options,
        event_socket.clone(),
        ca_bundle.clone(),
        blob_dir.clone(),
        gateway_token,
    );
    let workload = WorkloadConfig::from_options(options, event_socket, ca_bundle, workload_token);
    let request = ProvisionRequest::new(
        workload.workload_command(&runner.helper_path, options.command())?,
        gateway.worker_command(&runner.helper_path)?,
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
    let wait_result = session.wait().await;

    let _ = relay_shutdown_tx.send(());
    let relay_result = match relay_task.await {
        Ok(result) => result.context("serve transparent-run event relay"),
        Err(error) => Err(error).context("join transparent-run event relay"),
    };
    let network_observations = relay_capture.network().await;
    let relay_events = relay_capture.events().await;
    let inner_completion = relay_capture.take_completion().await;
    let mut result = supervisor.finish_wait(wait_result).await;
    let blob_outcome = drain_blobs(options, &blob_dir, gateway_credential.as_ref()).await;
    let blobs_complete = blob_outcome
        .as_ref()
        .is_none_or(BlobDrainOutcome::is_complete);
    if !blobs_complete && let Some(scratch) = scratch_blobs {
        eprintln!(
            "hiloop-interceptor: warning: captured payload blobs kept at `{}`",
            scratch.keep().display()
        );
    }

    // Settle the ordinary spool before projecting one canonical completion record to every
    // sink. Completion closes that data prefix; only its dedicated terminal lane may retry.
    let spool_report = match &spool {
        Some(spool) => Some(spool.drain(options.blob_drain_retry()).await),
        None => None,
    };
    let network = if relay_result.is_err() || result.is_err() {
        CaptureSourceReport::configured_unavailable(
            CaptureEvidenceTrust::PlatformObserved,
            CaptureSourceDegradation::RuntimeFailed,
        )
    } else {
        CaptureSourceReport::from_event_counts(
            CaptureEvidenceTrust::PlatformObserved,
            network_observations.full,
            network_observations.metadata_only,
            CaptureSourceDegradation::OpaqueNetworkTraffic,
        )
    };
    let fatal_events = result
        .as_ref()
        .err()
        .map(SupervisedRunError::fatal_event_delivery)
        .unwrap_or_default();
    let events = transparent_event_delivery(spool_report, relay_events, fatal_events);
    let missing_inner = CaptureSourceReport::configured_unavailable(
        CaptureEvidenceTrust::PlatformObserved,
        CaptureSourceDegradation::RuntimeFailed,
    );
    let sources = match inner_completion.as_ref() {
        Some((inner, _)) => CaptureSourcesReport::new(
            inner.sources().process().clone(),
            inner.sources().stdio().clone(),
            network,
            inner.sources().otlp().clone(),
        ),
        None => CaptureSourcesReport::new(
            missing_inner.clone(),
            missing_inner,
            network,
            CaptureSourceReport::configured_unavailable(
                CaptureEvidenceTrust::WorkloadReported,
                CaptureSourceDegradation::RuntimeFailed,
            ),
        ),
    };
    let mut terminal_errors = Vec::new();
    if let Some((inner, _)) = &inner_completion
        && let Some(error) = inner.error()
    {
        terminal_errors.push(error.to_owned());
    }
    if inner_completion.is_none() {
        terminal_errors.push("captured workload produced no completion report".to_owned());
    }
    if let Err(error) = &relay_result {
        terminal_errors.push(error.to_string());
    }
    if let Err(error) = &result {
        terminal_errors.push(error.to_string());
    }
    if let Some(error) = blob_outcome
        .as_ref()
        .and_then(|outcome| outcome.error.as_ref())
    {
        terminal_errors.push(error.to_string());
    }
    let report = CaptureCompletionReport::new(
        sources,
        events,
        blob_outcome.as_ref().map(|outcome| CaptureBlobDelivery {
            found: outcome.report.found as u64,
            landed: outcome.report.landed as u64,
            missing: outcome.report.missing as u64,
            oversize: outcome.report.oversize_skipped as u64,
            missing_bytes: outcome.report.missing_bytes,
        }),
        gateway_credential
            .as_ref()
            .map(GatewayCredential::refreshes),
        (!terminal_errors.is_empty()).then(|| terminal_errors.join("; ")),
    )
    .expect("transparent capture completion accounting is valid");
    let mut health_event = capture_drain_event(
        &NormalizationContext::new(options.context().clone())
            .with_attributes(options.attributes().clone()),
        hiloop_core::identity::HlcClock::new().tick(),
        &report,
    );
    if let Some((_, inner_event)) = inner_completion {
        for (key, value) in inner_event.attributes {
            if key.as_str().starts_with("process.")
                || key.as_str() == crate::seams::provenance_keys::EXECUTION_ID
            {
                health_event.attributes.insert(key, value);
            }
        }
    }
    if let Err(warning) = export_run_completion(exporter.as_ref(), health_event, &report).await {
        eprintln!("hiloop-interceptor: warning: telemetry capture incomplete: {warning:#}");
    }

    let flush_result = flush_after_supervision(&mut result, exporter.as_ref()).await;

    if let Some(spool) = spool {
        let report = spool.drain(options.blob_drain_retry()).await;
        if !report.is_clean() {
            eprintln!(
                "hiloop-interceptor: warning: transparent capture event drain incomplete: {} pending, {} dropped, {} rejected, completion pending={}, completion rejected={}",
                report.pending_events,
                report.dropped_events,
                report.rejected_events,
                report.completion_pending,
                report.completion_rejected,
            );
        }
    }

    let cleanup_error = combined_cleanup_error(relay_result, flush_result);
    match result {
        Err(error) => match cleanup_error {
            Some(cleanup) => Err(anyhow::anyhow!(
                "{error:#}; transparent capture cleanup also failed: {cleanup:#}"
            )),
            None => Err(error.into()),
        },
        Ok(exit) => {
            if let Some(error) = cleanup_error {
                return Err(error);
            }
            match exit {
                SubstrateExit::Code(code) => Ok(ExitCode::from(exit_byte(code))),
                SubstrateExit::Signal(signal) => Ok(ExitCode::from(exit_byte(128 + signal.get()))),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn transparent_event_delivery(
    spool: Option<crate::spool::SpoolReport>,
    relay: crate::netns::event_relay::RelayEventDelivery,
    fatal: CaptureEventDelivery,
) -> CaptureEventDelivery {
    let producer_observed = relay
        .observed
        .saturating_add(fatal.observed)
        .saturating_add(1); // capture.transport is exported directly by the host.
    match spool {
        Some(spool) => {
            let spool_observed = spool
                .delivered_events
                .saturating_add(spool.pending_events as u64)
                .saturating_add(spool.dropped_events)
                .saturating_add(spool.rejected_events);
            let pre_spool_dropped = producer_observed.saturating_sub(spool_observed);
            CaptureEventDelivery {
                observed: spool_observed.saturating_add(pre_spool_dropped),
                spooled: spool.spooled_events,
                landed: spool.delivered_events,
                dropped: spool.dropped_events.saturating_add(pre_spool_dropped),
                rejected: spool.rejected_events,
                pending: spool.pending_events as u64,
            }
        }
        None => CaptureEventDelivery {
            observed: producer_observed,
            landed: relay.landed.saturating_add(fatal.landed).saturating_add(1),
            dropped: relay.dropped.saturating_add(fatal.dropped),
            rejected: relay.rejected.saturating_add(fatal.rejected),
            ..CaptureEventDelivery::default()
        },
    }
}

#[cfg(target_os = "linux")]
async fn flush_after_supervision(
    result: &mut Result<SubstrateExit, SupervisedRunError>,
    exporter: &dyn Exporter,
) -> anyhow::Result<()> {
    FatalRunSupervisor::record_flush(result, exporter.flush().await)
        .map_err(anyhow::Error::new)
        .context("flush transparent-run events")
}

#[cfg(target_os = "linux")]
async fn export_run_completion(
    exporter: &dyn Exporter,
    event: Event,
    report: &CaptureCompletionReport,
) -> anyhow::Result<()> {
    match tokio::time::timeout(
        CAPTURE_HEALTH_EXPORT_TIMEOUT,
        exporter.export_completion(&event, report),
    )
    .await
    {
        Ok(result) => result.context("failed to export the capture-health event"),
        Err(_elapsed) => anyhow::bail!(
            "capture-health export timed out after {}s",
            CAPTURE_HEALTH_EXPORT_TIMEOUT.as_secs()
        ),
    }
}

#[cfg(target_os = "linux")]
fn combined_cleanup_error(
    relay: anyhow::Result<()>,
    flush: anyhow::Result<()>,
) -> Option<anyhow::Error> {
    match (relay.err(), flush.err()) {
        (Some(relay), Some(flush)) => Some(anyhow::anyhow!("{relay:#}; {flush:#}")),
        (Some(error), None) | (None, Some(error)) => Some(error),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
type NetnsSpool = SpoolingExporter<GrpcIngestExporter>;

#[cfg(target_os = "linux")]
async fn build_exporter(
    options: &RunOptions,
    gateway_credential: Option<&GatewayCredential>,
) -> anyhow::Result<(Arc<dyn Exporter>, Option<Arc<NetnsSpool>>)> {
    let mut exporters: Vec<Box<dyn Exporter>> = Vec::new();
    if let Some(path) = options.events_jsonl() {
        exporters.push(Box::new(JsonlExporter::create(path).await.with_context(
            || format!("create JSONL exporter at `{}`", path.display()),
        )?));
    }
    let mut spool = None;
    if let Some(grpc) = options.grpc_export() {
        let credential = gateway_credential
            .expect("run_system builds the gateway credential whenever a gRPC export is configured")
            .clone();
        let ingest = GrpcIngestExporter::with_credential(
            &grpc.endpoint,
            grpc.tenant_id.clone(),
            &grpc.project_id,
            grpc.insecure,
            credential,
        )
        .with_context(|| format!("build gRPC exporter for `{}`", grpc.endpoint))?;
        let created = Arc::new(SpoolingExporter::new(ingest, SpoolPolicy::default()));
        exporters.push(Box::new(Arc::clone(&created)));
        spool = Some(created);
    }
    Ok((Arc::new(FanOutExporter::new(exporters)), spool))
}

/// The authoritative run-end blob drain, or `None` when no gRPC export is configured. A store
/// that cannot even be opened yields an errored, incomplete outcome so the health record and the
/// scratch-keep decision see the loss instead of a silent skip.
#[cfg(target_os = "linux")]
async fn drain_blobs(
    options: &RunOptions,
    blob_dir: &std::path::Path,
    gateway_credential: Option<&GatewayCredential>,
) -> Option<BlobDrainOutcome> {
    let grpc = options.grpc_export()?;
    let store = match DirBlobStore::create(blob_dir).await {
        Ok(store) => store,
        Err(error) => {
            eprintln!("hiloop-interceptor: warning: open transparent blob store: {error:#}");
            return Some(BlobDrainOutcome {
                report: crate::blob_drain::BlobDrainReport::default(),
                error: Some(error),
            });
        }
    };
    let credential = gateway_credential
        .expect("run_system builds the gateway credential whenever a gRPC export is configured")
        .clone();
    let uploader: Arc<dyn BlobUploader> = match GrpcBlobUploader::with_credential(
        &grpc.endpoint,
        grpc.tenant_id.clone(),
        grpc.insecure,
        credential,
    ) {
        Ok(uploader) => Arc::new(uploader),
        Err(error) => Arc::new(UnavailableUploader::new(format!(
            "build transparent blob uploader: {error:#}",
            error = anyhow::Error::new(error)
        ))),
    };
    let outcome = BlobDrainer::new(store, uploader)
        .finish(options.blob_drain_retry())
        .await;
    if !outcome.is_complete() {
        eprintln!(
            "hiloop-interceptor: warning: transparent capture blob drain incomplete: {} of {} blob(s) missing",
            outcome.report.missing, outcome.report.found
        );
    }
    Some(outcome)
}

#[cfg(target_os = "linux")]
fn capture_policy(options: &RunOptions) -> CapturePolicy {
    if options.egress().is_allow_all() {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use hiloop_core::{
        capture::{
            CaptureCompletionReport, CaptureEventDelivery, CaptureEvidenceTrust,
            CaptureSourceReport, CaptureSourcesReport,
        },
        event::Event,
        identity::RunContext,
    };

    use super::{export_run_completion, flush_after_supervision, transparent_event_delivery};
    use crate::{
        netns::{
            FatalRunSupervisor, ProvisionError, SubstrateExit, SupervisedRunError,
            event_relay::RelayEventDelivery,
        },
        seams::{ExportError, Exporter},
        spool::SpoolReport,
    };

    #[derive(Debug, Default)]
    struct CountingExporter {
        events: Mutex<Vec<Event>>,
        flushes: AtomicUsize,
        fail_export: bool,
    }

    #[async_trait]
    impl Exporter for CountingExporter {
        async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
            if self.fail_export {
                return Err(ExportError::unavailable("fixture", "export failed"));
            }
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(events);
            Ok(())
        }

        async fn flush(&self) -> Result<(), ExportError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn composer_flushes_once_for_fatal_and_normal_results() {
        let fatal_exporter = Arc::new(CountingExporter::default());
        let supervisor = FatalRunSupervisor::new(
            RunContext::new_local_root(),
            Arc::<CountingExporter>::clone(&fatal_exporter),
        );
        let relay_tail = Event::new(
            &RunContext::new_local_root(),
            hiloop_core::identity::HlcClock::new().tick(),
            hiloop_core::event::SignalType::Net,
            hiloop_core::event::EventName::from_static("fixture.relay-tail"),
        );
        fatal_exporter
            .export(&[relay_tail])
            .await
            .expect("a buffered tail event precedes capture health");
        let mut fatal = supervisor
            .finish_wait(Err(ProvisionError::dataplane(
                "gateway_worker",
                "fixture crash",
            )))
            .await;
        let report = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::configured_unavailable(
                    CaptureEvidenceTrust::PlatformObserved,
                    hiloop_core::capture::CaptureSourceDegradation::RuntimeFailed,
                ),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery {
                observed: 2,
                landed: 2,
                ..CaptureEventDelivery::default()
            },
            None,
            None,
            Some("dataplane failed".to_owned()),
        )
        .expect("valid completion");
        let health = report.to_event(
            &RunContext::new_local_root(),
            hiloop_core::identity::HlcClock::new().tick(),
        );
        export_run_completion(fatal_exporter.as_ref(), health, &report)
            .await
            .expect("capture health exports without flushing");

        flush_after_supervision(&mut fatal, fatal_exporter.as_ref())
            .await
            .expect("the composer flushes all run events once");
        assert!(matches!(&fatal, Err(SupervisedRunError::Fatal(_))));
        assert_eq!(fatal_exporter.flushes.load(Ordering::SeqCst), 1);
        {
            let events = fatal_exporter
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                events
                    .iter()
                    .map(|event| event.name.as_str())
                    .collect::<Vec<_>>(),
                ["fixture.relay-tail", "capture.fatal", "capture.drain"]
            );
            assert!(matches!(
                &fatal,
                Err(SupervisedRunError::Fatal(error)) if error.event_persisted()
            ));
        }

        let normal_exporter = CountingExporter::default();
        let mut normal = Ok::<SubstrateExit, SupervisedRunError>(SubstrateExit::Code(0));
        flush_after_supervision(&mut normal, &normal_exporter)
            .await
            .expect("normal completion flushes at the composer boundary");
        assert_eq!(normal_exporter.flushes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn spooled_completion_counts_canceled_pre_admission_events_as_dropped() {
        let events = transparent_event_delivery(
            Some(SpoolReport {
                delivered_events: 1,
                ..SpoolReport::default()
            }),
            RelayEventDelivery {
                observed: 1,
                dropped: 1,
                ..RelayEventDelivery::default()
            },
            CaptureEventDelivery::default(),
        );

        assert_eq!(
            events,
            CaptureEventDelivery {
                observed: 2,
                landed: 1,
                dropped: 1,
                ..CaptureEventDelivery::default()
            }
        );
        CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            events,
            None,
            None,
            Some("fixture cancellation".to_owned()),
        )
        .expect("balanced spooled completion accounting");
    }

    #[tokio::test]
    async fn composer_flushes_after_failed_fatal_persistence() {
        let export_failure = Arc::new(CountingExporter {
            fail_export: true,
            ..CountingExporter::default()
        });
        let supervisor = FatalRunSupervisor::new(
            RunContext::new_local_root(),
            Arc::<CountingExporter>::clone(&export_failure),
        );
        let mut fatal = supervisor
            .finish_wait(Err(ProvisionError::dataplane(
                "gateway_worker",
                "fixture crash",
            )))
            .await;

        flush_after_supervision(&mut fatal, export_failure.as_ref())
            .await
            .expect("composer flushes buffered events after fatal export fails");
        assert_eq!(export_failure.flushes.load(Ordering::SeqCst), 1);
        let error = fatal.expect_err("dataplane failure remains fatal");
        let fatal = error.into_fatal().expect("typed fatal error");
        assert!(!fatal.event_persisted());
        let diagnostic = anyhow::Error::new(fatal);
        assert!(
            diagnostic
                .chain()
                .any(|cause| cause.to_string().contains("export failed"))
        );
    }

    #[derive(Debug)]
    struct SourceFlushFailure;

    #[async_trait]
    impl Exporter for SourceFlushFailure {
        async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
            Ok(())
        }

        async fn flush(&self) -> Result<(), ExportError> {
            Err(ExportError::with_source(
                "fixture",
                "flush failed",
                std::io::Error::other("disk full"),
            ))
        }
    }

    #[tokio::test]
    async fn composer_flush_preserves_the_export_error_source() {
        let mut normal = Ok::<SubstrateExit, SupervisedRunError>(SubstrateExit::Code(0));
        let error = flush_after_supervision(&mut normal, &SourceFlushFailure)
            .await
            .expect_err("fixture flush fails");

        assert!(error.chain().any(|cause| cause.to_string() == "disk full"));
    }
}
