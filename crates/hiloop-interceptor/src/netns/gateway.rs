//! Production transparent TCP/TLS/HTTP/DNS/UDP gateway worker.

use std::{
    convert::Infallible,
    future::{Ready, ready},
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr as _,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hiloop_core::{
    capture::TlsFlowIdentity,
    event::{Attributes, Event},
    identity::{HlcClock, RunContext},
};
use hudsucker::{Body, RequestOrResponse};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    http::uri::{Authority, Scheme},
    service::service_fn,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{HttpConnector, dns::Name},
    },
    rt::{TokioExecutor, TokioIo},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tower_service::Service;

use crate::{
    anomaly::AnomalyConfig,
    blob::{BlobStore, DirBlobStore},
    egress::{CanonicalHost, EgressMode, EgressPolicy},
    net_capture::CompatibilityRegistry,
    pipeline::{Pipeline, PipelineOptions},
    proxy::{CaptureHandler, ProxyCa, ProxyNormalizer, upstream_client_config},
    redact::RedactionPolicy,
    seams::{Exporter, NormalizationContext, NormalizerRouter, RawSignal, SourceError},
    secret::{BrokerConfig, SecretBinding, SecretInjector},
    supervisor::{RunOptions, run_captured_with_exporter},
};

use super::{
    AdmittedTcpFlow, AuthorizedRoute, DataplaneClosed, DirectTcpConnector, DnsAnswerTracker,
    DnsRelayClient, FatalReport, GatewayDnsRelay, GatewayFatalController, GatewayWorkerBootstrap,
    IngressError, NamespaceCommand, NetworkCapture, RequestAuthorityRejection, SecretRoute,
    TcpProtocol, TlsPolicyEngine, TlsPolicyFlow, TlsTransportDecision, TransparentTcpIngress,
    TransparentUdpChildSink, TransparentUdpIngress, UdpFlowRelay, UdpIngressError,
    classifier::HTTP2_PREFACE,
    classify_client_handshake_error, connect_authorized,
    event_relay::EventRelayExporter,
    routing::{GATEWAY_IPV4, GATEWAY_IPV6},
};

pub(super) const GATEWAY_WORKER_ROLE: &str = "__hiloop-netns-gateway-worker";
pub(super) const CAPTURED_WORKLOAD_ROLE: &str = "__hiloop-netns-captured-workload";

const GATEWAY_CONFIG_ENV: &str = "HILOOP_NETNS_GATEWAY_CONFIG";
const WORKLOAD_CONFIG_ENV: &str = "HILOOP_NETNS_WORKLOAD_CONFIG";
const BROKER_TOKEN_ENV: &str = "HILOOP_NETNS_BROKER_TOKEN";
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct GatewayConfig {
    context: RunContext,
    attributes: Attributes,
    event_socket: PathBuf,
    ca_bundle: PathBuf,
    blob_dir: PathBuf,
    max_capture_bytes: Option<u64>,
    redaction_enabled: bool,
    egress: EgressConfig,
    anomaly: AnomalyConfigWire,
    bindings: Vec<SecretBindingWire>,
    broker_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WorkloadConfig {
    context: RunContext,
    attributes: Attributes,
    event_socket: PathBuf,
    ca_bundle: PathBuf,
    execution_id: Option<String>,
    otlp: bool,
    redaction_enabled: bool,
    export_batch_size: usize,
    export_flush_interval_ms: Option<u64>,
    env_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EgressConfig {
    deny_by_default: bool,
    domains: Vec<String>,
    cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnomalyConfigWire {
    enabled: bool,
    block_on_match: bool,
    min_base64_bytes: u64,
    base64_ratio: f64,
    max_upload_bytes: u64,
    suspicious_content_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretBindingWire {
    name: String,
    env_placeholder: String,
    host: String,
    header: String,
    scheme: String,
}

impl GatewayConfig {
    pub(super) fn from_options(
        options: &RunOptions,
        event_socket: PathBuf,
        ca_bundle: PathBuf,
        blob_dir: PathBuf,
    ) -> Self {
        Self {
            context: options.context().clone(),
            attributes: options.attributes().clone(),
            event_socket,
            ca_bundle,
            blob_dir,
            max_capture_bytes: options.max_capture_bytes(),
            redaction_enabled: options.redaction().is_enabled(),
            egress: EgressConfig::from(options.egress()),
            anomaly: AnomalyConfigWire::from(options.anomaly()),
            bindings: options
                .secret_bindings()
                .iter()
                .map(SecretBindingWire::from)
                .collect(),
            broker_url: options.secret_broker().map(|broker| broker.url.clone()),
        }
    }

    pub(super) fn worker_command(
        &self,
        helper: &Path,
        broker: Option<&BrokerConfig>,
    ) -> io::Result<NamespaceCommand> {
        let mut command = NamespaceCommand::new(helper)
            .arg(GATEWAY_WORKER_ROLE)
            .env(GATEWAY_CONFIG_ENV, encode(self)?);
        if let Some(broker) = broker {
            command = command.env(BROKER_TOKEN_ENV, &broker.token);
        }
        Ok(command)
    }
}

impl WorkloadConfig {
    pub(super) fn from_options(
        options: &RunOptions,
        event_socket: PathBuf,
        ca_bundle: PathBuf,
    ) -> Self {
        Self {
            context: options.context().clone(),
            attributes: options.attributes().clone(),
            event_socket,
            ca_bundle,
            execution_id: options.execution_id().map(str::to_owned),
            otlp: options.otlp_enabled(),
            redaction_enabled: options.redaction().is_enabled(),
            export_batch_size: options.export_batch_size(),
            export_flush_interval_ms: options
                .export_flush_interval()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok()),
            env_allowlist: options.env_allowlist().to_vec(),
        }
    }

    pub(super) fn workload_command(
        &self,
        helper: &Path,
        command: &[String],
    ) -> io::Result<NamespaceCommand> {
        let mut workload = NamespaceCommand::new(helper)
            .arg(CAPTURED_WORKLOAD_ROLE)
            .args(command)
            .env(WORKLOAD_CONFIG_ENV, encode(self)?);
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            workload = workload.env_remove(name);
        }
        Ok(workload)
    }
}

impl From<&EgressPolicy> for EgressConfig {
    fn from(policy: &EgressPolicy) -> Self {
        Self {
            deny_by_default: policy.mode() == EgressMode::Deny,
            domains: policy.domain_rules().to_vec(),
            cidrs: policy.cidr_rules().collect(),
        }
    }
}

impl EgressConfig {
    fn build(&self) -> io::Result<EgressPolicy> {
        EgressPolicy::new(
            if self.deny_by_default {
                EgressMode::Deny
            } else {
                EgressMode::Allow
            },
            self.domains.clone(),
            self.cidrs.clone(),
        )
        .map_err(io::Error::other)
    }
}

impl From<&AnomalyConfig> for AnomalyConfigWire {
    fn from(config: &AnomalyConfig) -> Self {
        Self {
            enabled: config.is_enabled(),
            block_on_match: config.blocks_on_match(),
            min_base64_bytes: config.min_base64_bytes(),
            base64_ratio: config.base64_ratio(),
            max_upload_bytes: config.max_upload_bytes(),
            suspicious_content_types: config.suspicious_content_types().to_vec(),
        }
    }
}

impl AnomalyConfigWire {
    fn build(&self) -> AnomalyConfig {
        if !self.enabled {
            return AnomalyConfig::default();
        }
        AnomalyConfig::enabled()
            .with_block_on_match(self.block_on_match)
            .with_min_base64_bytes(self.min_base64_bytes)
            .with_base64_ratio(self.base64_ratio)
            .with_max_upload_bytes(self.max_upload_bytes)
            .with_suspicious_content_types(self.suspicious_content_types.clone())
    }
}

impl From<&SecretBinding> for SecretBindingWire {
    fn from(binding: &SecretBinding) -> Self {
        Self {
            name: binding.name.clone(),
            env_placeholder: binding.env_placeholder.clone(),
            host: binding.host.clone(),
            header: binding.header.clone(),
            scheme: binding.scheme.clone(),
        }
    }
}

impl From<SecretBindingWire> for SecretBinding {
    fn from(binding: SecretBindingWire) -> Self {
        Self {
            name: binding.name,
            env_placeholder: binding.env_placeholder,
            host: binding.host,
            header: binding.header,
            scheme: binding.scheme,
        }
    }
}

pub(super) fn gateway_worker_entrypoint() -> io::Result<ExitCode> {
    let config: GatewayConfig = decode_environment(GATEWAY_CONFIG_ENV)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_gateway(config))
}

pub(super) fn captured_workload_entrypoint() -> io::Result<ExitCode> {
    let config = take_workload_config()?;
    let command = std::env::args().skip(2).collect::<Vec<_>>();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let exporter = EventRelayExporter::connect(&config.event_socket).await?;
        let mut options = RunOptions::new(
            config.context,
            command,
            None,
            None,
            None,
            config.otlp,
            NetworkCapture::off(),
            None,
            None,
        )
        .with_attributes(config.attributes)
        .with_redaction(if config.redaction_enabled {
            RedactionPolicy::enabled()
        } else {
            RedactionPolicy::disabled()
        })
        .with_export_batch_size(config.export_batch_size)
        .with_export_flush_interval(config.export_flush_interval_ms.map(Duration::from_millis))
        .with_env_allowlist(config.env_allowlist)
        .with_ca_bundle(config.ca_bundle);
        if let Some(execution_id) = config.execution_id {
            options = options.with_execution_id(execution_id);
        }
        run_captured_with_exporter(&options, &exporter)
            .await
            .map_err(io::Error::other)
    })
}

#[expect(
    unsafe_code,
    reason = "the fresh re-exec helper is single-threaded and removes its private bootstrap value before constructing a runtime or child"
)]
fn take_workload_config() -> io::Result<WorkloadConfig> {
    let config = decode_environment(WORKLOAD_CONFIG_ENV)?;
    // SAFETY: dispatch_internal_helper runs before the embedding binary constructs any runtime;
    // this dedicated workload helper has not started a thread and performs no concurrent env access.
    unsafe { std::env::remove_var(WORKLOAD_CONFIG_ENV) };
    Ok(config)
}

async fn run_gateway(config: GatewayConfig) -> io::Result<ExitCode> {
    let bootstrap = GatewayWorkerBootstrap::from_inherited_fds()?;
    let exporter = Arc::new(EventRelayExporter::connect(&config.event_socket).await?);
    let clock = Arc::new(HlcClock::new());
    let ca = Arc::new(ProxyCa::generate().map_err(io::Error::other)?);
    write_ca_bundle(&config.ca_bundle, ca.cert_pem())?;
    let egress = Arc::new(config.egress.build()?);
    let anomaly = Arc::new(config.anomaly.build());
    let bindings = config
        .bindings
        .into_iter()
        .map(SecretBinding::from)
        .collect::<Vec<_>>();
    let bound_hosts = binding_hosts(&bindings)?;
    let injector = build_injector(bindings.clone(), config.broker_url)?;
    let tls_policy = Arc::new(TlsPolicyEngine::new(
        !bindings.is_empty(),
        &egress,
        CompatibilityRegistry::current(),
    ));
    let blob_store: Arc<dyn BlobStore> = Arc::new(
        DirBlobStore::create(&config.blob_dir)
            .await
            .map_err(io::Error::other)?,
    );
    let tracker = Arc::new(DnsAnswerTracker::default());
    let dns = GatewayDnsRelay::bind(
        GATEWAY_IPV4,
        GATEWAY_IPV6,
        DnsRelayClient::connect_from_environment().await?,
        Arc::clone(&tracker),
    )
    .await?;
    let listeners = bootstrap.notify_ready()?;
    let (tcp_ipv4, tcp_ipv6, udp_ipv4, udp_ipv6, broker) = listeners.into_parts();
    let tcp = Arc::new(TransparentTcpIngress::from_std(tcp_ipv4, tcp_ipv6)?);
    let udp = Arc::new(TransparentUdpIngress::from_std(udp_ipv4, udp_ipv6)?);
    let child_sink = Arc::new(TransparentUdpChildSink::new(broker.try_clone()?)?);
    let latch = super::DataplaneLatch::new();
    let fatal = GatewayFatalController::new(latch.clone(), &broker)?;
    let (fatal_tx, mut fatal_rx) = mpsc::channel::<FatalReport>(1);
    let (summary_tx, mut summary_rx) = mpsc::channel(128);
    let udp_relay = Arc::new(UdpFlowRelay::new(
        !bindings.is_empty(),
        &egress,
        UDP_IDLE_TIMEOUT,
        child_sink,
        summary_tx,
    ));
    let (raw_tx, raw_rx) = mpsc::channel::<Result<RawSignal, SourceError>>(1024);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(1024);
    let handler = CaptureHandler::new(
        raw_tx,
        Arc::clone(&clock),
        blob_store,
        config.max_capture_bytes,
        if config.redaction_enabled {
            RedactionPolicy::enabled()
        } else {
            RedactionPolicy::disabled()
        },
        Arc::clone(&egress),
        anomaly,
        injector,
    );

    let normalizer = ProxyNormalizer;
    let pipeline = Pipeline::with_router(
        NormalizationContext::new(config.context.clone()).with_attributes(config.attributes),
        NormalizerRouter::single(&normalizer),
        exporter.as_ref(),
    )
    .options(PipelineOptions::default().with_export_batch_size(1))
    .run(ReceiverStream::new(raw_rx));
    let event_exporter = Arc::clone(&exporter);
    let event_pump = async move {
        while let Some(event) = event_rx.recv().await {
            event_exporter
                .export(std::slice::from_ref(&event))
                .await
                .map_err(io::Error::other)?;
        }
        Ok::<(), io::Error>(())
    };
    let context = Arc::new(config.context);
    let tcp_task = latch.run(serve_tcp(TcpGateway {
        ingress: tcp,
        context: Arc::clone(&context),
        clock: Arc::clone(&clock),
        egress: Arc::clone(&egress),
        tracker: Arc::clone(&tracker),
        policy: tls_policy,
        bound_hosts: Arc::new(bound_hosts),
        handler,
        ca,
        event_tx,
        fatal_tx: fatal_tx.clone(),
        latch: latch.clone(),
    }));
    let dns_task = latch.run(dns.serve());
    let udp_task = serve_udp(latch.clone(), udp, udp_relay, fatal_tx.clone());
    let summary_context = Arc::clone(&context);
    let summary_clock = Arc::clone(&clock);
    let summary_exporter = Arc::clone(&exporter);
    let summary_task = async move {
        while let Some(summary) = summary_rx.recv().await {
            let event = summary
                .net_passthrough_event(&summary_context, summary_clock.tick())
                .map_err(io::Error::other)?;
            summary_exporter
                .export(std::slice::from_ref(&event))
                .await
                .map_err(io::Error::other)?;
        }
        Ok::<(), io::Error>(())
    };
    let fatal_task = async move {
        let report = fatal_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("gateway fatal channel closed"))?;
        fatal.trigger(&report).await.map_err(io::Error::other)?;
        std::future::pending::<()>().await;
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        result = pipeline => result.map(|_| ()).map_err(io::Error::other)?,
        result = event_pump => result?,
        result = tcp_task => require_latch_task("TCP gateway", result).await?,
        result = dns_task => require_latch_task("DNS gateway", result).await?,
        result = udp_task => result?,
        result = summary_task => result?,
        result = fatal_task => result?,
    }
    Err(io::Error::other("gateway worker stopped unexpectedly"))
}

struct TcpGateway {
    ingress: Arc<TransparentTcpIngress>,
    context: Arc<RunContext>,
    clock: Arc<HlcClock>,
    egress: Arc<EgressPolicy>,
    tracker: Arc<DnsAnswerTracker>,
    policy: Arc<TlsPolicyEngine>,
    bound_hosts: Arc<Vec<CanonicalHost>>,
    handler: CaptureHandler,
    ca: Arc<ProxyCa>,
    event_tx: mpsc::Sender<Event>,
    fatal_tx: mpsc::Sender<FatalReport>,
    latch: super::DataplaneLatch,
}

async fn serve_tcp(gateway: TcpGateway) -> io::Result<()> {
    loop {
        let admitted = match gateway
            .ingress
            .accept(&gateway.egress, &*gateway.tracker)
            .await
        {
            Ok(flow) => flow,
            Err(IngressError::Denied(_)) => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let latch = gateway.latch.clone();
            let _ = Box::pin(latch.run(handle_tcp_flow(gateway, admitted))).await;
        });
    }
}

impl Clone for TcpGateway {
    fn clone(&self) -> Self {
        Self {
            ingress: Arc::clone(&self.ingress),
            context: Arc::clone(&self.context),
            clock: Arc::clone(&self.clock),
            egress: Arc::clone(&self.egress),
            tracker: Arc::clone(&self.tracker),
            policy: Arc::clone(&self.policy),
            bound_hosts: Arc::clone(&self.bound_hosts),
            handler: self.handler.clone(),
            ca: Arc::clone(&self.ca),
            event_tx: self.event_tx.clone(),
            fatal_tx: self.fatal_tx.clone(),
            latch: self.latch.clone(),
        }
    }
}

async fn handle_tcp_flow(gateway: TcpGateway, admitted: AdmittedTcpFlow) -> io::Result<()> {
    let secret_route = secret_route(&admitted, &gateway.bound_hosts);
    let decision = gateway
        .policy
        .decide(TlsPolicyFlow::Admitted {
            route: admitted.route(),
            protocol: admitted.protocol(),
            secret_route,
        })
        .await;
    consume_transport_decision(gateway, admitted, secret_route, decision).await
}

async fn consume_transport_decision(
    gateway: TcpGateway,
    admitted: AdmittedTcpFlow,
    secret_route: SecretRoute,
    decision: TlsTransportDecision,
) -> io::Result<()> {
    match decision {
        TlsTransportDecision::Denied(_) => Ok(()),
        TlsTransportDecision::Fatal(reason) => {
            send_fatal(&gateway.fatal_tx, fatal_for_admitted(reason, &admitted)?).await
        }
        TlsTransportDecision::PassthroughTls(reason) => {
            let flow = admitted
                .tls_flow_identity()
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other("TLS passthrough selected for non-TLS flow"))?;
            let connected = connect_authorized(admitted, &DirectTcpConnector).await?;
            let (client, upstream, _, _) = connected.into_parts();
            super::raw_tls_splice(
                client,
                upstream,
                &gateway.context,
                gateway.clock.tick(),
                reason,
                &flow,
                &gateway.event_tx,
            )
            .await
            .map(|_| ())
            .map_err(io::Error::other)
        }
        TlsTransportDecision::PassthroughTcp => {
            let destination = admitted.route().original_destination();
            let connected = connect_authorized(admitted, &DirectTcpConnector).await?;
            let (client, upstream, _, _) = connected.into_parts();
            super::raw_tcp_splice(
                client,
                upstream,
                &gateway.context,
                gateway.clock.tick(),
                destination,
                &gateway.event_tx,
            )
            .await
            .map(|_| ())
            .map_err(io::Error::other)
        }
        TlsTransportDecision::CaptureHttp => {
            let (client, route, _) = admitted.into_parts();
            let h2 = cleartext_http2(&client).await?;
            serve_http(client, false, h2, route, None, secret_route, gateway).await
        }
        TlsTransportDecision::TerminateTls => terminate_tls(gateway, admitted, secret_route).await,
    }
}

async fn cleartext_http2(client: &tokio::net::TcpStream) -> io::Result<bool> {
    let mut prefix = [0_u8; HTTP2_PREFACE.len()];
    let length = client.peek(&mut prefix).await?;
    Ok(length == prefix.len() && prefix == HTTP2_PREFACE)
}

async fn terminate_tls(
    gateway: TcpGateway,
    admitted: AdmittedTcpFlow,
    secret_route: SecretRoute,
) -> io::Result<()> {
    if let Err(reason) = gateway.policy.validate_termination_destination(
        admitted.route(),
        &*gateway.tracker,
        secret_route,
    ) {
        return send_fatal(&gateway.fatal_tx, fatal_for_admitted(reason, &admitted)?).await;
    }
    let flow = admitted
        .tls_flow_identity()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("TLS termination selected for non-TLS flow"))?;
    let (client, route, protocol) = admitted.into_parts();
    let server_config = gateway
        .ca
        .server_config_for(route.identity().host_str().as_str())
        .map_err(io::Error::other)?;
    match TlsAcceptor::from(server_config).accept(client).await {
        Ok(tls) => {
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            serve_http(tls, true, h2, route, Some(flow), secret_route, gateway).await
        }
        Err(error) => {
            let decision = gateway
                .policy
                .record_handshake_failure(
                    TlsPolicyFlow::Admitted {
                        route: &route,
                        protocol: &protocol,
                        secret_route,
                    },
                    classify_client_handshake_error(&error),
                )
                .await;
            super::emit_interception_failure(
                &gateway.event_tx,
                &gateway.context,
                gateway.clock.tick(),
                &flow,
                decision,
                secret_route == SecretRoute::Bound,
            )
            .await
            .map_err(io::Error::other)?;
            if let Some(report) = decision.fatal_report(flow) {
                send_fatal(&gateway.fatal_tx, report).await?;
            }
            Ok(())
        }
    }
}

async fn serve_http<S>(
    stream: S,
    tls: bool,
    h2: bool,
    route: AuthorizedRoute,
    tls_flow: Option<TlsFlowIdentity>,
    secret_route: SecretRoute,
    gateway: TcpGateway,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream = pinned_client(&route)?;
    let expected = route.identity().host().clone();
    let handler = gateway.handler.clone().with_connect_host(expected);
    let forwarder = HttpForwarder {
        tls,
        route: Arc::new(route),
        tls_flow,
        secret_route,
        policy: Arc::clone(&gateway.policy),
        upstream,
        handler,
        fatal_tx: gateway.fatal_tx.clone(),
    };
    let service = service_fn(move |request: Request<Incoming>| {
        proxy_http_request(request, forwarder.clone())
    });
    if h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .map_err(io::Error::other)
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .map_err(io::Error::other)
    }
}

type PinnedClient = Client<hyper_rustls::HttpsConnector<HttpConnector<PinnedResolver>>, Body>;

#[derive(Clone)]
struct HttpForwarder {
    tls: bool,
    route: Arc<AuthorizedRoute>,
    tls_flow: Option<TlsFlowIdentity>,
    secret_route: SecretRoute,
    policy: Arc<TlsPolicyEngine>,
    upstream: PinnedClient,
    handler: CaptureHandler,
    fatal_tx: mpsc::Sender<FatalReport>,
}

fn pinned_client(route: &AuthorizedRoute) -> io::Result<PinnedClient> {
    let destination = route.original_destination();
    let resolver = PinnedResolver {
        expected: route.identity().host_str(),
        address: destination.ip(),
    };
    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(upstream_client_config(&[]).map_err(io::Error::other)?)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

async fn proxy_http_request(
    request: Request<Incoming>,
    mut forwarder: HttpForwarder,
) -> Result<Response<Body>, Infallible> {
    let request = request.map(Body::from);
    let authority = request_authority(&request);
    let validation = authority.as_deref().map_or_else(
        || {
            Err(RequestAuthorityRejection::Denied(
                super::RouteDenial::IdentityUnavailable,
            ))
        },
        |authority| {
            forwarder.policy.validate_request_authority(
                &forwarder.route,
                authority,
                forwarder.secret_route,
            )
        },
    );
    if let Err(rejection) = validation {
        if let Some(report) = rejection.fatal_report(
            forwarder
                .tls_flow
                .unwrap_or_else(|| tls_flow_for_route(&forwarder.route)),
        ) {
            let _ = forwarder.fatal_tx.send(report).await;
        }
        return Ok(forbidden());
    }
    let Ok(request) = absolute_request(request, &forwarder.route, forwarder.tls) else {
        return Ok(forbidden());
    };
    match forwarder.handler.on_request(request).await {
        RequestOrResponse::Response(response) => Ok(response),
        RequestOrResponse::Request(request) => match forwarder.upstream.request(request).await {
            Ok(response) => Ok(forwarder.handler.on_response(response.map(Body::from))),
            Err(error) => Ok(forwarder.handler.on_upstream_client_error(error).await),
        },
    }
}

fn absolute_request(
    request: Request<Body>,
    route: &AuthorizedRoute,
    tls: bool,
) -> io::Result<Request<Body>> {
    let (mut parts, body) = request.into_parts();
    let mut uri = parts.uri.into_parts();
    uri.scheme = Some(if tls { Scheme::HTTPS } else { Scheme::HTTP });
    uri.authority = Some(Authority::from_str(&route_authority(route)).map_err(invalid_data)?);
    parts.uri = Uri::from_parts(uri).map_err(invalid_data)?;
    Ok(Request::from_parts(parts, body))
}

fn request_authority(request: &Request<Body>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            request
                .headers()
                .get(hyper::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}

fn route_authority(route: &AuthorizedRoute) -> String {
    let host = match route.identity().host() {
        CanonicalHost::Domain(host) => host.clone(),
        CanonicalHost::Ip(IpAddr::V4(ip)) => ip.to_string(),
        CanonicalHost::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
    };
    match route.identity().port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

#[derive(Debug, Clone)]
struct PinnedResolver {
    expected: String,
    address: IpAddr,
}

impl Service<Name> for PinnedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        if name.as_str() != self.expected {
            return ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "upstream resolver received a request outside the admitted authority",
            )));
        }
        ready(Ok(vec![SocketAddr::new(self.address, 0)].into_iter()))
    }
}

async fn serve_udp(
    latch: super::DataplaneLatch,
    ingress: Arc<TransparentUdpIngress>,
    relay: Arc<UdpFlowRelay>,
    fatal_tx: mpsc::Sender<FatalReport>,
) -> io::Result<()> {
    match latch.run(ingress.serve(&relay)).await {
        Err(DataplaneClosed) => {
            std::future::pending::<()>().await;
            Ok(())
        }
        Ok(Ok(())) => Err(io::Error::other("UDP gateway stopped unexpectedly")),
        Ok(Err(error)) => {
            if let UdpIngressError::Relay(relay_error) = &error
                && let Some(report) = relay_error.fatal_report().map_err(io::Error::other)?
            {
                send_fatal(&fatal_tx, report).await?;
                return Ok(());
            }
            Err(io::Error::other(error))
        }
    }
}

fn secret_route(flow: &AdmittedTcpFlow, bound_hosts: &[CanonicalHost]) -> SecretRoute {
    if bound_hosts.is_empty() {
        return SecretRoute::Unbound;
    }
    if bound_hosts.contains(flow.route().identity().host()) {
        SecretRoute::Bound
    } else if matches!(
        flow.protocol(),
        TcpProtocol::TlsClientHello(hello) if hello.server_name().is_some() && !hello.encrypted_client_hello()
    ) || matches!(flow.protocol(), TcpProtocol::CleartextHttp(http) if http.authority().is_some())
    {
        SecretRoute::Unbound
    } else {
        SecretRoute::Ambiguous
    }
}

fn binding_hosts(bindings: &[SecretBinding]) -> io::Result<Vec<CanonicalHost>> {
    bindings
        .iter()
        .map(|binding| {
            crate::egress::canonicalize_host(&binding.host)
                .map(|destination| destination.host().clone())
                .map_err(io::Error::other)
        })
        .collect()
}

fn build_injector(
    bindings: Vec<SecretBinding>,
    broker_url: Option<String>,
) -> io::Result<Option<SecretInjector>> {
    if bindings.is_empty() {
        return Ok(None);
    }
    let url = broker_url.ok_or_else(|| io::Error::other("secret bindings require broker URL"))?;
    let token = std::env::var(BROKER_TOKEN_ENV)
        .map_err(|_| io::Error::other("secret bindings require broker token"))?;
    SecretInjector::new(bindings, &BrokerConfig { url, token })
        .map(Some)
        .map_err(io::Error::other)
}

fn fatal_for_admitted(
    reason: hiloop_core::capture::CaptureFatalReason,
    flow: &AdmittedTcpFlow,
) -> io::Result<FatalReport> {
    match flow.tls_flow_identity().map_err(io::Error::other)? {
        Some(identity) => Ok(FatalReport::tls(reason, identity)),
        None => Ok(FatalReport::destination(
            reason,
            flow.route().original_destination(),
        )),
    }
}

fn tls_flow_for_route(route: &AuthorizedRoute) -> TlsFlowIdentity {
    let flow = TlsFlowIdentity::new(route.original_destination());
    match route.identity().host() {
        CanonicalHost::Domain(host) => flow
            .with_server_name(host)
            .unwrap_or_else(|_| TlsFlowIdentity::new(route.original_destination())),
        CanonicalHost::Ip(_) => flow,
    }
}

async fn send_fatal(sender: &mpsc::Sender<FatalReport>, report: FatalReport) -> io::Result<()> {
    sender
        .send(report)
        .await
        .map_err(|_| io::Error::other("gateway fatal coordinator stopped"))
}

async fn require_latch_task(
    component: &str,
    result: Result<Result<(), io::Error>, DataplaneClosed>,
) -> io::Result<()> {
    match result {
        Err(DataplaneClosed) => {
            std::future::pending::<()>().await;
            Ok(())
        }
        Ok(Ok(())) => Err(io::Error::other(format!(
            "{component} stopped unexpectedly"
        ))),
        Ok(Err(error)) => Err(error),
    }
}

fn write_ca_bundle(path: &Path, ca_pem: &str) -> io::Result<()> {
    let bundle = crate::supervisor::union_ca_bundle(
        crate::supervisor::read_system_ca_roots().as_deref(),
        ca_pem,
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bundle)
}

fn forbidden() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("static forbidden response")
}

fn encode(value: &impl Serialize) -> io::Result<String> {
    serde_json::to_string(value).map_err(invalid_data)
}

fn decode_environment<T: serde::de::DeserializeOwned>(name: &str) -> io::Result<T> {
    let value = std::env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{name} is not set")))?;
    serde_json::from_str(&value).map_err(invalid_data)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netns::{
        ClassificationProgress, FragmentedUdpBehavior, SubstrateInfo, classify_tcp_prefix,
    };
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn production_dispatch_consumes_every_tls_transport_decision_variant() {
        fn assert_consumed(decision: &TlsTransportDecision) {
            match decision {
                TlsTransportDecision::Denied(_)
                | TlsTransportDecision::TerminateTls
                | TlsTransportDecision::CaptureHttp
                | TlsTransportDecision::PassthroughTls(_)
                | TlsTransportDecision::PassthroughTcp
                | TlsTransportDecision::Fatal(_) => {}
            }
        }

        let _ = SubstrateInfo::new(
            std::num::NonZeroU16::new(15_001).expect("port"),
            1_500,
            GATEWAY_IPV4,
            GATEWAY_IPV6,
            "169.254.2.2".parse().expect("host IPv4"),
            "fd00:6869:6c6f:6f71::2".parse().expect("host IPv6"),
            FragmentedUdpBehavior::Drop,
        )
        .expect("topology");
        assert_consumed(&TlsTransportDecision::TerminateTls);
        assert_consumed(&TlsTransportDecision::CaptureHttp);
    }

    #[test]
    fn secret_route_uses_visible_authority_and_treats_opaque_identity_as_ambiguous() {
        let visible = classified(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        assert!(matches!(visible, TcpProtocol::CleartextHttp(_)));
        let opaque = classified(b"SSH-2.0-fixture\r\n");
        assert_eq!(opaque, TcpProtocol::OtherTcp);
    }

    #[tokio::test]
    async fn cleartext_preface_selects_the_matching_hyper_server() {
        for (request, expected_h2) in [
            (HTTP2_PREFACE, true),
            (b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n".as_slice(), false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener");
            let mut sender =
                tokio::net::TcpStream::connect(listener.local_addr().expect("listener address"))
                    .await
                    .expect("connect");
            let (receiver, _) = listener.accept().await.expect("accept");
            sender.write_all(request).await.expect("write request");

            assert_eq!(
                cleartext_http2(&receiver).await.expect("inspect"),
                expected_h2
            );
        }
    }

    fn classified(bytes: &[u8]) -> TcpProtocol {
        let ClassificationProgress::Classified(protocol) =
            classify_tcp_prefix(bytes).expect("classification")
        else {
            panic!("fixture did not classify")
        };
        protocol
    }
}
