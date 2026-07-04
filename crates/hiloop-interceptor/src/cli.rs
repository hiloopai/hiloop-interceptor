//! Command-line interface for `hiloop-interceptor`.

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use hiloop_core::identity::{LineagePath, RunContext, RunId};
use hiloop_interceptor::anomaly::{
    AnomalyConfig, DEFAULT_BASE64_RATIO, DEFAULT_MAX_UPLOAD_BYTES, DEFAULT_MIN_BASE64_BYTES,
};
use hiloop_interceptor::egress::{EgressMode, EgressPolicy};
use hiloop_interceptor::pipeline::{DEFAULT_EXPORT_BATCH_SIZE, DEFAULT_EXPORT_FLUSH_INTERVAL_MS};
use hiloop_interceptor::proxy::DEFAULT_MAX_CAPTURE_BYTES;
use hiloop_interceptor::secret::{BrokerConfig, SecretBinding};
use hiloop_interceptor::{GrpcExportOptions, RedactionPolicy, RunOptions, run};
use std::{path::PathBuf, process::ExitCode, time::Duration};

pub(crate) async fn run_from_args() -> Result<ExitCode> {
    Box::pin(Cli::parse().execute()).await
}

#[derive(Debug, Parser)]
#[command(name = "hiloop-interceptor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    async fn execute(self) -> Result<ExitCode> {
        match self.command {
            Command::Run(args) => {
                let options = args.into_run_options()?;
                Box::pin(run(&options)).await
            }
            Command::Inspect(args) => {
                let diff = args
                    .diff
                    .as_ref()
                    .map(|paths| (paths[0].as_str(), paths[1].as_str()));
                crate::inspect_cli::run(&args.events_jsonl, diff)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "clap flattens each variant's Args struct into the subcommand; the size spread between run and inspect is inherent and not worth boxing through clap's derive"
)]
enum Command {
    /// Run a command under the interceptor supervisor.
    Run(RunArgs),
    /// Summarize a captured events JSONL file, grouped by run lineage path.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// Newline-delimited JSON events file produced by `run --events-jsonl`.
    events_jsonl: PathBuf,

    /// Compare two run lineage paths' event-name distributions.
    #[arg(long, num_args = 2, value_names = ["PATH_A", "PATH_B"])]
    diff: Option<Vec<String>>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Run id to stamp on telemetry. Generated locally when omitted.
    #[arg(long, env = "HILOOP_RUN_ID")]
    run_id: Option<RunId>,

    /// Run lineage path (dotted run ULIDs from the root run to this run) to stamp on
    /// telemetry. Defaults to a fresh root run whose path is the run id itself.
    #[arg(long = "lineage-path", env = "HILOOP_LINEAGE_PATH")]
    lineage_path: Option<LineagePath>,

    /// Create a newline-delimited JSON event file. Fails if the path exists.
    #[arg(long = "events-jsonl", env = "HILOOP_EVENTS_JSONL")]
    events_jsonl: Option<PathBuf>,

    /// Create a newline-delimited raw observation file. Requires `--events-jsonl`.
    #[arg(long = "raw-jsonl", env = "HILOOP_RAW_JSONL")]
    raw_jsonl: Option<PathBuf>,

    /// Directory for the content-addressed blob store the proxy streams bodies to.
    /// Created if absent. Required by `--proxy` unless `--export-grpc` is set, in
    /// which case captured bodies default to a per-run scratch store that is uploaded
    /// to the gateway and removed at run end.
    #[arg(long = "blob-dir", env = "HILOOP_BLOB_DIR")]
    blob_dir: Option<PathBuf>,

    /// Run an embedded OTLP receiver and capture the child's OpenTelemetry
    /// export. Requires `--events-jsonl`.
    #[arg(long = "otlp")]
    otlp: bool,

    /// Run an embedded MITM proxy and capture the child's HTTP(S) traffic.
    /// Requires an export target (`--events-jsonl` or `--export-grpc`) plus
    /// somewhere for captured bodies: `--blob-dir`, or `--export-grpc` (bodies are
    /// then uploaded to the gateway).
    #[arg(long = "proxy")]
    proxy: bool,

    /// Cap how many body bytes the proxy captures (blob + reported size) per
    /// request/response. Defaults to 8 MiB when omitted (the captured copy is buffered
    /// in memory, so a finite cap bounds interceptor memory). Set to `0` for unlimited.
    /// Never affects what the client or upstream receives.
    #[arg(long = "max-capture-bytes", env = "HILOOP_MAX_CAPTURE_BYTES")]
    max_capture_bytes: Option<u64>,

    /// Persist captured request/response bodies verbatim, without scrubbing
    /// credentials. Redaction is on by default and only affects the captured copy,
    /// never the traffic forwarded to the origin.
    #[arg(long = "no-redact", env = "HILOOP_NO_REDACT")]
    no_redact: bool,

    /// Egress policy mode for intercepted traffic: `allow` (deny only matched
    /// destinations) or `deny` (allow only matched destinations, deny by default).
    /// Defaults to `allow`. Requires `--proxy` when any rule is set.
    #[arg(long = "egress-mode", value_enum, default_value_t = EgressModeArg::Allow)]
    egress_mode: EgressModeArg,

    /// Egress domain rule (repeatable). Matched at a label boundary: `example.com`
    /// covers `example.com` and `api.example.com`, never `evil-example.com`.
    #[arg(long = "egress-domain")]
    egress_domain: Vec<String>,

    /// Egress CIDR rule (repeatable), e.g. `10.0.0.0/8` or a bare address as a host
    /// route. Matches IPv4 and IPv6 destinations, including IP-literal request hosts.
    #[arg(long = "egress-cidr")]
    egress_cidr: Vec<String>,

    /// Inspect captured request bodies for exfiltration-shaped anomalies (large
    /// base64 blobs, suspicious content-types, upload-shaped writes) and flag matches
    /// on the telemetry exchange. Cooperative detection over intercepted traffic only;
    /// requires `--proxy`. Off by default.
    #[arg(long = "detect-anomalies")]
    detect_anomalies: bool,

    /// Reject a request when an anomaly rule matches, instead of only flagging it.
    /// Requires `--detect-anomalies`. Audit-only (flag, don't block) by default.
    #[arg(long = "block-anomalies")]
    block_anomalies: bool,

    /// Body size (bytes) at or above which a base64-dominated body is flagged.
    #[arg(long = "anomaly-min-base64-bytes", default_value_t = DEFAULT_MIN_BASE64_BYTES)]
    anomaly_min_base64_bytes: u64,

    /// Fraction (0.0–1.0) of a body's bytes that must be base64-alphabet characters for
    /// it to count as a base64 blob.
    #[arg(
        long = "anomaly-base64-ratio",
        default_value_t = DEFAULT_BASE64_RATIO,
        value_parser = parse_base64_ratio,
    )]
    anomaly_base64_ratio: f64,

    /// Write-request body size (bytes) at or above which a request is flagged as
    /// upload-shaped.
    #[arg(long = "anomaly-max-upload-bytes", default_value_t = DEFAULT_MAX_UPLOAD_BYTES)]
    anomaly_max_upload_bytes: u64,

    /// Content-Type value treated as suspicious (repeatable). Overrides the built-in
    /// list when any are given.
    #[arg(long = "anomaly-suspicious-content-type")]
    anomaly_suspicious_content_type: Vec<String>,

    /// Bind a named secret to a destination host and header (repeatable), as
    /// `name=<name>,placeholder=<token>,host=<host>,header=<header>[,scheme=<scheme>]`.
    /// On a request to the bound host the proxy resolves the secret from the broker and
    /// writes `<scheme> <value>` into the header. Requires `--secret-broker-url`.
    #[arg(long = "secret-binding", value_parser = parse_secret_binding)]
    secret_binding: Vec<SecretBinding>,

    /// Credential broker endpoint the proxy resolves secret bindings from. The broker
    /// token is read from `HILOOP_SECRET_BROKER_TOKEN` (never a flag, to keep it out of
    /// argv). Required when `--secret-binding` is set.
    #[arg(long = "secret-broker-url", env = "HILOOP_SECRET_BROKER_URL")]
    secret_broker_url: Option<String>,

    /// Bearer token authenticating the proxy to the credential broker. Read only from
    /// the environment to keep it out of argv.
    #[arg(
        long = "secret-broker-token",
        env = "HILOOP_SECRET_BROKER_TOKEN",
        hide = true
    )]
    secret_broker_token: Option<String>,

    /// Stream captured events to a telemetry gateway over gRPC, e.g.
    /// `https://telemetry.example.com:443`. Composes with `--events-jsonl`. With `--proxy`,
    /// captured payload blobs are uploaded to the same gateway at run end (only content the
    /// gateway is missing is sent). The API token is read from the `HILOOP_API_KEY` environment
    /// variable (never a flag, to keep it out of argv).
    #[arg(long = "export-grpc", env = "HILOOP_TELEMETRY_ENDPOINT")]
    export_grpc: Option<String>,

    /// Use cleartext h2c instead of TLS for `--export-grpc` (local dev gateways only).
    #[arg(long = "insecure-grpc")]
    insecure_grpc: bool,

    /// Project to record events under when exporting over gRPC.
    #[arg(
        long = "project-id",
        env = "HILOOP_PROJECT_ID",
        default_value = "default"
    )]
    project_id: String,

    /// Tenant to record under when exporting over gRPC. Omit against an authenticated gateway
    /// (it derives the tenant from the API token); set only for a no-auth local gateway.
    #[arg(long = "tenant-id", env = "HILOOP_TENANT_ID")]
    tenant_id: Option<String>,

    /// Ship a partial batch once this many captured events accumulate (the size trigger).
    #[arg(
        long = "export-batch-size",
        env = "HILOOP_EXPORT_BATCH_SIZE",
        default_value_t = DEFAULT_EXPORT_BATCH_SIZE,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..),
    )]
    export_batch_size: usize,

    /// Ship a partial batch after it has waited this many milliseconds, even before it reaches
    /// `--export-batch-size` (the age trigger). This bounds how long an event waits before it
    /// reaches the exporter, so a live tail sees a long-running command's events progressively
    /// rather than all at once when it exits. Set to 0 to disable and flush only on size or exit.
    #[arg(
        long = "export-flush-interval-ms",
        env = "HILOOP_EXPORT_FLUSH_INTERVAL_MS",
        default_value_t = DEFAULT_EXPORT_FLUSH_INTERVAL_MS,
    )]
    export_flush_interval_ms: u64,

    /// Environment variable names to record on the run's `process.start` event
    /// (comma-separated, e.g. `PATH,HOME,PYTHONPATH`). Names only — values are
    /// never captured.
    #[arg(
        long = "env-allowlist",
        env = "HILOOP_ENV_ALLOWLIST",
        value_delimiter = ','
    )]
    env_allowlist: Vec<String>,

    /// Print wrapper diagnostics to stderr.
    #[arg(long = "verbose")]
    verbose: bool,

    /// Command to wrap. Everything after `--` is passed to the child.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

impl RunArgs {
    fn into_run_options(self) -> Result<RunOptions> {
        let context = resolve_run_context(self.run_id, self.lineage_path)?;

        let export_grpc = self.export_grpc.map(|endpoint| GrpcExportOptions {
            endpoint,
            insecure: self.insecure_grpc,
            tenant_id: self.tenant_id.filter(|t| !t.is_empty()),
            project_id: self.project_id,
        });

        let export_flush_interval = (self.export_flush_interval_ms > 0)
            .then(|| Duration::from_millis(self.export_flush_interval_ms));

        let redaction = if self.no_redact {
            RedactionPolicy::disabled()
        } else {
            RedactionPolicy::enabled()
        };

        let max_capture_bytes = resolve_max_capture_bytes(self.max_capture_bytes);

        let egress = EgressPolicy::new(
            self.egress_mode.into(),
            self.egress_domain,
            self.egress_cidr,
        )?;

        let anomaly = build_anomaly_config(
            self.detect_anomalies,
            self.block_anomalies,
            self.anomaly_min_base64_bytes,
            self.anomaly_base64_ratio,
            self.anomaly_max_upload_bytes,
            self.anomaly_suspicious_content_type,
        )?;

        let mut options = RunOptions::new(
            context,
            self.command,
            self.events_jsonl,
            self.raw_jsonl,
            self.blob_dir,
            self.otlp,
            self.proxy,
            max_capture_bytes,
            export_grpc,
        )
        .with_export_batch_size(self.export_batch_size)
        .with_export_flush_interval(export_flush_interval)
        .with_redaction(redaction)
        .with_egress(egress)
        .with_anomaly_detection(anomaly)
        .with_verbose_diagnostics(self.verbose)
        .with_env_allowlist(self.env_allowlist);

        if !self.secret_binding.is_empty() {
            let url = self
                .secret_broker_url
                .ok_or_else(|| anyhow::anyhow!("--secret-binding requires --secret-broker-url"))?;
            let token = self.secret_broker_token.ok_or_else(|| {
                anyhow::anyhow!(
                    "--secret-binding requires a broker token in HILOOP_SECRET_BROKER_TOKEN"
                )
            })?;
            options =
                options.with_secret_bindings(self.secret_binding, BrokerConfig { url, token });
        }

        Ok(options)
    }
}

/// CLI mirror of [`EgressMode`] so the lib crate stays clap-free.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum EgressModeArg {
    Allow,
    Deny,
}

impl From<EgressModeArg> for EgressMode {
    fn from(arg: EgressModeArg) -> Self {
        match arg {
            EgressModeArg::Allow => EgressMode::Allow,
            EgressModeArg::Deny => EgressMode::Deny,
        }
    }
}

/// Parse a `--secret-binding` value of the form
/// `name=<name>,placeholder=<token>,host=<host>,header=<header>[,scheme=<scheme>]`.
///
/// Fields are comma-separated, so **field values may not contain a comma** — a comma in
/// a value would be parsed as a field separator and silently truncate. Each field must
/// be a single `key=value` pair, each key may appear at most once, and an empty value is
/// rejected; any of these produces a clear error rather than a quietly mangled binding.
fn parse_secret_binding(raw: &str) -> Result<SecretBinding, String> {
    let mut name = None;
    let mut placeholder = None;
    let mut host = None;
    let mut header = None;
    let mut scheme = None;
    for field in raw.split(',') {
        let (key, value) = field.split_once('=').ok_or_else(|| {
            format!("expected `key=value`, got `{field}` (values may not contain a comma)")
        })?;
        let key = key.trim();
        if value.is_empty() {
            return Err(format!("secret-binding field `{key}` has an empty value"));
        }
        let slot = match key {
            "name" => &mut name,
            "placeholder" => &mut placeholder,
            "host" => &mut host,
            "header" => &mut header,
            "scheme" => &mut scheme,
            other => return Err(format!("unknown secret-binding field `{other}`")),
        };
        if slot.is_some() {
            return Err(format!("duplicate secret-binding field `{key}`"));
        }
        *slot = Some(value.to_owned());
    }
    Ok(SecretBinding {
        name: name.ok_or("secret-binding is missing `name`")?,
        env_placeholder: placeholder.ok_or("secret-binding is missing `placeholder`")?,
        host: host.ok_or("secret-binding is missing `host`")?,
        header: header.ok_or("secret-binding is missing `header`")?,
        scheme: scheme.unwrap_or_default(),
    })
}

/// Parse and validate `--anomaly-base64-ratio`: a finite fraction within `0.0..=1.0`.
///
/// Rejecting non-finite (`NaN`, `inf`) and out-of-range values here — rather than
/// silently clamping — keeps the threshold meaningful. `NaN` in particular survives a
/// clamp and drives the base64 threshold to zero, which would flag (and, under
/// `--block-anomalies`, block) every body at or above the size floor.
fn parse_base64_ratio(raw: &str) -> Result<f64, String> {
    let ratio: f64 = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a number"))?;
    if !ratio.is_finite() {
        return Err(format!("must be a finite number, got `{raw}`"));
    }
    if !(0.0..=1.0).contains(&ratio) {
        return Err(format!("must be within 0.0..=1.0, got `{raw}`"));
    }
    Ok(ratio)
}

/// Build the anomaly-detection policy from the CLI flags.
///
/// Returns the disabled default when `--detect-anomalies` is absent (so a run that
/// doesn't opt in pays nothing). `--block-anomalies` without `--detect-anomalies` is a
/// configuration error rather than a silent no-op.
fn build_anomaly_config(
    detect: bool,
    block: bool,
    min_base64_bytes: u64,
    base64_ratio: f64,
    max_upload_bytes: u64,
    suspicious_content_types: Vec<String>,
) -> Result<AnomalyConfig> {
    if !detect {
        if block {
            bail!("--block-anomalies requires --detect-anomalies");
        }
        return Ok(AnomalyConfig::default());
    }
    let mut config = AnomalyConfig::enabled()
        .with_block_on_match(block)
        .with_min_base64_bytes(min_base64_bytes)
        .with_base64_ratio(base64_ratio)
        .with_max_upload_bytes(max_upload_bytes);
    if !suspicious_content_types.is_empty() {
        config = config.with_suspicious_content_types(suspicious_content_types);
    }
    Ok(config)
}

/// Resolve the run context from the optional `--run-id` and `--lineage-path` flags.
///
/// - Neither set: a fresh local root run.
/// - `--run-id` only: a root run with that id (its lineage path is the id itself).
/// - `--lineage-path` only: the run is the path's leaf.
/// - Both set: they must agree — the path's leaf must equal `--run-id`.
fn resolve_run_context(
    run_id: Option<RunId>,
    lineage_path: Option<LineagePath>,
) -> Result<RunContext> {
    match (run_id, lineage_path) {
        (None, None) => Ok(RunContext::new_local_root()),
        (Some(run_id), None) => Ok(RunContext::new(run_id, LineagePath::root(run_id))?),
        (None, Some(lineage_path)) => {
            let run_id = lineage_path.run_id();
            Ok(RunContext::new(run_id, lineage_path)?)
        }
        (Some(run_id), Some(lineage_path)) => {
            if lineage_path.run_id() != run_id {
                bail!("--run-id {run_id} does not match the leaf of --lineage-path {lineage_path}");
            }
            Ok(RunContext::new(run_id, lineage_path)?)
        }
    }
}

/// Map the `--max-capture-bytes` CLI surface onto the internal representation, where
/// `None` means unlimited: omitted → the finite default (bounds interceptor memory),
/// `0` → unlimited, `N` → exactly `N`.
fn resolve_max_capture_bytes(flag: Option<u64>) -> Option<u64> {
    match flag {
        None => Some(DEFAULT_MAX_CAPTURE_BYTES),
        Some(0) => None,
        Some(n) => Some(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_cap_uses_finite_default() {
        assert_eq!(
            resolve_max_capture_bytes(None),
            Some(DEFAULT_MAX_CAPTURE_BYTES)
        );
    }

    #[test]
    fn zero_cap_means_unlimited() {
        assert_eq!(resolve_max_capture_bytes(Some(0)), None);
    }

    #[test]
    fn explicit_cap_is_passed_through() {
        assert_eq!(resolve_max_capture_bytes(Some(4096)), Some(4096));
    }

    #[test]
    fn parsed_run_args_apply_the_default_cap_when_omitted() {
        let cli = Cli::try_parse_from(["hiloop-interceptor", "run", "--", "echo", "hi"])
            .expect("parse run args");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        assert_eq!(
            resolve_max_capture_bytes(args.max_capture_bytes),
            Some(DEFAULT_MAX_CAPTURE_BYTES)
        );
    }

    #[test]
    fn secret_binding_parses_all_fields() {
        let binding = parse_secret_binding(
            "name=openai,placeholder=hil-secret://openai,host=api.openai.com,header=authorization,scheme=Bearer",
        )
        .expect("parse");
        assert_eq!(binding.name, "openai");
        assert_eq!(binding.env_placeholder, "hil-secret://openai");
        assert_eq!(binding.host, "api.openai.com");
        assert_eq!(binding.header, "authorization");
        assert_eq!(binding.scheme, "Bearer");
    }

    #[test]
    fn secret_binding_scheme_is_optional() {
        let binding = parse_secret_binding("name=k,placeholder=p,host=h.com,header=x-api-key")
            .expect("parse");
        assert_eq!(binding.scheme, "");
    }

    #[test]
    fn secret_binding_rejects_missing_field_and_bad_syntax() {
        assert!(parse_secret_binding("name=k,host=h.com,header=a").is_err());
        assert!(parse_secret_binding("not-a-pair").is_err());
        assert!(parse_secret_binding("name=k,bogus=x,placeholder=p,host=h,header=a").is_err());
    }

    #[test]
    fn secret_binding_rejects_comma_in_value() {
        // A value containing a comma would be split as a separate field; that field has
        // no `=`, so it is rejected with a clear error rather than silently truncating.
        let err = parse_secret_binding(
            "name=k,placeholder=hil-secret://x,host=h.com,header=a,scheme=foo,bar",
        )
        .expect_err("comma in value must error");
        assert!(err.contains("values may not contain a comma"), "got: {err}");
    }

    #[test]
    fn secret_binding_rejects_duplicate_field() {
        let err = parse_secret_binding("name=k,name=evil,placeholder=p,host=h.com,header=a")
            .expect_err("duplicate key must error");
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn secret_binding_rejects_empty_value() {
        let err = parse_secret_binding("name=,placeholder=p,host=h.com,header=a")
            .expect_err("empty value must error");
        assert!(err.contains("empty value"), "got: {err}");
    }

    #[test]
    fn egress_flags_build_a_deny_policy() {
        let cli = Cli::try_parse_from([
            "hiloop-interceptor",
            "run",
            "--proxy",
            "--events-jsonl",
            "/tmp/does-not-matter.jsonl",
            "--blob-dir",
            "/tmp/blob",
            "--egress-mode",
            "deny",
            "--egress-domain",
            "api.openai.com",
            "--egress-cidr",
            "10.0.0.0/8",
            "--",
            "echo",
            "hi",
        ])
        .expect("parse");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        let options = args.into_run_options().expect("options");
        assert!(!options.egress_policy().is_allow_all());
        assert_eq!(options.egress_policy().mode(), EgressMode::Deny);
    }

    #[test]
    fn anomaly_disabled_by_default() {
        let config = build_anomaly_config(
            false,
            false,
            DEFAULT_MIN_BASE64_BYTES,
            DEFAULT_BASE64_RATIO,
            DEFAULT_MAX_UPLOAD_BYTES,
            Vec::new(),
        )
        .expect("config");
        assert!(!config.is_enabled());
    }

    #[test]
    fn detect_flag_enables_audit_mode() {
        let config = build_anomaly_config(
            true,
            false,
            DEFAULT_MIN_BASE64_BYTES,
            DEFAULT_BASE64_RATIO,
            DEFAULT_MAX_UPLOAD_BYTES,
            Vec::new(),
        )
        .expect("config");
        assert!(config.is_enabled());
        assert!(!config.blocks_on_match(), "audit-only by default");
    }

    #[test]
    fn block_flag_requires_detect_flag() {
        let err = build_anomaly_config(
            false,
            true,
            DEFAULT_MIN_BASE64_BYTES,
            DEFAULT_BASE64_RATIO,
            DEFAULT_MAX_UPLOAD_BYTES,
            Vec::new(),
        )
        .expect_err("block without detect must error");
        assert!(err.to_string().contains("requires --detect-anomalies"));
    }

    #[test]
    fn detect_and_block_flags_enable_block_mode() {
        let config = build_anomaly_config(
            true,
            true,
            DEFAULT_MIN_BASE64_BYTES,
            DEFAULT_BASE64_RATIO,
            DEFAULT_MAX_UPLOAD_BYTES,
            Vec::new(),
        )
        .expect("config");
        assert!(config.blocks_on_match());
    }

    #[test]
    fn anomaly_flags_parse_through_run_args() {
        let cli = Cli::try_parse_from([
            "hiloop-interceptor",
            "run",
            "--proxy",
            "--events-jsonl",
            "/tmp/does-not-matter.jsonl",
            "--blob-dir",
            "/tmp/blob",
            "--detect-anomalies",
            "--block-anomalies",
            "--",
            "echo",
            "hi",
        ])
        .expect("parse");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        let options = args.into_run_options().expect("options");
        assert!(options.anomaly_config().is_enabled());
        assert!(options.anomaly_config().blocks_on_match());
    }

    #[test]
    fn base64_ratio_accepts_valid_fractions() {
        assert_eq!(parse_base64_ratio("0.0"), Ok(0.0));
        assert_eq!(parse_base64_ratio("0.95"), Ok(0.95));
        assert_eq!(parse_base64_ratio("1.0"), Ok(1.0));
        // The default must round-trip through the parser (clap re-parses `default_value_t`).
        assert_eq!(
            parse_base64_ratio(&DEFAULT_BASE64_RATIO.to_string()),
            Ok(DEFAULT_BASE64_RATIO)
        );
    }

    #[test]
    fn base64_ratio_rejects_non_finite_and_out_of_range() {
        assert!(parse_base64_ratio("NaN").is_err());
        assert!(parse_base64_ratio("nan").is_err());
        assert!(parse_base64_ratio("inf").is_err());
        assert!(parse_base64_ratio("-1.0").is_err());
        assert!(parse_base64_ratio("1.5").is_err());
        assert!(parse_base64_ratio("not-a-number").is_err());
    }

    #[test]
    fn base64_ratio_flag_rejects_nan_through_run_args() {
        let result = Cli::try_parse_from([
            "hiloop-interceptor",
            "run",
            "--proxy",
            "--events-jsonl",
            "/tmp/does-not-matter.jsonl",
            "--blob-dir",
            "/tmp/blob",
            "--detect-anomalies",
            "--anomaly-base64-ratio",
            "NaN",
            "--",
            "echo",
            "hi",
        ]);
        assert!(result.is_err(), "NaN ratio must be rejected at parse time");
    }

    #[test]
    fn parsed_zero_flag_maps_to_unlimited() {
        let cli = Cli::try_parse_from([
            "hiloop-interceptor",
            "run",
            "--max-capture-bytes",
            "0",
            "--",
            "echo",
            "hi",
        ])
        .expect("parse run args");
        let Command::Run(args) = cli.command else {
            panic!("expected run subcommand");
        };
        assert_eq!(resolve_max_capture_bytes(args.max_capture_bytes), None);
    }
}
