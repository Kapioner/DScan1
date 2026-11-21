use std::sync::Arc;

use chrono::Utc;
use clap::{Args, ValueEnum};
use dscan_config::AppConfig;
use dscan_engine::{
    RateSettings, ScanJobSettings, ScanJobSummary, ScanObserver, ScanProgress, SubgroupReport,
    WebFingerprintScanner, nmap_scanner, rate_per_process, run_scan_job,
};
use dscan_fingerprint::signatures::SignatureSet;
use dscan_fingerprint::{HttpFetcher, HttpOptions, HttpRateLimiter, WebAnalysis};
use dscan_scanner::nmap::{NmapProfile, ports_argument};
use dscan_scanner::pool::SubgroupScanner;
use ipnet::IpNet;

use super::scan_report::{format_hosts, format_progress_line, format_summary};
use super::targets::{build_plan, format_plan};
use super::{Command, Context, OverrideArgs, cipher_from_config, connect_database};
use crate::error::CliError;

/// Rodzaj skanu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanMode {
    /// Tylko wykrywanie aktywnych hostów (nmap -sn).
    Discovery,
    /// Porty z [scope] allowed_ports i rozpoznawanie usług (nmap -sV).
    Services,
}

impl ScanMode {
    fn profile(self) -> NmapProfile {
        match self {
            ScanMode::Discovery => NmapProfile::Discovery,
            ScanMode::Services => NmapProfile::Services,
        }
    }

    fn name(self) -> &'static str {
        match self {
            ScanMode::Discovery => "discovery",
            ScanMode::Services => "services",
        }
    }
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Cele: adresy IP, sieci CIDR lub domeny. Skanowane są tylko cele z [scope] allowed_networks.
    #[arg(required = true, value_name = "CEL")]
    pub targets: Vec<String>,
    /// Rodzaj skanu.
    #[arg(long, value_enum, default_value_t = ScanMode::Services)]
    pub mode: ScanMode,
    /// Nie wypisuj listy hostów na końcu (tylko podsumowanie).
    #[arg(long)]
    pub quiet: bool,
    #[command(flatten)]
    pub overrides: OverrideArgs,
}

impl Command for ScanArgs {
    /// Skan uruchamiany z tej binarki: podgrupy skanowane równolegle przez nmap, wyniki
    /// zapisywane w bazie na bieżąco. Po wdrożeniu RBAC (C5) skan będzie zlecany przez API.
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let config = context.load_config(self.overrides.to_overrides())?;
        let cipher = cipher_from_config(&config)?;
        let plan = build_plan(&config, &self.targets).await?;
        eprint!("{}", format_plan(&plan));
        if plan.networks.is_empty() {
            return Err(CliError::NoTargetsInScope);
        }

        let limits = &config.settings.limits;
        let rate = RateSettings {
            max_rate: limits.nmap_max_rate,
            bandwidth_kbps: config.settings.scope.max_bandwidth_kbps,
            parallel: limits.max_parallel_nmap,
        };
        let ports = ports_argument(&config.settings.scope.allowed_ports);
        let nmap = nmap_scanner(self.mode.profile(), ports, rate);
        let settings = ScanJobSettings {
            profile: self.mode.name().to_string(),
            subgroup_size: limits.subgroup_size,
            parallel: limits.max_parallel_nmap,
            max_addresses: limits.max_addresses_per_scan,
        };

        let pool = connect_database(&config).await?;
        let job = Job {
            pool: &pool,
            cipher: &cipher,
            networks: &plan.networks,
            settings: &settings,
            rate,
        };
        // Fingerprinting HTTP ma sens tylko po skanie usług (discovery nie zna portów).
        let summary = if self.mode == ScanMode::Services && config.settings.http.enabled {
            let fetcher = Arc::new(build_fetcher(&config)?);
            let analysis = Arc::new(build_analysis(&config)?);
            job.run(WebFingerprintScanner::new(nmap, fetcher, analysis))
                .await?
        } else {
            job.run(nmap).await?
        };

        eprint!("{}", format_summary(&summary));
        if !self.quiet {
            print!("{}", format_hosts(&summary.hosts));
        }
        Ok(())
    }
}

/// Parametry jednego przebiegu (żeby nie powtarzać ich dla obu rodzajów skanera).
struct Job<'a> {
    pool: &'a dscan_db::PgPool,
    cipher: &'a dscan_crypto::Cipher,
    networks: &'a [IpNet],
    settings: &'a ScanJobSettings,
    rate: RateSettings,
}

impl Job<'_> {
    async fn run<S: SubgroupScanner>(&self, scanner: S) -> Result<ScanJobSummary, CliError> {
        let observer = TerminalObserver { rate: self.rate };
        let scanner = Arc::new(scanner);
        Ok(run_scan_job(
            self.pool,
            self.cipher,
            self.networks,
            scanner,
            self.settings,
            &observer,
        )
        .await?)
    }
}

/// Sygnatury (wbudowane) i ścieżki do sondowania z `[http]`.
fn build_analysis(config: &AppConfig) -> Result<WebAnalysis, CliError> {
    let signatures = SignatureSet::builtin().map_err(|error| CliError::Http(error.to_string()))?;
    let http = &config.settings.http;
    Ok(WebAnalysis::new(
        signatures,
        &http.probe_paths,
        http.max_probes_per_service as usize,
    ))
}

/// Klient HTTP z limitami z konfiguracji (`[http]` i `[limits]`).
pub fn build_fetcher(config: &AppConfig) -> Result<HttpFetcher, CliError> {
    let http = &config.settings.http;
    let limits = &config.settings.limits;
    let options = HttpOptions {
        timeout: std::time::Duration::from_secs(http.timeout_seconds),
        max_redirects: http.max_redirects,
        max_body_bytes: http.max_body_bytes,
        user_agent: http.user_agent.clone(),
    };
    let limiter = Arc::new(HttpRateLimiter::new(
        limits.http_requests_per_second,
        limits.http_requests_per_host,
    ));
    HttpFetcher::new(options, Some(limiter)).map_err(|error| CliError::Http(error.to_string()))
}

/// Wypisuje postęp skanu na stderr (wyniki idą na stdout, więc można je przekierować do pliku).
struct TerminalObserver {
    rate: RateSettings,
}

impl ScanObserver for TerminalObserver {
    fn scan_started(&self, progress: &ScanProgress) {
        eprintln!(
            "Przebieg #{}: {} adresów w {} podgrupach; do {} procesów nmap naraz po {} pakietów/s",
            progress.run_id,
            progress.total_addresses,
            progress.total_subgroups,
            self.rate.parallel,
            rate_per_process(self.rate)
        );
    }

    fn subgroup_finished(&self, report: &SubgroupReport, progress: &ScanProgress) {
        eprintln!(
            "{}",
            format_progress_line(report, progress, progress.elapsed(Utc::now()))
        );
    }
}
