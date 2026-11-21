use chrono::{Local, Utc};
use clap::{Args, ValueEnum};
use dscan_engine::windows::window_stop;
use dscan_engine::{
    EngineError, RateSettings, ScanObserver, ScanProgress, ScanRequest, SubgroupReport, create_job,
    drive_job, effective_settings, prepare_scan, rate_per_process,
};
use tokio::sync::watch;

use super::scan_report::{format_hosts, format_progress_line, format_summary};
use super::targets::format_plan;
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
    pub fn name(self) -> &'static str {
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
    /// Nazwany profil z [profiles] w dscan.toml (porty, tempo, okna, ponowienia…).
    #[arg(long, value_name = "NAZWA")]
    pub profile: Option<String>,
    /// Rodzaj skanu (domyślnie z profilu albo `services`).
    #[arg(long, value_enum)]
    pub mode: Option<ScanMode>,
    /// Nie wypisuj listy hostów na końcu (tylko podsumowanie).
    #[arg(long)]
    pub quiet: bool,
    /// Skan bezpośrednio z tej binarki (bez serwera i RBAC) — wymaga klucza szyfrowania i dostępu do bazy.
    #[arg(long)]
    pub local: bool,
    #[command(flatten)]
    pub overrides: OverrideArgs,
}

impl ScanArgs {
    pub fn request(&self) -> ScanRequest {
        ScanRequest {
            targets: self.targets.clone(),
            profile: self.profile.clone(),
            mode: self.mode.map(|mode| mode.name().to_string()),
            ..ScanRequest::default()
        }
    }
}

impl Command for ScanArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        if !self.local {
            return crate::client::commands::scan_via_api(self).await;
        }
        run_local(self, context).await
    }
}

/// Skan lokalny: ten sam silnik co serwer, postęp w terminalu. Okna czasowe profilu są
/// respektowane — poza oknem skan nie startuje, a o końcu okna jest wstrzymywany (S9).
async fn run_local(args: &ScanArgs, context: &Context) -> Result<(), CliError> {
    let config = context.load_config(args.overrides.to_overrides())?;
    let cipher = cipher_from_config(&config)?;
    let request = args.request();
    let (settings, ..) = effective_settings(
        &config.settings,
        request.profile.as_deref(),
        request.mode.as_deref(),
    )?;
    let windows: Vec<(String, String)> = settings
        .schedule
        .windows
        .iter()
        .map(|w| (w.start.clone(), w.end.clone()))
        .collect();
    let stop_at = window_stop(&windows, Local::now()).map_err(|_| EngineError::OutsideWindow)?;

    let prepared = match prepare_scan(&config.settings, &request).await {
        Err(EngineError::NoTargetsInScope(plan)) => {
            eprint!("{}", format_plan(&plan));
            return Err(CliError::NoTargetsInScope);
        }
        other => other?,
    };
    eprint!("{}", format_plan(&prepared.plan));
    let pool = connect_database(&config).await?;
    let plan = create_job(&pool, &prepared.plan.networks, &prepared.job).await?;

    let (stop_sender, stop) = watch::channel(false);
    if let Some(at) = stop_at {
        eprintln!(
            "Okno czasowe kończy się o {} — wtedy skan zostanie wstrzymany.",
            at.with_timezone(&Local).format("%H:%M")
        );
        tokio::spawn(async move {
            tokio::time::sleep((at - Utc::now()).to_std().unwrap_or_default()).await;
            let _ = stop_sender.send(true);
        });
    }
    let rate = RateSettings {
        max_rate: settings.limits.nmap_max_rate,
        bandwidth_kbps: settings.scope.max_bandwidth_kbps,
        parallel: settings.limits.max_parallel_nmap,
    };
    let observer = TerminalObserver { rate };
    let summary = drive_job(
        &pool,
        &cipher,
        plan,
        prepared.scanner,
        &prepared.job,
        &observer,
        stop,
    )
    .await?;

    eprint!("{}", format_summary(&summary));
    if !args.quiet {
        print!("{}", format_hosts(&summary.hosts));
    }
    Ok(())
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
