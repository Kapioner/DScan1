use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use dscan_core::models::{Host, ScanStatus};
use dscan_crypto::Cipher;
use dscan_db::{NewRun, PgPool};
use dscan_scanner::pool::{SubgroupScanner, never_stop, run_pool};
use dscan_scanner::subgroups::split_into_subgroups;
use dscan_scanner::targets::count_addresses;
use ipnet::IpNet;
use tokio::sync::watch;

use crate::comparison::Comparison;
use crate::retry::remeasure_silent_hosts;
use crate::running::RunningJob;
use crate::{EngineError, ScanObserver, ScanProgress};

/// Ustawienia przebiegu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanJobSettings {
    /// Nazwa profilu zapisywana w przebiegu (np. `pelny` albo `services`).
    pub profile: String,
    /// `discovery` albo `services`.
    pub mode: String,
    /// Profil z bazy (harmonogram), jeśli to on uruchomił skan.
    pub profile_id: Option<i64>,
    /// Użytkownik, który zlecił skan (API).
    pub requested_by: Option<i64>,
    pub subgroup_size: u32,
    pub parallel: u32,
    pub max_addresses: u64,
    /// K — host nieaktywny po tylu kolejnych przebiegach bez odpowiedzi (S11).
    pub inactive_after_missed_runs: u32,
    /// N — powtórne pomiary znanych hostów, które nie odpowiedziały (S10); 0 = wyłączone.
    pub unstable_retries: u32,
    /// Odstęp między powtórkami w sekundach.
    pub retry_delay_seconds: u64,
}

/// Podsumowanie przebiegu (zakończonego albo wstrzymanego).
#[derive(Debug, Clone)]
pub struct ScanJobSummary {
    pub run_id: i64,
    /// Zmiany względem poprzedniego udanego przebiegu tego profilu (M1):
    /// `None`, gdy nie było z czym porównać albo przebieg się nie zakończył.
    pub comparison: Option<Comparison>,
    /// Zmiany obecności hostów (S11); `None` dla przebiegu nieudanego lub wstrzymanego.
    pub presence: Option<dscan_db::PresenceUpdate>,
    pub status: ScanStatus,
    pub duration: TimeDelta,
    pub subgroups: usize,
    pub failed_subgroups: usize,
    /// Hosty znalezione w tej sesji skanowania.
    pub hosts: Vec<Host>,
}

/// Przebieg gotowy do wykonania: podgrupy do zeskanowania (z id w bazie) i postęp.
#[derive(Debug, Clone)]
pub struct JobPlan {
    pub run_id: i64,
    pub subgroups: Vec<(i64, Vec<IpNet>)>,
    pub progress: ScanProgress,
}

/// Tworzy przebieg w bazie: sprawdza limit adresów i dzieli sieci na podgrupy.
pub async fn create_job(
    pool: &PgPool,
    networks: &[IpNet],
    settings: &ScanJobSettings,
) -> Result<JobPlan, EngineError> {
    let total = count_addresses(networks);
    if total == 0 {
        return Err(EngineError::NoTargets);
    }
    if total > u128::from(settings.max_addresses) {
        return Err(EngineError::TooManyAddresses {
            count: total,
            limit: settings.max_addresses,
        });
    }
    let groups = split_into_subgroups(networks, settings.subgroup_size);
    let texts: Vec<Vec<String>> = groups
        .iter()
        .map(|group| group.iter().map(ToString::to_string).collect())
        .collect();
    let run = NewRun {
        profile: settings.profile.clone(),
        mode: settings.mode.clone(),
        profile_id: settings.profile_id,
        requested_by: settings.requested_by,
    };
    let created = dscan_db::create_scan_run_with(pool, &run, total as u64, &texts).await?;
    let progress = ScanProgress::new(created.run_id, Utc::now(), groups.len(), total as u64);
    Ok(JobPlan {
        run_id: created.run_id,
        subgroups: created.subgroup_ids.into_iter().zip(groups).collect(),
        progress,
    })
}

/// Wczytuje wstrzymany przebieg do wznowienia (S9): tylko niedokończone podgrupy.
pub async fn load_job(
    pool: &PgPool,
    run_id: i64,
) -> Result<(JobPlan, dscan_db::ResumableRun), EngineError> {
    let run = dscan_db::load_resumable_run(pool, run_id)
        .await?
        .ok_or_else(|| EngineError::NotResumable(format!("nie ma przebiegu #{run_id}")))?;
    if run.pending.is_empty() {
        return Err(EngineError::NotResumable(format!(
            "przebieg #{run_id} nie ma niedokończonych podgrup"
        )));
    }
    let subgroups = run
        .pending
        .iter()
        .map(|(id, addresses)| {
            (
                *id,
                addresses
                    .iter()
                    .filter_map(|text| text.parse().ok())
                    .collect(),
            )
        })
        .collect();
    let mut progress = ScanProgress::new(
        run_id,
        Utc::now(),
        run.total_subgroups as usize,
        run.total_addresses,
    );
    progress.finished_subgroups = run.completed_subgroups as usize;
    progress.finished_addresses = run.completed_addresses;
    Ok((
        JobPlan {
            run_id,
            subgroups,
            progress,
        },
        run,
    ))
}

/// Tworzy i od razu wykonuje przebieg (bez możliwości zatrzymania).
pub async fn run_scan_job<S: SubgroupScanner>(
    pool: &PgPool,
    cipher: &Cipher,
    networks: &[IpNet],
    scanner: Arc<S>,
    settings: &ScanJobSettings,
    observer: &impl ScanObserver,
) -> Result<ScanJobSummary, EngineError> {
    let plan = create_job(pool, networks, settings).await?;
    drive_job(
        pool,
        cipher,
        plan,
        scanner,
        settings,
        observer,
        never_stop(),
    )
    .await
}

/// Wykonuje przebieg: skanuje podgrupy równolegle, zapisuje każdą od razu po zakończeniu,
/// powiadamia obserwatora. Sygnał `stop` (np. koniec okna czasowego) przerywa skan:
/// trwające procesy nmap są zabijane, niedokończone podgrupy wracają do kolejki,
/// a przebieg dostaje stan `paused` (wznowienie: [`load_job`] + `drive_job`).
pub async fn drive_job<S: SubgroupScanner>(
    pool: &PgPool,
    cipher: &Cipher,
    plan: JobPlan,
    scanner: Arc<S>,
    settings: &ScanJobSettings,
    observer: &impl ScanObserver,
    stop: watch::Receiver<bool>,
) -> Result<ScanJobSummary, EngineError> {
    dscan_db::set_run_status(pool, plan.run_id, ScanStatus::Running.as_str()).await?;
    let (ids, groups): (Vec<i64>, Vec<Vec<IpNet>>) = plan.subgroups.into_iter().unzip();
    let mut job = RunningJob {
        pool,
        cipher,
        sizes: groups
            .iter()
            .map(|group| count_addresses(group) as u64)
            .collect(),
        subgroup_ids: ids,
        progress: plan.progress,
        hosts: Vec::new(),
        interrupted: 0,
    };
    observer.scan_started(&job.progress);

    let events = run_pool(
        Arc::clone(&scanner),
        groups,
        settings.parallel as usize,
        stop.clone(),
    );
    if let Err(error) = job.consume(events, observer).await {
        // Najlepsza próba oznaczenia przebiegu — pierwotny błąd jest ważniejszy.
        let _ = dscan_db::finish_scan_run(pool, job.progress.run_id, ScanStatus::Failed).await;
        return Err(error);
    }
    let unfinished = job.progress.total_subgroups > job.progress.finished_subgroups;
    if *stop.borrow() && unfinished {
        return job.pause().await;
    }
    let unstable = if job.progress.failed_subgroups == 0 && settings.unstable_retries > 0 {
        remeasure_silent_hosts(
            pool,
            cipher,
            job.progress.run_id,
            scanner.as_ref(),
            settings,
            stop,
        )
        .await?
    } else {
        Vec::new()
    };
    job.finish(settings, &unstable).await
}
