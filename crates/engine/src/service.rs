//! Usługa skanów dla serwera: uruchamia przebiegi w tle (API, harmonogram), pozwala je
//! zatrzymać (S9) i wznowić. Trzyma sygnały zatrzymania trwających przebiegów.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Local, Utc};
use dscan_config::Settings;
use dscan_crypto::Cipher;
use dscan_db::PgPool;
use dscan_scanner::targets::TargetPlan;
use tokio::sync::watch;

use crate::adaptive::adaptive_subgroup_size;
use crate::launch::{JobScanner, build_scanner, effective_settings, job_settings};
use crate::windows::window_stop;
use crate::{
    EngineError, JobPlan, LogObserver, ScanJobSettings, ScanRequest, create_job, drive_job,
    load_job, prepare_scan,
};

/// Uruchomiony przebieg.
#[derive(Debug, Clone)]
pub struct StartedScan {
    pub run_id: i64,
    pub plan: TargetPlan,
    /// Kiedy przebieg zostanie wstrzymany (koniec okna), jeśli w ogóle.
    pub stop_at: Option<DateTime<Utc>>,
}

pub struct ScanService {
    pool: PgPool,
    cipher: Cipher,
    settings: Settings,
    running: Mutex<HashMap<i64, watch::Sender<bool>>>,
}

impl ScanService {
    pub fn new(pool: PgPool, cipher: Cipher, settings: Settings) -> Arc<Self> {
        Arc::new(ScanService {
            pool,
            cipher,
            settings,
            running: Mutex::new(HashMap::new()),
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Startuje skan w tle. Okna czasowe profilu (C4) są respektowane: poza oknem — błąd,
    /// w oknie — automatyczne wstrzymanie o jego końcu.
    pub async fn start(self: &Arc<Self>, request: ScanRequest) -> Result<StartedScan, EngineError> {
        let (settings, ..) = effective_settings(
            &self.settings,
            request.profile.as_deref(),
            request.mode.as_deref(),
        )?;
        let windows: Vec<(String, String)> = settings
            .schedule
            .windows
            .iter()
            .map(|w| (w.start.clone(), w.end.clone()))
            .collect();
        let stop_at =
            window_stop(&windows, Local::now()).map_err(|_| EngineError::OutsideWindow)?;
        self.start_until(request, stop_at).await
    }

    /// Startuje skan w tle z podanym czasem wstrzymania (harmonogram liczy go z okien profilu z bazy).
    pub async fn start_until(
        self: &Arc<Self>,
        request: ScanRequest,
        stop_at: Option<DateTime<Utc>>,
    ) -> Result<StartedScan, EngineError> {
        let mut prepared = prepare_scan(&self.settings, &request).await?;
        let (settings, ..) = effective_settings(
            &self.settings,
            request.profile.as_deref(),
            request.mode.as_deref(),
        )?;
        prepared.job.subgroup_size =
            adaptive_subgroup_size(&self.pool, &settings, &prepared.job.mode, stop_at).await?;
        let plan = create_job(&self.pool, &prepared.plan.networks, &prepared.job).await?;
        let run_id = plan.run_id;
        self.spawn(plan, prepared.scanner, prepared.job, stop_at);
        Ok(StartedScan {
            run_id,
            plan: prepared.plan,
            stop_at,
        })
    }

    /// Wznawia wstrzymany przebieg od niedokończonych podgrup.
    pub async fn resume(
        self: &Arc<Self>,
        run_id: i64,
        stop_at: Option<DateTime<Utc>>,
    ) -> Result<(), EngineError> {
        if self.is_running(run_id) {
            return Err(EngineError::NotResumable(format!(
                "przebieg #{run_id} właśnie trwa"
            )));
        }
        let (plan, run) = load_job(&self.pool, run_id).await?;
        let profile = self
            .settings
            .profiles
            .contains_key(&run.profile)
            .then_some(run.profile.as_str());
        let (settings, mode, _, tuning) =
            effective_settings(&self.settings, profile, Some(&run.mode))?;
        let scanner = Arc::new(build_scanner(&settings, &mode, tuning, &[])?);
        let request = ScanRequest {
            profile_id: run.profile_id,
            ..ScanRequest::default()
        };
        let job = job_settings(&settings, &mode, run.profile.clone(), &request);
        self.spawn(plan, scanner, job, stop_at);
        Ok(())
    }

    /// Wysyła sygnał zatrzymania; `false`, gdy przebieg nie trwa w tym procesie.
    pub fn stop(&self, run_id: i64) -> bool {
        self.lock()
            .get(&run_id)
            .is_some_and(|sender| sender.send(true).is_ok())
    }

    pub fn is_running(&self, run_id: i64) -> bool {
        self.lock().contains_key(&run_id)
    }

    fn spawn(
        self: &Arc<Self>,
        plan: JobPlan,
        scanner: Arc<JobScanner>,
        job: ScanJobSettings,
        stop_at: Option<DateTime<Utc>>,
    ) {
        let run_id = plan.run_id;
        let (sender, receiver) = watch::channel(false);
        if let Some(at) = stop_at {
            let timer = sender.clone();
            tokio::spawn(async move {
                let wait = (at - Utc::now()).to_std().unwrap_or_default();
                tokio::time::sleep(wait).await;
                let _ = timer.send(true);
            });
        }
        self.lock().insert(run_id, sender);
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let result = drive_job(
                &service.pool,
                &service.cipher,
                plan,
                scanner,
                &job,
                &LogObserver,
                receiver,
            )
            .await;
            match result {
                Ok(summary) => tracing::info!("przebieg #{run_id}: {}", summary.status.as_str()),
                Err(error) => tracing::warn!("przebieg #{run_id} przerwany błędem: {error}"),
            }
            service.lock().remove(&run_id);
        });
    }

    /// Mapa sygnałów — tylko proste operacje, więc po panice innego wątku można jej dalej używać.
    fn lock(&self) -> MutexGuard<'_, HashMap<i64, watch::Sender<bool>>> {
        self.running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
