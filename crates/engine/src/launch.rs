//! Od żądania skanu (cele, profil, tryb) do gotowego planu i skanera.

use std::net::IpAddr;
use std::sync::Arc;

use dscan_config::{Settings, resolve_profile};
use dscan_scanner::ScannerError;
use dscan_scanner::nmap::{NmapProfile, ScanOutput, ports_argument};
use dscan_scanner::pool::{NmapScanner, SubgroupScanner};
use dscan_scanner::safety::ports_within;
use dscan_scanner::targets::{SystemResolver, TargetPlan, prepare_targets};
use ipnet::IpNet;

use crate::setup::{build_analysis, build_fetcher};
use crate::{
    EngineError, NmapTuning, RateSettings, ScanJobSettings, WebFingerprintScanner, nmap_scanner,
};

/// Żądanie skanu — z CLI, API albo harmonogramu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    /// Nazwany profil z `[profiles]` (C4).
    pub profile: Option<String>,
    /// `discovery`/`services` — zastępuje tryb z profilu.
    pub mode: Option<String>,
    /// Porty zastępujące profil i konfigurację (np. z profilu w bazie).
    pub ports: Option<Vec<String>>,
    /// Profil z bazy (harmonogram), z którego pochodzi żądanie.
    pub profile_id: Option<i64>,
    /// Nazwa zapisywana w przebiegu, gdy inna niż profil (np. nazwa profilu z bazy).
    pub run_label: Option<String>,
    pub requested_by: Option<i64>,
    /// Limit tempa nmap z profilu w bazie (F4), zastępuje `[limits] nmap_max_rate`.
    pub max_rate: Option<u32>,
}

/// Skaner podgrup przebiegu: sam nmap albo nmap z fingerprintingiem WWW.
pub enum JobScanner {
    Plain(NmapScanner),
    Web(WebFingerprintScanner<NmapScanner>),
}

impl SubgroupScanner for JobScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        match self {
            JobScanner::Plain(scanner) => scanner.scan(targets).await,
            JobScanner::Web(scanner) => scanner.scan(targets).await,
        }
    }
}

/// Wszystko, czego potrzeba do utworzenia i wykonania przebiegu.
pub struct PreparedScan {
    pub plan: TargetPlan,
    pub job: ScanJobSettings,
    pub scanner: Arc<JobScanner>,
}

/// Ustawienia po nałożeniu profilu: (ustawienia, tryb, nazwa profilu, opcje nmap).
pub fn effective_settings(
    base: &Settings,
    profile: Option<&str>,
    mode: Option<&str>,
) -> Result<(Settings, String, String, NmapTuning), EngineError> {
    match profile {
        Some(name) => {
            let resolved = resolve_profile(base, name)
                .map_err(|error| EngineError::Setup(error.to_string()))?;
            let tuning = NmapTuning {
                host_timeout_seconds: resolved.host_timeout_seconds,
                max_retries: resolved.max_retries,
            };
            let mode = mode.map(String::from).unwrap_or(resolved.mode);
            Ok((resolved.settings, mode, name.to_string(), tuning))
        }
        None => {
            let mode = mode.unwrap_or("services").to_string();
            Ok((base.clone(), mode.clone(), mode, NmapTuning::default()))
        }
    }
}

/// Rozwiązuje cele (DNS, zakres) i buduje ustawienia przebiegu oraz skaner.
pub async fn prepare_scan(
    base: &Settings,
    request: &ScanRequest,
) -> Result<PreparedScan, EngineError> {
    let (mut settings, mode, profile_name, tuning) =
        effective_settings(base, request.profile.as_deref(), request.mode.as_deref())?;
    if let Some(ports) = &request.ports {
        settings.scope.allowed_ports = ports.clone();
    }
    if let Some(rate) = request.max_rate {
        settings.limits.nmap_max_rate = rate;
    }
    // Q5: porty z profilu (TOML lub bazy) muszą mieścić się w [scope] allowed_ports.
    if !ports_within(&settings.scope.allowed_ports, &base.scope.allowed_ports) {
        return Err(EngineError::Setup(format!(
            "porty profilu ({}) wykraczają poza [scope] allowed_ports ({})",
            settings.scope.allowed_ports.join(", "),
            base.scope.allowed_ports.join(", ")
        )));
    }
    let resolver = SystemResolver::from_system_config()
        .map_err(|error| EngineError::Setup(error.to_string()))?;
    let plan = prepare_targets(
        &request.targets,
        &resolver,
        &settings.scope.allowed_networks,
    )
    .await;
    if plan.networks.is_empty() {
        return Err(EngineError::NoTargetsInScope(Box::new(plan)));
    }
    let scanner = Arc::new(build_scanner(&settings, &mode, tuning, &plan.hostnames)?);
    let job = job_settings(
        &settings,
        &mode,
        request.run_label.clone().unwrap_or(profile_name),
        request,
    );
    Ok(PreparedScan { plan, job, scanner })
}

/// Skaner dla trybu: `services` z fingerprintingiem WWW (gdy `[http] enabled`), `discovery` — sam nmap.
pub fn build_scanner(
    settings: &Settings,
    mode: &str,
    tuning: NmapTuning,
    hostnames: &[(IpAddr, String)],
) -> Result<JobScanner, EngineError> {
    let rate = RateSettings {
        max_rate: settings.limits.nmap_max_rate,
        bandwidth_kbps: settings.scope.max_bandwidth_kbps,
        parallel: settings.limits.max_parallel_nmap,
    };
    let profile = if mode == "discovery" {
        NmapProfile::Discovery
    } else {
        NmapProfile::Services
    };
    let nmap = nmap_scanner(
        profile,
        ports_argument(&settings.scope.allowed_ports),
        rate,
        tuning,
    );
    if profile == NmapProfile::Services && settings.http.enabled {
        let fetcher = Arc::new(build_fetcher(settings)?);
        let analysis = Arc::new(build_analysis(settings, hostnames)?);
        return Ok(JobScanner::Web(WebFingerprintScanner::new(
            nmap, fetcher, analysis,
        )));
    }
    Ok(JobScanner::Plain(nmap))
}

/// Ustawienia przebiegu z konfiguracji i żądania.
pub fn job_settings(
    settings: &Settings,
    mode: &str,
    label: String,
    request: &ScanRequest,
) -> ScanJobSettings {
    ScanJobSettings {
        profile: label,
        mode: mode.to_string(),
        profile_id: request.profile_id,
        requested_by: request.requested_by,
        subgroup_size: settings.limits.subgroup_size,
        parallel: settings.limits.max_parallel_nmap,
        max_addresses: settings.limits.max_addresses_per_scan,
        inactive_after_missed_runs: settings.stability.inactive_after_missed_runs,
        unstable_retries: settings.stability.unstable_retries,
        retry_delay_seconds: settings.stability.retry_delay_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_config::ScanProfileSettings;

    #[test]
    fn without_profile_mode_defaults_to_services() {
        let (_, mode, name, tuning) = effective_settings(&Settings::default(), None, None).unwrap();
        assert_eq!((mode.as_str(), name.as_str()), ("services", "services"));
        assert_eq!(tuning, NmapTuning::default());
    }

    #[test]
    fn profile_and_explicit_mode() {
        let mut base = Settings::default();
        base.profiles.insert(
            "szybki".into(),
            ScanProfileSettings {
                mode: Some("discovery".into()),
                max_retries: Some(1),
                ..Default::default()
            },
        );
        let (_, mode, name, tuning) = effective_settings(&base, Some("szybki"), None).unwrap();
        assert_eq!(
            (mode.as_str(), name.as_str(), tuning.max_retries),
            ("discovery", "szybki", Some(1))
        );
        let (_, mode, _, _) = effective_settings(&base, Some("szybki"), Some("services")).unwrap();
        assert_eq!(mode, "services");
        assert!(effective_settings(&base, Some("nie-ma"), None).is_err());
    }
}
