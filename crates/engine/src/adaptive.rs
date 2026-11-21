//! Adaptacyjny rozmiar podgrup (S5) i plan skanu bez wysyłania pakietów (C8).
//!
//! Z czasów ukończonych podgrup liczymy średnią kroczącą przepustowości (EWMA, adresy/s
//! na jeden proces nmap) i dobieramy rozmiar podgrupy tak, by jedna trwała około
//! `target_subgroup_seconds` — a przy oknie czasowym nie dłużej niż ćwierć pozostałego okna,
//! żeby o końcu okna tracić jak najmniej pracy.

use chrono::{DateTime, TimeDelta, Utc};
use dscan_config::Settings;
use dscan_db::PgPool;
use dscan_scanner::subgroups::split_into_subgroups;
use dscan_scanner::targets::count_addresses;
use ipnet::IpNet;

use crate::EngineError;

/// Waga najnowszego pomiaru w EWMA.
pub const EWMA_ALPHA: f64 = 0.3;
/// Ile ostatnich podgrup brać pod uwagę.
const SAMPLES: i64 = 50;
/// Najmniejsza podgrupa (/28).
pub const MIN_SUBGROUP_SIZE: u32 = 16;

/// EWMA przepustowości z pomiarów (adresy, sekundy), od najstarszego. `None` bez pomiarów.
pub fn ewma_throughput(samples: &[(u64, f64)], alpha: f64) -> Option<f64> {
    samples
        .iter()
        .filter(|(addresses, seconds)| *addresses > 0 && *seconds > 0.0)
        .map(|(addresses, seconds)| *addresses as f64 / seconds)
        .fold(None, |average, rate| {
            Some(average.map_or(rate, |avg| alpha * rate + (1.0 - alpha) * avg))
        })
}

/// Docelowy czas podgrupy: z konfiguracji, a w oknie najwyżej ćwierć pozostałego czasu (min. 30 s).
pub fn target_seconds(configured: u64, now: DateTime<Utc>, stop_at: Option<DateTime<Utc>>) -> u64 {
    match stop_at {
        Some(stop) => {
            let quarter = ((stop - now).num_seconds().max(0) / 4) as u64;
            configured.min(quarter.max(30))
        }
        None => configured,
    }
}

/// Rozmiar podgrupy: przepustowość × czas docelowy, zaokrąglone w dół do potęgi dwójki
/// (podgrupa = blok CIDR) i ograniczone do [`MIN_SUBGROUP_SIZE`]..=`max`. Bez pomiarów — `max`.
pub fn choose_subgroup_size(rate_per_process: Option<f64>, target_seconds: u64, max: u32) -> u32 {
    let Some(rate) = rate_per_process else {
        return max;
    };
    let wanted = (rate * target_seconds as f64).clamp(1.0, f64::from(u32::MAX)) as u32;
    let power = if wanted.is_power_of_two() {
        wanted
    } else {
        wanted.next_power_of_two() / 2
    };
    power.clamp(MIN_SUBGROUP_SIZE.min(max), max)
}

/// Zmierzona przepustowość na proces dla trybu (`None`, gdy brak historii).
pub async fn measured_throughput(pool: &PgPool, mode: &str) -> Result<Option<f64>, EngineError> {
    let samples: Vec<(u64, f64)> = dscan_db::recent_subgroup_timings(pool, mode, SAMPLES)
        .await?
        .into_iter()
        .map(|(addresses, seconds)| {
            let nets: Vec<IpNet> = addresses.iter().filter_map(|a| a.parse().ok()).collect();
            (count_addresses(&nets) as u64, seconds)
        })
        .collect();
    Ok(ewma_throughput(&samples, EWMA_ALPHA))
}

/// Rozmiar podgrup dla nowego przebiegu (S5); z `adaptive_subgroups = false` — stały.
pub async fn adaptive_subgroup_size(
    pool: &PgPool,
    settings: &Settings,
    mode: &str,
    stop_at: Option<DateTime<Utc>>,
) -> Result<u32, EngineError> {
    let limits = &settings.limits;
    if !limits.adaptive_subgroups {
        return Ok(limits.subgroup_size);
    }
    let rate = measured_throughput(pool, mode).await?;
    let target = target_seconds(limits.target_subgroup_seconds, Utc::now(), stop_at);
    Ok(choose_subgroup_size(rate, target, limits.subgroup_size))
}

/// Plan skanu (C8) — nic nie jest wysyłane do sieci.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanPlanEstimate {
    pub addresses: u128,
    pub subgroup_size: u32,
    /// Rozmiary kolejnych podgrup (ostatnie mogą być mniejsze).
    pub subgroup_sizes: Vec<u64>,
    pub parallel: u32,
    /// Przepustowość na proces (adresy/s): zmierzona albo szacowana z limitu pakietów.
    pub rate_per_process: f64,
    pub measured: bool,
    pub estimated_duration: TimeDelta,
}

/// Szacunek przepustowości bez historii: pakiety/s na proces ÷ pakiety na adres
/// (wykrywanie ~2, usługi ~2 na port).
pub fn fallback_throughput(settings: &Settings, mode: &str) -> f64 {
    let per_process = f64::from(settings.limits.nmap_max_rate)
        / f64::from(settings.limits.max_parallel_nmap.max(1));
    let packets_per_address = if mode == "discovery" {
        2.0
    } else {
        let ports: u64 = settings
            .scope
            .allowed_ports
            .iter()
            .filter_map(|p| dscan_core::models::parse_port_range(p).ok())
            .map(|r| u64::from(r.end - r.start) + 1)
            .sum();
        2.0 * ports.max(1) as f64
    };
    (per_process / packets_per_address).max(0.001)
}

/// Liczy plan: podział na podgrupy i czas przy `parallel` procesach (fale po `parallel` podgrup).
pub fn estimate_plan(
    networks: &[IpNet],
    subgroup_size: u32,
    parallel: u32,
    rate: f64,
    measured: bool,
) -> ScanPlanEstimate {
    let groups = split_into_subgroups(networks, subgroup_size);
    let sizes: Vec<u64> = groups.iter().map(|g| count_addresses(g) as u64).collect();
    let parallel = parallel.max(1);
    // Każda fala trwa tyle, co jej największa podgrupa.
    let seconds: f64 = sizes
        .chunks(parallel as usize)
        .map(|wave| wave.iter().copied().max().unwrap_or(0) as f64 / rate)
        .sum();
    ScanPlanEstimate {
        addresses: count_addresses(networks),
        subgroup_size,
        subgroup_sizes: sizes,
        parallel,
        rate_per_process: rate,
        measured,
        estimated_duration: TimeDelta::milliseconds((seconds * 1000.0) as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_weights_recent_samples() {
        assert_eq!(ewma_throughput(&[], 0.3), None);
        assert_eq!(ewma_throughput(&[(100, 10.0)], 0.3), Some(10.0));
        let rate = ewma_throughput(&[(100, 10.0), (200, 10.0)], 0.5).unwrap();
        assert!((rate - 15.0).abs() < 1e-9);
        // Pomiary zerowe są pomijane.
        assert_eq!(ewma_throughput(&[(0, 5.0), (50, 0.0)], 0.3), None);
    }

    #[test]
    fn size_is_power_of_two_within_bounds() {
        assert_eq!(choose_subgroup_size(None, 300, 256), 256);
        assert_eq!(choose_subgroup_size(Some(0.5), 300, 256), 128); // 150 → 128
        assert_eq!(choose_subgroup_size(Some(10.0), 300, 256), 256);
        assert_eq!(choose_subgroup_size(Some(0.01), 300, 256), 16);
        assert_eq!(choose_subgroup_size(Some(0.01), 300, 8), 8);
        assert_eq!(choose_subgroup_size(Some(64.0 / 300.0), 300, 256), 64);
    }

    #[test]
    fn window_limits_target_time() {
        let now = Utc::now();
        assert_eq!(target_seconds(300, now, None), 300);
        assert_eq!(
            target_seconds(300, now, Some(now + TimeDelta::minutes(8))),
            120
        );
        assert_eq!(
            target_seconds(300, now, Some(now + TimeDelta::seconds(20))),
            30
        );
    }

    #[test]
    fn plan_counts_waves() {
        let nets: Vec<IpNet> = vec!["10.0.0.0/24".parse().unwrap()];
        let plan = estimate_plan(&nets, 64, 2, 1.0, true);
        assert_eq!(plan.subgroup_sizes, vec![64, 64, 64, 64]);
        // 2 fale po 64 s.
        assert_eq!(plan.estimated_duration.num_seconds(), 128);
        assert_eq!(plan.addresses, 256);
    }

    #[test]
    fn fallback_uses_rate_and_ports() {
        let mut settings = Settings::default();
        settings.limits.nmap_max_rate = 100;
        settings.limits.max_parallel_nmap = 4;
        assert!((fallback_throughput(&settings, "discovery") - 12.5).abs() < 1e-9);
        settings.scope.allowed_ports = vec!["22".into(), "80-81".into()];
        assert!((fallback_throughput(&settings, "services") - 25.0 / 6.0).abs() < 1e-9);
    }
}
