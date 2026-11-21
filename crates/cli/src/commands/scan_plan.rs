//! `dscan scan --dry-run` (C8): liczba adresów, podział na podgrupy i szacowany czas —
//! bez wysyłania pakietów do celów (tylko DNS dla domen i odczyt historii z bazy, jeśli jest).

use std::fmt::Write;

use chrono::Local;
use dscan_engine::adaptive::{
    ScanPlanEstimate, adaptive_subgroup_size, choose_subgroup_size, estimate_plan,
    fallback_throughput, measured_throughput, target_seconds,
};
use dscan_engine::windows::window_stop;
use dscan_engine::{EngineError, effective_settings, prepare_scan};

use super::scan::ScanArgs;
use super::targets::format_plan;
use super::{Context, connect_database};
use crate::error::CliError;
use dscan_core::format::format_duration;

pub async fn dry_run(args: &ScanArgs, context: &Context) -> Result<(), CliError> {
    let config = context.load_config(args.overrides.to_overrides())?;
    let request = args.request();
    let (settings, mode, profile, _) = effective_settings(
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
    let stop_at = window_stop(&windows, Local::now());
    let prepared = match prepare_scan(&config.settings, &request).await {
        Err(EngineError::NoTargetsInScope(plan)) => {
            eprint!("{}", format_plan(&plan));
            return Err(CliError::NoTargetsInScope);
        }
        other => other?,
    };
    print!("{}", format_plan(&prepared.plan));

    // Historia z bazy jest opcjonalna — bez niej szacujemy z limitu pakietów.
    let pool = match config.require_database_url() {
        Ok(_) => connect_database(&config).await.ok(),
        Err(_) => None,
    };
    let stop = stop_at.ok().flatten();
    let (rate, size) = match &pool {
        Some(pool) => {
            let measured = measured_throughput(pool, &mode).await?;
            (
                measured,
                adaptive_subgroup_size(pool, &settings, &mode, stop).await?,
            )
        }
        None => {
            let target = target_seconds(
                settings.limits.target_subgroup_seconds,
                chrono::Utc::now(),
                stop,
            );
            (
                None,
                choose_subgroup_size(None, target, settings.limits.subgroup_size),
            )
        }
    };
    let estimate = estimate_plan(
        &prepared.plan.networks,
        size,
        settings.limits.max_parallel_nmap,
        rate.unwrap_or_else(|| fallback_throughput(&settings, &mode)),
        rate.is_some(),
    );
    print!("{}", format_estimate(&estimate, &profile, &mode));
    match stop_at {
        Err(_) => {
            println!("Uwaga: teraz jest poza oknem czasowym — prawdziwy skan by nie wystartował.")
        }
        Ok(Some(at)) => println!(
            "Okno czasowe kończy się o {}.",
            at.with_timezone(&Local).format("%H:%M")
        ),
        Ok(None) => {}
    }
    println!("Tryb próbny — nie wysłano żadnego pakietu do celów.");
    Ok(())
}

/// Opis planu, np. `Podgrupy: 4 × /26 (64 adresy) …`.
pub fn format_estimate(estimate: &ScanPlanEstimate, profile: &str, mode: &str) -> String {
    let mut text = format!("Profil: {profile}, tryb: {mode}\n");
    let count = estimate.subgroup_sizes.len();
    let prefix = 32 - estimate.subgroup_size.trailing_zeros();
    // Zapis do String nie może się nie udać.
    let _ = writeln!(
        text,
        "Adresy: {}, podgrupy: {count} (rozmiar do {} adresów = /{prefix}), równolegle: {} procesów nmap",
        estimate.addresses, estimate.subgroup_size, estimate.parallel
    );
    let source = if estimate.measured {
        "zmierzona (EWMA)"
    } else {
        "szacowana z limitu pakietów"
    };
    let _ = writeln!(
        text,
        "Przepustowość na proces: {:.2} adresów/s — {source}",
        estimate.rate_per_process
    );
    let _ = writeln!(
        text,
        "Szacowany czas: {}",
        format_duration(estimate.estimated_duration)
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_described() {
        let nets = vec!["10.0.0.0/24".parse().unwrap()];
        let text = format_estimate(
            &estimate_plan(&nets, 64, 2, 1.0, false),
            "pelny",
            "services",
        );
        assert!(
            text.contains("podgrupy: 4 (rozmiar do 64 adresów = /26)"),
            "{text}"
        );
        assert!(text.contains("szacowana z limitu pakietów"));
        assert!(text.contains("Szacowany czas: 2:08"), "{text}");
    }
}
