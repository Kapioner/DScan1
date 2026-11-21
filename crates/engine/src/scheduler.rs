//! Harmonogram skanów (zadanie S8): co minutę sprawdza profile z bazy i uruchamia te,
//! na które przyszła pora — w ich oknie czasowym, z ich częstotliwością. Wstrzymany przebieg
//! profilu (koniec okna, S9) jest wznawiany w kolejnym oknie zamiast startu nowego.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use dscan_db::ScanProfile;

use crate::windows::window_stop;
use crate::{ScanRequest, ScanService};

/// Co ile harmonogram sprawdza profile.
pub const SCHEDULER_TICK: Duration = Duration::from_secs(60);

/// Co zrobić z profilem w danej chwili.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Wait,
    Start {
        stop_at: Option<DateTime<Utc>>,
    },
    Resume {
        run_id: i64,
        stop_at: Option<DateTime<Utc>>,
    },
}

/// Ostatni przebieg profilu: (id, stan, start).
pub type LastRun = (i64, String, DateTime<Utc>);

/// Decyzja dla profilu: wyłączony lub bez częstotliwości — tylko ręcznie; poza oknem — czekamy;
/// wstrzymany przebieg — wznawiamy; trwający — czekamy; minęła częstotliwość — start.
pub fn decide(profile: &ScanProfile, last: Option<&LastRun>, now: DateTime<Local>) -> Decision {
    let data = &profile.data;
    let Some(frequency) = data.frequency_minutes else {
        return Decision::Wait;
    };
    if !data.enabled {
        return Decision::Wait;
    }
    let windows: Vec<(String, String)> = data
        .windows
        .iter()
        .map(|w| (w.start.clone(), w.end.clone()))
        .collect();
    let Ok(stop_at) = window_stop(&windows, now) else {
        return Decision::Wait;
    };
    match last {
        Some((run_id, status, _)) if status == "paused" => Decision::Resume {
            run_id: *run_id,
            stop_at,
        },
        Some((_, status, _)) if status == "running" => Decision::Wait,
        Some((_, _, started))
            if now.with_timezone(&Utc) - *started
                < chrono::Duration::minutes(i64::from(frequency)) =>
        {
            Decision::Wait
        }
        _ => Decision::Start { stop_at },
    }
}

/// Pętla harmonogramu (uruchamiana przez `dscan serve`).
pub async fn run_scheduler(service: Arc<ScanService>) {
    let mut interval = tokio::time::interval(SCHEDULER_TICK);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&service).await {
            tracing::warn!("harmonogram: {error}");
        }
    }
}

/// Jedno sprawdzenie wszystkich profili.
pub async fn tick(service: &Arc<ScanService>) -> Result<(), crate::EngineError> {
    let now = Local::now();
    for profile in dscan_db::list_profiles(service.pool()).await? {
        let last = dscan_db::last_profile_run(service.pool(), profile.id).await?;
        // Przebieg uruchomiony przez ten proces jest w toku, nawet jeśli baza jeszcze tego nie pokazuje.
        if last
            .as_ref()
            .is_some_and(|(id, _, _)| service.is_running(*id))
        {
            continue;
        }
        match decide(&profile, last.as_ref(), now) {
            Decision::Wait => {}
            Decision::Resume { run_id, stop_at } => {
                tracing::info!(
                    "harmonogram: wznawiam przebieg #{run_id} profilu '{}'",
                    profile.data.name
                );
                service.resume(run_id, stop_at).await?;
            }
            Decision::Start { stop_at } => start_profile(service, &profile, stop_at).await,
        }
    }
    Ok(())
}

async fn start_profile(
    service: &Arc<ScanService>,
    profile: &ScanProfile,
    stop_at: Option<DateTime<Utc>>,
) {
    let data = &profile.data;
    let targets = match dscan_db::list_targets(
        service.pool(),
        service.cipher(),
        data.target_group.as_deref(),
    )
    .await
    {
        Ok(targets) => targets
            .into_iter()
            .map(|target| target.value)
            .collect::<Vec<_>>(),
        Err(error) => return tracing::warn!("harmonogram: profil '{}': {error}", data.name),
    };
    if targets.is_empty() {
        return tracing::info!("harmonogram: profil '{}' nie ma celów", data.name);
    }
    let request = ScanRequest {
        targets,
        mode: Some(data.mode.clone()),
        ports: (!data.ports.is_empty()).then(|| data.ports.clone()),
        profile_id: Some(profile.id),
        run_label: Some(data.name.clone()),
        max_rate: data.max_rate.and_then(|rate| u32::try_from(rate).ok()),
        ..ScanRequest::default()
    };
    match service.start_until(request, stop_at).await {
        Ok(started) => tracing::info!(
            "harmonogram: profil '{}' → przebieg #{}",
            data.name,
            started.run_id
        ),
        Err(error) => tracing::warn!("harmonogram: profil '{}': {error}", data.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use dscan_db::{ProfileData, ProfileWindow};

    fn profile(frequency: Option<i32>, windows: &[(&str, &str)], enabled: bool) -> ScanProfile {
        ScanProfile {
            id: 1,
            data: ProfileData {
                name: "nocny".into(),
                mode: "services".into(),
                target_group: None,
                ports: Vec::new(),
                windows: windows
                    .iter()
                    .map(|(s, e)| ProfileWindow {
                        start: s.to_string(),
                        end: e.to_string(),
                    })
                    .collect(),
                frequency_minutes: frequency,
                enabled,
                max_rate: None,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn at(text: &str) -> DateTime<Local> {
        Local
            .from_local_datetime(
                &chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn manual_or_disabled_profiles_wait() {
        let now = at("2026-11-21 12:00");
        assert_eq!(decide(&profile(None, &[], true), None, now), Decision::Wait);
        assert_eq!(
            decide(&profile(Some(60), &[], false), None, now),
            Decision::Wait
        );
    }

    #[test]
    fn first_run_starts_inside_window_only() {
        let night = profile(Some(1440), &[("22:00", "06:00")], true);
        assert_eq!(decide(&night, None, at("2026-11-21 12:00")), Decision::Wait);
        let Decision::Start {
            stop_at: Some(stop),
        } = decide(&night, None, at("2026-11-21 23:00"))
        else {
            panic!("powinien wystartować");
        };
        assert_eq!(stop, at("2026-11-22 06:00").with_timezone(&Utc));
    }

    #[test]
    fn frequency_is_respected() {
        let hourly = profile(Some(60), &[], true);
        let now = at("2026-11-21 12:00");
        let recent: LastRun = (
            5,
            "completed".into(),
            (now - chrono::Duration::minutes(30)).with_timezone(&Utc),
        );
        let old: LastRun = (
            5,
            "completed".into(),
            (now - chrono::Duration::minutes(61)).with_timezone(&Utc),
        );
        assert_eq!(decide(&hourly, Some(&recent), now), Decision::Wait);
        assert_eq!(
            decide(&hourly, Some(&old), now),
            Decision::Start { stop_at: None }
        );
    }

    #[test]
    fn paused_run_is_resumed_and_running_one_waits() {
        let hourly = profile(Some(60), &[], true);
        let now = at("2026-11-21 12:00");
        let paused: LastRun = (7, "paused".into(), Utc::now());
        let running: LastRun = (7, "running".into(), Utc::now());
        assert_eq!(
            decide(&hourly, Some(&paused), now),
            Decision::Resume {
                run_id: 7,
                stop_at: None
            }
        );
        assert_eq!(decide(&hourly, Some(&running), now), Decision::Wait);
    }
}
