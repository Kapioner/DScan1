//! Struktury szablonów askama. Pola są wstawiane do HTML z automatycznym
//! escapowaniem, więc dane z sieci (np. tytuły stron) nie mogą wstrzyknąć kodu.

use askama::Template;
use chrono::{DateTime, Utc};
use dscan_core::format::format_duration;
use dscan_core::models::ScanRun;

use crate::MenuItem;

/// Pasek użytkownika w nagłówku strony.
pub struct UserBar {
    pub username: String,
    pub role: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub error: Option<String>,
    pub username: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    /// Formularz „Uruchom skan” tylko dla ról z `targets:write`.
    pub can_scan: bool,
    /// Nazwy profili z `[profiles]` w dscan.toml (C4).
    pub profiles: Vec<String>,
}

#[derive(Template)]
#[template(path = "scans_table.html")]
pub struct ScansTable {
    pub scans: Vec<ScanRow>,
    /// Przyciski „Wstrzymaj”/„Wznów” (S9) dla ról z `targets:write`.
    pub can_control: bool,
}

/// Wiersz tabeli przebiegów (wartości już sformatowane).
pub struct ScanRow {
    pub id: i64,
    pub profile: String,
    pub status: String,
    pub started_at: String,
    pub progress: String,
    /// Postęp jako liczba całkowita (do paska `<progress>`).
    pub percent: u32,
    pub subgroups: String,
    pub elapsed: String,
    pub remaining: String,
}

impl ScanRow {
    pub fn from_run(run: &ScanRun, now: DateTime<Utc>) -> Self {
        ScanRow {
            id: run.id,
            profile: run.profile.clone(),
            status: run.status.as_str().to_string(),
            started_at: run.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            progress: format!("{:.0}%", run.progress_percent()),
            percent: run.progress_percent().round().clamp(0.0, 100.0) as u32,
            subgroups: format!("{}/{}", run.completed_subgroups, run.total_subgroups),
            elapsed: format_duration(run.elapsed(now)),
            remaining: run
                .estimated_remaining(now)
                .map(format_duration)
                .unwrap_or_else(|| "—".into()),
        }
    }
}

#[derive(Template)]
#[template(path = "targets.html")]
pub struct TargetsPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub section: TargetsSection,
}

/// Sekcja celów (tabela, komunikat, raport importu) — część strony i odpowiedź htmx.
#[derive(Template)]
#[template(path = "targets_section.html")]
pub struct TargetsSection {
    pub targets: Vec<dscan_db::StoredTarget>,
    pub can_edit: bool,
    pub notice: Option<Notice>,
    pub report: Option<ImportReportView>,
}

/// Komunikat po akcji (sukces albo błąd).
pub struct Notice {
    pub ok: bool,
    pub text: String,
}

impl Notice {
    pub fn ok(text: impl Into<String>) -> Self {
        Notice {
            ok: true,
            text: text.into(),
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Notice {
            ok: false,
            text: text.into(),
        }
    }
}

/// Raport z wgrania pliku z celami.
pub struct ImportReportView {
    pub file_name: String,
    pub accepted: usize,
    pub rejected: Vec<dscan_integrations::RejectedRow>,
    pub dry_run: bool,
    /// (nowe, już istniejące) — gdy cele zapisano.
    pub saved: Option<(u64, u64)>,
}

impl ImportReportView {
    pub fn new(file_name: &str, import: &dscan_integrations::TargetImport, dry_run: bool) -> Self {
        ImportReportView {
            file_name: file_name.to_string(),
            accepted: import.accepted.len(),
            rejected: import.rejected.clone(),
            dry_run,
            saved: None,
        }
    }
}

#[derive(Template)]
#[template(path = "profiles.html")]
pub struct ProfilesPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub profiles: Vec<ProfileRow>,
    /// Formularze tylko dla ról z `targets:write` (F4).
    pub can_edit: bool,
    pub message: Option<String>,
    /// Profile z `[profiles]` w dscan.toml: (nazwa, opis ustawień).
    pub config_profiles: Vec<(String, String)>,
}

/// Wiersz tabeli profili.
pub struct ProfileRow {
    pub id: i64,
    /// Wartości do pól formularza edycji.
    pub group_raw: String,
    pub ports_raw: String,
    pub windows_raw: String,
    pub frequency_raw: String,
    pub rate_raw: String,
    pub rate: String,
    pub name: String,
    pub mode: String,
    pub group: String,
    pub ports: String,
    pub windows: String,
    pub frequency: String,
    pub enabled: bool,
}

impl ProfileRow {
    pub fn from_profile(profile: &dscan_db::ScanProfile) -> Self {
        let data = &profile.data;
        let windows: Vec<String> = data
            .windows
            .iter()
            .map(|w| format!("{}–{}", w.start, w.end))
            .collect();
        let windows_raw: Vec<String> = data
            .windows
            .iter()
            .map(|w| format!("{}-{}", w.start, w.end))
            .collect();
        ProfileRow {
            id: profile.id,
            group_raw: data.target_group.clone().unwrap_or_default(),
            ports_raw: data.ports.join(", "),
            windows_raw: windows_raw.join(", "),
            frequency_raw: data
                .frequency_minutes
                .map(|m| m.to_string())
                .unwrap_or_default(),
            rate_raw: data.max_rate.map(|r| r.to_string()).unwrap_or_default(),
            rate: data
                .max_rate
                .map_or("z konfiguracji".into(), |r| format!("{r} pakietów/s")),
            name: data.name.clone(),
            mode: data.mode.clone(),
            group: data
                .target_group
                .clone()
                .unwrap_or_else(|| "wszystkie".into()),
            ports: if data.ports.is_empty() {
                "z konfiguracji".into()
            } else {
                data.ports.join(", ")
            },
            windows: if windows.is_empty() {
                "cała doba".into()
            } else {
                windows.join(", ")
            },
            frequency: data
                .frequency_minutes
                .map_or("ręcznie".into(), |m| format!("co {m} min")),
            enabled: data.enabled,
        }
    }
}

#[derive(Template)]
#[template(path = "forbidden.html")]
pub struct ForbiddenPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use dscan_core::models::ScanStatus;

    #[test]
    fn scan_row_is_formatted() {
        let started_at: DateTime<Utc> = "2026-11-21T10:00:00Z".parse().unwrap();
        let run = ScanRun {
            id: 3,
            profile: "services".into(),
            status: ScanStatus::Running,
            started_at,
            finished_at: None,
            total_addresses: 100,
            completed_addresses: 25,
            total_subgroups: 4,
            completed_subgroups: 1,
        };

        let row = ScanRow::from_run(&run, started_at + TimeDelta::seconds(30));

        assert_eq!(row.progress, "25%");
        assert_eq!(row.subgroups, "1/4");
        assert_eq!(row.elapsed, "0:30");
        assert_eq!(row.remaining, "1:30");
    }

    #[test]
    fn untrusted_text_is_escaped_in_html() {
        let page = LoginPage {
            error: None,
            username: "<script>alert(1)</script>".into(),
        };
        let html = page.render().unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
