//! Wykrywanie środowisk testowych i paneli (zadanie M6) — heurystyki uzupełniające sygnatury:
//! nazwy hostów (dev/test/staging…), nagłówki debugowania, domyślne strony serwerów,
//! zawartość `robots.txt` i tytuły paneli. Wynik to detekcje z dowodami, jak przy sygnaturach.

use dscan_core::models::{Detection, Evidence, EvidenceKind, HttpInfo};

use crate::ProbeResult;
use crate::robots::robots_evidence;

pub const TEST_ENVIRONMENT: &str = "Środowisko testowe";
pub const DEBUG_MODE: &str = "Tryb debugowania";
pub const DEFAULT_PAGE: &str = "Strona domyślna serwera";
pub const ADMIN_PANEL: &str = "Panel administracyjny";
pub const ROBOTS_HINTS: &str = "Wskazówki w robots.txt";

/// Czy detekcja pochodzi z heurystyk M6 (a nie z sygnatury).
pub fn is_environment_finding(technology: &str) -> bool {
    [
        TEST_ENVIRONMENT,
        DEBUG_MODE,
        DEFAULT_PAGE,
        ADMIN_PANEL,
        ROBOTS_HINTS,
    ]
    .contains(&technology)
}

/// Etykiety nazw hostów typowe dla środowisk nieprodukcyjnych.
const TEST_LABELS: [&str; 13] = [
    "dev", "devel", "test", "testing", "staging", "stage", "stg", "uat", "qa", "preprod",
    "sandbox", "demo", "beta",
];

/// Tytuły domyślnych stron po instalacji serwera.
const DEFAULT_TITLES: [&str; 8] = [
    "welcome to nginx",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "test page for the apache",
    "iis windows server",
    "welcome to centos",
    "it works!",
    "default web site page",
];

/// Słowa w tytule strony wskazujące na panel lub logowanie.
const PANEL_WORDS: [&str; 12] = [
    "admin",
    "panel",
    "dashboard",
    "login",
    "logowanie",
    "zaloguj",
    "sign in",
    "console",
    "konsola",
    "management",
    "zarządzanie",
    "control center",
];

/// Wszystkie ustalenia M6 dla jednej usługi WWW.
pub fn environment_findings(
    hostnames: &[String],
    info: &HttpInfo,
    probes: &[ProbeResult],
) -> Vec<Detection> {
    let mut test_evidence = test_hostname_evidence(hostnames);
    test_evidence.extend(environment_header_evidence(info));
    let findings = [
        (TEST_ENVIRONMENT, test_evidence),
        (DEBUG_MODE, debug_header_evidence(info)),
        (DEFAULT_PAGE, default_page_evidence(info)),
        (ADMIN_PANEL, panel_title_evidence(info)),
        (ROBOTS_HINTS, robots_evidence(probes)),
    ];
    findings
        .into_iter()
        .filter(|(_, evidence)| !evidence.is_empty())
        .map(|(name, evidence)| Detection::from_evidence(name.to_string(), None, evidence))
        .collect()
}

fn evidence(kind: EvidenceKind, description: String, weight: u8) -> Evidence {
    Evidence {
        kind,
        description,
        weight,
    }
}

/// Nazwa hosta z etykietą testową, np. `staging.firma.pl`, `api-dev.firma.pl`, `test2.firma.pl`.
pub fn test_hostname_evidence(hostnames: &[String]) -> Vec<Evidence> {
    hostnames
        .iter()
        .filter(|name| name.split('.').any(is_test_label))
        .map(|name| evidence(EvidenceKind::Path, format!("nazwa hosta {name}"), 60))
        .collect()
}

fn is_test_label(label: &str) -> bool {
    let label = label.to_ascii_lowercase();
    label.split('-').any(|part| {
        let word = part.trim_end_matches(|c: char| c.is_ascii_digit());
        TEST_LABELS.contains(&word)
    })
}

/// Nagłówki z nazwą środowiska, np. `X-Environment: staging`.
fn environment_header_evidence(info: &HttpInfo) -> Vec<Evidence> {
    ["x-environment", "x-env", "x-app-env"]
        .iter()
        .filter_map(|name| info.header(name).map(|value| (name, value)))
        .filter(|(_, value)| {
            value
                .split(|c: char| !c.is_alphanumeric())
                .any(is_test_label)
        })
        .map(|(name, value)| {
            evidence(
                EvidenceKind::Header,
                format!("nagłówek {name}: {value}"),
                70,
            )
        })
        .collect()
}

/// Nagłówki zdradzające włączone narzędzia debugowania (np. profiler Symfony).
fn debug_header_evidence(info: &HttpInfo) -> Vec<Evidence> {
    [
        ("x-debug-token", 80),
        ("x-debug-token-link", 80),
        ("x-debug", 60),
        ("x-debug-mode", 60),
    ]
    .iter()
    .filter(|(name, _)| info.header(name).is_some())
    .map(|(name, weight)| evidence(EvidenceKind::Header, format!("nagłówek {name}"), *weight))
    .collect()
}

fn default_page_evidence(info: &HttpInfo) -> Vec<Evidence> {
    let Some(title) = info.title.as_deref() else {
        return Vec::new();
    };
    let lower = title.to_lowercase();
    DEFAULT_TITLES
        .iter()
        .filter(|default| lower.contains(*default))
        .map(|_| evidence(EvidenceKind::Body, format!("tytuł „{title}”"), 80))
        .take(1)
        .collect()
}

fn panel_title_evidence(info: &HttpInfo) -> Vec<Evidence> {
    let Some(title) = info.title.as_deref() else {
        return Vec::new();
    };
    let lower = title.to_lowercase();
    if PANEL_WORDS.iter().any(|word| lower.contains(word)) {
        vec![evidence(EvidenceKind::Body, format!("tytuł „{title}”"), 50)]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::HttpHeader;

    fn info(title: Option<&str>, headers: &[(&str, &str)]) -> HttpInfo {
        HttpInfo {
            url: "http://10.0.0.5/".into(),
            status_code: 200,
            title: title.map(String::from),
            headers: headers
                .iter()
                .map(|(n, v)| HttpHeader {
                    name: n.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            cookies: Vec::new(),
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
        }
    }

    fn names(found: &[Detection]) -> Vec<&str> {
        found.iter().map(|d| d.technology.as_str()).collect()
    }

    #[test]
    fn test_hostnames_are_recognized() {
        let hosts: Vec<String> = [
            "staging.firma.pl",
            "api-dev.firma.pl",
            "test2.firma.pl",
            "www.firma.pl",
            "devops.firma.pl",
        ]
        .iter()
        .map(|h| h.to_string())
        .collect();
        let evidence = test_hostname_evidence(&hosts);
        assert_eq!(evidence.len(), 3, "{evidence:?}");
        assert!(
            evidence
                .iter()
                .all(|e| !e.description.contains("www") && !e.description.contains("devops"))
        );
    }

    #[test]
    fn debug_and_environment_headers() {
        let found = environment_findings(
            &[],
            &info(
                None,
                &[("X-Debug-Token", "abc"), ("X-Environment", "staging")],
            ),
            &[],
        );
        assert_eq!(names(&found), vec![TEST_ENVIRONMENT, DEBUG_MODE]);
        let production =
            environment_findings(&[], &info(None, &[("X-Environment", "production")]), &[]);
        assert!(production.is_empty());
    }

    #[test]
    fn default_pages_and_panels_by_title() {
        assert_eq!(
            names(&environment_findings(
                &[],
                &info(Some("Welcome to nginx!"), &[]),
                &[]
            )),
            vec![DEFAULT_PAGE]
        );
        assert_eq!(
            names(&environment_findings(
                &[],
                &info(Some("Panel logowania — Admin"), &[]),
                &[]
            )),
            vec![ADMIN_PANEL]
        );
        assert!(environment_findings(&[], &info(Some("Sklep internetowy"), &[]), &[]).is_empty());
    }
}
