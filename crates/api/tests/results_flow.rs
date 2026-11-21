//! Import wyników (I2) → dashboard (A8) → eksport (I3) z uprawnieniami według roli,
//! na prawdziwej bazie (pomijane bez `DSCAN_TEST_DATABASE_URL`).

#![allow(clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::TestApp;
use dscan_config::Settings;
use serde_json::json;

const FIRST: &str = r#"<nmaprun version="7.94">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port></ports></host>
<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/></host>
</nmaprun>"#;

const SECOND_CSV: &str = "ip,port,protocol,state,service,product,version\n10.0.0.5,22,tcp,open,ssh,OpenSSH,9.7\n10.0.0.5,8080,tcp,open,http,Jenkins,\n";

fn settings() -> Settings {
    let mut settings = Settings::default();
    settings.scope.allowed_networks = vec!["10.0.0.0/8".parse().unwrap()];
    settings
}

#[tokio::test]
async fn import_dashboard_and_export_with_roles() {
    let Some(app) = TestApp::start_with_scans(settings()).await else {
        return;
    };
    app.add_user(
        "operator",
        "operator-haslo-123",
        "dodawanie_usuwanie_modyfikacja",
    )
    .await;
    app.add_user("czytelnik", "czytelnik-haslo-123", "odczyt")
        .await;
    let operator = app.login("operator", "operator-haslo-123").await;
    let reader = app.login("czytelnik", "czytelnik-haslo-123").await;

    // Odczyt nie może importować (RBAC).
    let body = json!({"format": "nmap-xml", "content": FIRST});
    let (status, ..) = app
        .call(
            "POST",
            "/api/v1/imports/results",
            Some(&reader),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Tryb próbny niczego nie zapisuje; host spoza [scope] jest odrzucony.
    let dry = json!({"format": "nmap-xml", "content": FIRST, "dry_run": true});
    let (status, report, _) = app
        .call(
            "POST",
            "/api/v1/imports/results",
            Some(&operator),
            Some(dry),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["run_id"], serde_json::Value::Null);
    assert_eq!(report["out_of_scope"], json!(["8.8.8.8"]));

    let (status, first, _) = app
        .call(
            "POST",
            "/api/v1/imports/results",
            Some(&operator),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["hosts"], 1);

    // Drugi import (CSV) jest porównywany z pierwszym: nowa usługa i zmieniona wersja.
    let csv = json!({"format": "csv", "content": SECOND_CSV});
    let (status, second, _) = app
        .call(
            "POST",
            "/api/v1/imports/results",
            Some(&operator),
            Some(csv),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let kinds: Vec<&str> = second["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"appeared") && kinds.contains(&"modified"),
        "{kinds:?}"
    );
    let run = second["run_id"].as_i64().unwrap();

    // Dashboard: ostatni przebieg, zmiany i liczniki widzi także rola odczytu.
    let (status, dashboard, _) = app
        .call("GET", "/api/v1/dashboard", Some(&reader), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dashboard["latest_run"]["id"], run);
    assert_eq!(dashboard["open_services"], 2);
    assert_eq!(dashboard["changes"].as_array().unwrap().len(), 2);
    assert_eq!(dashboard["active_hosts"], 1);

    // Eksport usług do CSV z filtrem portu.
    let (status, text, mime) = app
        .call_text("/api/v1/exports/services?format=csv&port=8080", &reader)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(mime.starts_with("text/csv"));
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("10.0.0.5,,8080,tcp,open,http,Jenkins"));

    // Zmiany jako JSON; filtr „tylko poprawione” wymaga results:write.
    let (status, changes, _) = app
        .call(
            "GET",
            &format!("/api/v1/exports/changes?run={run}"),
            Some(&reader),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changes.as_array().unwrap().len(), 2);
    let (status, ..) = app
        .call(
            "GET",
            "/api/v1/exports/hosts?edited=true",
            Some(&reader),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = app
        .call(
            "GET",
            "/api/v1/exports/hosts?format=csv",
            Some(&operator),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    app.stop().await;
}

#[tokio::test]
async fn scan_control_validates_input() {
    let Some(app) = TestApp::start_with_scans(settings()).await else {
        return;
    };
    app.add_user(
        "operator",
        "operator-haslo-123",
        "dodawanie_usuwanie_modyfikacja",
    )
    .await;
    let token = app.login("operator", "operator-haslo-123").await;

    // Cel spoza [scope] — skan nie startuje.
    let (status, body, _) = app
        .call(
            "POST",
            "/api/v1/scans",
            Some(&token),
            Some(json!({"targets": ["8.8.8.8"]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // Nieznany profil.
    let request = json!({"targets": ["10.0.0.1"], "profile": "nie-ma"});
    let (status, ..) = app
        .call("POST", "/api/v1/scans", Some(&token), Some(request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Zatrzymanie skanu, który nie trwa.
    let (status, ..) = app
        .call("POST", "/api/v1/scans/999/stop", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, profiles, _) = app
        .call("GET", "/api/v1/scan-profiles", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(profiles, json!([]));

    app.stop().await;
}
