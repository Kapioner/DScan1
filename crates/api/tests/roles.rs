//! Testy ról (Q3): dla każdej z 4 ról wbudowanych dozwolone i zabronione akcje na
//! wszystkich obszarach API (pomijane bez `DSCAN_TEST_DATABASE_URL`).

#![allow(clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::TestApp;
use dscan_config::Settings;
use serde_json::{Value, json};

/// Obszar uprawnień potrzebny do akcji.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Needs {
    Read,
    TargetsWrite,
    ResultsWrite,
    Admin,
}

/// (metoda, ścieżka, treść, wymagane uprawnienie). Ciała są poprawne, więc zamiast 403
/// dozwolona akcja zwraca kod inny niż 401/403 (np. 200, 201, 204, 400, 404).
fn actions() -> Vec<(&'static str, String, Option<Value>, Needs)> {
    vec![
        ("GET", "/api/v1/targets".into(), None, Needs::Read),
        ("GET", "/api/v1/profiles".into(), None, Needs::Read),
        ("GET", "/api/v1/scans".into(), None, Needs::Read),
        ("GET", "/api/v1/dashboard".into(), None, Needs::Read),
        ("GET", "/api/v1/signatures".into(), None, Needs::Read),
        ("GET", "/api/v1/search?cookie=PHPSESSID".into(), None, Needs::Read),
        ("GET", "/api/v1/exports/changes?run=999999".into(), None, Needs::Read),
        ("POST", "/api/v1/targets".into(), Some(json!({"target": "10.77.0.0/24"})), Needs::TargetsWrite),
        ("DELETE", "/api/v1/targets/999999".into(), None, Needs::TargetsWrite),
        ("POST", "/api/v1/profiles".into(), Some(json!({"name": "", "mode": "x"})), Needs::TargetsWrite),
        ("POST", "/api/v1/scans".into(), Some(json!({"targets": ["8.8.8.8"]})), Needs::TargetsWrite),
        ("POST", "/api/v1/scans/999999/stop".into(), None, Needs::TargetsWrite),
        ("POST", "/api/v1/imports/targets".into(), Some(json!({"format": "csv", "content": "target\n", "dry_run": true})), Needs::TargetsWrite),
        ("PUT", "/api/v1/overrides".into(), Some(json!({"ip": "10.7.7.7", "field": "host_note", "value": "x"})), Needs::ResultsWrite),
        ("DELETE", "/api/v1/overrides?ip=10.7.7.7&field=host_note".into(), None, Needs::ResultsWrite),
        ("GET", "/api/v1/users".into(), None, Needs::Admin),
        ("GET", "/api/v1/accounts".into(), None, Needs::Admin),
        ("GET", "/api/v1/roles".into(), None, Needs::Admin),
        ("GET", "/api/v1/audit".into(), None, Needs::Admin),
        ("POST", "/api/v1/roles".into(), Some(json!({"name": "", "permissions": []})), Needs::Admin),
        ("PUT", "/api/v1/users/999999".into(), Some(json!({"role_id": 1, "blocked": false})), Needs::Admin),
    ]
}

/// Czy rola ma uprawnienie (zgodnie z migracją 0001).
fn allowed(role: &str, needs: Needs) -> bool {
    match role {
        "administracja" => true,
        "dodawanie_usuwanie_modyfikacja" => needs != Needs::Admin,
        "modyfikacja_odczyt" => matches!(needs, Needs::Read | Needs::ResultsWrite),
        _ => needs == Needs::Read,
    }
}

#[tokio::test]
async fn every_role_against_every_area() {
    let mut settings = Settings::default();
    settings.scope.allowed_networks = vec!["10.0.0.0/8".parse().unwrap()];
    let Some(app) = TestApp::start_with_scans(settings).await else { return };
    let roles = ["administracja", "dodawanie_usuwanie_modyfikacja", "modyfikacja_odczyt", "odczyt"];
    for (index, role) in roles.iter().enumerate() {
        let login = format!("rola{index}");
        app.add_user(&login, "haslo-testowe-123", role).await;
        let token = app.login(&login, "haslo-testowe-123").await;
        for (method, path, body, needs) in actions() {
            let (status, response, _) = app.call(method, &path, Some(&token), body).await;
            if allowed(role, needs) {
                assert!(
                    status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
                    "{role}: {method} {path} powinno być dozwolone, jest {status} {response}"
                );
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {method} {path} powinno być zabronione");
            }
        }
    }
    // Bez logowania: wszystko poza trasami publicznymi → 401.
    for (method, path, body, _) in actions() {
        let (status, ..) = app.call(method, &path, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} bez sesji");
    }
    app.stop().await;
}

#[tokio::test]
async fn admin_manages_accounts_and_custom_roles() {
    let Some(app) = TestApp::start().await else { return };
    app.add_user("szef", "haslo-testowe-123", "administracja").await;
    let admin = app.login("szef", "haslo-testowe-123").await;

    // Własna rola „audytor”: tylko odczyt.
    let (status, role, _) =
        app.call("POST", "/api/v1/roles", Some(&admin), Some(json!({"name": "audytor", "permissions": ["read"]}))).await;
    assert_eq!(status, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_i64().unwrap();
    let new_user = json!({"username": "jan", "password": "bardzo-dlugie-haslo", "role_id": role_id});
    let (status, user, _) = app.call("POST", "/api/v1/users", Some(&admin), Some(new_user)).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let user_id = user["id"].as_i64().unwrap();

    let jan = app.login("jan", "bardzo-dlugie-haslo").await;
    let (status, ..) = app.call("GET", "/api/v1/targets", Some(&jan), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, ..) = app.call("POST", "/api/v1/targets", Some(&jan), Some(json!({"target": "10.1.1.1"}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Blokada kończy sesję.
    let block = json!({"role_id": role_id, "blocked": true});
    let (status, ..) = app.call("PUT", &format!("/api/v1/users/{user_id}"), Some(&admin), Some(block)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = app.call("GET", "/api/v1/targets", Some(&jan), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Rola z kontem nie da się usunąć; wbudowanej nie można zmienić.
    let (status, ..) = app.call("DELETE", &format!("/api/v1/roles/{role_id}"), Some(&admin), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, roles, _) = app.call("GET", "/api/v1/roles", Some(&admin), None).await;
    let builtin = roles.as_array().unwrap().iter().find(|r| r["built_in"] == true).unwrap()["id"].as_i64().unwrap();
    let change = json!({"name": "x", "permissions": ["read"]});
    let (status, ..) = app.call("PUT", &format!("/api/v1/roles/{builtin}"), Some(&admin), Some(change)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Ostatniego administratora nie można zablokować.
    let (_, accounts, _) = app.call("GET", "/api/v1/accounts", Some(&admin), None).await;
    let me = accounts.as_array().unwrap().iter().find(|a| a["username"] == "szef").unwrap();
    let block_me = json!({"role_id": me["role_id"], "blocked": true});
    let (status, ..) = app.call("PUT", &format!("/api/v1/users/{}", me["id"]), Some(&admin), Some(block_me)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wszystko trafiło do dziennika audytu.
    let (_, audit, _) = app.call("GET", "/api/v1/audit?entity=user", Some(&admin), None).await;
    assert!(audit.as_array().unwrap().len() >= 2, "{audit}");
    app.stop().await;
}
