//! Logowanie, sesje i CRUD na prawdziwej bazie (pomijane bez `DSCAN_TEST_DATABASE_URL`).
//! Każdy test działa we własnym schemacie PostgreSQL.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::TestApp;
use dscan_crypto::Cipher;
use serde_json::json;

#[tokio::test]
async fn login_session_and_logout() {
    let Some(app) = TestApp::start().await else {
        return;
    };
    app.add_user("admin", "bardzo-tajne-haslo", "administracja")
        .await;

    let (status, _, _) = app
        .call(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username": "admin", "password": "złe-hasło"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = app
        .call(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username": "nikt", "password": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body, cookie) = app
        .call(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username": "admin", "password": "bardzo-tajne-haslo"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["role"], "administracja");
    let cookie = cookie.unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let token = body["token"].as_str().unwrap();

    let (status, me, _) = app.call("GET", "/api/v1/auth/me", Some(token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["username"], "admin");

    let (status, _, cookie) = app
        .call("POST", "/api/v1/auth/logout", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(cookie.unwrap().contains("Max-Age=0"));
    let (status, _, _) = app.call("GET", "/api/v1/auth/me", Some(token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    app.stop().await;
}

#[tokio::test]
async fn targets_crud_with_permissions() {
    let Some(app) = TestApp::start().await else {
        return;
    };
    app.add_user(
        "operator",
        "haslo-operatora-1",
        "dodawanie_usuwanie_modyfikacja",
    )
    .await;
    app.add_user("czytelnik", "haslo-czytelnika-1", "odczyt")
        .await;
    let operator = app.login("operator", "haslo-operatora-1").await;
    let reader = app.login("czytelnik", "haslo-czytelnika-1").await;
    let new_target = json!({"target": "10.0.0.7/24", "group": "lab", "note": "sieć testowa"});

    let (status, _, _) = app
        .call(
            "POST",
            "/api/v1/targets",
            Some(&reader),
            Some(new_target.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, created, _) = app
        .call(
            "POST",
            "/api/v1/targets",
            Some(&operator),
            Some(new_target.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["value"], "10.0.0.0/24");
    assert_eq!(created["note"], "sieć testowa");
    let id = created["id"].as_i64().unwrap();

    let (status, _, _) = app
        .call("POST", "/api/v1/targets", Some(&operator), Some(new_target))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body, _) = app
        .call(
            "POST",
            "/api/v1/targets",
            Some(&operator),
            Some(json!({"target": "zły cel"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("niepoprawny cel"));

    let (status, list, _) = app
        .call("GET", "/api/v1/targets?group=lab", Some(&reader), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);

    let (status, updated, _) = app
        .call(
            "PUT",
            &format!("/api/v1/targets/{id}"),
            Some(&operator),
            Some(json!({"group": "prod", "note": null})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["group"], "prod");
    let (_, groups, _) = app.call("GET", "/api/v1/groups", Some(&reader), None).await;
    assert_eq!(groups, json!([{"name": "prod", "targets": 1}]));

    let (status, _, _) = app
        .call(
            "DELETE",
            &format!("/api/v1/targets/{id}"),
            Some(&operator),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = app
        .call("GET", &format!("/api/v1/targets/{id}"), Some(&reader), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    app.stop().await;
}

#[tokio::test]
async fn profiles_crud_and_validation() {
    let Some(app) = TestApp::start().await else {
        return;
    };
    app.add_user("admin", "bardzo-tajne-haslo", "administracja")
        .await;
    let token = app.login("admin", "bardzo-tajne-haslo").await;
    let profile = json!({
        "name": "nocny", "mode": "services", "target_group": "lab", "ports": ["22", "80-90"],
        "windows": [{"start": "22:00", "end": "06:00"}], "frequency_minutes": 1440
    });

    let (status, created, _) = app
        .call(
            "POST",
            "/api/v1/profiles",
            Some(&token),
            Some(profile.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["enabled"], true);
    assert_eq!(created["windows"][0]["start"], "22:00");
    let id = created["id"].as_i64().unwrap();

    let (status, _, _) = app
        .call("POST", "/api/v1/profiles", Some(&token), Some(profile))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, _) = app
        .call(
            "POST",
            "/api/v1/profiles",
            Some(&token),
            Some(json!({"name": "x", "mode": "services", "frequency_minutes": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, updated, _) = app
        .call(
            "PUT",
            &format!("/api/v1/profiles/{id}"),
            Some(&token),
            Some(json!({"name": "nocny", "mode": "discovery", "enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["mode"], "discovery");
    assert_eq!(updated["windows"], json!([]));

    let (_, list, _) = app
        .call("GET", "/api/v1/profiles", Some(&token), None)
        .await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (status, _, _) = app
        .call(
            "DELETE",
            &format!("/api/v1/profiles/{id}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    app.stop().await;
}

#[tokio::test]
async fn overrides_are_applied_to_run_results() {
    use dscan_core::models::{Host, Protocol, Service, ServiceState};

    let Some(app) = TestApp::start().await else {
        return;
    };
    app.add_user("analityk", "haslo-analityka-1", "modyfikacja_odczyt")
        .await;
    app.add_user("czytelnik", "haslo-czytelnika-1", "odczyt")
        .await;
    let analyst = app.login("analityk", "haslo-analityka-1").await;
    let reader = app.login("czytelnik", "haslo-czytelnika-1").await;

    let run = dscan_db::create_scan_run(&app.pool, "services", 1, &[])
        .await
        .unwrap();
    let mut host = Host::new("10.0.0.5".parse().unwrap(), chrono::Utc::now());
    let mut web = Service::new(80, Protocol::Tcp, ServiceState::Open);
    web.product = Some("nginx".into());
    host.services = vec![web];
    dscan_db::save_scan_results(&app.pool, &Cipher::new(&[2; 32]), run.run_id, &[host])
        .await
        .unwrap();

    let edit = json!({"ip": "10.0.0.5", "port": 80, "protocol": "tcp", "field": "product", "value": "Kamera Hikvision"});
    let (status, _, _) = app
        .call(
            "PUT",
            "/api/v1/overrides",
            Some(&reader),
            Some(edit.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = app
        .call("PUT", "/api/v1/overrides", Some(&analyst), Some(edit))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body, _) = app
        .call(
            "PUT",
            "/api/v1/overrides",
            Some(&analyst),
            Some(json!({"ip": "10.0.0.5", "field": "product", "value": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("portu"));

    let (status, hosts, _) = app
        .call(
            "GET",
            &format!("/api/v1/scans/{}/hosts", run.run_id),
            Some(&reader),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hosts[0]["services"][0]["product"], "Kamera Hikvision");
    assert_eq!(hosts[0]["services"][0]["edited_fields"], json!(["product"]));

    let (_, list, _) = app
        .call("GET", "/api/v1/overrides", Some(&reader), None)
        .await;
    assert_eq!(list[0]["updated_by"], "analityk");

    let (status, _, _) = app
        .call(
            "DELETE",
            "/api/v1/overrides?ip=10.0.0.5&port=80&protocol=tcp&field=product",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, hosts, _) = app
        .call(
            "GET",
            &format!("/api/v1/scans/{}/hosts", run.run_id),
            Some(&reader),
            None,
        )
        .await;
    assert_eq!(hosts[0]["services"][0]["product"], "nginx");
    let (status, _, _) = app
        .call("GET", "/api/v1/scans/999999/hosts", Some(&reader), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    app.stop().await;
}

/// Macierz uprawnień (A3): każda rola × każdy rodzaj operacji.
#[tokio::test]
async fn role_permission_matrix() {
    let Some(app) = TestApp::start().await else {
        return;
    };
    let roles = [
        ("administracja", true, true, true),
        ("dodawanie_usuwanie_modyfikacja", true, true, false),
        ("modyfikacja_odczyt", false, true, false),
        ("odczyt", false, false, false),
    ];
    for (index, (role, can_write_targets, can_write_results, can_admin)) in
        roles.into_iter().enumerate()
    {
        let login = format!("u{index}");
        app.add_user(&login, "haslo-testowe-123", role).await;
        let token = app.login(&login, "haslo-testowe-123").await;

        let (status, _, _) = app.call("GET", "/api/v1/targets", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK, "{role}: odczyt");

        let target = json!({"target": format!("10.9.{index}.0/24")});
        let (status, _, _) = app
            .call("POST", "/api/v1/targets", Some(&token), Some(target))
            .await;
        let expected = if can_write_targets {
            StatusCode::CREATED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(status, expected, "{role}: zapis celu");

        let edit = json!({"ip": "10.9.9.9", "field": "host_note", "value": "x"});
        let (status, _, _) = app
            .call("PUT", "/api/v1/overrides", Some(&token), Some(edit))
            .await;
        let expected = if can_write_results {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(status, expected, "{role}: poprawka wyniku");

        let (status, _, _) = app.call("GET", "/api/v1/users", Some(&token), None).await;
        let expected = if can_admin {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(status, expected, "{role}: administracja");
    }
    let (status, _, _) = app.call("GET", "/api/v1/targets", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    app.stop().await;
}
