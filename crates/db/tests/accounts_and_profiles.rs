// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use chrono::{TimeDelta, Utc};
use common::TestDatabase;
use dscan_core::models::{
    Cookie, Detection, Evidence, EvidenceKind, Host, HttpHeader, HttpInfo, Protocol, Service,
    ServiceState, Target, TargetKind,
};
use dscan_crypto::{Cipher, hash_token};
use dscan_db::*;

fn cipher() -> Cipher {
    Cipher::new(&[8; 32])
}

#[tokio::test]
async fn session_is_valid_until_expiry_or_block() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let user_id = create_admin(&db.pool, "admin", "$argon2id$x")
        .await
        .unwrap();
    let (valid, expired) = (hash_token("ważny"), hash_token("wygasły"));
    create_session(&db.pool, user_id, &valid, Utc::now() + TimeDelta::hours(1))
        .await
        .unwrap();
    create_session(
        &db.pool,
        user_id,
        &expired,
        Utc::now() - TimeDelta::minutes(1),
    )
    .await
    .unwrap();

    let user = find_session_user(&db.pool, &valid).await.unwrap().unwrap();
    assert_eq!(user.username, "admin");
    assert_eq!(user.role, ADMIN_ROLE);
    assert!(user.permissions.contains(&"admin".to_string()));
    assert!(
        find_session_user(&db.pool, &expired)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(delete_expired_sessions(&db.pool).await.unwrap(), 1);

    sqlx::query("UPDATE users SET is_blocked = TRUE")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(find_session_user(&db.pool, &valid).await.unwrap().is_none());

    delete_session(&db.pool, &valid).await.unwrap();
    assert_eq!(count_users(&db.pool).await.unwrap(), 1);
    db.drop().await;
}

#[tokio::test]
async fn target_crud_and_groups() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let target = Target {
        kind: TargetKind::Cidr("10.0.0.0/24".parse().unwrap()),
        group: Some("lab".into()),
        note: Some("notatka".into()),
    };

    let created = create_target(&db.pool, &cipher(), &target)
        .await
        .unwrap()
        .unwrap();
    assert!(
        create_target(&db.pool, &cipher(), &target)
            .await
            .unwrap()
            .is_none()
    );

    let updated = update_target(&db.pool, &cipher(), created.id, Some("prod"), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.group.as_deref(), Some("prod"));
    assert_eq!(updated.note, None);

    let groups = list_target_groups(&db.pool).await.unwrap();
    assert_eq!(
        groups,
        vec![TargetGroup {
            name: "prod".into(),
            targets: 1
        }]
    );
    assert_eq!(
        list_targets(&db.pool, &cipher(), Some("prod"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        list_targets(&db.pool, &cipher(), Some("lab"))
            .await
            .unwrap()
            .is_empty()
    );

    assert!(delete_target(&db.pool, created.id).await.unwrap());
    assert!(!delete_target(&db.pool, created.id).await.unwrap());
    assert!(
        get_target(&db.pool, &cipher(), created.id)
            .await
            .unwrap()
            .is_none()
    );
    db.drop().await;
}

fn profile(name: &str) -> ProfileData {
    ProfileData {
        name: name.into(),
        mode: "services".into(),
        target_group: Some("lab".into()),
        ports: vec!["22".into(), "80-90".into()],
        windows: vec![ProfileWindow {
            start: "22:00".into(),
            end: "06:00".into(),
        }],
        frequency_minutes: Some(1440),
        enabled: true,
        max_rate: Some(50),
    }
}

#[tokio::test]
async fn profile_crud() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let ProfileSaved::Saved(created) = create_profile(&db.pool, &profile("nocny")).await.unwrap()
    else {
        panic!("profil nie został zapisany");
    };
    assert_eq!(created.data, profile("nocny"));
    assert_eq!(
        create_profile(&db.pool, &profile("nocny")).await.unwrap(),
        ProfileSaved::NameTaken
    );

    let mut changed = profile("nocny");
    changed.frequency_minutes = None;
    changed.windows.clear();
    let ProfileSaved::Saved(updated) = update_profile(&db.pool, created.id, &changed)
        .await
        .unwrap()
    else {
        panic!("profil nie został zmieniony");
    };
    assert_eq!(updated.data, changed);
    assert_eq!(
        update_profile(&db.pool, 999_999, &changed).await.unwrap(),
        ProfileSaved::NotFound
    );

    assert_eq!(list_profiles(&db.pool).await.unwrap().len(), 1);
    assert!(delete_profile(&db.pool, created.id).await.unwrap());
    assert!(get_profile(&db.pool, created.id).await.unwrap().is_none());
    db.drop().await;
}

#[tokio::test]
async fn http_info_is_saved_with_encrypted_headers_and_cookies() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let run = create_scan_run(&db.pool, "test", 1, &[]).await.unwrap();
    let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
    let mut web = Service::new(443, Protocol::Tcp, ServiceState::Open);
    web.http = Some(HttpInfo {
        url: "https://10.0.0.5:443/".into(),
        status_code: 200,
        title: Some("Panel".into()),
        headers: vec![HttpHeader {
            name: "Server".into(),
            value: "tajny-serwer".into(),
        }],
        cookies: vec![Cookie {
            name: "sid".into(),
            value: "sekretna-sesja".into(),
            domain: None,
            path: None,
            secure: true,
            http_only: true,
            same_site: None,
        }],
        redirect_chain: Vec::new(),
        tls_verified: Some(false),
        certificate: None,
        favicon: None,
        simhash: None,
    });
    host.services = vec![web, Service::new(22, Protocol::Tcp, ServiceState::Open)];

    let summary = save_scan_results(&db.pool, &cipher(), run.run_id, &[host])
        .await
        .unwrap();
    assert_eq!(summary.http, 1);

    let (title, tls, headers, cookies): (Option<String>, Option<bool>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT title, tls_verified, headers, cookies FROM http_info")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(title.as_deref(), Some("Panel"));
    assert_eq!(tls, Some(false));
    assert!(!String::from_utf8_lossy(&headers).contains("tajny"));
    assert!(!String::from_utf8_lossy(&cookies).contains("sekretna"));
    let opened: Vec<HttpHeader> = Encrypted::from_bytes(headers)
        .open(&cipher(), &columns::HTTP_INFO_HEADERS)
        .unwrap();
    assert_eq!(opened[0].value, "tajny-serwer");
    db.drop().await;
}

#[tokio::test]
async fn detections_and_fingerprints_are_saved() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let run = create_scan_run(&db.pool, "test", 1, &[]).await.unwrap();
    let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
    let mut web = Service::new(80, Protocol::Tcp, ServiceState::Open);
    web.product = Some("nginx".into());
    web.detections = vec![Detection::from_evidence(
        "nginx".into(),
        Some("1.24.0".into()),
        vec![Evidence {
            kind: EvidenceKind::Header,
            description: "nagłówek server".into(),
            weight: 90,
        }],
    )];
    host.services = vec![web];

    save_scan_results(&db.pool, &cipher(), run.run_id, &[host])
        .await
        .unwrap();

    let (technology, version, confidence, evidence): (String, Option<String>, i16, String) =
        sqlx::query_as("SELECT technology, version, confidence, evidence::text FROM detections")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        (technology.as_str(), version.as_deref(), confidence),
        ("nginx", Some("1.24.0"), 90)
    );
    assert!(evidence.contains("nagłówek server"));

    let fingerprints = run_fingerprints(&db.pool, run.run_id).await.unwrap();
    assert_eq!(fingerprints.len(), 1);
    assert_eq!(fingerprints.values().next().unwrap().len(), 64);
    db.drop().await;
}

#[tokio::test]
async fn overrides_survive_new_runs_and_are_applied_on_read() {
    use dscan_core::models::{OverrideField, apply_overrides};

    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = create_admin(&db.pool, "admin", "$argon2id$x")
        .await
        .unwrap();
    let scan = |product: &'static str| {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut web = Service::new(80, Protocol::Tcp, ServiceState::Open);
        web.product = Some(product.into());
        host.services = vec![web];
        host
    };
    let first = create_scan_run(&db.pool, "test", 1, &[]).await.unwrap();
    save_scan_results(&db.pool, &cipher(), first.run_id, &[scan("nginx")])
        .await
        .unwrap();
    let target = OverrideTarget {
        ip: "10.0.0.5".parse().unwrap(),
        port: Some(80),
        protocol: Some(Protocol::Tcp),
    };
    set_override(
        &db.pool,
        &cipher(),
        target,
        OverrideField::Product,
        "Kamera Hikvision",
        Some(admin),
    )
    .await
    .unwrap();
    set_override(
        &db.pool,
        &cipher(),
        target,
        OverrideField::Product,
        "Kamera Hikvision DS-2CD",
        Some(admin),
    )
    .await
    .unwrap();

    // Nowy przebieg (np. trwający skan) — poprawka nadal obowiązuje, bo jest przypięta do adresu.
    let second = create_scan_run(&db.pool, "test", 1, &[]).await.unwrap();
    save_scan_results(&db.pool, &cipher(), second.run_id, &[scan("nginx")])
        .await
        .unwrap();
    let overrides = list_overrides(&db.pool, &cipher()).await.unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].updated_by.as_deref(), Some("admin"));
    let mut hosts = load_run_hosts(&db.pool, second.run_id).await.unwrap();
    apply_overrides(&mut hosts, &overrides);
    assert_eq!(
        hosts[0].services[0].product.as_deref(),
        Some("Kamera Hikvision DS-2CD")
    );
    assert_eq!(hosts[0].services[0].edited_fields, vec!["product"]);

    // Obserwacja w bazie bez zmian, a wartość poprawki jest zaszyfrowana.
    let stored: String =
        sqlx::query_scalar("SELECT product FROM services ORDER BY id DESC LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(stored, "nginx");
    let raw: Vec<u8> = sqlx::query_scalar("SELECT value FROM overrides")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("Hikvision"));

    assert!(
        delete_override(&db.pool, target, OverrideField::Product)
            .await
            .unwrap()
    );
    assert!(
        list_overrides(&db.pool, &cipher())
            .await
            .unwrap()
            .is_empty()
    );
    db.drop().await;
}
