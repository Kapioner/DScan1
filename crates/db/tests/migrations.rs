//! Testy na prawdziwej bazie PostgreSQL. Uruchamiają się tylko, gdy ustawiona jest
//! zmienna `DSCAN_TEST_DATABASE_URL` (CI ustawia ją automatycznie).
//! Baza testowa jest czyszczona — nie wskazuj tu bazy z danymi!

use std::time::Duration;

use dscan_db::{PoolOptions, check_connection, connect, migration_status, run_migrations};

const TEST_DB_ENV: &str = "DSCAN_TEST_DATABASE_URL";

const EXPECTED_TABLES: [&str; 13] = [
    "targets",
    "scan_runs",
    "subgroups",
    "hosts",
    "services",
    "http_info",
    "detections",
    "signatures",
    "changes",
    "overrides",
    "users",
    "roles",
    "audit_log",
];

fn test_database_url() -> Option<String> {
    let url = std::env::var(TEST_DB_ENV).ok();
    if url.is_none() {
        eprintln!("pomijam test: brak zmiennej {TEST_DB_ENV}");
    }
    url
}

fn options() -> PoolOptions {
    PoolOptions {
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn migrations_create_all_tables_and_are_idempotent() {
    let Some(url) = test_database_url() else {
        return;
    };
    let pool = connect(&url, options()).await.unwrap();
    check_connection(&pool).await.unwrap();

    run_migrations(&pool).await.unwrap();
    // Drugie uruchomienie nie może nic zepsuć.
    run_migrations(&pool).await.unwrap();

    for table in EXPECTED_TABLES {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("public.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists, "brak tabeli {table}");
    }

    let status = migration_status(&pool).await.unwrap();
    assert!(status.iter().all(|migration| migration.applied));
}

#[tokio::test]
async fn built_in_roles_are_seeded() {
    let Some(url) = test_database_url() else {
        return;
    };
    let pool = connect(&url, options()).await.unwrap();
    run_migrations(&pool).await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM roles WHERE built_in")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(count, 4);
}
