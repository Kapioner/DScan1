// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use common::TestDatabase;
use dscan_db::{check_connection, migration_status, run_migrations};

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

#[tokio::test]
async fn migrations_create_all_tables_and_are_idempotent() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    check_connection(&db.pool).await.unwrap();
    // Drugie uruchomienie nie może nic zepsuć.
    run_migrations(&db.pool).await.unwrap();

    for table in EXPECTED_TABLES {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert!(exists, "brak tabeli {table}");
    }

    let status = migration_status(&db.pool).await.unwrap();
    assert!(status.iter().all(|migration| migration.applied));
    db.drop().await;
}

#[tokio::test]
async fn built_in_roles_are_seeded() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM roles WHERE built_in")
        .fetch_one(&db.pool)
        .await
        .unwrap();

    assert_eq!(count, 4);
    db.drop().await;
}
