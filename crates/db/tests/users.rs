// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use common::TestDatabase;
use dscan_db::{ADMIN_ROLE, DbError, create_admin, list_users};

#[tokio::test]
async fn admin_is_created_with_admin_role() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };

    create_admin(&db.pool, "admin", "$argon2id$fake")
        .await
        .unwrap();

    let users = list_users(&db.pool).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "admin");
    assert_eq!(users[0].role, ADMIN_ROLE);
    assert!(!users[0].is_blocked);
    db.drop().await;
}

#[tokio::test]
async fn duplicate_username_is_reported() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    create_admin(&db.pool, "admin", "$argon2id$fake")
        .await
        .unwrap();

    let result = create_admin(&db.pool, "admin", "$argon2id$other").await;

    assert!(matches!(result, Err(DbError::UserExists(name)) if name == "admin"));
    db.drop().await;
}
