// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use common::TestDatabase;
use dscan_core::models::{Target, TargetKind};
use dscan_crypto::Cipher;
use dscan_db::{insert_targets, list_targets, rotate_encryption_key};

fn target_with_note(value: &str, note: &str) -> Target {
    Target {
        kind: TargetKind::Ip(value.parse().unwrap()),
        group: Some("lab".to_string()),
        note: Some(note.to_string()),
    }
}

#[tokio::test]
async fn note_is_stored_encrypted_and_read_back() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let cipher = Cipher::new(&[1; 32]);

    let summary = insert_targets(
        &db.pool,
        &cipher,
        &[target_with_note("10.0.0.1", "hasło w notatce")],
    )
    .await
    .unwrap();
    assert_eq!(summary.inserted, 1);

    let raw: Vec<u8> = sqlx::query_scalar("SELECT note FROM targets")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("notatce"));

    let targets = list_targets(&db.pool, &cipher, None).await.unwrap();
    assert_eq!(targets[0].note.as_deref(), Some("hasło w notatce"));
    assert_eq!(targets[0].group.as_deref(), Some("lab"));
    db.drop().await;
}

#[tokio::test]
async fn duplicates_are_skipped() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let cipher = Cipher::new(&[1; 32]);
    let target = target_with_note("10.0.0.1", "x");

    insert_targets(&db.pool, &cipher, std::slice::from_ref(&target))
        .await
        .unwrap();
    let second = insert_targets(&db.pool, &cipher, &[target]).await.unwrap();

    assert_eq!(second.inserted, 0);
    assert_eq!(second.already_present, 1);
    db.drop().await;
}

#[tokio::test]
async fn key_rotation_reencrypts_all_values() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let old = Cipher::new(&[1; 32]);
    let new = Cipher::new(&[2; 32]);
    insert_targets(
        &db.pool,
        &old,
        &[
            target_with_note("10.0.0.1", "a"),
            target_with_note("10.0.0.2", "b"),
        ],
    )
    .await
    .unwrap();

    let report = rotate_encryption_key(&db.pool, &old, &new).await.unwrap();

    let notes = report
        .iter()
        .find(|column| column.context == "targets.note")
        .unwrap();
    assert_eq!(notes.values, 2);
    assert_eq!(
        list_targets(&db.pool, &new, None).await.unwrap()[1]
            .note
            .as_deref(),
        Some("b")
    );
    assert!(list_targets(&db.pool, &old, None).await.is_err());
    db.drop().await;
}

#[tokio::test]
async fn rotation_with_wrong_old_key_changes_nothing() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let real = Cipher::new(&[1; 32]);
    let wrong = Cipher::new(&[9; 32]);
    insert_targets(&db.pool, &real, &[target_with_note("10.0.0.1", "a")])
        .await
        .unwrap();

    assert!(
        rotate_encryption_key(&db.pool, &wrong, &Cipher::new(&[2; 32]))
            .await
            .is_err()
    );

    // Transakcja wycofana: dane nadal otwiera prawdziwy klucz.
    assert!(list_targets(&db.pool, &real, None).await.is_ok());
    db.drop().await;
}
