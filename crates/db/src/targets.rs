use chrono::{DateTime, Utc};
use dscan_core::models::{Target, TargetKind};
use dscan_crypto::Cipher;

use crate::columns::TARGETS_NOTE;
use crate::{DbError, Encrypted, PgPool};

/// Cel zapisany w bazie (notatka już odszyfrowana).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTarget {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub group: Option<String>,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Wynik zapisu: ile celów dodano, a ile już było w bazie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InsertSummary {
    pub inserted: u64,
    pub already_present: u64,
}

/// Nazwa rodzaju celu zapisywana w kolumnie `targets.kind`.
pub fn target_kind_name(kind: &TargetKind) -> &'static str {
    match kind {
        TargetKind::Ip(_) => "ip",
        TargetKind::Cidr(_) => "cidr",
        TargetKind::Domain(_) => "domain",
    }
}

/// Zapisuje cele w jednej transakcji; istniejące (ten sam rodzaj i wartość) są pomijane.
/// Notatki są szyfrowane przed zapisem.
pub async fn insert_targets(
    pool: &PgPool,
    cipher: &Cipher,
    targets: &[Target],
) -> Result<InsertSummary, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let mut summary = InsertSummary::default();

    for target in targets {
        let note = match &target.note {
            Some(text) => Some(Encrypted::seal(cipher, &TARGETS_NOTE, text)?),
            None => None,
        };
        let result = sqlx::query(
            "INSERT INTO targets (kind, value, target_group, note) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (kind, value) DO NOTHING",
        )
        .bind(target_kind_name(&target.kind))
        .bind(target.kind.to_string())
        .bind(&target.group)
        .bind(note)
        .execute(&mut *transaction)
        .await
        .map_err(DbError::Query)?;

        if result.rows_affected() == 1 {
            summary.inserted += 1;
        } else {
            summary.already_present += 1;
        }
    }

    transaction.commit().await.map_err(DbError::Query)?;
    Ok(summary)
}

type TargetRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<Encrypted<String>>,
    DateTime<Utc>,
);

/// Wszystkie cele z odszyfrowanymi notatkami.
pub async fn list_targets(pool: &PgPool, cipher: &Cipher) -> Result<Vec<StoredTarget>, DbError> {
    let rows: Vec<TargetRow> = sqlx::query_as(
        "SELECT id, kind, value, target_group, note, created_at FROM targets ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    rows.into_iter()
        .map(|(id, kind, value, group, note, created_at)| {
            let note = match note {
                Some(encrypted) => Some(encrypted.open(cipher, &TARGETS_NOTE)?),
                None => None,
            };
            Ok(StoredTarget {
                id,
                kind,
                value,
                group,
                note,
                created_at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_match_database_check_constraint() {
        assert_eq!(
            target_kind_name(&TargetKind::Ip("10.0.0.1".parse().unwrap())),
            "ip"
        );
        assert_eq!(
            target_kind_name(&TargetKind::Cidr("10.0.0.0/24".parse().unwrap())),
            "cidr"
        );
        assert_eq!(
            target_kind_name(&TargetKind::Domain("a.pl".into())),
            "domain"
        );
    }
}
