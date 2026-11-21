//! Porównanie przebiegu z poprzednim (zadanie M1).

use chrono::Utc;
use dscan_core::models::{Change, compare_runs};
use dscan_db::PgPool;

use crate::EngineError;

/// Wynik porównania z poprzednim przebiegiem.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub previous_run_id: i64,
    pub changes: Vec<Change>,
}

/// Porównuje przebieg z poprzednim udanym przebiegiem tego samego profilu i zapisuje zmiany.
pub async fn compare_with_previous(
    pool: &PgPool,
    run_id: i64,
    profile: &str,
) -> Result<Option<Comparison>, EngineError> {
    let Some(previous_run_id) = dscan_db::previous_completed_run(pool, run_id, profile).await?
    else {
        return Ok(None);
    };
    let previous = dscan_db::run_fingerprints(pool, previous_run_id).await?;
    let current = dscan_db::run_fingerprints(pool, run_id).await?;
    let changes = compare_runs(&previous, &current, (previous_run_id, run_id), Utc::now());
    dscan_db::save_changes(pool, &changes).await?;
    Ok(Some(Comparison {
        previous_run_id,
        changes,
    }))
}
