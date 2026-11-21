use sqlx::migrate::Migrator;

use crate::{DbError, PgPool};

/// Migracje wkompilowane w binarkę z katalogu `crates/db/migrations`
/// (do uruchomienia nie są potrzebne żadne pliki obok programu).
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Stan pojedynczej migracji.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationInfo {
    pub version: i64,
    pub description: String,
    pub applied: bool,
}

/// Wykonuje wszystkie jeszcze niezastosowane migracje.
pub async fn run_migrations(pool: &PgPool) -> Result<(), DbError> {
    MIGRATOR.run(pool).await.map_err(DbError::Migrate)
}

/// Lista migracji dostępnych w binarce: (wersja, opis).
pub fn available_migrations() -> Vec<(i64, String)> {
    MIGRATOR
        .iter()
        .map(|migration| (migration.version, migration.description.to_string()))
        .collect()
}

/// Stan migracji w podłączonej bazie.
pub async fn migration_status(pool: &PgPool) -> Result<Vec<MigrationInfo>, DbError> {
    let applied = applied_versions(pool).await?;
    Ok(compute_migration_status(&available_migrations(), &applied))
}

/// Łączy listę dostępnych migracji z wersjami zapisanymi w bazie.
pub fn compute_migration_status(
    available: &[(i64, String)],
    applied_versions: &[i64],
) -> Vec<MigrationInfo> {
    available
        .iter()
        .map(|(version, description)| MigrationInfo {
            version: *version,
            description: description.clone(),
            applied: applied_versions.contains(version),
        })
        .collect()
}

/// Wersje zapisane przez sqlx w tabeli `_sqlx_migrations` (pusta lista, gdy tabeli jeszcze nie ma).
async fn applied_versions(pool: &PgPool) -> Result<Vec<i64>, DbError> {
    let table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(DbError::Query)?;

    if !table_exists {
        return Ok(Vec::new());
    }

    sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_are_present() {
        let migrations = available_migrations();
        assert!(!migrations.is_empty());
        assert_eq!(migrations[0].0, 1);
    }

    #[test]
    fn status_marks_applied_versions() {
        let available = vec![(1, "initial".to_string()), (2, "next".to_string())];

        let status = compute_migration_status(&available, &[1]);

        assert!(status[0].applied);
        assert!(!status[1].applied);
        assert_eq!(status[1].description, "next");
    }

    #[test]
    fn status_without_applied_versions() {
        let available = vec![(1, "initial".to_string())];
        let status = compute_migration_status(&available, &[]);
        assert!(!status[0].applied);
    }
}
