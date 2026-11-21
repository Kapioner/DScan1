use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use crate::DbError;

pub use sqlx::PgPool;

/// Parametry puli połączeń (z sekcji `[database]` konfiguracji).
#[derive(Debug, Clone, Copy)]
pub struct PoolOptions {
    pub max_connections: u32,
    pub connect_timeout: Duration,
}

/// Łączy się z bazą od razu — błąd połączenia wychodzi przy starcie, a nie przy pierwszym zapytaniu.
pub async fn connect(url: &str, options: PoolOptions) -> Result<PgPool, DbError> {
    pool_options(options)
        .connect(url)
        .await
        .map_err(DbError::Connect)
}

/// Tworzy pulę bez łączenia się (połączenie przy pierwszym zapytaniu). Przydatne w testach.
pub fn connect_lazy(url: &str, options: PoolOptions) -> Result<PgPool, DbError> {
    pool_options(options)
        .connect_lazy(url)
        .map_err(DbError::Connect)
}

/// Sprawdza, czy baza odpowiada na proste zapytanie.
pub async fn check_connection(pool: &PgPool) -> Result<(), DbError> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

fn pool_options(options: PoolOptions) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(options.max_connections)
        .acquire_timeout(options.connect_timeout)
}
