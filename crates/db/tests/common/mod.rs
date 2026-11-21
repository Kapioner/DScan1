//! Pomocnicze funkcje testów na prawdziwej bazie. Uruchamiają się tylko, gdy ustawiona jest
//! zmienna `DSCAN_TEST_DATABASE_URL` (CI ustawia ją automatycznie).
//!
//! Każdy test dostaje własny, świeży schemat PostgreSQL, więc testy mogą działać równolegle.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]
// Nie każdy plik testowy używa wszystkich funkcji pomocniczych.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dscan_db::{PgPool, run_migrations};
use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;

const TEST_DB_ENV: &str = "DSCAN_TEST_DATABASE_URL";

static SCHEMA_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Baza testowa z własnym schematem i wykonanymi migracjami.
pub struct TestDatabase {
    pub pool: PgPool,
    schema: String,
    admin_pool: PgPool,
}

impl TestDatabase {
    /// `None`, gdy zmienna z adresem bazy testowej nie jest ustawiona (test zostaje pominięty).
    pub async fn create() -> Option<TestDatabase> {
        let Ok(url) = std::env::var(TEST_DB_ENV) else {
            eprintln!("pomijam test: brak zmiennej {TEST_DB_ENV}");
            return None;
        };
        let schema = unique_schema_name();
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        admin_pool
            .execute(format!("CREATE SCHEMA {schema}").as_str())
            .await
            .unwrap();

        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    connection.execute(search_path.as_str()).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();

        Some(TestDatabase {
            pool,
            schema,
            admin_pool,
        })
    }

    /// Usuwa schemat testu (wywoływane na końcu testu).
    pub async fn drop(self) {
        self.pool.close().await;
        self.admin_pool
            .execute(format!("DROP SCHEMA {} CASCADE", self.schema).as_str())
            .await
            .unwrap();
    }
}

fn unique_schema_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    let counter = SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("test_{}_{}_{}", std::process::id(), counter, nanos)
}
