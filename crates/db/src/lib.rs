//! Warstwa bazy danych DScan (PostgreSQL + sqlx).
//!
//! Na tym etapie: łączenie z bazą i migracje schematu. Zapytania do
//! poszczególnych tabel dojdą razem z funkcjami, które ich potrzebują.

mod error;
mod migrations;
mod pool;

pub use error::DbError;
pub use migrations::{
    MigrationInfo, available_migrations, compute_migration_status, migration_status, run_migrations,
};
pub use pool::{PgPool, PoolOptions, check_connection, connect, connect_lazy};
