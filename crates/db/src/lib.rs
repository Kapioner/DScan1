//! Warstwa bazy danych DScan (PostgreSQL + sqlx).
//!
//! Łączenie z bazą, migracje, szyfrowane kolumny ([`Encrypted`]), rotacja klucza,
//! użytkownicy i cele. Zapytania do kolejnych tabel dochodzą razem z funkcjami, które ich potrzebują.

pub mod columns;
mod encrypted;
mod error;
mod keys;
mod migrations;
mod pool;
mod targets;
mod users;

pub use columns::{ENCRYPTED_COLUMNS, EncryptedColumn};
pub use encrypted::Encrypted;
pub use error::DbError;
pub use keys::{RotatedColumn, reencrypt, rotate_encryption_key};
pub use migrations::{
    MigrationInfo, available_migrations, compute_migration_status, migration_status, run_migrations,
};
pub use pool::{PgPool, PoolOptions, check_connection, connect, connect_lazy};
pub use targets::{InsertSummary, StoredTarget, insert_targets, list_targets, target_kind_name};
pub use users::{ADMIN_ROLE, UserSummary, create_admin, list_users};
