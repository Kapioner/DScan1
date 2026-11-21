//! Warstwa bazy danych DScan (PostgreSQL + sqlx).
//!
//! Łączenie z bazą, migracje, szyfrowane kolumny ([`Encrypted`]), rotacja klucza,
//! użytkownicy, cele, przebiegi skanów i wsadowy zapis wyników. Zapytania do kolejnych tabel dochodzą razem z funkcjami, które ich potrzebują.

pub mod columns;
mod encrypted;
mod error;
mod keys;
mod migrations;
mod pool;
mod results;
mod scan_runs;
mod subgroups;
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
pub use results::{
    HOSTS_PER_INSERT, SERVICES_PER_INSERT, SaveSummary, insert_hosts_with_services,
    save_scan_results,
};
pub use scan_runs::{
    CreatedScanRun, create_scan_run, finish_scan_run, get_scan_run, list_scan_runs,
};
pub use subgroups::{SubgroupCompletion, complete_subgroup, fail_subgroup, mark_subgroup_running};
pub use targets::{InsertSummary, StoredTarget, insert_targets, list_targets, target_kind_name};
pub use users::{ADMIN_ROLE, UserSummary, create_admin, list_users};
