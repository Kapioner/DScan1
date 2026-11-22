//! Warstwa bazy danych DScan (PostgreSQL + sqlx).
//!
//! Łączenie z bazą, migracje, szyfrowane kolumny ([`Encrypted`]), rotacja klucza,
//! użytkownicy i sesje, cele, profile skanów, przebiegi skanów i wsadowy zapis wyników. Zapytania do kolejnych tabel dochodzą razem z funkcjami, które ich potrzebują.

mod accounts;
mod audit;
mod blind_index;
mod changes;
pub mod columns;
mod encrypted;
mod error;
mod http_results;
mod keys;
mod migrations;
mod overrides;
mod pool;
mod presence;
mod profiles;
mod results;
mod resume;
mod run_hosts;
mod scan_runs;
mod sessions;
mod signatures;
mod subgroups;
mod target_crud;
mod targets;
mod users;

pub use accounts::{
    ALL_PERMISSIONS, AccountChange, Role, UserDetails, create_role, create_user, delete_role,
    list_roles, list_user_details, set_password, update_role, update_user, validate_role,
};
pub use audit::{AuditEntry, AuditFilter, AuditRecord, insert_audit, list_audit};
pub use blind_index::{BlindKind, BlindMatch, blind_entries, header_value_key, search_blind_index};
pub use changes::{
    changes_for_ip, list_changes, previous_completed_run, run_fingerprints, save_changes,
};
pub use columns::{ENCRYPTED_COLUMNS, EncryptedColumn};
pub use encrypted::Encrypted;
pub use error::DbError;
pub use http_results::HTTP_INFO_PER_INSERT;
pub use keys::{RotatedColumn, reencrypt, rotate_encryption_key};
pub use migrations::{
    MigrationInfo, available_migrations, compute_migration_status, migration_status, run_migrations,
};
pub use overrides::{OverrideTarget, delete_override, list_overrides, set_override};
pub use pool::{PgPool, PoolOptions, check_connection, connect, connect_lazy};
pub use presence::{
    PresenceUpdate, load_presence, mark_unstable, response_history, update_presence,
};
pub use profiles::{
    ProfileData, ProfileSaved, ProfileWindow, ScanProfile, create_profile, delete_profile,
    get_profile, list_profiles, update_profile,
};
pub use results::{
    HOSTS_PER_INSERT, SERVICES_PER_INSERT, SaveSummary, insert_hosts_with_services,
    save_scan_results,
};
pub use resume::{
    ResumableRun, add_retry_subgroup, last_profile_run, load_resumable_run, pause_orphaned_runs,
    recent_subgroup_timings, reset_subgroup, run_networks, set_run_status,
};
pub use run_hosts::{load_run_hosts, load_run_hosts_with_certificates};
pub use scan_runs::{
    CreatedScanRun, NewRun, create_scan_run, create_scan_run_with, finish_scan_run, get_scan_run,
    list_scan_runs,
};
pub use sessions::{
    SessionUser, create_session, delete_expired_sessions, delete_session, find_session_user,
};
pub use signatures::{
    CustomSignature, delete_custom_signature, list_custom_signatures, save_custom_signature,
};
pub use subgroups::{
    SubgroupCompletion, complete_subgroup, fail_subgroup, mark_subgroup_running, run_raw_xml,
};
pub use target_crud::{
    TargetGroup, create_target, delete_target, get_target, list_target_groups, update_target,
};
pub use targets::{InsertSummary, StoredTarget, insert_targets, list_targets, target_kind_name};
pub use users::{
    ADMIN_ROLE, LoginUser, UserSummary, count_users, create_admin, find_login_user, list_users,
    record_login,
};
