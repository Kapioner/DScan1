//! Integracje z plikami i systemami zewnętrznymi.
//!
//! Na tym etapie: import celów z CSV/JSON z walidacją i raportem odrzuconych wierszy (zadanie I1).

mod error;
mod target_import;

pub use error::ImportError;
pub use target_import::{ImportFormat, RejectedRow, TargetImport, detect_format, import_targets};
