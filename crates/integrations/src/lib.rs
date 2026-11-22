//! Integracje z plikami i systemami zewnętrznymi.
//!
//! Import celów z CSV/JSON (I1), import wyników skanów — nmap XML, JSON, CSV (I2) —
//! oraz eksport hostów, usług i zmian do JSON/CSV z filtrami (I3).

pub mod defectdojo;
mod error;
mod evaluation;
mod export;
mod result_import;
mod target_import;

pub use error::ImportError;
pub use evaluation::{Evaluation, Score, evaluate};
pub use export::{
    ChangeRow, ExportFilter, ServiceRow, change_rows, filter_hosts, service_rows, to_csv,
};
pub use result_import::{
    ParsedResults, ResultFormat, detect_result_format, parse_result_format, parse_results,
};
pub use target_import::{ImportFormat, RejectedRow, TargetImport, detect_format, import_targets};
