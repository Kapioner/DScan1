//! Silnik skanów: przebieg skanu od podziału na podgrupy do zapisu wyników.
//!
//! - [`run_scan_job`] — tworzy przebieg w bazie, skanuje podgrupy równolegle (S4),
//!   zapisuje każdą podgrupę wsadowo (B5) i mierzy czasy (S6),
//! - [`ScanObserver`] — powiadomienia o postępie (wzorzec Observer), np. dla terminala,
//! - [`nmap_scanner`] — skaner nmap z tempem podzielonym między procesy (S7),
//! - [`WebFingerprintScanner`] — dekorator dodający fingerprinting HTTP (H1, H2).

pub mod adaptive;
mod comparison;
pub mod custom_signatures;
mod dashboard;
mod error;
mod import;
mod job;
mod launch;
mod options;
mod progress;
mod retry;
mod running;
pub mod scheduler;
pub mod scoring;
mod service;
mod setup;
pub mod signature_test;
mod web;
pub mod windows;

pub use comparison::{Comparison, compare_with_previous};
pub use dashboard::{
    Dashboard, Finding, IMPORTANT_CATEGORIES, important_findings, load_dashboard, technology_stats,
};
pub use error::EngineError;
pub use import::{ImportOutcome, ResultImport, import_results, split_by_scope};
pub use job::{
    JobPlan, ScanJobSettings, ScanJobSummary, create_job, drive_job, load_job, run_scan_job,
};
pub use launch::{
    JobScanner, PreparedScan, ScanRequest, build_scanner, effective_settings, job_settings,
    prepare_scan,
};
pub use options::{NmapTuning, RateSettings, nmap_scanner, rate_per_process};
pub use progress::{LogObserver, ScanObserver, ScanProgress, SilentObserver, SubgroupReport};
pub use retry::{RetryPolicy, retry_candidates};
pub use service::{ScanService, StartedScan};
pub use setup::{build_analysis, build_fetcher, load_signatures};
pub use web::WebFingerprintScanner;
