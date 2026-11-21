//! Silnik skanów: przebieg skanu od podziału na podgrupy do zapisu wyników.
//!
//! - [`run_scan_job`] — tworzy przebieg w bazie, skanuje podgrupy równolegle (S4),
//!   zapisuje każdą podgrupę wsadowo (B5) i mierzy czasy (S6),
//! - [`ScanObserver`] — powiadomienia o postępie (wzorzec Observer), np. dla terminala,
//! - [`nmap_scanner`] — skaner nmap z tempem podzielonym między procesy (S7).

mod error;
mod job;
mod options;
mod progress;

pub use error::EngineError;
pub use job::{ScanJobSettings, ScanJobSummary, run_scan_job};
pub use options::{RateSettings, nmap_scanner, rate_per_process};
pub use progress::{ScanObserver, ScanProgress, SilentObserver, SubgroupReport};
