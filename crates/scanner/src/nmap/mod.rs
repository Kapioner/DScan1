//! Wrapper nmap (zadanie S3).
//!
//! 1. [`build_nmap_args`] — argumenty dla profilu (`discovery`: `-sn`, `services`: `-sV`),
//! 2. [`NmapCommand::run`] — uruchomienie nmap (`tokio::process`), cele podawane przez stdin,
//! 3. [`parse_nmap_xml`] — wynik `-oX` → struktury serde,
//! 4. [`to_hosts`] — zamiana na model domeny (`Host`, `Service`).
//!
//! Surowy XML jest zachowywany w [`ScanOutput::raw_xml`] (do importu w DefectDojo).

mod args;
mod convert;
mod runner;
mod xml;

pub use args::{NmapOptions, NmapProfile, build_nmap_args, ports_argument};
pub use convert::{map_port_state, map_protocol, to_hosts};
pub use runner::{NmapCommand, ScanOutput, run_scan};
pub use xml::{NmapRun, parse_nmap_xml};
