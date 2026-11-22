//! Skaner DScan.
//!
//! - [`targets`]: parsowanie i walidacja celów (IP, CIDR, domeny), deduplikacja,
//!   kontrola zakresu i strumieniowe rozwijanie adresów (zadanie S2),
//! - [`nmap`]: uruchamianie nmap i parsowanie jego wyniku XML (zadanie S3),
//! - [`subgroups`] i [`pool`]: podział na podgrupy i równoległe skanowanie (zadanie S4),
//! - [`rate`]: łączny limit tempa dzielony między procesy nmap (zadanie S7).

mod error;
pub mod nmap;
pub mod pool;
pub mod rate;
pub mod safety;
pub mod subgroups;
pub mod targets;

pub use error::ScannerError;
