//! Skaner DScan.
//!
//! - [`targets`]: parsowanie i walidacja celów (IP, CIDR, domeny), deduplikacja,
//!   kontrola zakresu i strumieniowe rozwijanie adresów (zadanie S2),
//! - [`nmap`]: uruchamianie nmap i parsowanie jego wyniku XML (zadanie S3).

mod error;
pub mod nmap;
pub mod targets;

pub use error::ScannerError;
