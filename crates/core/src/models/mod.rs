//! Struktury danych opisujące cele, wyniki skanów i zmiany między przebiegami.

mod change;
mod detection;
mod host;
mod http;
mod port_range;
mod scan_run;
mod service;
mod target;

pub use change::{Change, ChangeKind};
pub use detection::{Detection, Evidence, EvidenceKind, MAX_CONFIDENCE, cap_confidence};
pub use host::{Host, HostStatus};
pub use http::{Cookie, HttpHeader, HttpInfo, Redirect};
pub use port_range::{PortRange, PortRangeError, parse_port_range};
pub use scan_run::{ScanRun, ScanStatus};
pub use service::{Protocol, Service, ServiceKey, ServiceState};
pub use target::{Target, TargetKind};
