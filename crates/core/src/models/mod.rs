//! Struktury danych opisujące cele, wyniki skanów i zmiany między przebiegami.

mod certificate;
mod change;
mod compare;
mod detection;
mod host;
mod http;
mod overrides;
mod port_range;
mod presence;
mod scan_run;
mod service;
mod target;

pub use certificate::CertificateInfo;
pub use change::{Change, ChangeKind};
pub use compare::{compare_runs, fingerprint_input, service_fingerprint};
pub use detection::{Detection, Evidence, EvidenceKind, MAX_CONFIDENCE, cap_confidence};
pub use host::{Host, HostStatus};
pub use http::{Cookie, HttpHeader, HttpInfo, Redirect};
pub use overrides::{Override, OverrideField, apply_overrides};
pub use port_range::{PortRange, PortRangeError, parse_port_range};
pub use presence::{Presence, next_presence};
pub use scan_run::{ScanRun, ScanStatus, calculate_progress_percent, estimate_remaining};
pub use service::{Protocol, Service, ServiceKey, ServiceState};
pub use target::{Target, TargetKind};
