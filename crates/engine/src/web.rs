//! Skan podgrupy uzupełniony o fingerprinting HTTP (zadania H1, H2).
//!
//! Wzorzec Dekorator: [`WebFingerprintScanner`] opakowuje dowolny skaner podgrup
//! (np. nmap) i po jego wyniku odpytuje znalezione serwery WWW. Pula workerów nic o tym
//! nie wie, a fingerprinting działa równolegle — w ramach każdej podgrupy osobno.

use std::sync::Arc;

use dscan_fingerprint::{HttpFetcher, fingerprint_hosts};
use dscan_scanner::ScannerError;
use dscan_scanner::nmap::ScanOutput;
use dscan_scanner::pool::SubgroupScanner;
use ipnet::IpNet;

/// Skaner podgrup, który po skanie portów pobiera informacje HTTP z usług WWW.
pub struct WebFingerprintScanner<S> {
    inner: S,
    fetcher: Arc<HttpFetcher>,
}

impl<S> WebFingerprintScanner<S> {
    pub fn new(inner: S, fetcher: Arc<HttpFetcher>) -> Self {
        WebFingerprintScanner { inner, fetcher }
    }
}

impl<S: SubgroupScanner> SubgroupScanner for WebFingerprintScanner<S> {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        let mut output = self.inner.scan(targets).await?;
        fingerprint_hosts(&self.fetcher, &mut output.hosts).await;
        Ok(output)
    }
}
