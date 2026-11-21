//! Odpowiedzi API widziane przez klienta (tylko pola potrzebne CLI).

use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RejectedTarget {
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct StartScanResponse {
    pub run_id: i64,
    pub address_count: String,
    pub networks: Vec<String>,
    pub rejected: Vec<RejectedTarget>,
    pub stop_at: Option<DateTime<Utc>>,
}

/// Przebieg (`GET /api/v1/scans/{id}`).
#[derive(Debug, Deserialize)]
pub struct ScanRunView {
    pub id: i64,
    pub status: String,
    pub progress_percent: f64,
    pub completed_subgroups: u32,
    pub total_subgroups: u32,
    pub elapsed_seconds: i64,
    pub estimated_remaining_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeView {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Deserialize)]
pub struct RejectedRow {
    pub line: usize,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct TargetImportResponse {
    pub accepted: usize,
    pub rejected: Vec<RejectedRow>,
    pub inserted: u64,
    pub duplicates: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResultImportResponse {
    pub run_id: Option<i64>,
    pub hosts: usize,
    pub open_ports: usize,
    pub out_of_scope: Vec<String>,
    pub previous_run_id: Option<i64>,
    pub changes: Vec<ChangeView>,
    pub became_inactive: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureView {
    pub name: String,
    pub category: Option<String>,
    pub matchers: usize,
}

#[derive(Debug, Deserialize)]
pub struct EvidenceView {
    pub description: String,
    pub weight: u8,
}

#[derive(Debug, Deserialize)]
pub struct DetectionView {
    pub technology: String,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<EvidenceView>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureTestResponse {
    pub status_code: u16,
    pub url: String,
    pub probes: usize,
    pub detections: Vec<DetectionView>,
}

#[derive(Debug, Deserialize)]
pub struct TargetView {
    pub id: i64,
    pub value: String,
}
