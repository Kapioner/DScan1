use serde::{Deserialize, Serialize};

/// Górna granica pewności identyfikacji.
pub const MAX_CONFIDENCE: u8 = 100;

/// Źródło dowodu, na podstawie którego rozpoznano technologię.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Header,
    Cookie,
    Body,
    Favicon,
    Path,
    Certificate,
    /// Pola product/version/CPE z `nmap -sV`.
    NmapService,
}

/// Pojedynczy dowód wraz z wagą, jaką wnosi do pewności detekcji.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub description: String,
    pub weight: u8,
}

/// Rozpoznana technologia (np. WordPress 6.4) z pewnością 0–100.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub technology: String,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<Evidence>,
}

impl Detection {
    /// Tworzy detekcję, wyliczając pewność z wag dowodów.
    pub fn from_evidence(
        technology: String,
        version: Option<String>,
        evidence: Vec<Evidence>,
    ) -> Self {
        let total_weight: u32 = evidence.iter().map(|item| u32::from(item.weight)).sum();
        Detection {
            technology,
            version,
            confidence: cap_confidence(total_weight),
            evidence,
        }
    }
}

/// Sumę wag przycina do zakresu 0–100.
pub fn cap_confidence(total_weight: u32) -> u8 {
    let capped = total_weight.min(u32::from(MAX_CONFIDENCE));
    // Po przycięciu wartość zawsze mieści się w u8, więc fallback nigdy nie wystąpi.
    u8::try_from(capped).unwrap_or(MAX_CONFIDENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(weight: u8) -> Evidence {
        Evidence {
            kind: EvidenceKind::Header,
            description: "X-Powered-By".to_string(),
            weight,
        }
    }

    #[test]
    fn cap_confidence_limits_to_hundred() {
        assert_eq!(cap_confidence(0), 0);
        assert_eq!(cap_confidence(55), 55);
        assert_eq!(cap_confidence(100), 100);
        assert_eq!(cap_confidence(250), 100);
    }

    #[test]
    fn confidence_is_sum_of_evidence_weights() {
        let detection = Detection::from_evidence(
            "WordPress".to_string(),
            None,
            vec![evidence(30), evidence(40)],
        );
        assert_eq!(detection.confidence, 70);
    }

    #[test]
    fn confidence_without_evidence_is_zero() {
        let detection = Detection::from_evidence("nginx".to_string(), None, Vec::new());
        assert_eq!(detection.confidence, 0);
    }
}
