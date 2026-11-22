//! Obserwacje DScan jako findingi informacyjne w formacie „Generic Findings Import” (I5).

use serde_json::{Value, json};

/// Wybrana obserwacja (np. detekcja technologii na usłudze) z dowodami.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    /// Np. `Panel administracyjny` albo `Jenkins 2.4`.
    pub title: String,
    pub confidence: u8,
    /// Dowody: opisy matcherów, nagłówki, tytuł i kod odpowiedzi HTTP.
    pub evidence: Vec<String>,
    /// Adres usługi WWW, jeśli jest.
    pub url: Option<String>,
}

/// Dokument JSON dla parsera „Generic Findings Import”.
pub fn findings_document(observations: &[Observation]) -> Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let findings: Vec<Value> = observations
        .iter()
        .map(|o| {
            let evidence = o.evidence.iter().map(|e| format!("- {e}")).collect::<Vec<_>>().join("\n");
            json!({
                "title": format!("DScan: {} ({}:{}/{})", o.title, o.ip, o.port, o.protocol),
                "severity": "Info",
                "date": today,
                "description": format!(
                    "Obserwacja DScan: **{}** na {}:{}/{} (pewność {}%).\n\nDowody:\n{evidence}",
                    o.title, o.ip, o.port, o.protocol, o.confidence
                ),
                "unique_id_from_tool": format!("dscan:{}:{}:{}:{}", o.ip, o.port, o.protocol, o.title),
                "vuln_id_from_tool": "dscan-observation",
                "endpoints": [ {
                    "host": o.ip,
                    "port": o.port,
                    "protocol": o.url.as_deref().and_then(|u| u.split_once("://")).map(|(s, _)| s.to_string()),
                } ],
                "static_finding": false,
                "dynamic_finding": true,
            })
        })
        .collect();
    json!({ "findings": findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_contains_evidence_and_info_severity() {
        let observation = Observation {
            ip: "10.0.0.5".into(),
            port: 8080,
            protocol: "tcp".into(),
            title: "Jenkins".into(),
            confidence: 90,
            evidence: vec!["nagłówek X-Jenkins: 2.4".into()],
            url: Some("http://10.0.0.5:8080/".into()),
        };
        let document = findings_document(&[observation]);
        let finding = &document["findings"][0];
        assert_eq!(finding["severity"], "Info");
        assert!(
            finding["description"]
                .as_str()
                .unwrap()
                .contains("X-Jenkins")
        );
        assert_eq!(finding["endpoints"][0]["protocol"], "http");
    }
}
