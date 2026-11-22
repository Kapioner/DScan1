//! DefectDojo (I4, I5): import surowego XML nmap przez API v2 `/import-scan/` (parser
//! „Nmap Scan”) i eksport wybranych obserwacji jako findingów informacyjnych
//! (parser „Generic Findings Import”). Produkt i engagement z sekcji `[defectdojo]`.

mod findings;
mod xml;

use std::time::Duration;

use dscan_config::{ApiToken, DefectDojoSettings};
use reqwest::multipart::{Form, Part};
use serde::Deserialize;

pub use findings::{Observation, findings_document};
pub use xml::merge_nmap_xml;

/// Błąd komunikacji z DefectDojo.
#[derive(Debug)]
pub struct DojoError(pub String);

impl std::fmt::Display for DojoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DefectDojo: {}", self.0)
    }
}

impl std::error::Error for DojoError {}

/// Odpowiedź `/import-scan/` (tylko potrzebne pola).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ImportResult {
    #[serde(default)]
    pub test: Option<i64>,
    #[serde(default)]
    pub engagement_id: Option<i64>,
    #[serde(default)]
    pub product_id: Option<i64>,
}

/// Klient API DefectDojo z tokenem (`Authorization: Token …`).
#[derive(Debug, Clone)]
pub struct DefectDojoClient {
    http: reqwest::Client,
    settings: DefectDojoSettings,
    token: ApiToken,
}

impl DefectDojoClient {
    /// `None`, gdy integracja jest wyłączona albo brak tokenu.
    pub fn from_config(
        settings: &DefectDojoSettings,
        token: Option<&ApiToken>,
    ) -> Result<Option<Self>, DojoError> {
        let (true, Some(token)) = (settings.enabled, token) else {
            return Ok(None);
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .danger_accept_invalid_certs(!settings.verify_tls)
            .build()
            .map_err(|e| DojoError(e.to_string()))?;
        Ok(Some(DefectDojoClient {
            http,
            settings: settings.clone(),
            token: token.clone(),
        }))
    }

    pub fn settings(&self) -> &DefectDojoSettings {
        &self.settings
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.settings.url.trim_end_matches('/'))
    }

    /// Wspólne pola importu: produkt, engagement (tworzone automatycznie), data, tagi.
    fn base_form(&self, scan_type: &str, test_title: &str) -> Form {
        Form::new()
            .text("scan_type", scan_type.to_string())
            .text("product_name", self.settings.product_name.clone())
            .text("product_type_name", self.settings.product_type.clone())
            .text("engagement_name", self.settings.engagement_name.clone())
            .text("auto_create_context", "true")
            .text("active", "true")
            .text("verified", "false")
            .text("minimum_severity", "Info")
            .text("close_old_findings", "false")
            .text(
                "scan_date",
                chrono::Utc::now().format("%Y-%m-%d").to_string(),
            )
            .text("test_title", test_title.to_string())
            .text("tags", "dscan")
    }

    async fn send(&self, form: Form) -> Result<ImportResult, DojoError> {
        let response = self
            .http
            .post(self.url("/api/v2/import-scan/"))
            .header("Authorization", format!("Token {}", self.token.expose()))
            .multipart(form)
            .send()
            .await
            .map_err(|e| DojoError(format!("brak połączenia: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let excerpt: String = body.chars().take(300).collect();
            return Err(DojoError(format!("HTTP {status}: {excerpt}")));
        }
        response
            .json()
            .await
            .map_err(|e| DojoError(format!("niezrozumiała odpowiedź: {e}")))
    }

    /// I4: import surowego XML nmap przebiegu (parser „Nmap Scan”).
    pub async fn import_nmap(&self, run_id: i64, xml: String) -> Result<ImportResult, DojoError> {
        let file = Part::text(xml)
            .file_name(format!("dscan-przebieg-{run_id}.xml"))
            .mime_str("application/xml")
            .map_err(|e| DojoError(e.to_string()))?;
        let form = self
            .base_form("Nmap Scan", &format!("DScan przebieg #{run_id}"))
            .part("file", file);
        self.send(form).await
    }

    /// I5: wybrane obserwacje jako findingi informacyjne (parser „Generic Findings Import”).
    pub async fn export_findings(
        &self,
        run_id: i64,
        observations: &[Observation],
    ) -> Result<ImportResult, DojoError> {
        let document = findings_document(observations);
        let json = serde_json::to_string(&document).map_err(|e| DojoError(e.to_string()))?;
        let file = Part::text(json)
            .file_name(format!("dscan-obserwacje-{run_id}.json"))
            .mime_str("application/json")
            .map_err(|e| DojoError(e.to_string()))?;
        let form = self
            .base_form(
                "Generic Findings Import",
                &format!("DScan obserwacje #{run_id}"),
            )
            .part("file", file);
        self.send(form).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_requires_enabled_and_token() {
        let mut settings = DefectDojoSettings::default();
        let token = ApiToken::from_value(Some("abc"));
        assert!(
            DefectDojoClient::from_config(&settings, token.as_ref())
                .unwrap()
                .is_none()
        );
        settings.enabled = true;
        assert!(
            DefectDojoClient::from_config(&settings, None)
                .unwrap()
                .is_none()
        );
        let client = DefectDojoClient::from_config(&settings, token.as_ref())
            .unwrap()
            .unwrap();
        assert_eq!(
            client.url("/api/v2/import-scan/"),
            "http://127.0.0.1:8081/api/v2/import-scan/"
        );
    }
}
