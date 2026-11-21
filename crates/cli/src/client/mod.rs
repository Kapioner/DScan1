//! CLI jako klient API (C5): polecenia `scan`, `import`, `export`, `diff` i `sig` wysyłają
//! żądania do serwera z tokenem z `dscan login`, więc obowiązują je te same uprawnienia
//! (RBAC) co interfejs WWW.

pub mod commands;
pub mod credentials;
pub mod report;
pub mod types;

use chrono::Utc;
use reqwest::{Method, RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::CliError;
use credentials::Credentials;

/// Klient HTTP serwera DScan z tokenem `Authorization: Bearer`.
pub struct ApiClient {
    http: reqwest::Client,
    server: String,
    token: String,
}

impl ApiClient {
    pub fn new(server: &str, token: &str) -> Result<Self, CliError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("dscan-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CliError::Http(e.to_string()))?;
        Ok(ApiClient {
            http,
            server: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Klient z zapisanego logowania; brak pliku albo wygasły token → [`CliError::NotLoggedIn`].
    pub fn from_saved() -> Result<Self, CliError> {
        let path = credentials::credentials_path().ok_or(CliError::NotLoggedIn)?;
        let saved: Credentials = credentials::load(&path)?.ok_or(CliError::NotLoggedIn)?;
        if saved.is_expired(Utc::now()) {
            return Err(CliError::NotLoggedIn);
        }
        Self::new(&saved.server, &saved.token)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server)
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, self.url(path))
            .bearer_auth(&self.token)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        decode(send(self.request(Method::GET, path)).await?).await
    }

    /// Odpowiedź jako tekst (np. eksport CSV).
    pub async fn get_text(&self, path: &str) -> Result<String, CliError> {
        send(self.request(Method::GET, path))
            .await?
            .text()
            .await
            .map_err(|e| CliError::Http(e.to_string()))
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        decode(send(self.request(Method::POST, path).json(body)).await?).await
    }

    pub async fn delete(&self, path: &str) -> Result<(), CliError> {
        send(self.request(Method::DELETE, path)).await.map(|_| ())
    }

    /// POST bez treści odpowiedzi (np. zatrzymanie skanu).
    pub async fn post_empty(&self, path: &str) -> Result<(), CliError> {
        send(self.request(Method::POST, path)).await.map(|_| ())
    }
}

/// Wysyła żądanie; status błędu zamienia na [`CliError`] z komunikatem serwera.
async fn send(request: RequestBuilder) -> Result<Response, CliError> {
    let response = request
        .send()
        .await
        .map_err(|e| CliError::Http(format!("brak połączenia z serwerem: {e}")))?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotLoggedIn);
    }
    let body = response.text().await.unwrap_or_default();
    Err(CliError::Api {
        status: status.as_u16(),
        message: error_message(&body),
    })
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, CliError> {
    response
        .json()
        .await
        .map_err(|e| CliError::Http(format!("niezrozumiała odpowiedź serwera: {e}")))
}

/// Pole `error` z odpowiedzi błędu API albo cała treść.
pub fn error_message(body: &str) -> String {
    serde_json::from_str::<types::ErrorBody>(body)
        .map(|b| b.error)
        .unwrap_or_else(|_| body.trim().to_string())
}

/// Koduje wartość do parametru zapytania (litery, cyfry i `-._~` bez zmian).
pub fn encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_is_normalized() {
        let client = ApiClient::new("http://127.0.0.1:8080/", "t").unwrap();
        assert_eq!(
            client.url("/api/v1/scans"),
            "http://127.0.0.1:8080/api/v1/scans"
        );
    }

    #[test]
    fn error_message_prefers_json_field() {
        assert_eq!(
            error_message(r#"{"error":"brak uprawnień"}"#),
            "brak uprawnień"
        );
        assert_eq!(error_message("zwykły tekst\n"), "zwykły tekst");
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode_query("WordPress 6"), "WordPress%206");
        assert_eq!(encode_query("a-b_c"), "a-b_c");
    }
}
