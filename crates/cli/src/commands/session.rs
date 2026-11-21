//! `dscan login` / `dscan logout` (C5): token sesji zapisany w pliku użytkownika.

use std::net::SocketAddr;

use clap::Args;
use dscan_config::CliOverrides;
use serde_json::json;

use super::{Command, Context};
use crate::client::credentials::{self, Credentials};
use crate::client::types::LoginResponse;
use crate::client::{ApiClient, error_message};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Nazwa użytkownika.
    #[arg(long, short, value_name = "NAZWA")]
    pub user: String,
    /// Adres serwera (domyślnie z [server] listen w dscan.toml).
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,
}

impl Command for LoginArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let server = match &self.server {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => server_url(
                context
                    .load_config(CliOverrides::default())?
                    .settings
                    .server
                    .listen,
            ),
        };
        let password = rpassword::prompt_password(format!("Hasło dla {}: ", self.user))
            .map_err(CliError::Input)?;
        let client = ApiClient::new(&server, "")?;
        let response = reqwest::Client::new()
            .post(client.url("/api/v1/auth/login"))
            .json(&json!({ "username": self.user, "password": password }))
            .send()
            .await
            .map_err(|e| CliError::Http(format!("brak połączenia z {server}: {e}")))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::Api {
                status,
                message: error_message(&body),
            });
        }
        let login: LoginResponse = response
            .json()
            .await
            .map_err(|e| CliError::Http(e.to_string()))?;
        let path = credentials::credentials_path().ok_or(CliError::NotLoggedIn)?;
        let saved = Credentials {
            server,
            username: self.user.clone(),
            token: login.token,
            expires_at: login.expires_at,
        };
        credentials::save(&path, &saved)?;
        println!(
            "Zalogowano jako {} (sesja ważna do {}). Token: {}",
            saved.username,
            saved.expires_at,
            path.display()
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct LogoutArgs {}

impl Command for LogoutArgs {
    /// Kończy sesję na serwerze (najlepsza próba) i usuwa zapisany token.
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        if let Ok(client) = ApiClient::from_saved() {
            let _ = client.post_empty("/api/v1/auth/logout").await;
        }
        let path = credentials::credentials_path().ok_or(CliError::NotLoggedIn)?;
        if credentials::remove(&path)? {
            println!("Wylogowano — usunięto {}", path.display());
        } else {
            println!("Nie byłeś zalogowany.");
        }
        Ok(())
    }
}

/// Adres serwera z `[server] listen`; adres „wszystkie interfejsy” zamieniamy na localhost.
pub fn server_url(listen: SocketAddr) -> String {
    let host = match listen.ip() {
        ip if ip.is_unspecified() && ip.is_ipv4() => "127.0.0.1".to_string(),
        ip if ip.is_unspecified() => "[::1]".to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };
    format!("http://{host}:{}", listen.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_from_listen_address() {
        assert_eq!(
            server_url("127.0.0.1:8080".parse().unwrap()),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            server_url("0.0.0.0:9000".parse().unwrap()),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            server_url("[::]:8080".parse().unwrap()),
            "http://[::1]:8080"
        );
    }
}
