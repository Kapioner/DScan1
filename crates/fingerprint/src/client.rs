//! Klient HTTP/HTTPS (zadanie H1).
//!
//! - przekierowania obsługujemy sami, żeby zapisać cały łańcuch i nie wychodzić poza host,
//! - najpierw próbujemy z weryfikacją certyfikatu; jeśli połączenie HTTPS się nie uda,
//!   ponawiamy bez weryfikacji i oznaczamy `tls_verified = false` (tylko odczyt informacji —
//!   nie wysyłamy żadnych danych logowania ani ciasteczek),
//! - tylko metoda GET, treść czytana do limitu bajtów, bez systemowego proxy.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dscan_core::models::Redirect;
use reqwest::header::LOCATION;
use reqwest::redirect::Policy;
use reqwest::{Client, Url};

use crate::{FetchError, HttpRateLimiter, is_same_host, resolve_location};

/// Ustawienia klienta (z sekcji `[http]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpOptions {
    pub timeout: Duration,
    pub max_redirects: u32,
    pub max_body_bytes: usize,
    pub user_agent: String,
}

/// Odpowiedź po przejściu łańcucha przekierowań.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    /// Adres, pod którym zakończył się łańcuch.
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Początek treści (najwyżej `max_body_bytes`).
    pub body: Vec<u8>,
    pub redirects: Vec<Redirect>,
    pub tls_verified: Option<bool>,
}

/// Klient do odpytywania usług WWW.
pub struct HttpFetcher {
    strict: Client,
    lenient: Client,
    options: HttpOptions,
    limiter: Option<Arc<HttpRateLimiter>>,
}

impl HttpFetcher {
    pub fn new(
        options: HttpOptions,
        limiter: Option<Arc<HttpRateLimiter>>,
    ) -> Result<Self, FetchError> {
        Ok(HttpFetcher {
            strict: build_client(&options, false)?,
            lenient: build_client(&options, true)?,
            options,
            limiter,
        })
    }

    /// Limit czasu zapytań (używany też przy odczycie certyfikatu TLS).
    pub fn timeout(&self) -> Duration {
        self.options.timeout
    }

    /// Pobiera stronę spod `url`; `ip` to adres hosta (do limitu zapytań na host).
    pub async fn fetch(&self, url: &str, ip: IpAddr) -> Result<RawResponse, FetchError> {
        let start = Url::parse(url).map_err(|_| FetchError::InvalidUrl(url.to_string()))?;
        let is_https = start.scheme() == "https";

        match self.follow(&self.strict, start.clone(), ip).await {
            Ok(mut response) => {
                response.tls_verified = is_https.then_some(true);
                Ok(response)
            }
            Err(FetchError::Request(error)) if is_https && error.is_connect() => {
                // Najczęstsza przyczyna: certyfikat self-signed, wygasły lub na inną nazwę.
                let mut response = self.follow(&self.lenient, start, ip).await?;
                response.tls_verified = Some(false);
                Ok(response)
            }
            Err(error) => Err(error),
        }
    }

    /// Wykonuje zapytania GET, śledząc przekierowania w obrębie hosta.
    async fn follow(
        &self,
        client: &Client,
        start: Url,
        ip: IpAddr,
    ) -> Result<RawResponse, FetchError> {
        let mut current = start;
        let mut redirects = Vec::new();
        loop {
            if let Some(limiter) = &self.limiter {
                limiter.acquire(ip).await.map_err(FetchError::Budget)?;
            }
            let response = client
                .get(current.clone())
                .send()
                .await
                .map_err(FetchError::Request)?;
            let status = response.status();
            let next = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|location| resolve_location(&current, location))
                .filter(|_| status.is_redirection());

            if let Some(next) = next {
                redirects.push(Redirect {
                    from: current.to_string(),
                    to: next.to_string(),
                    status_code: status.as_u16(),
                });
                if redirects.len() as u32 > self.options.max_redirects {
                    return Err(FetchError::TooManyRedirects(self.options.max_redirects));
                }
                if is_same_host(&current, &next) {
                    current = next;
                    continue;
                }
                // Przekierowanie na inny host: zapisujemy je, ale tam nie idziemy.
            }
            return self.finish(response, current, redirects).await;
        }
    }

    async fn finish(
        &self,
        mut response: reqwest::Response,
        url: Url,
        redirects: Vec<Redirect>,
    ) -> Result<RawResponse, FetchError> {
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let mut body = Vec::new();
        while body.len() < self.options.max_body_bytes {
            match response.chunk().await.map_err(FetchError::Request)? {
                Some(chunk) => body.extend_from_slice(&chunk),
                None => break,
            }
        }
        body.truncate(self.options.max_body_bytes);
        Ok(RawResponse {
            url: url.to_string(),
            status,
            headers,
            body,
            redirects,
            tls_verified: None,
        })
    }
}

fn build_client(options: &HttpOptions, accept_invalid_certs: bool) -> Result<Client, FetchError> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(options.timeout)
        .connect_timeout(options.timeout.min(Duration::from_secs(5)))
        .user_agent(options.user_agent.clone())
        // Ruch skanera nigdy nie idzie przez proxy z otoczenia (HTTPS_PROXY itp.).
        .no_proxy()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .build()
        .map_err(FetchError::Request)
}
