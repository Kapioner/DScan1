//! Wspólna aplikacja testowa: router API na prawdziwej bazie, każdy test we własnym schemacie
//! (pomijane bez `DSCAN_TEST_DATABASE_URL`).

// Nie każdy plik testowy używa wszystkich funkcji pomocniczych.
#![allow(dead_code, clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use dscan_api::{AppState, AuthConfig, build_router};
use dscan_config::Settings;
use dscan_crypto::Cipher;
use dscan_db::{PgPool, run_migrations};
use dscan_engine::ScanService;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

pub struct TestApp {
    pub router: Router,
    pub pool: PgPool,
    schema: String,
    url: String,
}

impl TestApp {
    pub async fn start() -> Option<TestApp> {
        Self::start_with(None).await
    }

    /// Jak `start`, ale z usługą skanów (import, eksport, dashboard) z podanymi ustawieniami.
    pub async fn start_with_scans(settings: Settings) -> Option<TestApp> {
        Self::start_with(Some(settings)).await
    }

    async fn start_with(settings: Option<Settings>) -> Option<TestApp> {
        let Ok(url) = std::env::var("DSCAN_TEST_DATABASE_URL") else {
            eprintln!("pomijam test: brak zmiennej DSCAN_TEST_DATABASE_URL");
            return None;
        };
        let schema = format!(
            "test_api_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_subsec_nanos()
        );
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        admin
            .execute(format!("CREATE SCHEMA {schema}").as_str())
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    connection.execute(search_path.as_str()).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        let auth = AuthConfig {
            session_hours: 1,
            secure_cookies: false,
        };
        let cipher = Cipher::new(&[2; 32]);
        let mut state = AppState::new(pool.clone(), cipher.clone(), auth);
        if let Some(settings) = settings {
            state = state.with_scans(ScanService::new(pool.clone(), cipher, settings));
        }
        let router = build_router(state, 1 << 20);
        Some(TestApp {
            router,
            pool,
            schema,
            url,
        })
    }

    pub async fn add_user(&self, username: &str, password: &str, role: &str) {
        let hash = dscan_auth::hash_password(password).unwrap();
        sqlx::query("INSERT INTO users (username, password_hash, role_id) SELECT $1, $2, id FROM roles WHERE name = $3")
            .bind(username)
            .bind(hash)
            .bind(role)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            cookie,
        )
    }

    /// Odpowiedź jako tekst z typem treści (np. eksport CSV).
    pub async fn call_text(&self, path: &str, token: &str) -> (StatusCode, String, String) {
        let request = Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let mime = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned(), mime)
    }

    pub async fn login(&self, username: &str, password: &str) -> String {
        let (status, body, _) = self
            .call(
                "POST",
                "/api/v1/auth/login",
                None,
                Some(json!({"username": username, "password": password})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        body["token"].as_str().unwrap().to_string()
    }

    pub async fn stop(self) {
        self.pool.close().await;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.url)
            .await
            .unwrap();
        admin
            .execute(format!("DROP SCHEMA {} CASCADE", self.schema).as_str())
            .await
            .unwrap();
    }
}
