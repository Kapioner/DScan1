use clap::Args;
use dscan_api::{AppState, AuthConfig, build_router_with};
use dscan_auth::{hash_password, validate_password_strength, validate_username};
use dscan_config::{AppConfig, collect_warnings};
use dscan_db::PgPool;
use std::sync::Arc;

use dscan_engine::ScanService;
use dscan_engine::scheduler::run_scheduler;
use dscan_integrations::defectdojo::DefectDojoClient;
use tokio::net::TcpListener;

use super::{Command, Context, OverrideArgs, cipher_from_config, connect_database};
use crate::error::CliError;
use crate::logging::init_logging;

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[command(flatten)]
    pub overrides: OverrideArgs,
}

impl Command for ServeArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        init_logging();
        let config = context.load_config(self.overrides.to_overrides())?;
        log_warnings(&config);

        // Serwer zapisuje dane wrażliwe, więc bez klucza szyfrowania nie startuje.
        let cipher = cipher_from_config(&config)?;
        let url = config.require_database_url()?;
        tracing::info!("łączenie z bazą {}", url.masked());
        let pool = connect_database(&config).await?;
        dscan_db::run_migrations(&pool).await?;
        tracing::info!("schemat bazy aktualny");
        ensure_initial_admin(&pool, &config).await?;
        let expired = dscan_db::delete_expired_sessions(&pool).await?;
        if expired > 0 {
            tracing::info!("usunięto wygasłe sesje: {expired}");
        }

        let address = config.settings.server.listen;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|source| CliError::Bind { address, source })?;
        tracing::info!("DScan działa: http://{address}/ (API: /api/v1, Ctrl+C kończy)");

        let server = &config.settings.server;
        let auth = AuthConfig {
            session_hours: server.session_hours,
            secure_cookies: server.secure_cookies,
        };
        // Przebiegi przerwane np. restartem serwera nie trwają — wstrzymujemy je do wznowienia (S9).
        let orphaned = dscan_db::pause_orphaned_runs(&pool).await?;
        if orphaned > 0 {
            tracing::warn!(
                "wstrzymano przerwane przebiegi: {orphaned} (wznowienie: dscan resume ID)"
            );
        }
        let scans = ScanService::new(pool.clone(), cipher.clone(), config.settings.clone());
        // Harmonogram profili z bazy (S8): sprawdza co minutę okna i częstotliwość.
        tokio::spawn(run_scheduler(scans.clone()));
        let mut state = AppState::new(pool, cipher, auth).with_scans(scans.clone());
        let dojo = &config.settings.defectdojo;
        match DefectDojoClient::from_config(dojo, config.defectdojo_token.as_ref()) {
            Ok(Some(client)) => {
                tracing::info!("DefectDojo: {} (produkt „{}”)", dojo.url, dojo.product_name);
                state = state.with_defectdojo(Arc::new(client));
                if dojo.auto_import {
                    tokio::spawn(auto_import(state.clone(), scans.subscribe_completed()));
                }
            }
            Ok(None) if dojo.enabled => {
                tracing::warn!("DefectDojo włączone, ale brak DSCAN_DEFECTDOJO_TOKEN")
            }
            Ok(None) => {}
            Err(error) => tracing::warn!("{error}"),
        }
        let router = build_router_with(state, server.max_body_bytes, dscan_web::web_routes());
        dscan_api::serve(listener, router)
            .await
            .map_err(CliError::Server)
    }
}

/// I4: po każdym udanym przebiegu wysyła surowy XML nmap do DefectDojo.
async fn auto_import(state: AppState, mut completed: tokio::sync::broadcast::Receiver<i64>) {
    while let Ok(run_id) = completed.recv().await {
        let Some(client) = state.defectdojo.clone() else {
            return;
        };
        match dscan_api::defectdojo_import_run(&state, &client, run_id).await {
            Ok(response) => tracing::info!(
                "DefectDojo: przebieg #{run_id} → test {:?}",
                response.test_id
            ),
            Err(error) => tracing::warn!("DefectDojo: przebieg #{run_id}: {error:?}"),
        }
    }
}

/// Pierwszy start (pusta tabela użytkowników): tworzy administratora z
/// `DSCAN_ADMIN_USERNAME` / `DSCAN_ADMIN_PASSWORD`. Gdy konta już istnieją, nic nie robi.
async fn ensure_initial_admin(pool: &PgPool, config: &AppConfig) -> Result<(), CliError> {
    if dscan_db::count_users(pool).await? > 0 {
        if config.initial_admin.is_some() {
            tracing::info!(
                "w bazie są już konta — DSCAN_ADMIN_USERNAME/DSCAN_ADMIN_PASSWORD nie są używane"
            );
        }
        return Ok(());
    }
    let Some(admin) = &config.initial_admin else {
        tracing::warn!(
            "brak kont użytkowników — ustaw DSCAN_ADMIN_USERNAME i DSCAN_ADMIN_PASSWORD \
             albo utwórz konto: dscan user create-admin LOGIN"
        );
        return Ok(());
    };
    validate_username(&admin.username)?;
    validate_password_strength(admin.expose_password())?;
    let hash = hash_password(admin.expose_password())?;
    dscan_db::create_admin(pool, &admin.username, &hash).await?;
    tracing::info!(
        "utworzono administratora '{}' ze zmiennych środowiskowych",
        admin.username
    );
    Ok(())
}

fn log_warnings(config: &AppConfig) {
    for warning in collect_warnings(config) {
        tracing::warn!("{warning}");
    }
}
