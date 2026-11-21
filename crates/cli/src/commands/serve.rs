use clap::Args;
use dscan_api::{AppState, build_router};
use dscan_config::{AppConfig, collect_warnings};
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
        cipher_from_config(&config)?;
        let url = config.require_database_url()?;
        tracing::info!("łączenie z bazą {}", url.masked());
        let pool = connect_database(&config).await?;
        dscan_db::run_migrations(&pool).await?;
        tracing::info!("schemat bazy aktualny");

        let address = config.settings.server.listen;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|source| CliError::Bind { address, source })?;
        tracing::info!("DScan działa: http://{address}/api/v1/health (Ctrl+C kończy)");

        let router = build_router(AppState::new(pool), config.settings.server.max_body_bytes);
        dscan_api::serve(listener, router)
            .await
            .map_err(CliError::Server)
    }
}

fn log_warnings(config: &AppConfig) {
    for warning in collect_warnings(config) {
        tracing::warn!("{warning}");
    }
}
