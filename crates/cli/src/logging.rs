use tracing_subscriber::EnvFilter;

/// Włącza logi na stderr. Poziom ustawia zmienna `RUST_LOG` (domyślnie `info`;
/// komunikaty sqlx tylko od `warn`, bo NOTICE z PostgreSQL to szum).
pub fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));
    // try_init: drugie wywołanie (np. w testach) nie przerywa programu.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
