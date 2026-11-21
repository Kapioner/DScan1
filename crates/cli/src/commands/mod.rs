//! Implementacje podkomend (wzorzec Command): każda podkomenda to osobny typ
//! z metodą `execute`, a [`Commands`] tylko przekazuje wywołanie dalej.

pub mod config;
pub mod db;
pub mod diff;
pub mod import;
pub mod keys;
pub mod planned;
pub mod scan;
pub mod scan_report;
pub mod serve;
pub mod sig;
pub mod targets;
pub mod user;
pub mod web_setup;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use dscan_config::{AppConfig, CliOverrides, ConfigLoader, DatabaseSettings};
use dscan_crypto::Cipher;
use dscan_db::{PgPool, PoolOptions};

use crate::cli::Commands;
use crate::error::CliError;

/// Plik wczytywany automatycznie, jeśli użytkownik nie poda innego.
pub const DEFAULT_CONFIG_FILE: &str = "dscan.toml";

/// Wspólny interfejs wszystkich poleceń.
// Trait używamy tylko wewnątrz tej binarki, a polecenia są wykonywane bezpośrednio
// w `main` (bez `tokio::spawn`),
// więc ograniczenie `Send` dla zwracanego Future nie jest potrzebne.
#[allow(async_fn_in_trait)]
pub trait Command {
    async fn execute(&self, context: &Context) -> Result<(), CliError>;
}

/// Dane wspólne dla wszystkich poleceń (globalne flagi).
#[derive(Debug, Clone)]
pub struct Context {
    config_path: Option<PathBuf>,
}

impl Context {
    pub fn new(config_path: Option<PathBuf>) -> Self {
        Context { config_path }
    }

    /// Wczytuje konfigurację: domyślne < plik < zmienne DSCAN_* < flagi CLI.
    /// Jawnie podany plik musi istnieć; domyślny `dscan.toml` jest opcjonalny.
    pub fn load_config(&self, overrides: CliOverrides) -> Result<AppConfig, CliError> {
        let loader = match &self.config_path {
            Some(path) => ConfigLoader::new().file(path),
            None => ConfigLoader::new().optional_file(DEFAULT_CONFIG_FILE),
        };
        Ok(loader.cli_overrides(overrides).load()?)
    }

    /// Opis źródła konfiguracji do wyświetlenia użytkownikowi.
    pub fn config_source(&self) -> String {
        let default_exists = Path::new(DEFAULT_CONFIG_FILE).exists();
        describe_config_source(self.config_path.as_deref(), default_exists)
    }
}

/// Skąd pochodzi konfiguracja: plik jawny, plik domyślny albo same wartości domyślne.
pub fn describe_config_source(explicit_path: Option<&Path>, default_exists: bool) -> String {
    match (explicit_path, default_exists) {
        (Some(path), _) => path.display().to_string(),
        (None, true) => DEFAULT_CONFIG_FILE.to_string(),
        (None, false) => "brak pliku (wartości domyślne + zmienne DSCAN_*)".to_string(),
    }
}

/// Flagi nadpisujące konfigurację — najwyższa warstwa (C3).
#[derive(Debug, Clone, Default, Args)]
#[command(next_help_heading = "Nadpisanie konfiguracji")]
pub struct OverrideArgs {
    /// Adres nasłuchiwania serwera, np. 127.0.0.1:8080 [server.listen].
    #[arg(long, value_name = "ADRES:PORT")]
    pub listen: Option<SocketAddr>,
    /// Limit pakietów na sekundę dla nmap [limits.nmap_max_rate].
    #[arg(long, value_name = "PAKIETY/S")]
    pub max_rate: Option<u32>,
    /// Liczba równoległych procesów nmap [limits.max_parallel_nmap].
    #[arg(long, value_name = "LICZBA")]
    pub parallel: Option<u32>,
}

impl OverrideArgs {
    pub fn to_overrides(&self) -> CliOverrides {
        CliOverrides {
            listen: self.listen,
            nmap_max_rate: self.max_rate,
            max_parallel_nmap: self.parallel,
        }
    }
}

/// Parametry puli połączeń z sekcji `[database]`.
pub fn pool_options(settings: &DatabaseSettings) -> PoolOptions {
    PoolOptions {
        max_connections: settings.max_connections,
        connect_timeout: Duration::from_secs(settings.connect_timeout_seconds),
    }
}

/// Szyfr z klucza `DSCAN_ENCRYPTION_KEY`. Polecenia administracyjne wymagają klucza (C6) —
/// kto go nie zna, nie powinien zmieniać danych bezpośrednio w bazie.
pub fn cipher_from_config(config: &AppConfig) -> Result<Cipher, CliError> {
    let key = config.require_encryption_key()?;
    Ok(Cipher::new(key.as_bytes()))
}

/// Łączy się z bazą wskazaną w `DSCAN_DATABASE_URL`.
pub async fn connect_database(config: &AppConfig) -> Result<PgPool, CliError> {
    let url = config.require_database_url()?;
    let options = pool_options(&config.settings.database);
    Ok(dscan_db::connect(url.expose(), options).await?)
}

impl Command for Commands {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        match self {
            Commands::Serve(args) => args.execute(context).await,
            Commands::Scan(args) => args.execute(context).await,
            Commands::Targets(args) => args.execute(context).await,
            Commands::Import(args) => args.execute(context).await,
            Commands::Export(args) => args.execute(context).await,
            Commands::Diff(args) => args.execute(context).await,
            Commands::Sig(args) => args.execute(context).await,
            Commands::User(args) => args.execute(context).await,
            Commands::Config(args) => args.execute(context).await,
            Commands::Db(args) => args.execute(context).await,
            Commands::Keys(args) => args.execute(context).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_args_map_to_config_overrides() {
        let args = OverrideArgs {
            listen: Some("0.0.0.0:9000".parse().unwrap()),
            max_rate: Some(5),
            parallel: None,
        };

        let overrides = args.to_overrides();

        assert_eq!(overrides.nmap_max_rate, Some(5));
        assert_eq!(overrides.max_parallel_nmap, None);
        assert_eq!(overrides.listen.map(|addr| addr.port()), Some(9000));
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        let context = Context::new(Some(PathBuf::from("/nie/ma/takiego/pliku.toml")));
        let result = context.load_config(CliOverrides::default());
        assert!(matches!(result, Err(CliError::Config(_))));
    }

    #[test]
    fn config_source_descriptions() {
        assert_eq!(
            describe_config_source(Some(Path::new("a.toml")), true),
            "a.toml"
        );
        assert_eq!(describe_config_source(None, true), "dscan.toml");
        assert!(describe_config_source(None, false).starts_with("brak pliku"));
    }

    #[test]
    fn pool_options_convert_seconds() {
        let options = pool_options(&DatabaseSettings::default());
        assert_eq!(options.connect_timeout, Duration::from_secs(5));
        assert_eq!(options.max_connections, 10);
    }
}
