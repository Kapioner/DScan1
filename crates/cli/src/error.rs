use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use dscan_auth::AuthError;
use dscan_config::ConfigError;
use dscan_db::DbError;
use dscan_engine::EngineError;
use dscan_integrations::ImportError;
use dscan_scanner::ScannerError;

/// Błędy zgłaszane przez polecenia `dscan`.
#[derive(Debug)]
pub enum CliError {
    Config(ConfigError),
    Database(DbError),
    Scanner(ScannerError),
    Engine(EngineError),
    Import(ImportError),
    Auth(AuthError),
    /// Nie udało się otworzyć portu (zajęty albo brak uprawnień).
    Bind {
        address: SocketAddr,
        source: std::io::Error,
    },
    Server(std::io::Error),
    File {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Błąd odczytu z terminala (np. hasła).
    Input(std::io::Error),
    PasswordMismatch,
    /// Nie udało się przygotować klienta HTTP.
    Http(String),
    NoTargetsInScope,
    MissingNewKey(&'static str),
    SameKey,
    /// Polecenie jest zdefiniowane, ale jego implementacja jest zaplanowana na później.
    NotImplemented {
        command: &'static str,
        tasks: &'static str,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Config(error) => write!(f, "{error}"),
            CliError::Database(error) => write!(f, "{error}"),
            CliError::Scanner(error) => write!(f, "{error}"),
            CliError::Engine(error) => write!(f, "{error}"),
            CliError::Import(error) => write!(f, "{error}"),
            CliError::Auth(error) => write!(f, "{error}"),
            CliError::Bind { address, source } => {
                write!(f, "nie można nasłuchiwać na {address}: {source}")
            }
            CliError::Server(error) => write!(f, "błąd serwera: {error}"),
            CliError::File { path, source } => write!(f, "plik {}: {source}", path.display()),
            CliError::Input(error) => write!(f, "błąd odczytu z terminala: {error}"),
            CliError::PasswordMismatch => write!(f, "podane hasła różnią się"),
            CliError::Http(reason) => write!(f, "klient HTTP: {reason}"),
            CliError::NoTargetsInScope => write!(
                f,
                "brak celów do skanowania w dozwolonym zakresie — dodaj sieci do [scope] allowed_networks w dscan.toml"
            ),
            CliError::MissingNewKey(variable) => write!(
                f,
                "brak nowego klucza — ustaw zmienną {variable} (wygeneruj: dscan keys generate)"
            ),
            CliError::SameKey => write!(f, "nowy klucz jest taki sam jak obecny"),
            CliError::NotImplemented { command, tasks } => write!(
                f,
                "polecenie '{command}' nie jest jeszcze dostępne (zaplanowane w zadaniach: {tasks})"
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ConfigError> for CliError {
    fn from(error: ConfigError) -> Self {
        CliError::Config(error)
    }
}

impl From<DbError> for CliError {
    fn from(error: DbError) -> Self {
        CliError::Database(error)
    }
}

impl From<ScannerError> for CliError {
    fn from(error: ScannerError) -> Self {
        CliError::Scanner(error)
    }
}

impl From<EngineError> for CliError {
    fn from(error: EngineError) -> Self {
        CliError::Engine(error)
    }
}

impl From<ImportError> for CliError {
    fn from(error: ImportError) -> Self {
        CliError::Import(error)
    }
}

impl From<AuthError> for CliError {
    fn from(error: AuthError) -> Self {
        CliError::Auth(error)
    }
}
