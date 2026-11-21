use std::fmt;
use std::net::SocketAddr;

use dscan_config::ConfigError;
use dscan_db::DbError;

/// Błędy zgłaszane przez polecenia `dscan`.
#[derive(Debug)]
pub enum CliError {
    Config(ConfigError),
    Database(DbError),
    /// Nie udało się otworzyć portu (zajęty albo brak uprawnień).
    Bind {
        address: SocketAddr,
        source: std::io::Error,
    },
    Server(std::io::Error),
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
            CliError::Bind { address, source } => {
                write!(f, "nie można nasłuchiwać na {address}: {source}")
            }
            CliError::Server(error) => write!(f, "błąd serwera: {error}"),
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
