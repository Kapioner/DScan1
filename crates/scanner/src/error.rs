use std::fmt;

/// Błędy skanera.
#[derive(Debug)]
pub enum ScannerError {
    InvalidTarget {
        input: String,
        reason: String,
    },
    /// Nie udało się przygotować resolvera DNS (np. brak konfiguracji systemowej).
    Resolver(String),
    /// Program nmap nie jest zainstalowany albo nie ma go w PATH.
    NmapNotFound,
    NmapFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    InvalidNmapOutput(String),
    Io(std::io::Error),
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::InvalidTarget { input, reason } => {
                write!(f, "niepoprawny cel '{input}': {reason}")
            }
            ScannerError::Resolver(reason) => write!(f, "błąd resolvera DNS: {reason}"),
            ScannerError::NmapNotFound => write!(
                f,
                "nie znaleziono programu nmap — zainstaluj go (np. sudo apt install nmap)"
            ),
            ScannerError::NmapFailed { exit_code, stderr } => {
                let code = exit_code.map_or("brak".to_string(), |code| code.to_string());
                write!(
                    f,
                    "nmap zakończył się błędem (kod {code}): {}",
                    stderr.trim()
                )
            }
            ScannerError::InvalidNmapOutput(reason) => {
                write!(f, "niepoprawny wynik XML z nmap: {reason}")
            }
            ScannerError::Io(error) => write!(f, "błąd wejścia/wyjścia: {error}"),
        }
    }
}

impl std::error::Error for ScannerError {}

impl From<std::io::Error> for ScannerError {
    fn from(error: std::io::Error) -> Self {
        ScannerError::Io(error)
    }
}
