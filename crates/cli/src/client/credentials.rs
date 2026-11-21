//! Token sesji zapisany w pliku użytkownika (C5): `~/.config/dscan/credentials.json`
//! z uprawnieniami 0600 (czyta go tylko właściciel). Ścieżkę można zmienić zmienną
//! `DSCAN_CREDENTIALS`.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CliError;

/// Zapisane dane logowania.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// Adres serwera, np. `http://127.0.0.1:8080`.
    pub server: String,
    pub username: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl Credentials {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// Domyślna ścieżka pliku: `DSCAN_CREDENTIALS`, potem `$XDG_CONFIG_HOME/dscan`, potem `~/.config/dscan`.
pub fn credentials_path() -> Option<PathBuf> {
    resolve_path(
        std::env::var_os("DSCAN_CREDENTIALS").map(PathBuf::from),
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// Wybór ścieżki z podanych zmiennych (osobno, żeby dało się to przetestować).
pub fn resolve_path(
    explicit: Option<PathBuf>,
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    explicit.or_else(|| {
        xdg.or_else(|| home.map(|home| home.join(".config")))
            .map(|base| base.join("dscan").join("credentials.json"))
    })
}

/// Zapisuje dane logowania (tworzy katalog; plik dostaje uprawnienia 0600).
pub fn save(path: &Path, credentials: &Credentials) -> Result<(), CliError> {
    let file_error = |source| CliError::File {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(file_error)?;
    }
    let json =
        serde_json::to_string_pretty(credentials).map_err(|e| CliError::Http(e.to_string()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(file_error)?;
    // Plik mógł istnieć wcześniej z szerszymi uprawnieniami.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(file_error)?;
    }
    file.write_all(json.as_bytes()).map_err(file_error)
}

/// Wczytuje dane logowania; `None`, gdy pliku nie ma.
pub fn load(path: &Path) -> Result<Option<Credentials>, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| CliError::NotLoggedIn),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::File {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Usuwa plik; `false`, gdy go nie było.
pub fn remove(path: &Path) -> Result<bool, CliError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CliError::File {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Credentials {
        Credentials {
            server: "http://127.0.0.1:8080".into(),
            username: "admin".into(),
            token: "abc".into(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
        }
    }

    #[test]
    fn path_precedence() {
        let p = |s: &str| Some(PathBuf::from(s));
        assert_eq!(
            resolve_path(p("/x/c.json"), p("/xdg"), p("/home/a")),
            p("/x/c.json")
        );
        assert_eq!(
            resolve_path(None, p("/xdg"), p("/home/a")),
            p("/xdg/dscan/credentials.json")
        );
        assert_eq!(
            resolve_path(None, None, p("/home/a")),
            p("/home/a/.config/dscan/credentials.json")
        );
    }

    #[test]
    fn save_load_remove_with_private_permissions() {
        let dir = std::env::temp_dir().join(format!("dscan-cred-{}", std::process::id()));
        let path = dir.join("sub").join("credentials.json");
        let credentials = sample();
        save(&path, &credentials).unwrap();
        assert_eq!(load(&path).unwrap(), Some(credentials));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(remove(&path).unwrap());
        assert_eq!(load(&path).unwrap(), None);
        assert!(!remove(&path).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn expiry_is_checked() {
        let mut credentials = sample();
        assert!(!credentials.is_expired(Utc::now()));
        credentials.expires_at = Utc::now() - chrono::TimeDelta::seconds(1);
        assert!(credentials.is_expired(Utc::now()));
    }
}
