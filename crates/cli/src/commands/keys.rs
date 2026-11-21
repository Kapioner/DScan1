use std::fmt::Write;

use clap::{Args, Subcommand};
use dscan_config::{CliOverrides, EncryptionKey, NEW_ENCRYPTION_KEY_ENV};
use dscan_crypto::{Cipher, generate_key_hex};
use dscan_db::RotatedColumn;

use super::{Command, Context, connect_database};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub action: KeysAction,
}

#[derive(Debug, Subcommand)]
pub enum KeysAction {
    /// Przeszyfrowuje dane wrażliwe nowym kluczem.
    ///
    /// Stary klucz: DSCAN_ENCRYPTION_KEY, nowy: DSCAN_NEW_ENCRYPTION_KEY.
    /// Całość w jednej transakcji — przy błędzie nic się nie zmienia.
    Rotate,
    /// Wypisuje nowy losowy klucz (64 znaki hex).
    Generate,
}

impl Command for KeysArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        match self.action {
            KeysAction::Generate => println!("{}", generate_key_hex()),
            KeysAction::Rotate => rotate(context).await?,
        }
        Ok(())
    }
}

async fn rotate(context: &Context) -> Result<(), CliError> {
    let config = context.load_config(CliOverrides::default())?;
    let old_key = config.require_encryption_key()?;
    let new_key = read_new_key()?;
    if new_key == *old_key {
        return Err(CliError::SameKey);
    }

    let pool = connect_database(&config).await?;
    let old = Cipher::new(old_key.as_bytes());
    let new = Cipher::new(new_key.as_bytes());
    let report = dscan_db::rotate_encryption_key(&pool, &old, &new).await?;
    print!("{}", format_rotation_report(&report));
    Ok(())
}

fn read_new_key() -> Result<EncryptionKey, CliError> {
    let value = std::env::var(NEW_ENCRYPTION_KEY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CliError::MissingNewKey(NEW_ENCRYPTION_KEY_ENV))?;
    Ok(EncryptionKey::from_hex(&value)?)
}

/// Podsumowanie rotacji z instrukcją, co zrobić dalej.
pub fn format_rotation_report(columns: &[RotatedColumn]) -> String {
    let total: u64 = columns.iter().map(|column| column.values).sum();
    let mut text = format!("Przeszyfrowano {total} wartości:\n");
    for column in columns {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(text, "  {:<24} {}", column.context, column.values);
    }
    text.push_str(
        "\nWAŻNE: ustaw teraz w .env DSCAN_ENCRYPTION_KEY na nowy klucz \
         i usuń DSCAN_NEW_ENCRYPTION_KEY. Stary klucz już nie odczyta danych.\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_sums_values_and_tells_what_to_do() {
        let columns = vec![
            RotatedColumn {
                context: "targets.note".into(),
                values: 3,
            },
            RotatedColumn {
                context: "services.banner".into(),
                values: 2,
            },
        ];

        let report = format_rotation_report(&columns);

        assert!(report.starts_with("Przeszyfrowano 5 wartości"));
        assert!(report.contains("targets.note"));
        assert!(report.contains("DSCAN_ENCRYPTION_KEY na nowy klucz"));
    }
}
