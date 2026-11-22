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
    /// Pokazuje, ile rekordów zaszyfrowano którym kluczem (B6).
    Status,
    /// Stopniowa rotacja (B6): przeszyfrowuje partiami rekordy zapisane starszym kluczem.
    ///
    /// Bieżący klucz: DSCAN_ENCRYPTION_KEY + DSCAN_ENCRYPTION_KEY_ID; stare klucze do odczytu:
    /// DSCAN_PREVIOUS_ENCRYPTION_KEYS (id:hex,…). Serwer może w tym czasie działać.
    Reencrypt {
        /// Rekordów na transakcję.
        #[arg(long, default_value_t = 500)]
        batch: i64,
    },
}

impl Command for KeysArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        match &self.action {
            KeysAction::Generate => println!("{}", generate_key_hex()),
            KeysAction::Rotate => rotate(context).await?,
            KeysAction::Status => {
                let config = context.load_config(CliOverrides::default())?;
                let cipher = super::cipher_from_config(&config)?;
                let pool = connect_database(&config).await?;
                print!(
                    "{}",
                    format_usage(cipher.key_id(), &dscan_db::key_usage(&pool).await?)
                );
            }
            KeysAction::Reencrypt { batch } => {
                let config = context.load_config(CliOverrides::default())?;
                let cipher = super::cipher_from_config(&config)?;
                let pool = connect_database(&config).await?;
                let report = dscan_db::reencrypt_stale(&pool, &cipher, (*batch).max(1)).await?;
                let total: u64 = report.iter().map(|c| c.values).sum();
                println!("Przeszyfrowano kluczem #{}: {total}", cipher.key_id());
                for column in &report {
                    println!("  {:<32} {}", column.context, column.values);
                }
                println!(
                    "Gdy `dscan keys status` pokazuje tylko klucz #{}, usuń DSCAN_PREVIOUS_ENCRYPTION_KEYS.",
                    cipher.key_id()
                );
            }
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

/// Raport `keys status`.
pub fn format_usage(current: u8, usage: &[dscan_db::KeyUsage]) -> String {
    let mut text = format!("Bieżący klucz: #{current}\n");
    for row in usage {
        let key = row
            .key_id
            .map_or("bez identyfikatora (format 1)".to_string(), |id| {
                format!("klucz #{id}")
            });
        let stale = if row.key_id == Some(current) {
            ""
        } else {
            "  ← do przeszyfrowania"
        };
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "  {:<24} {key:<30} {:>8}{stale}",
            row.context, row.records
        );
    }
    text
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
