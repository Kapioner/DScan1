use std::fmt::Write;
use std::io::BufRead;

use clap::{Args, Subcommand};
use dscan_auth::{hash_password, validate_password_strength, validate_username};
use dscan_config::CliOverrides;
use dscan_db::UserSummary;

use super::{Command, Context, cipher_from_config, connect_database};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub action: UserAction,
}

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Tworzy konto administratora bezpośrednio w bazie (wymaga klucza szyfrowania).
    CreateAdmin {
        /// Login: 3–64 znaki, małe litery a-z, cyfry oraz . _ -
        #[arg(value_name = "LOGIN")]
        username: String,
        /// Czyta hasło z pierwszej linii standardowego wejścia (do skryptów)
        /// zamiast pytać w terminalu.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Wyświetla użytkowników.
    List,
}

impl Command for UserArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let config = context.load_config(CliOverrides::default())?;
        match &self.action {
            UserAction::CreateAdmin {
                username,
                password_stdin,
            } => {
                cipher_from_config(&config)?;
                validate_username(username)?;
                let password = read_password(*password_stdin)?;
                validate_password_strength(&password)?;
                let hash = hash_password(&password)?;

                let pool = connect_database(&config).await?;
                let id = dscan_db::create_admin(&pool, username, &hash).await?;
                println!("Utworzono administratora '{username}' (id {id}).");
            }
            UserAction::List => {
                let pool = connect_database(&config).await?;
                print!(
                    "{}",
                    format_users_table(&dscan_db::list_users(&pool).await?)
                );
            }
        }
        Ok(())
    }
}

/// Hasło ze stdin albo z terminala (bez wyświetlania znaków, z potwierdzeniem).
fn read_password(from_stdin: bool) -> Result<String, CliError> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(CliError::Input)?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    let first = rpassword::prompt_password("Hasło: ").map_err(CliError::Input)?;
    let second = rpassword::prompt_password("Powtórz hasło: ").map_err(CliError::Input)?;
    if first != second {
        return Err(CliError::PasswordMismatch);
    }
    Ok(first)
}

/// Tabela użytkowników.
pub fn format_users_table(users: &[UserSummary]) -> String {
    if users.is_empty() {
        return "Brak użytkowników. Utwórz administratora: dscan user create-admin LOGIN\n".into();
    }
    let mut text = format!("{:<5} {:<24} {:<32} {}\n", "ID", "LOGIN", "ROLA", "STAN");
    for user in users {
        let state = if user.is_blocked {
            "zablokowany"
        } else {
            "aktywny"
        };
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "{:<5} {:<24} {:<32} {state}",
            user.id, user.username, user.role
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn empty_list_suggests_creating_admin() {
        assert!(format_users_table(&[]).contains("create-admin"));
    }

    #[test]
    fn users_are_listed_with_role_and_state() {
        let users = vec![UserSummary {
            id: 1,
            username: "admin".into(),
            role: "administracja".into(),
            is_blocked: false,
            created_at: Utc::now(),
        }];

        let table = format_users_table(&users);

        assert!(table.contains("admin"));
        assert!(table.contains("administracja"));
        assert!(table.contains("aktywny"));
    }
}
