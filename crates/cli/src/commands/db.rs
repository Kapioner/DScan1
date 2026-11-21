use std::fmt::Write;

use clap::{Args, Subcommand};
use dscan_config::CliOverrides;
use dscan_db::{MigrationInfo, PgPool};

use super::{Command, Context, pool_options};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Debug, Subcommand)]
pub enum DbAction {
    /// Wykonuje zaległe migracje schematu bazy.
    Migrate,
    /// Pokazuje, które migracje są już zastosowane.
    Status,
}

impl Command for DbArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let pool = connect_to_database(context).await?;
        if let DbAction::Migrate = self.action {
            dscan_db::run_migrations(&pool).await?;
            println!("Migracje wykonane.");
        }
        let status = dscan_db::migration_status(&pool).await?;
        print!("{}", format_migration_status(&status));
        Ok(())
    }
}

/// Łączy się z bazą wskazaną w `DSCAN_DATABASE_URL`.
pub async fn connect_to_database(context: &Context) -> Result<PgPool, CliError> {
    let config = context.load_config(CliOverrides::default())?;
    let url = config.require_database_url()?;
    let options = pool_options(&config.settings.database);
    Ok(dscan_db::connect(url.expose(), options).await?)
}

/// Tabela stanu migracji, np. `[x] 0001 initial schema`.
pub fn format_migration_status(migrations: &[MigrationInfo]) -> String {
    let mut text = String::from("Migracje ([x] zastosowana, [ ] oczekuje):\n");
    for migration in migrations {
        let mark = if migration.applied { "x" } else { " " };
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "  [{mark}] {:04} {}",
            migration.version, migration.description
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_table_marks_applied_migrations() {
        let migrations = vec![
            MigrationInfo {
                version: 1,
                description: "initial schema".into(),
                applied: true,
            },
            MigrationInfo {
                version: 2,
                description: "next".into(),
                applied: false,
            },
        ];

        let text = format_migration_status(&migrations);

        assert!(text.contains("[x] 0001 initial schema"));
        assert!(text.contains("[ ] 0002 next"));
    }
}
