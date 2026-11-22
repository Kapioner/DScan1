//! `dscan config init` i dokumentacja CLI (C9) oraz autouzupełnianie w powłoce (C10).

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::Shell;

use super::{Command, Context};
use crate::cli::Cli;
use crate::error::CliError;

/// Skomentowany plik konfiguracji ze wszystkimi parametrami (ten sam co `dscan.example.toml`).
pub const EXAMPLE_CONFIG: &str = include_str!("../../../../dscan.example.toml");

/// Tworzy plik konfiguracji; istniejącego nie nadpisuje bez `force`.
pub fn write_config(path: &Path, force: bool) -> Result<(), CliError> {
    if path.exists() && !force {
        return Err(CliError::File {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "plik już istnieje (użyj --force)",
            ),
        });
    }
    std::fs::write(path, EXAMPLE_CONFIG).map_err(|source| CliError::File {
        path: path.to_path_buf(),
        source,
    })
}

/// Format dokumentacji.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DocsFormat {
    /// Strona podręcznika (man, roff).
    Man,
    /// Markdown ze wszystkimi podkomendami i opcjami.
    Markdown,
}

#[derive(Debug, Args)]
pub struct DocsArgs {
    #[arg(long, value_enum, default_value_t = DocsFormat::Markdown)]
    pub format: DocsFormat,
    /// Plik wynikowy (domyślnie standardowe wyjście).
    #[arg(long, short, value_name = "PLIK")]
    pub output: Option<PathBuf>,
}

/// Dokumentacja Markdown wygenerowana z definicji clap (opisy, argumenty, opcje).
pub fn markdown() -> String {
    let mut command = Cli::command();
    command.build();
    let mut text = format!(
        "# dscan {}\n\n{}\n\n",
        env!("CARGO_PKG_VERSION"),
        command
            .get_about()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    write_command(&mut text, &command, "dscan");
    text
}

fn write_command(text: &mut String, command: &clap::Command, path: &str) {
    for sub in command.get_subcommands().filter(|s| s.get_name() != "help") {
        let name = format!("{path} {}", sub.get_name());
        text.push_str(&format!(
            "## `{name}`\n\n{}\n\n",
            sub.get_about().map(|a| a.to_string()).unwrap_or_default()
        ));
        let args: Vec<_> = sub
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "version")
            .collect();
        if !args.is_empty() {
            text.push_str("| Argument | Opis |\n|---|---|\n");
            for arg in args {
                let label = match (arg.get_long(), arg.get_short()) {
                    (Some(long), Some(short)) => format!("`-{short}, --{long}`"),
                    (Some(long), None) => format!("`--{long}`"),
                    (None, Some(short)) => format!("`-{short}`"),
                    (None, None) => format!(
                        "`{}`",
                        arg.get_value_names()
                            .and_then(|v| v.first())
                            .map_or(arg.get_id().to_string(), |v| v.to_string())
                    ),
                };
                let help = arg
                    .get_help()
                    .map(|h| h.to_string())
                    .unwrap_or_default()
                    .replace('|', "\\|");
                text.push_str(&format!("| {label} | {help} |\n"));
            }
            text.push('\n');
        }
        write_command(text, sub, &name);
    }
}

impl Command for DocsArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        let content: Vec<u8> = match self.format {
            DocsFormat::Markdown => markdown().into_bytes(),
            DocsFormat::Man => {
                let mut buffer = Vec::new();
                clap_mangen::Man::new(Cli::command())
                    .render(&mut buffer)
                    .map_err(CliError::Input)?;
                buffer
            }
        };
        match &self.output {
            Some(path) => std::fs::write(path, &content).map_err(|source| CliError::File {
                path: path.clone(),
                source,
            }),
            None => std::io::stdout()
                .write_all(&content)
                .map_err(CliError::Input),
        }
    }
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Powłoka: bash, zsh, fish, elvish, powershell.
    #[arg(value_enum)]
    pub shell: Shell,
}

impl Command for CompletionsArgs {
    /// Skrypt autouzupełniania na standardowe wyjście, np. `dscan completions bash > ~/.local/share/bash-completion/completions/dscan`.
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        clap_complete::generate(
            self.shell,
            &mut Cli::command(),
            "dscan",
            &mut std::io::stdout(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_config::{ConfigLoader, Settings};

    #[test]
    fn example_config_loads_and_covers_every_setting() {
        let loaded = ConfigLoader::new()
            .without_env()
            .toml_str(EXAMPLE_CONFIG)
            .load()
            .unwrap();
        assert!(!loaded.settings.profiles.is_empty());
        // Każde pole każdej sekcji ustawień musi występować w pliku (w tym komentarzem).
        let defaults = toml::Value::try_from(Settings::default()).unwrap();
        for (section, fields) in defaults.as_table().unwrap() {
            assert!(
                EXAMPLE_CONFIG.contains(&format!("[{section}")),
                "brak sekcji [{section}]"
            );
            if let Some(fields) = fields.as_table() {
                for field in fields.keys() {
                    assert!(
                        EXAMPLE_CONFIG.contains(&format!("{field} ="))
                            || EXAMPLE_CONFIG.contains(field.as_str()),
                        "brak {section}.{field}"
                    );
                }
            }
        }
    }

    #[test]
    fn markdown_lists_subcommands_and_options() {
        let text = markdown();
        assert!(text.contains("## `dscan scan`"));
        assert!(text.contains("`--dry-run`"));
        assert!(text.contains("## `dscan dojo export`"));
    }

    #[test]
    fn config_is_not_overwritten() {
        let path = std::env::temp_dir().join(format!("dscan-init-{}.toml", std::process::id()));
        write_config(&path, false).unwrap();
        assert!(write_config(&path, false).is_err());
        assert!(write_config(&path, true).is_ok());
        let _ = std::fs::remove_file(path);
    }
}
