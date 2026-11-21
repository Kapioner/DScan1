use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;

use clap::{Args, Subcommand};
use dscan_config::CliOverrides;
use dscan_core::models::Detection;
use dscan_fingerprint::signatures::{SignatureSet, WebEvidence};
use dscan_fingerprint::{merge_probe_paths, probe_paths, to_http_info};
use dscan_scanner::targets::{is_in_scope, single_address_network};

use super::scan::build_fetcher;
use super::{Command, Context};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct SigArgs {
    #[command(subcommand)]
    pub action: SigAction,
}

#[derive(Debug, Subcommand)]
pub enum SigAction {
    /// Wyświetla wbudowane sygnatury.
    List,
    /// Sprawdza sygnaturę na adresie usługi WWW (tylko w zakresie [scope]).
    Test {
        /// Nazwa sygnatury (np. WordPress); „*” = wszystkie.
        #[arg(value_name = "SYGNATURA")]
        signature: String,
        /// Adres usługi, np. http://10.0.0.5:80/ (host musi być adresem IP z [scope]).
        #[arg(long, value_name = "URL")]
        host: String,
    },
}

impl Command for SigArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let signatures =
            SignatureSet::builtin().map_err(|error| CliError::Http(error.to_string()))?;
        match &self.action {
            SigAction::List => print!("{}", format_signature_list(&signatures)),
            SigAction::Test { signature, host } => {
                test_signature(context, &signatures, signature, host).await?
            }
        }
        Ok(())
    }
}

async fn test_signature(
    context: &Context,
    signatures: &SignatureSet,
    name: &str,
    url: &str,
) -> Result<(), CliError> {
    let config = context.load_config(CliOverrides::default())?;
    let ip = host_ip(url).ok_or_else(|| {
        CliError::Http(format!(
            "adres {url} musi zawierać IP hosta, np. http://10.0.0.5:80/"
        ))
    })?;
    if !is_in_scope(
        &single_address_network(ip),
        &config.settings.scope.allowed_networks,
    ) {
        return Err(CliError::NoTargetsInScope);
    }
    let fetcher = Arc::new(build_fetcher(&config)?);
    let response = fetcher
        .fetch(url, ip)
        .await
        .map_err(|error| CliError::Http(error.to_string()))?;
    let info = to_http_info(&response);
    let body = String::from_utf8_lossy(&response.body);
    let paths = merge_probe_paths(&config.settings.http.probe_paths, &signatures.probe_paths());
    let max = config.settings.http.max_probes_per_service as usize;
    let probes = probe_paths(&fetcher, url, ip, &paths, max).await;
    let evidence = WebEvidence {
        info: &info,
        body: &body,
        probes: &probes,
        favicon_hash: None,
    };
    let detections: Vec<Detection> = signatures
        .detect(&evidence)
        .into_iter()
        .filter(|detection| name == "*" || detection.technology.eq_ignore_ascii_case(name))
        .collect();
    println!(
        "HTTP {} {} (sondy: {})",
        info.status_code,
        info.url,
        probes.len()
    );
    print!("{}", format_detections(&detections, name));
    Ok(())
}

/// IP z adresu URL (`http://10.0.0.5:80/` → 10.0.0.5, `http://[::1]/` → ::1).
pub fn host_ip(url: &str) -> Option<IpAddr> {
    let rest = url.split_once("://")?.1;
    let host = rest.split('/').next()?;
    if let Some(v6) = host.strip_prefix('[') {
        return v6.split(']').next()?.parse().ok();
    }
    host.rsplit_once(':')
        .map_or(host, |(name, _)| name)
        .parse()
        .ok()
}

pub fn format_signature_list(signatures: &SignatureSet) -> String {
    let mut text = format!("{:<24} {:<16} {}\n", "SYGNATURA", "KATEGORIA", "MATCHERY");
    for (name, category, matchers) in signatures.summaries() {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "{name:<24} {:<16} {matchers}",
            category.unwrap_or_default()
        );
    }
    text
}

pub fn format_detections(detections: &[Detection], name: &str) -> String {
    if detections.is_empty() {
        return format!("Sygnatura „{name}” nie pasuje.\n");
    }
    let mut text = String::new();
    for detection in detections {
        let version = detection
            .version
            .as_deref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "{}{version} — pewność {}%",
            detection.technology, detection.confidence
        );
        for evidence in &detection.evidence {
            let _ = writeln!(text, "  • {} (+{})", evidence.description, evidence.weight);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_is_read_from_url() {
        assert_eq!(
            host_ip("http://10.0.0.5:80/").unwrap().to_string(),
            "10.0.0.5"
        );
        assert_eq!(
            host_ip("https://10.0.0.5/admin").unwrap().to_string(),
            "10.0.0.5"
        );
        assert_eq!(host_ip("http://[::1]:8080/").unwrap().to_string(), "::1");
        assert_eq!(host_ip("http://example.com/"), None);
        assert_eq!(host_ip("10.0.0.5"), None);
    }

    #[test]
    fn signature_list_has_builtin_entries() {
        let text = format_signature_list(&SignatureSet::builtin().unwrap());
        assert!(text.contains("WordPress") && text.contains("cms"));
    }
}
