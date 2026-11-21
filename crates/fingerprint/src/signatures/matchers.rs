//! Matchery sygnatur: sprawdzenie pojedynczego warunku i ekstrakcja wersji.

use dscan_core::models::{Evidence, EvidenceKind};
use regex::Regex;

use super::engine::WebEvidence;
use super::model::VersionSource;

/// Matcher z już skompilowanymi wyrażeniami regularnymi.
pub(super) enum Matcher {
    Header {
        name: String,
        pattern: Option<Regex>,
        weight: u8,
    },
    Cookie {
        name: String,
        pattern: Option<Regex>,
        weight: u8,
    },
    Body {
        pattern: Regex,
        weight: u8,
    },
    Favicon {
        hash: i32,
        weight: u8,
    },
    Path {
        path: String,
        status: u16,
        pattern: Option<Regex>,
        weight: u8,
    },
}

impl Matcher {
    /// Dowód, jeśli matcher pasuje.
    pub(super) fn check(&self, evidence: &WebEvidence<'_>) -> Option<Evidence> {
        let info = evidence.info;
        match self {
            Matcher::Header {
                name,
                pattern,
                weight,
            } => {
                let value = info.header(name)?;
                matches_optional(pattern.as_ref(), value).then(|| {
                    proof(
                        EvidenceKind::Header,
                        format!("nagłówek {name}: {value}"),
                        *weight,
                    )
                })
            }
            Matcher::Cookie {
                name,
                pattern,
                weight,
            } => {
                let cookie = info
                    .cookies
                    .iter()
                    .find(|cookie| cookie.name.eq_ignore_ascii_case(name))?;
                // W dowodzie tylko nazwa ciasteczka — wartość bywa identyfikatorem sesji.
                matches_optional(pattern.as_ref(), &cookie.value).then(|| {
                    proof(
                        EvidenceKind::Cookie,
                        format!("ciasteczko {}", cookie.name),
                        *weight,
                    )
                })
            }
            Matcher::Body { pattern, weight } => pattern.is_match(evidence.body).then(|| {
                proof(
                    EvidenceKind::Body,
                    format!("treść pasuje do /{pattern}/"),
                    *weight,
                )
            }),
            Matcher::Favicon { hash, weight } => {
                (evidence.favicon_hash == Some(*hash)).then(|| {
                    proof(
                        EvidenceKind::Favicon,
                        format!("favicon mmh3 {hash}"),
                        *weight,
                    )
                })
            }
            Matcher::Path {
                path,
                status,
                pattern,
                weight,
            } => {
                let probe = evidence.probes.iter().find(|probe| &probe.path == path)?;
                let ok = probe.status == *status && matches_optional(pattern.as_ref(), &probe.body);
                ok.then(|| {
                    proof(
                        EvidenceKind::Path,
                        format!("{path} → {}", probe.status),
                        *weight,
                    )
                })
            }
        }
    }
}

fn proof(kind: EvidenceKind, description: String, weight: u8) -> Evidence {
    Evidence {
        kind,
        description,
        weight,
    }
}

fn matches_optional(pattern: Option<&Regex>, value: &str) -> bool {
    pattern.is_none_or(|pattern| pattern.is_match(value))
}

/// Wersja z pierwszej grupy przechwytującej wzorca.
pub(super) fn extract_version(
    evidence: &WebEvidence<'_>,
    source: VersionSource,
    header: Option<&str>,
    pattern: &Regex,
) -> Option<String> {
    let text = match source {
        VersionSource::Body => evidence.body,
        VersionSource::Header => evidence.info.header(header?)?,
    };
    pattern
        .captures(text)?
        .get(1)
        .map(|version| version.as_str().to_string())
}
