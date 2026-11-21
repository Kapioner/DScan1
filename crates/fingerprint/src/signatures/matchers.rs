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

#[cfg(test)]
mod tests {
    //! Każdy rodzaj matchera i błędy kompilacji sygnatur (Q4).
    use dscan_core::models::{Cookie, HttpHeader, HttpInfo};

    use super::super::{SignatureSet, WebEvidence};
    use crate::ProbeResult;

    fn info(headers: &[(&str, &str)], cookies: &[(&str, &str)]) -> HttpInfo {
        HttpInfo {
            url: "http://10.0.0.5/".into(),
            status_code: 200,
            title: None,
            headers: headers
                .iter()
                .map(|(n, v)| HttpHeader {
                    name: n.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            cookies: cookies
                .iter()
                .map(|(n, v)| Cookie {
                    name: n.to_string(),
                    value: v.to_string(),
                    domain: None,
                    path: None,
                    secure: false,
                    http_only: false,
                    same_site: None,
                })
                .collect(),
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
        }
    }

    fn names(
        yaml: &str,
        info: &HttpInfo,
        body: &str,
        probes: &[ProbeResult],
        favicon: Option<i32>,
    ) -> Vec<(String, u8)> {
        let set = SignatureSet::from_yaml(yaml).unwrap();
        set.detect(&WebEvidence {
            info,
            body,
            probes,
            favicon_hash: favicon,
        })
        .into_iter()
        .map(|d| (d.technology, d.confidence))
        .collect()
    }

    #[test]
    fn cookie_matcher_checks_name_and_value_and_hides_value() {
        let yaml = "- { name: App, matchers: [ { type: cookie, name: SESSID, pattern: '^[a-f0-9]+$', weight: 60 } ] }";
        assert_eq!(
            names(yaml, &info(&[], &[("sessid", "abc123")]), "", &[], None),
            vec![("App".into(), 60)]
        );
        assert!(names(yaml, &info(&[], &[("SESSID", "XYZ")]), "", &[], None).is_empty());
        let set = SignatureSet::from_yaml(yaml).unwrap();
        let cookie_info = info(&[], &[("SESSID", "deadbeef")]);
        let found = set.detect(&WebEvidence {
            info: &cookie_info,
            body: "",
            probes: &[],
            favicon_hash: None,
        });
        assert!(!found[0].evidence[0].description.contains("deadbeef"));
    }

    #[test]
    fn body_favicon_and_path_matchers() {
        let yaml = r#"
- { name: Body, matchers: [ { type: body, pattern: 'wp-content', weight: 40 } ] }
- { name: Ikona, matchers: [ { type: favicon, hash: -1234, weight: 80 } ] }
- { name: Sciezka, matchers: [ { type: path, path: /admin, status: 401, weight: 50 } ] }
- { name: SciezkaTresc, matchers: [ { type: path, path: /version, pattern: 'v\d', weight: 30 } ] }
"#;
        let probes = vec![
            ProbeResult {
                path: "/admin".into(),
                status: 401,
                body: String::new(),
            },
            ProbeResult {
                path: "/version".into(),
                status: 200,
                body: "v2.1".into(),
            },
        ];
        let found = names(
            yaml,
            &info(&[], &[]),
            "<link href=/wp-content/x.css>",
            &probes,
            Some(-1234),
        );
        let found: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(found, vec!["Body", "Ikona", "Sciezka", "SciezkaTresc"]);
        // Zły status ścieżki i inna ikona nie pasują.
        let wrong = vec![ProbeResult {
            path: "/admin".into(),
            status: 200,
            body: String::new(),
        }];
        assert!(names(yaml, &info(&[], &[]), "", &wrong, Some(1)).is_empty());
    }

    #[test]
    fn condition_all_requires_every_matcher() {
        let yaml = "- { name: Oba, condition: all, matchers: [ { type: header, name: Server, weight: 30 }, { type: body, pattern: Grafana, weight: 50 } ] }";
        let server = info(&[("Server", "x")], &[]);
        assert!(names(yaml, &server, "", &[], None).is_empty());
        assert_eq!(
            names(yaml, &server, "Grafana", &[], None),
            vec![("Oba".into(), 80)]
        );
    }

    #[test]
    fn invalid_signatures_are_rejected() {
        assert!(
            SignatureSet::from_yaml(
                "- { name: Zly, matchers: [ { type: body, pattern: '(', weight: 10 } ] }"
            )
            .is_err()
        );
        assert!(
            SignatureSet::from_yaml("- { name: Typ, matchers: [ { type: dns, weight: 10 } ] }")
                .is_err()
        );
        assert!(
            SignatureSet::from_yaml(
                "- { name: Pole, matchers: [ { type: body, pattern: a, weight: 10, extra: 1 } ] }"
            )
            .is_err()
        );
        assert!(SignatureSet::from_yaml("nie: [lista").is_err());
    }
}
