use dscan_core::models::{Detection, Evidence, HttpInfo};
use regex::Regex;

use super::compile::compile_signature;
use super::matchers::{Matcher, extract_version};
use super::model::{Condition, SignatureDef, SignatureError, VersionSource};
use crate::probe::ProbeResult;

/// Wbudowany zestaw sygnatur.
const BUILTIN_SIGNATURES: &str = include_str!("../../signatures/default.yaml");

/// Co wiemy o usłudze WWW: odpowiedź strony głównej, jej treść, wyniki sondowania ścieżek
/// i (od zadania H4) hash favicony.
pub struct WebEvidence<'a> {
    pub info: &'a HttpInfo,
    pub body: &'a str,
    pub probes: &'a [ProbeResult],
    pub favicon_hash: Option<i32>,
}

pub(super) struct Signature {
    pub(super) name: String,
    pub(super) category: Option<String>,
    pub(super) condition: Condition,
    pub(super) matchers: Vec<Matcher>,
    pub(super) version: Option<(VersionSource, Option<String>, Regex)>,
}

/// Zbiór sygnatur gotowych do dopasowania (wyrażenia kompilowane raz, przy wczytaniu).
pub struct SignatureSet {
    signatures: Vec<Signature>,
}

impl SignatureSet {
    /// Wczytuje sygnatury z YAML i sprawdza wszystkie wyrażenia regularne.
    pub fn from_yaml(text: &str) -> Result<SignatureSet, SignatureError> {
        let definitions: Vec<SignatureDef> =
            serde_yaml::from_str(text).map_err(|error| SignatureError::Yaml(error.to_string()))?;
        let signatures = definitions
            .into_iter()
            .map(compile_signature)
            .collect::<Result<_, _>>()?;
        Ok(SignatureSet { signatures })
    }

    /// Wbudowane sygnatury uzupełnione o sygnatury z dodatkowego pliku YAML (np. od organizatora).
    pub fn builtin_with(extra_yaml: Option<&str>) -> Result<SignatureSet, SignatureError> {
        let mut set = Self::builtin()?;
        if let Some(text) = extra_yaml {
            set.signatures.extend(Self::from_yaml(text)?.signatures);
        }
        Ok(set)
    }

    /// Wbudowany zestaw sygnatur (`signatures/default.yaml`).
    pub fn builtin() -> Result<SignatureSet, SignatureError> {
        Self::from_yaml(BUILTIN_SIGNATURES)
    }

    /// (nazwa, kategoria, liczba matcherów) każdej sygnatury — do wyświetlenia listy.
    pub fn summaries(&self) -> Vec<(String, Option<String>, usize)> {
        self.signatures
            .iter()
            .map(|signature| {
                (
                    signature.name.clone(),
                    signature.category.clone(),
                    signature.matchers.len(),
                )
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Ścieżki, które trzeba sondować, żeby sprawdzić matchery `path` (bez powtórzeń, posortowane).
    pub fn probe_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .signatures
            .iter()
            .flat_map(|signature| &signature.matchers)
            .filter_map(|matcher| match matcher {
                Matcher::Path { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// Wszystkie technologie rozpoznane w dowodach.
    pub fn detect(&self, evidence: &WebEvidence<'_>) -> Vec<Detection> {
        self.signatures
            .iter()
            .filter_map(|signature| signature.detect(evidence))
            .collect()
    }
}

impl Signature {
    fn detect(&self, evidence: &WebEvidence<'_>) -> Option<Detection> {
        let matched: Vec<Evidence> = self
            .matchers
            .iter()
            .filter_map(|matcher| matcher.check(evidence))
            .collect();
        let satisfied = match self.condition {
            Condition::Any => !matched.is_empty(),
            Condition::All => matched.len() == self.matchers.len(),
        };
        if !satisfied {
            return None;
        }
        let version = self.version.as_ref().and_then(|(source, name, pattern)| {
            extract_version(evidence, *source, name.as_deref(), pattern)
        });
        Some(Detection::from_evidence(
            self.name.clone(),
            version,
            matched,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::{Cookie, HttpHeader};

    fn info(headers: &[(&str, &str)], cookies: &[&str]) -> HttpInfo {
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
                .map(|name| Cookie {
                    name: name.to_string(),
                    value: "x".into(),
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
        }
    }

    fn detect(
        set: &SignatureSet,
        info: &HttpInfo,
        body: &str,
        probes: &[ProbeResult],
    ) -> Vec<Detection> {
        set.detect(&WebEvidence {
            info,
            body,
            probes,
            favicon_hash: None,
        })
    }

    #[test]
    fn builtin_signatures_load() {
        let set = SignatureSet::builtin().unwrap();
        assert!(set.len() >= 8);
        assert!(set.probe_paths().contains(&"/wp-login.php".to_string()));
    }

    #[test]
    fn header_match_with_version() {
        let set = SignatureSet::builtin().unwrap();
        let found = detect(&set, &info(&[("Server", "nginx/1.24.0")], &[]), "", &[]);
        let nginx = found.iter().find(|d| d.technology == "nginx").unwrap();
        assert_eq!(nginx.version.as_deref(), Some("1.24.0"));
        assert_eq!(nginx.confidence, 90);
        assert!(nginx.evidence[0].description.contains("nginx/1.24.0"));
    }

    #[test]
    fn confidence_is_sum_of_matched_weights() {
        let set = SignatureSet::builtin().unwrap();
        let body =
            r#"<link href="/wp-content/x.css"><meta name="generator" content="WordPress 6.4.2" />"#;
        let found = detect(&set, &info(&[], &[]), body, &[]);
        let wordpress = found.iter().find(|d| d.technology == "WordPress").unwrap();
        assert_eq!(wordpress.confidence, 90);
        assert_eq!(wordpress.version.as_deref(), Some("6.4.2"));
    }

    #[test]
    fn cookie_evidence_does_not_contain_value() {
        let set = SignatureSet::builtin().unwrap();
        let found = detect(&set, &info(&[], &["PHPSESSID"]), "", &[]);
        let php = found.iter().find(|d| d.technology == "PHP").unwrap();
        assert_eq!(php.evidence[0].description, "ciasteczko PHPSESSID");
    }

    #[test]
    fn path_matcher_uses_probe_results() {
        let set = SignatureSet::builtin().unwrap();
        let probe = ProbeResult {
            path: "/wp-login.php".into(),
            status: 200,
            body: r#"<input id="user_login">"#.into(),
        };
        let found = detect(&set, &info(&[], &[]), "", &[probe]);
        assert!(
            found
                .iter()
                .any(|d| d.technology == "WordPress" && d.confidence == 40)
        );
    }

    #[test]
    fn condition_all_requires_every_matcher() {
        let yaml = r#"
- name: Oba
  condition: all
  matchers:
    - { type: header, name: server, pattern: 'x', weight: 50 }
    - { type: body, pattern: 'y', weight: 50 }
"#;
        let set = SignatureSet::from_yaml(yaml).unwrap();
        assert!(detect(&set, &info(&[("server", "x")], &[]), "nic", &[]).is_empty());
        assert_eq!(
            detect(&set, &info(&[("server", "x")], &[]), "y", &[])[0].confidence,
            100
        );
    }

    #[test]
    fn nothing_matches_on_plain_response() {
        let set = SignatureSet::builtin().unwrap();
        assert!(detect(&set, &info(&[], &[]), "<html>zwykła strona</html>", &[]).is_empty());
    }

    #[test]
    fn invalid_definitions_are_rejected() {
        let bad_regex = "- { name: X, matchers: [ { type: body, pattern: '(', weight: 1 } ] }";
        assert!(matches!(
            SignatureSet::from_yaml(bad_regex),
            Err(SignatureError::InvalidPattern { .. })
        ));
        let bad_path = "- { name: X, matchers: [ { type: path, path: 'admin', weight: 1 } ] }";
        assert!(matches!(
            SignatureSet::from_yaml(bad_path),
            Err(SignatureError::Invalid { .. })
        ));
        let no_matchers = "- { name: X, matchers: [] }";
        assert!(SignatureSet::from_yaml(no_matchers).is_err());
        assert!(matches!(
            SignatureSet::from_yaml("- { name: X, matchers: [ { type: magic, weight: 1 } ] }"),
            Err(SignatureError::Yaml(_))
        ));
    }
}
