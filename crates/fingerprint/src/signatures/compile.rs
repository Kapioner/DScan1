//! Zamiana definicji z YAML na sygnaturę z gotowymi wyrażeniami regularnymi.

use regex::Regex;

use super::engine::Signature;
use super::matchers::Matcher;
use super::model::{MatcherDef, SignatureDef, SignatureError, VersionDef};

pub(super) fn compile_signature(definition: SignatureDef) -> Result<Signature, SignatureError> {
    let name = definition.name.clone();
    if definition.matchers.is_empty() {
        return Err(SignatureError::Invalid {
            signature: name,
            reason: "brak matcherów".into(),
        });
    }
    let compile = |pattern: &str| {
        Regex::new(pattern).map_err(|error| SignatureError::InvalidPattern {
            signature: name.clone(),
            reason: error.to_string(),
        })
    };
    let compile_optional = |pattern: &Option<String>| pattern.as_deref().map(compile).transpose();

    let mut matchers = Vec::with_capacity(definition.matchers.len());
    for matcher in &definition.matchers {
        matchers.push(match matcher {
            MatcherDef::Header {
                name,
                pattern,
                weight,
            } => Matcher::Header {
                name: name.clone(),
                pattern: compile_optional(pattern)?,
                weight: *weight,
            },
            MatcherDef::Cookie {
                name,
                pattern,
                weight,
            } => Matcher::Cookie {
                name: name.clone(),
                pattern: compile_optional(pattern)?,
                weight: *weight,
            },
            MatcherDef::Body { pattern, weight } => Matcher::Body {
                pattern: compile(pattern)?,
                weight: *weight,
            },
            MatcherDef::Favicon { hash, weight } => Matcher::Favicon {
                hash: *hash,
                weight: *weight,
            },
            MatcherDef::Path {
                path,
                status,
                pattern,
                weight,
            } => {
                if !path.starts_with('/') {
                    return Err(SignatureError::Invalid {
                        signature: name.clone(),
                        reason: format!("ścieżka '{path}' musi zaczynać się od /"),
                    });
                }
                Matcher::Path {
                    path: path.clone(),
                    status: status.unwrap_or(200),
                    pattern: compile_optional(pattern)?,
                    weight: *weight,
                }
            }
        });
    }
    let version = match &definition.version {
        Some(VersionDef {
            source,
            name,
            pattern,
        }) => Some((*source, name.clone(), compile(pattern)?)),
        None => None,
    };
    Ok(Signature {
        name,
        category: definition.category,
        condition: definition.condition,
        matchers,
        version,
    })
}
