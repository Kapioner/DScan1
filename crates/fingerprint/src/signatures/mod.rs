//! Silnik sygnatur technologii (zadanie H5).
//!
//! Sygnatury są w YAML (wbudowany zestaw: `signatures/default.yaml`). Każda ma matchery:
//! `header`, `cookie`, `body` (regex), `favicon` (hash) i `path` (sondowana ścieżka),
//! łączone warunkiem `any` (wystarczy jeden) albo `all` (wszystkie), oraz opcjonalną
//! ekstrakcję wersji wyrażeniem regularnym z grupą przechwytującą.

mod compile;
mod engine;
mod matchers;
mod model;

pub use engine::{SignatureSet, WebEvidence};
pub use model::{Condition, MatcherDef, SignatureDef, SignatureError, VersionDef, VersionSource};
