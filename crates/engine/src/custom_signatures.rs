//! Własne sygnatury z edytora (F8) dostępne dla każdego skanu w procesie.
//! Wzorzec Singleton przez `OnceLock`: jeden rejestr w procesie, odświeżany z bazy
//! przy starcie serwera i po każdej zmianie w edytorze.

use std::sync::{OnceLock, RwLock};

use dscan_db::PgPool;
use dscan_fingerprint::signatures::SignatureSet;

use crate::EngineError;

fn registry() -> &'static RwLock<Vec<String>> {
    static REGISTRY: OnceLock<RwLock<Vec<String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Zastępuje zawartość rejestru (YAML włączonych sygnatur).
pub fn set_custom_signatures(yaml: Vec<String>) {
    if let Ok(mut guard) = registry().write() {
        *guard = yaml;
    }
}

/// Wczytuje włączone sygnatury z bazy; błędne są pomijane z ostrzeżeniem.
pub async fn refresh_custom_signatures(pool: &PgPool) -> Result<usize, EngineError> {
    let enabled: Vec<String> = dscan_db::list_custom_signatures(pool)
        .await?
        .into_iter()
        .filter(|s| s.enabled)
        .filter(
            |s| match SignatureSet::from_single_yaml(&s.definition_yaml) {
                Ok(_) => true,
                Err(error) => {
                    tracing::warn!("sygnatura „{}” pominięta: {error}", s.name);
                    false
                }
            },
        )
        .map(|s| s.definition_yaml)
        .collect();
    let count = enabled.len();
    set_custom_signatures(enabled);
    Ok(count)
}

/// Dołącza sygnatury z rejestru do zestawu.
pub fn append_custom_signatures(set: &mut SignatureSet) {
    let Ok(guard) = registry().read() else { return };
    for yaml in guard.iter() {
        if let Ok(custom) = SignatureSet::from_single_yaml(yaml) {
            set.extend(custom);
        }
    }
}
