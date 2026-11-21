//! Pilnuje, żeby przykładowy plik konfiguracyjny w repozytorium był zawsze poprawny.

use std::path::PathBuf;

use dscan_config::ConfigLoader;

fn example_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dscan.example.toml")
}

#[test]
fn example_config_loads_and_validates() {
    let config = ConfigLoader::new()
        .without_env()
        .file(example_config_path())
        .load()
        .unwrap();

    assert!(!config.settings.scope.allowed_networks.is_empty());
    assert!(!config.settings.schedule.windows.is_empty());
}
