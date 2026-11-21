//! Biblioteka DScan. Cała logika aplikacji trafia tutaj (i do modułów),
//! a `main.rs` pozostaje jedynie punktem wejścia.

/// Zwraca tekst powitalny wraz z wersją aplikacji.
pub fn welcome_message() -> String {
    format!("DScan v{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welcome_message_contains_name_and_version() {
        let message = welcome_message();
        assert!(message.starts_with("DScan v"));
        assert!(message.ends_with(env!("CARGO_PKG_VERSION")));
    }
}
