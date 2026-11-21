use reqwest::Url;

/// Adres docelowy przekierowania (nagłówek `Location` może być względny, np. `/login`).
pub fn resolve_location(current: &Url, location: &str) -> Option<Url> {
    current.join(location).ok()
}

/// Czy przekierowanie zostaje na tym samym hoście (port i schemat mogą się zmienić,
/// np. http:80 → https:443). Przekierowań na inne hosty nie śledzimy — mogą prowadzić
/// poza dozwolony zakres skanowania.
pub fn is_same_host(from: &Url, to: &Url) -> bool {
    from.host_str().is_some() && from.host_str() == to.host_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn relative_location_is_resolved() {
        let next = resolve_location(&url("http://10.0.0.5/app/"), "/login?x=1").unwrap();
        assert_eq!(next.as_str(), "http://10.0.0.5/login?x=1");
    }

    #[test]
    fn absolute_location_is_kept() {
        let next = resolve_location(&url("http://10.0.0.5/"), "https://10.0.0.5:8443/").unwrap();
        assert_eq!(next.as_str(), "https://10.0.0.5:8443/");
    }

    #[test]
    fn same_host_ignores_scheme_and_port() {
        assert!(is_same_host(
            &url("http://10.0.0.5/"),
            &url("https://10.0.0.5:8443/a")
        ));
        assert!(!is_same_host(
            &url("http://10.0.0.5/"),
            &url("https://example.com/")
        ));
    }
}
