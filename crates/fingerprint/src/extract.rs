//! Ekstrakcja informacji z odpowiedzi HTTP (zadanie H2).

use dscan_core::models::{Cookie, HttpHeader, HttpInfo};
use scraper::{Html, Selector};

use crate::RawResponse;

/// Tytuł bywa bardzo długi (np. całe zdania SEO) — przycinamy do rozsądnej długości.
const MAX_TITLE_CHARS: usize = 300;

/// Zamienia odpowiedź na `HttpInfo`: nagłówki, ciasteczka z atrybutami, tytuł strony
/// i łańcuch przekierowań. Treść strony nie jest zapisywana.
pub fn to_http_info(response: &RawResponse) -> HttpInfo {
    let headers: Vec<HttpHeader> = response
        .headers
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();
    let cookies = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, value)| parse_set_cookie(value))
        .collect();
    let body = String::from_utf8_lossy(&response.body);

    HttpInfo {
        url: response.url.clone(),
        status_code: response.status,
        title: extract_title(&body),
        headers,
        cookies,
        redirect_chain: response.redirects.clone(),
        tls_verified: response.tls_verified,
        certificate: None,
        favicon: None,
        simhash: None,
    }
}

/// Tekst z `<title>` (białe znaki scalone, przycięty). `None`, gdy tytułu brak lub jest pusty.
pub fn extract_title(html: &str) -> Option<String> {
    let selector = Selector::parse("title").ok()?;
    let document = Html::parse_document(html);
    let raw: String = document.select(&selector).next()?.text().collect();
    let title = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if title.is_empty() {
        return None;
    }
    Some(title.chars().take(MAX_TITLE_CHARS).collect())
}

/// Parsuje nagłówek `Set-Cookie`, np. `sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax`.
pub fn parse_set_cookie(header: &str) -> Option<Cookie> {
    let mut parts = header.split(';').map(str::trim);
    let (name, value) = parts.next()?.split_once('=')?;
    if name.trim().is_empty() {
        return None;
    }
    let mut cookie = Cookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: None,
    };
    for attribute in parts {
        let (key, attribute_value) = match attribute.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim().to_string())),
            None => (attribute, None),
        };
        match key.to_ascii_lowercase().as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = attribute_value,
            "domain" => cookie.domain = attribute_value,
            "path" => cookie.path = attribute_value,
            _ => {}
        }
    }
    Some(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_extracted_and_normalized() {
        let html = "<html><head><title>\n  Panel   logowania\n</title></head></html>";
        assert_eq!(extract_title(html).as_deref(), Some("Panel logowania"));
    }

    #[test]
    fn missing_or_empty_title_gives_none() {
        assert_eq!(extract_title("<html><body>bez tytułu</body></html>"), None);
        assert_eq!(extract_title("<title>  </title>"), None);
        assert_eq!(extract_title("to nie jest HTML"), None);
    }

    #[test]
    fn long_title_is_truncated() {
        let html = format!("<title>{}</title>", "a".repeat(1000));
        assert_eq!(
            extract_title(&html).unwrap().chars().count(),
            MAX_TITLE_CHARS
        );
    }

    #[test]
    fn cookie_attributes_are_parsed() {
        let cookie = parse_set_cookie(
            "PHPSESSID=abc123; path=/; Secure; HttpOnly; SameSite=Lax; Domain=.lab.local",
        )
        .unwrap();
        assert_eq!(cookie.name, "PHPSESSID");
        assert_eq!(cookie.value, "abc123");
        assert_eq!(cookie.path.as_deref(), Some("/"));
        assert_eq!(cookie.domain.as_deref(), Some(".lab.local"));
        assert_eq!(cookie.same_site.as_deref(), Some("Lax"));
        assert!(cookie.secure && cookie.http_only);
    }

    #[test]
    fn insecure_cookie_has_flags_off() {
        let cookie = parse_set_cookie("tracking=1").unwrap();
        assert!(!cookie.secure && !cookie.http_only);
        assert_eq!(cookie.same_site, None);
    }

    #[test]
    fn invalid_cookie_header_gives_none() {
        assert_eq!(parse_set_cookie("bez-znaku-rownosci"), None);
        assert_eq!(parse_set_cookie("=wartosc"), None);
    }

    #[test]
    fn response_is_converted_to_http_info() {
        let response = RawResponse {
            url: "http://10.0.0.5/login".into(),
            status: 200,
            headers: vec![
                ("server".into(), "nginx".into()),
                ("set-cookie".into(), "sid=1; HttpOnly".into()),
            ],
            body: b"<title>Logowanie</title>".to_vec(),
            redirects: Vec::new(),
            tls_verified: None,
        };

        let info = to_http_info(&response);

        assert_eq!(info.title.as_deref(), Some("Logowanie"));
        assert_eq!(info.header("Server"), Some("nginx"));
        assert_eq!(info.cookies.len(), 1);
        assert!(info.cookies[0].http_only);
    }
}
