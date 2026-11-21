use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};

/// Nazwa ciasteczka sesji.
pub const SESSION_COOKIE: &str = "dscan_session";

/// Ciasteczko sesji: `HttpOnly` (niedostępne dla JavaScriptu), `SameSite=Strict`
/// (nie jest wysyłane z obcych stron — ochrona przed CSRF), opcjonalnie `Secure`.
pub fn session_cookie(token: &str, max_age_seconds: i64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_seconds}{secure}"
    )
}

/// Ciasteczko usuwające sesję w przeglądarce (wylogowanie).
pub fn clear_session_cookie(secure: bool) -> String {
    session_cookie("", 0, secure)
}

/// Token sesji z nagłówka `Authorization: Bearer …` (CLI) albo z ciasteczka (przeglądarka).
pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    if let Some(token) = bearer {
        return Some(token.to_string());
    }
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, value)| *name == SESSION_COOKIE && !value.is_empty())
        .map(|(_, value)| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn cookie_has_security_attributes() {
        let cookie = session_cookie("abc", 3600, false);
        assert_eq!(
            cookie,
            "dscan_session=abc; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"
        );
        assert!(session_cookie("abc", 1, true).ends_with("; Secure"));
        assert!(clear_session_cookie(false).contains("Max-Age=0"));
    }

    #[test]
    fn token_is_read_from_bearer_header() {
        assert_eq!(
            token_from_headers(&headers(&[("authorization", "Bearer xyz")])).as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn token_is_read_from_cookie_among_others() {
        let map = headers(&[("cookie", "theme=dark; dscan_session=tok123; lang=pl")]);
        assert_eq!(token_from_headers(&map).as_deref(), Some("tok123"));
    }

    #[test]
    fn missing_or_empty_token_gives_none() {
        assert_eq!(token_from_headers(&headers(&[])), None);
        assert_eq!(
            token_from_headers(&headers(&[("cookie", "dscan_session=")])),
            None
        );
        assert_eq!(
            token_from_headers(&headers(&[("authorization", "Basic abc")])),
            None
        );
    }
}
