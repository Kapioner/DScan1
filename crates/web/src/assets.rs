use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

/// htmx 2.0.11 (licencja 0BSD, `static/htmx-LICENSE`) — wkompilowany w binarkę.
const HTMX: &str = include_str!("../static/htmx.min.js");
const STYLESHEET: &str = include_str!("../static/style.css");

const ONE_DAY: &str = "public, max-age=86400";

/// Logo DScan: pełne (znak + napis), sam znak i favicon — wkompilowane w binarkę.
const LOGO: &[u8] = include_bytes!("../static/img/logo.png");
const LOGO_MARK: &[u8] = include_bytes!("../static/img/logo-mark.png");
const FAVICON: &[u8] = include_bytes!("../static/img/favicon.png");

fn png(bytes: &'static [u8]) -> impl IntoResponse {
    ([(CONTENT_TYPE, "image/png"), (CACHE_CONTROL, ONE_DAY)], bytes)
}

pub async fn logo() -> impl IntoResponse {
    png(LOGO)
}

pub async fn logo_mark() -> impl IntoResponse {
    png(LOGO_MARK)
}

pub async fn favicon() -> impl IntoResponse {
    png(FAVICON)
}

pub async fn htmx() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, ONE_DAY),
        ],
        HTMX,
    )
}

pub async fn stylesheet() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, ONE_DAY),
        ],
        STYLESHEET,
    )
}
