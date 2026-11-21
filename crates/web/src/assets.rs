use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

/// htmx 2.0.11 (licencja 0BSD, `static/htmx-LICENSE`) — wkompilowany w binarkę.
const HTMX: &str = include_str!("../static/htmx.min.js");
const STYLESHEET: &str = include_str!("../static/style.css");

const ONE_DAY: &str = "public, max-age=86400";

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
