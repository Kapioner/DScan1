//! Fingerprinting usług: klient HTTP/HTTPS, certyfikaty TLS, silnik sygnatur.
//!
//! Na tym etapie: limiter zapytań HTTP (zadanie S7), z którego skorzysta klient HTTP (H1).

mod rate_limit;

pub use rate_limit::{BudgetExceeded, HttpRateLimiter};
