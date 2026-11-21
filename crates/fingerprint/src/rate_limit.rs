//! Ograniczanie zapytań HTTP (zadanie S7):
//! - **globalne tempo** — `limits.http_requests_per_second` dla całego skanera (crate governor),
//! - **budżet na host** — `limits.http_requests_per_host` zapytań do jednego hosta w przebiegu.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Mutex;

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};

/// Host wyczerpał budżet zapytań w tym przebiegu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub host: IpAddr,
    pub limit: u32,
}

impl fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "host {} wyczerpał limit {} zapytań HTTP w przebiegu",
            self.host, self.limit
        )
    }
}

impl std::error::Error for BudgetExceeded {}

/// Wspólny limiter dla wszystkich zapytań HTTP jednego przebiegu.
pub struct HttpRateLimiter {
    global: DefaultDirectRateLimiter,
    per_host_limit: u32,
    used: Mutex<HashMap<IpAddr, u32>>,
}

impl HttpRateLimiter {
    /// `requests_per_second` zapytań na sekundę łącznie i najwyżej `requests_per_host` na host.
    /// Zapytania są rozkładane równomiernie (bez serii na starcie), żeby nie obciążać celów skokowo.
    pub fn new(requests_per_second: u32, requests_per_host: u32) -> Self {
        let rate = NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(rate).allow_burst(NonZeroU32::MIN);
        HttpRateLimiter {
            global: RateLimiter::direct(quota),
            per_host_limit: requests_per_host,
            used: Mutex::new(HashMap::new()),
        }
    }

    /// Czeka na zgodę na zapytanie do `host`. Gdy host wyczerpał budżet, zwraca błąd od razu.
    pub async fn acquire(&self, host: IpAddr) -> Result<(), BudgetExceeded> {
        self.reserve(host)?;
        self.global.until_ready().await;
        Ok(())
    }

    /// Ile zapytań do hosta jeszcze zostało w tym przebiegu.
    pub fn remaining(&self, host: IpAddr) -> u32 {
        let used = self.lock_used().get(&host).copied().unwrap_or(0);
        self.per_host_limit.saturating_sub(used)
    }

    fn reserve(&self, host: IpAddr) -> Result<(), BudgetExceeded> {
        let mut used = self.lock_used();
        let count = used.entry(host).or_insert(0);
        if *count >= self.per_host_limit {
            return Err(BudgetExceeded {
                host,
                limit: self.per_host_limit,
            });
        }
        *count += 1;
        Ok(())
    }

    /// Licznik jest tylko liczbą — nawet po panice innego wątku można go bezpiecznie używać.
    fn lock_used(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, u32>> {
        self.used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn per_host_budget_is_enforced() {
        let limiter = HttpRateLimiter::new(1000, 2);
        let host = ip("10.0.0.1");

        assert!(limiter.acquire(host).await.is_ok());
        assert!(limiter.acquire(host).await.is_ok());
        assert_eq!(
            limiter.acquire(host).await,
            Err(BudgetExceeded { host, limit: 2 })
        );
        assert_eq!(limiter.remaining(host), 0);
    }

    #[tokio::test]
    async fn budget_is_separate_for_each_host() {
        let limiter = HttpRateLimiter::new(1000, 1);
        assert!(limiter.acquire(ip("10.0.0.1")).await.is_ok());
        assert!(limiter.acquire(ip("10.0.0.2")).await.is_ok());
        assert_eq!(limiter.remaining(ip("10.0.0.3")), 1);
    }

    #[tokio::test]
    async fn global_rate_spaces_requests_evenly() {
        // 20 zapytań/s = co 50 ms; 6 zapytań → pierwsze od razu, 5 kolejnych po 50 ms.
        let limiter = HttpRateLimiter::new(20, 100);
        let begin = Instant::now();
        for i in 0..6 {
            limiter.acquire(ip(&format!("10.0.0.{i}"))).await.unwrap();
        }
        let elapsed = begin.elapsed();
        assert!(
            elapsed >= Duration::from_millis(230),
            "za szybko: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "za wolno: {elapsed:?}"
        );
    }

    #[test]
    fn zero_rate_is_treated_as_one_per_second() {
        let limiter = HttpRateLimiter::new(0, 1);
        assert_eq!(limiter.remaining(ip("10.0.0.1")), 1);
    }
}
