//! Obecność hosta w kolejnych przebiegach (zadanie S11).
//!
//! Host jest „nieaktywny” dopiero po K kolejnych przebiegach bez odpowiedzi
//! (K = `stability.inactive_after_missed_runs`) — pojedynczy brak odpowiedzi
//! (np. chwilowa awaria sieci) nie zmienia statusu.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::HostStatus;

/// Stan obecności hosta po ostatnim przebiegu, który go obejmował.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    pub ip: IpAddr,
    pub status: HostStatus,
    /// Ile kolejnych przebiegów host nie odpowiedział.
    pub consecutive_misses: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Nowy stan obecności po przebiegu: `responded` = host odpowiedział w tym przebiegu.
/// `previous = None` oznacza host widziany po raz pierwszy (wtedy musiał odpowiedzieć).
pub fn next_presence(
    previous: Option<&Presence>,
    ip: IpAddr,
    responded: bool,
    inactive_after: u32,
    now: DateTime<Utc>,
) -> Presence {
    let (first_seen, last_seen, misses) = match previous {
        Some(old) => (old.first_seen, old.last_seen, old.consecutive_misses),
        None => (now, now, 0),
    };
    if responded {
        return Presence {
            ip,
            status: HostStatus::Active,
            consecutive_misses: 0,
            first_seen,
            last_seen: now,
        };
    }
    let consecutive_misses = misses + 1;
    let status = if consecutive_misses >= inactive_after.max(1) {
        HostStatus::Inactive
    } else {
        HostStatus::Active
    };
    Presence {
        ip,
        status,
        consecutive_misses,
        first_seen,
        last_seen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "10.0.0.5".parse().unwrap()
    }

    #[test]
    fn host_becomes_inactive_only_after_k_misses() {
        let now = Utc::now();
        let mut presence = next_presence(None, ip(), true, 3, now);
        let mut statuses = Vec::new();
        for _ in 0..3 {
            presence = next_presence(Some(&presence), ip(), false, 3, now);
            statuses.push((presence.status, presence.consecutive_misses));
        }
        assert_eq!(
            statuses,
            vec![
                (HostStatus::Active, 1),
                (HostStatus::Active, 2),
                (HostStatus::Inactive, 3)
            ]
        );
    }

    #[test]
    fn response_resets_misses_and_reactivates() {
        let start: DateTime<Utc> = "2026-11-01T00:00:00Z".parse().unwrap();
        let later: DateTime<Utc> = "2026-11-20T00:00:00Z".parse().unwrap();
        let mut presence = next_presence(None, ip(), true, 1, start);
        presence = next_presence(Some(&presence), ip(), false, 1, later);
        assert_eq!(presence.status, HostStatus::Inactive);
        assert_eq!(presence.last_seen, start);

        presence = next_presence(Some(&presence), ip(), true, 1, later);
        assert_eq!(
            (presence.status, presence.consecutive_misses),
            (HostStatus::Active, 0)
        );
        assert_eq!((presence.first_seen, presence.last_seen), (start, later));
    }
}
