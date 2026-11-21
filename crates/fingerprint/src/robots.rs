//! Analiza `robots.txt` (część zadania M6): blokada całej witryny (typowa dla stagingu)
//! i ukryte ścieżki warte ręcznego sprawdzenia.

use dscan_core::models::{Evidence, EvidenceKind};

use crate::ProbeResult;

/// Ścieżki w robots.txt, które warto sprawdzić ręcznie.
const INTERESTING_ROBOTS_WORDS: [&str; 7] = [
    "admin", "staging", "test", "dev", "backup", "private", "internal",
];

/// `robots.txt`: blokada całej witryny (typowe dla stagingu) i ścieżki warte uwagi.
pub fn robots_evidence(probes: &[ProbeResult]) -> Vec<Evidence> {
    let Some(robots) = probes
        .iter()
        .find(|probe| probe.path == "/robots.txt" && probe.status == 200)
    else {
        return Vec::new();
    };
    let disallowed: Vec<&str> = robots
        .body
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("disallow")
                .then(|| value.trim())
        })
        .collect();
    let mut found = Vec::new();
    if disallowed.contains(&"/") {
        found.push(evidence(
            EvidenceKind::Path,
            "robots.txt blokuje całą witrynę".into(),
            30,
        ));
    }
    let interesting: Vec<&str> = disallowed
        .iter()
        .copied()
        .filter(|path| {
            INTERESTING_ROBOTS_WORDS
                .iter()
                .any(|word| path.to_lowercase().contains(word))
        })
        .collect();
    if !interesting.is_empty() {
        found.push(evidence(
            EvidenceKind::Path,
            format!("robots.txt ukrywa: {}", interesting.join(", ")),
            40,
        ));
    }
    found
}

fn evidence(kind: EvidenceKind, description: String, weight: u8) -> Evidence {
    Evidence {
        kind,
        description,
        weight,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_txt_hints() {
        let robots = ProbeResult {
            path: "/robots.txt".into(),
            status: 200,
            body: "User-agent: *\nDisallow: /\nDisallow: /admin-old/\nDisallow: /images/".into(),
        };
        let evidence = robots_evidence(&[robots]);
        assert_eq!(evidence.len(), 2);
        assert!(evidence[1].description.contains("/admin-old/"));
        assert!(!evidence[1].description.contains("/images/"));
        let missing = ProbeResult {
            path: "/robots.txt".into(),
            status: 404,
            body: "Disallow: /".into(),
        };
        assert!(robots_evidence(&[missing]).is_empty());
    }
}
