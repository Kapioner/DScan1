//! SimHash odpowiedzi HTTP (M4): z tytułu, nagłówków i struktury HTML, tak by podobne
//! usługi (np. „te same 40 kamer”) miały skróty różniące się na niewielu bitach.

use scraper::Html;
use sha2::{Digest, Sha256};

/// Cecha z wagą.
type Feature = (String, i32);

/// 64-bitowy skrót cechy (pierwsze 8 bajtów SHA-256).
fn feature_hash(text: &str) -> u64 {
    let digest = Sha256::digest(text.as_bytes());
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// SimHash z listy cech: każdy bit to znak sumy wag cech, które mają go ustawionego.
pub fn simhash(features: &[Feature]) -> u64 {
    let mut weights = [0i64; 64];
    for (feature, weight) in features {
        let hash = feature_hash(feature);
        for (bit, slot) in weights.iter_mut().enumerate() {
            if hash >> bit & 1 == 1 {
                *slot += i64::from(*weight)
            } else {
                *slot -= i64::from(*weight)
            }
        }
    }
    weights
        .iter()
        .enumerate()
        .filter(|(_, w)| **w > 0)
        .fold(0u64, |acc, (bit, _)| acc | 1 << bit)
}

/// Liczba różnych bitów.
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Cechy odpowiedzi: słowa tytułu (waga 3), nazwy nagłówków i wartość `Server` (2),
/// trójki kolejnych znaczników HTML (1) — treść tekstowa strony nie ma znaczenia.
pub fn response_features(
    title: Option<&str>,
    headers: &[(String, String)],
    body: &str,
) -> Vec<Feature> {
    let mut features: Vec<Feature> = Vec::new();
    if let Some(title) = title {
        features.extend(
            title
                .to_lowercase()
                .split_whitespace()
                .map(|w| (format!("t:{w}"), 3)),
        );
    }
    for (name, value) in headers {
        let name = name.to_lowercase();
        if name == "server" {
            features.push((format!("s:{}", value.to_lowercase()), 2));
        }
        if !matches!(
            name.as_str(),
            "date" | "content-length" | "set-cookie" | "etag" | "last-modified" | "expires"
        ) {
            features.push((format!("h:{name}"), 2));
        }
    }
    let document = Html::parse_document(body);
    let tags: Vec<String> = document
        .root_element()
        .descendants()
        .filter_map(|node| node.value().as_element().map(|e| e.name().to_string()))
        .take(2_000)
        .collect();
    features.extend(tags.windows(3).map(|w| (format!("g:{}", w.join(">")), 1)));
    features
}

/// SimHash odpowiedzi (bity zapisane jako i64 — typ kolumny BIGINT).
pub fn response_simhash(info: &dscan_core::models::HttpInfo, body: &str) -> i64 {
    let headers: Vec<(String, String)> = info
        .headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    simhash(&response_features(info.title.as_deref(), &headers, body)) as i64
}

/// Grupy indeksów skrótów odległych o najwyżej `max_distance` bitów (łączenie przechodnie).
pub fn cluster(hashes: &[u64], max_distance: u32) -> Vec<Vec<usize>> {
    let mut parent: Vec<usize> = (0..hashes.len()).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    for i in 0..hashes.len() {
        for j in i + 1..hashes.len() {
            if hamming(hashes[i], hashes[j]) <= max_distance {
                let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                parent[a] = b;
            }
        }
    }
    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for i in 0..hashes.len() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    let mut clusters: Vec<Vec<usize>> = groups.into_values().collect();
    clusters.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0])));
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn camera(serial: &str) -> u64 {
        let body = format!(
            "<html><head><title>IP Camera</title></head><body><div id=login><form><input name=user><input name=pass></form></div><p>{serial}</p></body></html>"
        );
        simhash(&response_features(
            Some("IP Camera"),
            &[("Server".into(), "Boa/0.94".into())],
            &body,
        ))
    }

    #[test]
    fn similar_pages_are_close_and_different_far() {
        let (a, b) = (camera("SN-001"), camera("SN-002"));
        let blog = simhash(&response_features(
            Some("Mój blog o gotowaniu"),
            &[
                ("Server".into(), "nginx".into()),
                ("X-Powered-By".into(), "PHP".into()),
            ],
            "<html><body><article><h1>x</h1><p>y</p><ul><li>a</li><li>b</li></ul></article><footer></footer></body></html>",
        ));
        assert!(hamming(a, b) <= 3, "{}", hamming(a, b));
        assert!(hamming(a, blog) > 10, "{}", hamming(a, blog));
        let groups = cluster(&[a, blog, b], 3);
        assert_eq!(groups, vec![vec![0, 2], vec![1]]);
    }
}
