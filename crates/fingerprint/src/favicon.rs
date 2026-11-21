//! Hash favicony (H4): `/favicon.ico` albo ikona z `<link rel="icon">`.
//! mmh3 liczony jak w Shodanie (`mmh3.hash(base64.encodebytes(dane))`, 32 bity ze znakiem)
//! oraz SHA-256 surowych bajtów.

use std::net::IpAddr;

use dscan_core::models::Favicon;
use reqwest::Url;
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};

use crate::HttpFetcher;
use crate::redirect::{is_same_host, resolve_location};

/// MurmurHash3 x86 32-bit (wynik jako liczba ze znakiem — tak zapisuje go Shodan).
pub fn mmh3_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut hash = seed;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= k;
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }
    let tail = chunks.remainder();
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, byte) in tail.iter().enumerate() {
            k |= u32::from(*byte) << (8 * i);
        }
        hash ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^= hash >> 16;
    hash as i32
}

/// Base64 z podziałem na linie po 76 znaków zakończone `\n` (jak Pythonowe `base64.encodebytes`).
pub fn base64_lines(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    let mut text = String::with_capacity(encoded.len() + encoded.len() / 76 + 1);
    for line in encoded.as_bytes().chunks(76) {
        text.push_str(&String::from_utf8_lossy(line));
        text.push('\n');
    }
    text
}

/// Oba skróty ikony.
pub fn favicon_hashes(url: &str, data: &[u8]) -> Favicon {
    let sha = Sha256::digest(data);
    Favicon {
        url: url.to_string(),
        mmh3: mmh3_32(base64_lines(data).as_bytes(), 0),
        sha256: sha.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Adres ikony z `<link rel="icon">` / `<link rel="shortcut icon">`.
pub fn icon_link(html: &str) -> Option<String> {
    let selector = Selector::parse("link[rel][href]").ok()?;
    let document = Html::parse_document(html);
    document.select(&selector).find_map(|link| {
        let rel = link.value().attr("rel")?.to_ascii_lowercase();
        rel.split_whitespace()
            .any(|part| part == "icon")
            .then(|| link.value().attr("href").map(str::to_string))?
    })
}

/// Kandydaci na adres ikony: najpierw z `<link>` (tylko ten sam host), potem `/favicon.ico`.
pub fn favicon_candidates(page_url: &str, html: &str) -> Vec<String> {
    let Ok(base) = Url::parse(page_url) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    if let Some(link) = icon_link(html).and_then(|href| resolve_location(&base, &href)) {
        if is_same_host(&base, &link) {
            candidates.push(link.to_string());
        }
    }
    if let Some(default) = resolve_location(&base, "/favicon.ico") {
        if !candidates.contains(&default.to_string()) {
            candidates.push(default.to_string());
        }
    }
    candidates
}

/// Pobiera pierwszą dostępną ikonę (GET, ten sam host) i liczy skróty.
pub async fn fetch_favicon(
    fetcher: &HttpFetcher,
    page_url: &str,
    ip: IpAddr,
    html: &str,
) -> Option<Favicon> {
    for url in favicon_candidates(page_url, html) {
        if let Ok(response) = fetcher.fetch(&url, ip).await {
            if response.status == 200
                && !response.body.is_empty()
                && !looks_like_html(&response.body)
            {
                return Some(favicon_hashes(&url, &response.body));
            }
        }
    }
    None
}

/// Strona błędu zwrócona z kodem 200 to nie ikona.
fn looks_like_html(body: &[u8]) -> bool {
    let start = String::from_utf8_lossy(&body[..body.len().min(64)]).to_ascii_lowercase();
    start.trim_start().starts_with("<!doctype html") || start.trim_start().starts_with("<html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmh3_matches_reference_values() {
        // Wartości referencyjne z Pythonowego pakietu mmh3.
        assert_eq!(mmh3_32(b"", 0), 0);
        assert_eq!(mmh3_32(b"hello", 0), 613_153_351);
        assert_eq!(mmh3_32(b"foo", 0), -156_908_512);
        assert_eq!(
            mmh3_32(b"The quick brown fox jumps over the lazy dog", 0),
            776_992_547
        );
    }

    #[test]
    fn base64_is_split_into_76_char_lines() {
        assert_eq!(base64_lines(b"abc"), "YWJj\n");
        assert_eq!(base64_lines(b"ab"), "YWI=\n");
        let long = base64_lines(&[0u8; 100]);
        let lines: Vec<&str> = long.lines().collect();
        assert_eq!(lines[0].len(), 76);
        assert!(long.ends_with('\n'));
    }

    #[test]
    fn icon_link_and_candidates() {
        let html =
            r#"<link rel="stylesheet" href="a.css"><link rel="Shortcut Icon" href="/img/i.png">"#;
        assert_eq!(icon_link(html).as_deref(), Some("/img/i.png"));
        assert_eq!(
            favicon_candidates("http://10.0.0.5:8080/app/", html),
            vec![
                "http://10.0.0.5:8080/img/i.png",
                "http://10.0.0.5:8080/favicon.ico"
            ]
        );
        // Ikona z innego hosta jest pomijana.
        let external = r#"<link rel="icon" href="https://cdn.example.com/i.ico">"#;
        assert_eq!(
            favicon_candidates("http://10.0.0.5/", external),
            vec!["http://10.0.0.5/favicon.ico"]
        );
    }

    #[test]
    fn hashes_are_computed() {
        let favicon = favicon_hashes("http://h/favicon.ico", b"abc");
        assert_eq!(
            favicon.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(favicon.mmh3, mmh3_32(b"YWJj\n", 0));
        assert!(looks_like_html(b"<!DOCTYPE html><html>"));
    }
}
