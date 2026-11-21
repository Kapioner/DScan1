/// Zapis bajtów jako małe znaki szesnastkowe (np. do wypisania nowego klucza).
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bytes_as_lowercase_hex() {
        assert_eq!(encode_hex(&[0x00, 0x0a, 0xff]), "000aff");
        assert_eq!(encode_hex(&[]), "");
    }
}
