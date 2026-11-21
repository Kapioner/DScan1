//! HMAC-SHA256 (RFC 2104) — podstawa ślepego indeksu (B3).

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

/// HMAC-SHA256 klucza i wiadomości.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_hex;

    #[test]
    fn rfc4231_test_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            encode_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn long_keys_are_hashed() {
        let key = [0xaa; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            encode_hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }
}
