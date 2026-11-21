//! Typ [`Encrypted<T>`] — wartość zaszyfrowana po stronie aplikacji, zapisywana w kolumnie `BYTEA`.
//!
//! Baza widzi wyłącznie szyfrogram. Wartość jest serializowana do JSON, więc `T` może być
//! dowolnym typem z serde (np. `String` dla notatki albo `Vec<HttpHeader>` dla nagłówków).

use std::marker::PhantomData;

use dscan_crypto::Cipher;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};

use crate::{DbError, EncryptedColumn};

/// Zaszyfrowana wartość typu `T` przeznaczona dla konkretnej kolumny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted<T> {
    ciphertext: Vec<u8>,
    _value_type: PhantomData<T>,
}

impl<T> Encrypted<T> {
    /// Opakowuje bajty odczytane z bazy.
    pub fn from_bytes(ciphertext: Vec<u8>) -> Self {
        Encrypted {
            ciphertext,
            _value_type: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl<T: Serialize> Encrypted<T> {
    /// Szyfruje wartość dla kolumny `column`.
    pub fn seal(cipher: &Cipher, column: &EncryptedColumn, value: &T) -> Result<Self, DbError> {
        let plaintext =
            serde_json::to_vec(value).map_err(|error| DbError::Serialization(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(&plaintext, column.context().as_bytes())
            .map_err(|source| column.crypto_error(source))?;
        Ok(Encrypted::from_bytes(ciphertext))
    }
}

impl<T: DeserializeOwned> Encrypted<T> {
    /// Odszyfrowuje wartość zapisaną w kolumnie `column`.
    pub fn open(&self, cipher: &Cipher, column: &EncryptedColumn) -> Result<T, DbError> {
        let plaintext = cipher
            .decrypt(&self.ciphertext, column.context().as_bytes())
            .map_err(|source| column.crypto_error(source))?;
        serde_json::from_slice(&plaintext)
            .map_err(|error| DbError::Serialization(error.to_string()))
    }
}

// Dla sqlx `Encrypted<T>` zachowuje się dokładnie jak `BYTEA` (Vec<u8>).
impl<T> Type<Postgres> for Encrypted<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(type_info: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(type_info)
    }
}

impl<T> Encode<'_, Postgres> for Encrypted<T> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <Vec<u8> as Encode<Postgres>>::encode_by_ref(&self.ciphertext, buffer)
    }
}

impl<'r, T> Decode<'r, Postgres> for Encrypted<T> {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<Postgres>>::decode(value)?;
        Ok(Encrypted::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::columns::{SERVICES_BANNER, TARGETS_NOTE};

    fn cipher() -> Cipher {
        Cipher::new(&[7; 32])
    }

    #[test]
    fn seal_and_open_round_trip() {
        let sealed =
            Encrypted::seal(&cipher(), &TARGETS_NOTE, &"serwer testowy".to_string()).unwrap();
        let opened: String = sealed.open(&cipher(), &TARGETS_NOTE).unwrap();
        assert_eq!(opened, "serwer testowy");
    }

    #[test]
    fn structured_values_are_supported() {
        let headers = vec![("Server".to_string(), "nginx".to_string())];
        let sealed = Encrypted::seal(&cipher(), &SERVICES_BANNER, &headers).unwrap();
        let opened: Vec<(String, String)> = sealed.open(&cipher(), &SERVICES_BANNER).unwrap();
        assert_eq!(opened, headers);
    }

    #[test]
    fn value_from_other_column_cannot_be_opened() {
        let sealed = Encrypted::seal(&cipher(), &TARGETS_NOTE, &"x".to_string()).unwrap();
        let moved: Encrypted<String> = Encrypted::from_bytes(sealed.as_bytes().to_vec());
        assert!(matches!(
            moved.open(&cipher(), &SERVICES_BANNER),
            Err(DbError::Crypto { .. })
        ));
    }
}
