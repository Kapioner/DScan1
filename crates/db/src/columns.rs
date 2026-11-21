//! Rejestr kolumn z danymi wrażliwymi. Każda wartość w nich jest zaszyfrowana
//! (patrz [`crate::Encrypted`]), a rotacja klucza przechodzi po wszystkich kolumnach z tej listy.

use dscan_crypto::CryptoError;

use crate::DbError;

/// Kolumna `BYTEA` przechowująca zaszyfrowane wartości. Każda z tych tabel ma klucz `id BIGINT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedColumn {
    pub table: &'static str,
    pub column: &'static str,
}

impl EncryptedColumn {
    /// Kontekst szyfrowania (AAD), np. `"services.banner"`.
    pub fn context(&self) -> String {
        format!("{}.{}", self.table, self.column)
    }

    pub(crate) fn crypto_error(&self, source: CryptoError) -> DbError {
        DbError::Crypto {
            context: self.context(),
            source,
        }
    }
}

pub const TARGETS_NOTE: EncryptedColumn = EncryptedColumn {
    table: "targets",
    column: "note",
};
pub const SUBGROUPS_RAW_NMAP_XML: EncryptedColumn = EncryptedColumn {
    table: "subgroups",
    column: "raw_nmap_xml",
};
pub const SERVICES_BANNER: EncryptedColumn = EncryptedColumn {
    table: "services",
    column: "banner",
};
pub const HTTP_INFO_HEADERS: EncryptedColumn = EncryptedColumn {
    table: "http_info",
    column: "headers",
};
pub const HTTP_INFO_COOKIES: EncryptedColumn = EncryptedColumn {
    table: "http_info",
    column: "cookies",
};
pub const HTTP_INFO_CERTIFICATE: EncryptedColumn = EncryptedColumn {
    table: "http_info",
    column: "certificate",
};
pub const OVERRIDES_VALUE: EncryptedColumn = EncryptedColumn {
    table: "overrides",
    column: "value",
};

/// Wszystkie kolumny szyfrowane — przy dodaniu nowej trzeba ją dopisać tutaj.
pub const ENCRYPTED_COLUMNS: [EncryptedColumn; 7] = [
    TARGETS_NOTE,
    SUBGROUPS_RAW_NMAP_XML,
    SERVICES_BANNER,
    HTTP_INFO_HEADERS,
    HTTP_INFO_COOKIES,
    HTTP_INFO_CERTIFICATE,
    OVERRIDES_VALUE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_combines_table_and_column() {
        assert_eq!(SERVICES_BANNER.context(), "services.banner");
    }

    #[test]
    fn contexts_are_unique() {
        let mut contexts: Vec<String> = ENCRYPTED_COLUMNS.iter().map(|c| c.context()).collect();
        contexts.sort();
        contexts.dedup();
        assert_eq!(contexts.len(), ENCRYPTED_COLUMNS.len());
    }
}
