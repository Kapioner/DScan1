-- B3: ślepy indeks (HMAC-SHA256) pól szyfrowanych, po których trzeba wyszukiwać:
-- nazwy ciasteczek, nazwy nagłówków i pary nagłówek=wartość z http_info.
-- Skrót nie zdradza wartości bez klucza; ta sama wartość daje ten sam skrót.
CREATE TABLE http_blind_index (
    service_id BIGINT NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    kind       TEXT   NOT NULL CHECK (kind IN ('cookie', 'header', 'header_value')),
    digest     BYTEA  NOT NULL,
    PRIMARY KEY (service_id, kind, digest)
);

CREATE INDEX http_blind_index_lookup_idx ON http_blind_index (kind, digest);
