-- M4: SimHash odpowiedzi HTTP do grupowania podobnych usług.
ALTER TABLE http_info ADD COLUMN simhash BIGINT;

-- F11: tagi hostów (port IS NULL) i usług — niezależne od przebiegu, jak poprawki (A6).
CREATE TABLE tags (
    id         BIGSERIAL PRIMARY KEY,
    ip         INET        NOT NULL,
    port       INTEGER,
    protocol   TEXT,
    tag        TEXT        NOT NULL CHECK (char_length(tag) BETWEEN 1 AND 40),
    created_by BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (ip, port, protocol, tag)
);

CREATE INDEX tags_tag_idx ON tags (tag);
