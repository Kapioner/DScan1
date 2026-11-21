-- Sesje logowania (A2), profile skanów (A5), weryfikacja TLS w wynikach HTTP (H1).

-- W bazie tylko skrót SHA-256 tokenu — sam token jest wyłącznie w ciasteczku użytkownika.
CREATE TABLE sessions (
    token_hash BYTEA       PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

ALTER TABLE users ADD COLUMN last_login_at TIMESTAMPTZ;

-- Profil skanu: co skanować (grupa celów), jak (tryb, porty), kiedy (okna) i jak często.
CREATE TABLE scan_profiles (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT        NOT NULL UNIQUE,
    mode              TEXT        NOT NULL CHECK (mode IN ('discovery', 'services')),
    target_group      TEXT,                          -- NULL = wszystkie cele
    ports             TEXT[]      NOT NULL DEFAULT '{}', -- puste = [scope] allowed_ports
    windows           JSONB       NOT NULL DEFAULT '[]', -- [{"start":"22:00","end":"06:00"}]
    frequency_minutes INTEGER CHECK (frequency_minutes IS NULL OR frequency_minutes >= 5),
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NULL = zwykłe HTTP; FALSE = HTTPS z certyfikatem, który nie przeszedł weryfikacji.
ALTER TABLE http_info ADD COLUMN tls_verified BOOLEAN;
