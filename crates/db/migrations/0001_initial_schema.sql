-- Schemat początkowy DScan (zadanie B1).
--
-- Kolumny typu BYTEA oznaczone „zaszyfrowane (B2)” przechowują dane wrażliwe
-- (banery, nagłówki, ciasteczka, certyfikaty, notatki) zaszyfrowane po stronie
-- aplikacji AES-256-GCM. Baza nigdy nie widzi ich jawnej postaci.

-- ---------------------------------------------------------------------------
-- Użytkownicy i role (A2, A3, A4)
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    permissions TEXT[]      NOT NULL DEFAULT '{}',
    built_in    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cztery role wbudowane z wymagań. Uprawnienia są listą, więc admin może
-- później zdefiniować nową rolę z dowolnego zestawu (A4).
INSERT INTO roles (name, permissions, built_in) VALUES
    ('administracja',                  '{admin,targets:write,results:write,read}', TRUE),
    ('dodawanie_usuwanie_modyfikacja', '{targets:write,results:write,read}',       TRUE),
    ('modyfikacja_odczyt',             '{results:write,read}',                     TRUE),
    ('odczyt',                         '{read}',                                   TRUE);

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,             -- argon2 (A2)
    role_id       BIGINT      NOT NULL REFERENCES roles (id),
    is_blocked    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Cele skanowania
-- ---------------------------------------------------------------------------
CREATE TABLE targets (
    id           BIGSERIAL PRIMARY KEY,
    kind         TEXT        NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
    value        TEXT        NOT NULL,
    target_group TEXT,
    note         BYTEA,                              -- zaszyfrowane (B2)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

-- ---------------------------------------------------------------------------
-- Przebiegi skanów i podgrupy (S4, S6, S9)
-- ---------------------------------------------------------------------------
CREATE TABLE scan_runs (
    id                  BIGSERIAL PRIMARY KEY,
    profile             TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    total_addresses     BIGINT      NOT NULL DEFAULT 0,
    total_subgroups     INTEGER     NOT NULL DEFAULT 0,
    completed_subgroups INTEGER     NOT NULL DEFAULT 0
);

CREATE TABLE subgroups (
    id           BIGSERIAL PRIMARY KEY,
    scan_run_id  BIGINT      NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    sequence_no  INTEGER     NOT NULL,
    addresses    TEXT[]      NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    raw_nmap_xml BYTEA,                              -- zaszyfrowane (B2); surowy XML dla DefectDojo
    UNIQUE (scan_run_id, sequence_no)
);

-- Wznawianie: szybkie wyszukanie niedokończonych podgrup przebiegu.
CREATE INDEX subgroups_run_status_idx ON subgroups (scan_run_id, status);

-- ---------------------------------------------------------------------------
-- Wyniki: hosty, usługi, HTTP, detekcje
-- ---------------------------------------------------------------------------
CREATE TABLE hosts (
    id          BIGSERIAL PRIMARY KEY,
    scan_run_id BIGINT      NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    ip          INET        NOT NULL,
    hostnames   TEXT[]      NOT NULL DEFAULT '{}',
    status      TEXT        NOT NULL CHECK (status IN ('active', 'inactive', 'unstable')),
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    UNIQUE (scan_run_id, ip)
);

CREATE INDEX hosts_ip_idx ON hosts (ip);

CREATE TABLE services (
    id               BIGSERIAL PRIMARY KEY,
    host_id          BIGINT  NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol         TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    state            TEXT    NOT NULL CHECK (state IN ('open', 'closed', 'filtered')),
    name             TEXT,
    product          TEXT,
    version          TEXT,
    cpe              TEXT[]  NOT NULL DEFAULT '{}',
    banner           BYTEA,                          -- zaszyfrowane (B2)
    fingerprint_hash TEXT,                           -- odcisk usługi do porównań (M1)
    UNIQUE (host_id, port, protocol)
);

CREATE TABLE http_info (
    id             BIGSERIAL PRIMARY KEY,
    service_id     BIGINT  NOT NULL UNIQUE REFERENCES services (id) ON DELETE CASCADE,
    url            TEXT    NOT NULL,
    status_code    INTEGER NOT NULL,
    title          TEXT,
    headers        BYTEA,                            -- zaszyfrowane (B2)
    cookies        BYTEA,                            -- zaszyfrowane (B2)
    certificate    BYTEA,                            -- zaszyfrowane (B2)
    redirect_chain JSONB   NOT NULL DEFAULT '[]'
);

CREATE TABLE signatures (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT        NOT NULL UNIQUE,
    category        TEXT,
    definition_yaml TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE detections (
    id           BIGSERIAL PRIMARY KEY,
    service_id   BIGINT   NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    signature_id BIGINT   REFERENCES signatures (id) ON DELETE SET NULL,
    technology   TEXT     NOT NULL,
    version      TEXT,
    confidence   SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    evidence     JSONB    NOT NULL DEFAULT '[]'
);

CREATE INDEX detections_service_idx ON detections (service_id);
CREATE INDEX detections_technology_idx ON detections (technology);

-- ---------------------------------------------------------------------------
-- Zmiany między przebiegami (M1)
-- ---------------------------------------------------------------------------
CREATE TABLE changes (
    id                   BIGSERIAL PRIMARY KEY,
    previous_run_id      BIGINT      REFERENCES scan_runs (id) ON DELETE CASCADE,
    current_run_id       BIGINT      NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    ip                   INET        NOT NULL,
    port                 INTEGER     NOT NULL,
    protocol             TEXT        NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    kind                 TEXT        NOT NULL CHECK (kind IN ('appeared', 'disappeared', 'modified')),
    previous_fingerprint TEXT,
    current_fingerprint  TEXT,
    detected_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX changes_current_run_idx ON changes (current_run_id);

-- ---------------------------------------------------------------------------
-- Ręczne nadpisania wyników (A6): przechowywane osobno od obserwacji,
-- kluczowane adresem (a nie przebiegiem), więc przetrwają kolejne skany.
-- port = NULL oznacza nadpisanie dotyczące całego hosta.
-- ---------------------------------------------------------------------------
CREATE TABLE overrides (
    id         BIGSERIAL PRIMARY KEY,
    ip         INET        NOT NULL,
    port       INTEGER,
    protocol   TEXT CHECK (protocol IN ('tcp', 'udp')),
    field      TEXT        NOT NULL,
    value      BYTEA       NOT NULL,                 -- zaszyfrowane (B2)
    created_by BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (ip, port, protocol, field)
);

-- ---------------------------------------------------------------------------
-- Dziennik audytu (A7)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    action     TEXT        NOT NULL,
    entity     TEXT        NOT NULL,
    entity_id  TEXT,
    details    JSONB       NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_created_idx ON audit_log (created_at);
