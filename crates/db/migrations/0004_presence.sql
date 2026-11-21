-- Obecność hostów w kolejnych przebiegach (S11).

-- Bieżący stan każdego znanego hosta (niezależny od przebiegu).
CREATE TABLE host_presence (
    ip                 INET PRIMARY KEY,
    status             TEXT        NOT NULL CHECK (status IN ('active', 'inactive', 'unstable')),
    consecutive_misses INTEGER     NOT NULL DEFAULT 0,
    first_seen         TIMESTAMPTZ NOT NULL,
    last_seen          TIMESTAMPTZ NOT NULL,
    last_run_id        BIGINT      REFERENCES scan_runs (id) ON DELETE SET NULL
);

CREATE INDEX host_presence_status_idx ON host_presence (status);

-- Historia odpowiedzi: czy host odpowiedział w danym przebiegu.
CREATE TABLE host_responses (
    ip          INET        NOT NULL,
    scan_run_id BIGINT      NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    responded   BOOLEAN     NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ip, scan_run_id)
);

CREATE INDEX host_responses_run_idx ON host_responses (scan_run_id);
