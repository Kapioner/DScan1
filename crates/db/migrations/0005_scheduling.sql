-- Harmonogram i wznawianie (S8, S9), profile z konfiguracji (C4), skany przez API (C5).

-- Tryb skanu (discovery/services) — potrzebny przy wznowieniu przebiegu.
ALTER TABLE scan_runs ADD COLUMN mode TEXT NOT NULL DEFAULT 'services'
    CHECK (mode IN ('discovery', 'services'));
-- Profil z bazy, który uruchomił przebieg (harmonogram); NULL = skan ręczny.
ALTER TABLE scan_runs ADD COLUMN profile_id BIGINT REFERENCES scan_profiles (id) ON DELETE SET NULL;
-- Kto zlecił skan (NULL = harmonogram albo CLI lokalnie).
ALTER TABLE scan_runs ADD COLUMN requested_by BIGINT REFERENCES users (id) ON DELETE SET NULL;

CREATE INDEX scan_runs_profile_idx ON scan_runs (profile_id, started_at DESC);
CREATE INDEX scan_runs_status_idx ON scan_runs (status);
