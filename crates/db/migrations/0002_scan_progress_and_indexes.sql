-- Postęp skanu (S4, S6) i indeksy pod porównania przebiegów (B5).

-- Prognoza czasu do końca liczona z ukończonych adresów (podgrupy mogą mieć różne rozmiary).
ALTER TABLE scan_runs ADD COLUMN completed_addresses BIGINT NOT NULL DEFAULT 0;

-- Powód niepowodzenia podgrupy (np. błąd nmap) — do raportu i ponowienia (S9).
ALTER TABLE subgroups ADD COLUMN error TEXT;

-- Lista ostatnich przebiegów i wyszukiwanie „poprzedniego przebiegu” do porównania.
CREATE INDEX scan_runs_started_idx ON scan_runs (started_at DESC);

-- Historia hosta między przebiegami: najpierw po adresie, potem po przebiegu.
DROP INDEX hosts_ip_idx;
CREATE INDEX hosts_ip_run_idx ON hosts (ip, scan_run_id);

-- Porównanie przebiegów (M1) łączy usługi po host_id i kluczu (port, protokół).
-- INCLUDE pozwala odczytać odcisk i stan z samego indeksu, bez sięgania do tabeli.
CREATE INDEX services_comparison_idx ON services (host_id, port, protocol)
    INCLUDE (fingerprint_hash, state);

-- Zmiany wykryte względem konkretnego poprzedniego przebiegu.
CREATE INDEX changes_previous_run_idx ON changes (previous_run_id);
