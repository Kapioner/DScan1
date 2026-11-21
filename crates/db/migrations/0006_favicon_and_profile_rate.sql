-- H4: hash favicony (mmh3 w wariancie Shodana i SHA-256) — skróty nie są danymi poufnymi.
ALTER TABLE http_info ADD COLUMN favicon JSONB;
CREATE INDEX http_info_favicon_mmh3_idx ON http_info (((favicon ->> 'mmh3')::integer));

-- F4: limit tempa (pakiety/s) w profilu skanu z bazy; NULL = [limits] nmap_max_rate.
ALTER TABLE scan_profiles ADD COLUMN max_rate INTEGER CHECK (max_rate IS NULL OR max_rate > 0);

-- S10: dodatkowe podgrupy z powtórnymi pomiarami hostów niestabilnych.
ALTER TABLE subgroups ADD COLUMN retry_of INTEGER;
