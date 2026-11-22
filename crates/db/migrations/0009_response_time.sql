-- Czas odpowiedzi strony głównej usługi WWW (np. opóźnienia symulowane przez Toxiproxy).
ALTER TABLE http_info ADD COLUMN response_ms INTEGER;
