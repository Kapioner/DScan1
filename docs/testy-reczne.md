# DScan — testy ręczne

Przygotowanie: serwer `./run.sh` w osobnym terminalu, potem `./run.sh login --user admin`.
W Neovimie każde polecenie można uruchomić jako `:!polecenie` albo w `:terminal`.
Zapytania do bazy: `docker compose exec -T postgres psql -U dscan -d dscan -c "…"` (dalej: `psql`).

## Automatyczne

| Test | Polecenie | Oczekiwane |
|---|---|---|
| format | `cargo fmt --all -- --check` | brak wyjścia |
| lint | `cargo clippy --workspace --all-targets -- -D warnings` | brak ostrzeżeń |
| testy | `cargo test --workspace` | 0 failed |
| testy na bazie | `DSCAN_TEST_DATABASE_URL=… cargo test --workspace` | 0 failed |

## Uruchomienie i konfiguracja

| Sprawdzenie | Polecenie | Oczekiwane |
|---|---|---|
| pierwszy start | `rm -f dscan.toml .env && ./run.sh` | `Utworzono dscan.toml`, `Dodano … do .env`, hasło w logu `***` |
| zdrowie | `curl -s localhost:8080/api/v1/health` | `{"status":"ok",…,"database":"ok"}` |
| uprawnienia `.env` | `ls -l .env` | `-rw-------` |
| env > plik | `DSCAN_LIMITS__NMAP_MAX_RATE=50 ./run.sh config show \| grep nmap_max_rate` | `50` |
| flaga > env | `… config show --max-rate 7` | `7` |
| sekrety ukryte | `./run.sh config show \| tail -3` | `wartość ukryta`, `dscan:***@` |
| sekret w TOML | `encryption_key = "aa"` w `dscan.toml` | `unknown field` |
| zły port / godzina | `"70000"`, `end = "25:00"` | czytelny błąd walidacji |
| migracje | `./run.sh db status` | `[x] 0001` … `[x] 0009` |

## Cele i skanowanie

| Sprawdzenie | Polecenie | Oczekiwane |
|---|---|---|
| walidacja celów | `./run.sh targets check 127.0.0.1 127.0.0.0/30 localhost 8.8.8.8 'zły cel'` | scalenie, sekcje odrzucone / poza zakresem |
| import celów | `./run.sh import docs/examples/cele.csv --dry-run` | 3 poprawne, 3 odrzucone z numerem wiersza |
| poza zakresem | `./run.sh scan 8.8.8.8; echo $?` | brak celów w zakresie, kod 1 |
| podgrupy | `DSCAN_LIMITS__SUBGROUP_SIZE=32 ./run.sh scan 127.0.0.0/25 --mode discovery --parallel 2` | 4 podgrupy, max 2 naraz |
| tempo | `./run.sh scan 127.0.0.1 --parallel 4 --max-rate 100` | `po 25 pakietów/s` |
| bezpiecznik | `DSCAN_LIMITS__MAX_ADDRESSES_PER_SCAN=10 ./run.sh scan 127.0.0.0/28` | odrzucony: 16 > 10 |
| plan | `./run.sh scan 127.0.0.0/28 --dry-run` | adresy, podgrupy, czas |
| prognoza | `curl -s 'localhost:8080/api/v1/scans?limit=1'` w trakcie | `progress_percent`, `estimated_remaining_seconds` |
| zmiany | `python3 -m http.server 8000`, skan, stop serwera, skan | `+ …:8000 nowa`, potem `- …:8000 zniknęła` |
| stop / wznów | `./run.sh stop N`, `./run.sh resume N` | `paused`, potem tylko niedokończone podgrupy |

## Fingerprinting

| Sprawdzenie | Polecenie | Oczekiwane |
|---|---|---|
| sygnatury | `./run.sh sig list` | ok. 50 sygnatur |
| test sygnatury | strona z `generator WordPress 6.4.2`, `./run.sh sig test WordPress --host http://127.0.0.1:8000/` | `WordPress 6.4.2 — pewność 90%` z dowodami |
| tylko GET | log `python3 -m http.server` podczas `sig test '*'` | wyłącznie `GET` |
| limit sond | `DSCAN_HTTP__MAX_PROBES_PER_SERVICE=2 …` | `(sondy: 2)` |
| zła ścieżka | `DSCAN_HTTP__PROBE_PATHS='["/../etc"]' ./run.sh config validate` | `niedozwolona ścieżka` |
| TLS | `openssl s_server -www -accept 8443 …`, skan | CN, ważność, `self-signed`, `TLS niezweryfikowany` |
| staging | `staging.lab.local` w `/etc/hosts`, skan | `⚑ Środowisko testowe`, `robots.txt`, `Panel administracyjny` |

## Bezpieczeństwo i role

| Sprawdzenie | Polecenie | Oczekiwane |
|---|---|---|
| szyfrogram w bazie | `psql "SELECT encode(substr(note,1,16),'hex') FROM targets"` | zaczyna się od `01`/`02` |
| zły klucz | `DSCAN_ENCRYPTION_KEY=$(./run.sh keys generate) ./run.sh targets list` | błąd odszyfrowania |
| rotacja | `DSCAN_NEW_ENCRYPTION_KEY=… ./run.sh keys rotate` | stary klucz przestaje działać |
| bez sesji | `curl -s localhost:8080/api/v1/targets` | `401` |
| token w bazie | `psql "SELECT encode(token_hash,'hex') FROM sessions"` | tylko skrót |
| rola `odczyt` | `GET /api/v1/users` | `403` |
| wylogowanie CLI | `./run.sh logout && ./run.sh diff 1 2` | `brak ważnej sesji` |
| poprawka wyniku | `PUT /api/v1/overrides` + nowy skan | wartość zostaje, `edited_fields` |

## Harmonogram, import, eksport

| Sprawdzenie | Polecenie | Oczekiwane |
|---|---|---|
| profil co 5 min | `POST /api/v1/profiles` z oknem 00:00–23:59 | nowy przebieg co 5 min |
| profil TOML | `./run.sh scan 127.0.0.1 --profile szybki` | przebieg z profilem |
| nieaktywny host | 3 importy bez hosta | `Hosty nieaktywne`, `inactive_hosts` rośnie |
| import nmap | `nmap -sV -oX /tmp/w.xml 127.0.0.1 && ./run.sh import --kind results /tmp/w.xml` | przebieg i zmiany |
| eksport | `./run.sh export services --format csv --port 22` | CSV z filtrem |
| DefectDojo | `./scripts/defectdojo-setup.sh` | token i produkt w `.env` |

## Interfejs WWW

| Sprawdzenie | Oczekiwane |
|---|---|
| `/` bez sesji | przekierowanie na `/login` |
| nagłówki | `Content-Security-Policy`, `X-Frame-Options: DENY` |
| Pulpit | karty, trwające skany, znaleziska, zmiany, technologie (co 10 s) |
| Cele | dodawanie, import z tabelą odrzuconych, usuwanie |
| rola `odczyt` | brak formularzy i przycisków |
