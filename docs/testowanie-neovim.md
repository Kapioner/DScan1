# Testowanie DScan w Neovimie (zadania 1–10 planu)

Aplikacja: **DScan** (*Defect Scan*), binarka `dscan`.

Otwórz Neovim w katalogu repozytorium:

```bash
cd DScan && nvim .
```

- `:!polecenie` uruchamia polecenie powłoki i pokazuje wynik.
- `:terminal` otwiera pełny terminal (wyjście z trybu wpisywania: `Ctrl-\ Ctrl-n`; nowa karta: `:tabnew | terminal`).
- W `:!` Neovim zamienia znaki `%` i `#` na nazwy plików, dlatego poniższe polecenia ich nie używają.

Na początek zbuduj binarkę: `:!cargo build -q --release`.
Polecenia `./target/release/dscan …` **nie** wczytują `.env` (sekretów), a `./run.sh …` wczytuje.

## 1. Workspace i CI (D1)

1. `:!cargo metadata --no-deps --format-version 1 | grep -o '"name":"dscan[a-z-]*"'`
   → 8 crate'ów: `dscan`, `dscan-core`, `dscan-config`, `dscan-db`, `dscan-api`,
   `dscan-scanner`, `dscan-fingerprint`, `dscan-web`.
2. `:!cargo fmt --all -- --check` → brak wyjścia.
3. `:!cargo clippy --workspace --all-targets -- -D warnings` → bez ostrzeżeń.
4. `:!cargo test --workspace 2>&1 | grep "test result"` → wszystkie wiersze `ok`, 0 failed.
5. `:e .github/workflows/ci.yml` → zadanie `check` (fmt, clippy, test z usługą PostgreSQL)
   i zadanie `docker` (budowa obrazu). Na GitHubie w zakładce **Actions** oba mają być zielone.

## 2. Nazwa (C1) i uruchomienie jedną komendą

Wymaga działającego Dockera (`:!docker info` bez błędu).

1. **Pierwsze uruchomienie:** zasymuluj świeże repo: `:!rm -f dscan.toml .env`.
2. Otwórz terminal (`:tabnew | terminal`) i wpisz `./run.sh`. Oczekiwane:
   - `[run.sh] Utworzono dscan.toml…` i kilka wierszy `[run.sh] Dodano … do .env`,
   - `[run.sh] Uruchamiam PostgreSQL (docker compose)…`,
   - logi `INFO łączenie z bazą postgres://dscan:***@127.0.0.1:5433/dscan` — **hasło ukryte**,
   - `INFO DScan działa: http://127.0.0.1:8080/api/v1/health`.
3. Wróć do pierwszej karty (`gt`) i wpisz `:!curl -s localhost:8080/api/v1/health`
   → `{"status":"ok","version":"0.1.0","database":"ok"}`.
4. W karcie z serwerem: `i`, potem `Ctrl+C` → `INFO zatrzymywanie serwera…`. Zamknij kartę (`:q`).
5. **Kolejne uruchomienie** `./run.sh` → bez wierszy `Utworzono/Dodano`, serwer startuje od razu.
6. `:e .env` → 7 zmiennych (`DSCAN_ENCRYPTION_KEY`, `POSTGRES_*`, `USE_DOCKER_POSTGRES`, `DSCAN_DATABASE_URL`).
   `:!ls -l .env` → uprawnienia `-rw-------`.

## 3. Podkomendy (C2)

1. `:!./target/release/dscan --help` → 11 podkomend: serve, scan, targets, import, export,
   diff, sig, user, config, db, keys.
2. Pomoc każdej podkomendy, np. `:!./target/release/dscan targets add --help`,
   `:!./target/release/dscan export --help` → opisy po polsku, wartości domyślne.
3. Polecenie zaplanowane na później: `:!./target/release/dscan scan 10.0.0.1`
   → `Błąd: polecenie 'scan' nie jest jeszcze dostępne (zaplanowane w zadaniach: S2, S3, S4, C5)`.
4. Kod wyjścia: `:!./target/release/dscan scan 10.0.0.1; echo "kod=$?"` → `kod=1`.
5. Zły argument: `:!./target/release/dscan diff abc 2` → błąd clap o niepoprawnej wartości.

## 4. Konfiguracja warstwowa (D5, C3)

1. `:!cp dscan.example.toml dscan.toml`, a potem `:e dscan.toml`.
2. **Plik:** `:!./target/release/dscan config show | grep nmap_max_rate` → `nmap_max_rate = 100`.
3. W buforze zmień `nmap_max_rate = 100` na `25`, zapisz (`:w`), powtórz polecenie → `25`.
4. **Env nadpisuje plik:**
   `:!DSCAN_LIMITS__NMAP_MAX_RATE=50 ./target/release/dscan config show | grep nmap_max_rate` → `50`.
5. **Flaga nadpisuje env:**
   `:!DSCAN_LIMITS__NMAP_MAX_RATE=50 ./target/release/dscan config show --max-rate 7 | grep nmap_max_rate` → `7`.
6. **Sekrety ukryte:** `:!./run.sh config show | tail -3`
   → `DSCAN_ENCRYPTION_KEY = ustawiony (wartość ukryta)` i `DSCAN_DATABASE_URL = postgres://dscan:***@…`.
7. **validate:** `:!./run.sh config validate` → `Konfiguracja poprawna (źródło: dscan.toml).`
   - bez sekretów: `:!./target/release/dscan config validate` → ostrzeżenia o braku klucza i adresu bazy,
   - `:!./target/release/dscan config validate --listen 0.0.0.0:9000` → ostrzeżenie o dostępie z sieci.
8. **Sekret w TOML jest odrzucany:** dopisz na początku pliku (`gg`, `O`) `encryption_key = "aa"`,
   zapisz, uruchom `:!./target/release/dscan config validate` → `unknown field`. Cofnij (`u`, `:w`).
9. **Walidacja wartości** (po każdej próbie cofnij zmianę przez `u` i `:w`):
   - port `"70000"` w `allowed_ports` → `niepoprawny zakres portów '70000'`,
   - `end = "25:00"` w oknie → `niepoprawna godzina '25:00'`,
   - `max_parallel_nmap = 0` → `ustawienie 'limits.max_parallel_nmap' musi być większe od zera`,
   - literówka `nmap_maxrate` → `unknown field`.
10. **Literówka w env:** `:!DSCAN_LIMITS__NMAP_MAXRATE=5 ./target/release/dscan config validate` → błąd.
    Inne zmienne `DSCAN_…` (np. `DSCAN_TEST_X=1`) są ignorowane.
11. **Brak wskazanego pliku:** `:!./target/release/dscan -c brak.toml config show` → `plik konfiguracyjny nie istnieje`.

## 5. Środowisko testowe (D3)

1. `:e dscan.toml` i w sekcji `[scope]` wpisz dane od organizatora:
   `allowed_networks`, `allowed_ports`, `max_bandwidth_kbps`; w `[limits]` `nmap_max_rate` z regulaminu.
2. `:!./run.sh config validate` → `Konfiguracja poprawna`, bez ostrzeżenia o pustym `allowed_networks`.
3. Dostępność kontenerów laboratorium sprawdź w `:terminal`, np. `ping -c1 <adres>`.
   **Nie skanuj** niczego spoza dozwolonej listy.

## 6. Model domeny (S1)

1. `:!cargo test -p dscan-core` → wszystkie testy `ok`.
2. Przejrzyj typy: `:e crates/core/src/models/mod.rs`; `gd` na nazwie typu (rust-analyzer) przenosi do definicji.

## 7. Schemat i migracje (B1)

1. `:!./run.sh db status` → `[x] 0001 initial schema`.
2. Lista tabel w bazie z Dockera:
   `:!docker compose exec postgres psql -U dscan -d dscan -c '\dt'`
   → 13 tabel + `_sqlx_migrations`.
3. Role wbudowane:
   `:!docker compose exec postgres psql -U dscan -d dscan -c 'SELECT name, permissions FROM roles'`
   → 4 role (administracja, dodawanie_usuwanie_modyfikacja, modyfikacja_odczyt, odczyt).
4. Kolumny szyfrowane: `:!docker compose exec postgres psql -U dscan -d dscan -c '\d services'`
   → `banner` typu `bytea`.
5. Ponowne `:!./run.sh db migrate` → `Migracje wykonane.`, bez błędów (migracje są idempotentne).
6. Testy migracji na bazie z Dockera (baza zostanie zmieniona, ale to baza deweloperska):
   `:!./run.sh config validate >/dev/null; . ./.env; DSCAN_TEST_DATABASE_URL=$DSCAN_DATABASE_URL cargo test -q -p dscan-db 2>&1 | grep "test result"`
   → każdy wiersz `ok`.

## 8. API (A1)

Uruchom serwer w terminalu (`:tabnew | terminal`, `./run.sh`), wróć do pierwszej karty (`gt`) i sprawdź:

1. `:!curl -s localhost:8080/api/v1/health` → `"database":"ok"`.
2. `:!curl -s localhost:8080/api/openapi.json | head -c 300` → `"openapi":"3.1.0"`, `"title":"DScan API"`.
   Pełny opis możesz wkleić na <https://editor.swagger.io>.
3. `:!curl -s localhost:8080/api/v1/nie-ma` → `{"error":"nie znaleziono zasobu"}`;
   `:!curl -si localhost:8080/api/v1/nie-ma | head -1` → `HTTP/1.1 404 Not Found`.
4. Limit rozmiaru (domyślnie 2 MiB):
   `:!head -c 3000000 /dev/zero | curl -si -X POST --data-binary @- localhost:8080/api/v1/health | head -1`
   → `HTTP/1.1 413 Payload Too Large`.
5. W karcie serwera każde żądanie ma wiersz `INFO request{method=GET uri=…}: … status=200`.
6. Zatrzymaj serwer (`i`, `Ctrl+C`) → `zatrzymywanie serwera…`.

## 9. Docker (D2)

1. `:e Dockerfile` → dwa etapy: `rust:1-slim-trixie` (kompilacja) i `debian:trixie-slim` z nmap,
   `setcap cap_net_raw`, użytkownik `dscan` (bez roota).
2. W terminalu (`:tabnew | terminal`): `docker compose up --build` (pierwsza budowa: kilka minut).
   → logi `dscan-1 | INFO DScan działa: http://0.0.0.0:8080/…`.
3. Z pierwszej karty: `:!curl -s localhost:8080/api/v1/health` → `"database":"ok"`.
4. Użytkownik i nmap w kontenerze:
   `:!docker compose exec dscan id` → `uid=10001(dscan)`;
   `:!docker compose exec dscan nmap --privileged -sS -Pn -p 5432 postgres` → `5432/tcp open postgresql`.
5. `:!docker compose down` (dane bazy zostają w wolumenie `pgdata`;
   `docker compose down -v` usuwa je bezpowrotnie).

## Na koniec

`:!docker compose stop` zatrzymuje bazę uruchomioną przez `./run.sh`.
`dscan.toml` i `.env` są w `.gitignore`. Nie usuwaj `.env`, bo jest w nim klucz szyfrowania i hasło bazy.
