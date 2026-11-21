# Testowanie DScan w Neovimie (zadania 1–20 planu)

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
   → 12 crate'ów: `dscan`, `dscan-core`, `dscan-config`, `dscan-db`, `dscan-api`, `dscan-crypto`,
   `dscan-auth`, `dscan-scanner`, `dscan-engine`, `dscan-integrations`, `dscan-fingerprint`, `dscan-web`.
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
3. Polecenie zaplanowane na później: `:!./target/release/dscan diff 1 2`
   → `Błąd: polecenie 'diff' nie jest jeszcze dostępne (zaplanowane w zadaniach: M1, C5)`.
4. Kod wyjścia: `:!./target/release/dscan diff 1 2; echo "kod=$?"` → `kod=1`.
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

## 10. Polecenia administracyjne (C6)

1. **Bez klucza nie da się zmieniać bazy:**
   `:!env -u DSCAN_ENCRYPTION_KEY DSCAN_DATABASE_URL=postgres://a:b@127.0.0.1:1/x ./target/release/dscan db migrate`
   → `Błąd: brak klucza szyfrowania — ustaw zmienną DSCAN_ENCRYPTION_KEY`
   (to samo dla `user create-admin`, `keys rotate`, `serve`).
2. `:!./run.sh db migrate` → `Migracje wykonane.`
3. **Konto administratora** — w terminalu (`:tabnew | terminal`): `./run.sh user create-admin admin`,
   wpisz dwa razy hasło (min. 12 znaków; znaki nie są wyświetlane) → `Utworzono administratora 'admin'`.
   Wariant skryptowy z pierwszej karty: `:!echo 'inne-dlugie-haslo-1' | ./run.sh user create-admin operator --password-stdin`.
4. Odrzucenia:
   - `:!echo 'krotkie' | ./run.sh user create-admin jan --password-stdin` → `musi mieć co najmniej 12 znaków`,
   - ponownie `admin` → `użytkownik 'admin' już istnieje`,
   - `:!echo 'x' | ./run.sh user create-admin Jan --password-stdin` → `niepoprawny login`,
   - różne hasła w terminalu → `podane hasła różnią się`.
5. `:!./run.sh user list` → tabela z rolą `administracja`.
6. Hasło w bazie jest skrótem argon2id:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c 'SELECT username, left(password_hash, 30) FROM users'`
   → `$argon2id$v=19$m=19456,t=2,p=1…`.

## 11. Parsowanie i walidacja celów (S2)

1. W `dscan.toml` dopisz do `allowed_networks` sieć lokalną: `:e dscan.toml`, zmień na
   `allowed_networks = ["172.20.0.0/24", "127.0.0.0/8"]`, zapisz (`:w`).
2. `:!./run.sh targets check 127.0.0.1 127.0.0.0/30 localhost 8.8.8.8 'zły cel' nie-istnieje.invalid --show 5`
   → `Do skanowania: 4 adresów w 1 zakresach` (127.0.0.1 i localhost scalone z 127.0.0.0/30),
   sekcje „Odrzucone”, „Nierozwiązane domeny” i „Poza zakresem” (8.8.8.8), lista pierwszych adresów.
3. Normalizacja: `:!./run.sh targets check 127.0.0.7/30` → zakres `127.0.0.4/30`.
4. **Ponad 10 000 adresów:** dopisz `"10.0.0.0/16"` do `allowed_networks`, zapisz i uruchom
   `:!./run.sh targets check 10.0.0.0/16 10.0.5.0/24 --show 3` → `65536 adresów w 1 zakresach`
   (bez zauważalnego czasu i pamięci). Usuń potem tę sieć z pliku.
5. Testy: `:!cargo test -q -p dscan-scanner targets 2>&1 | grep "test result"` → `ok`.

## 12. Wrapper nmap (S3)

Wymaga nmap na hoście (`:!nmap --version`).

1. **Wykrywanie hostów:** `:!./run.sh scan 127.0.0.1 --mode discovery` → `127.0.0.1` i `Aktywne hosty: 1`.
2. **Usługi:** `:!./run.sh scan 127.0.0.1` → np. `5432/tcp open postgresql PostgreSQL DB …`
   (porty z `[scope] allowed_ports`).
3. Surowy XML jest w bazie (zaszyfrowany):
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT scan_run_id, length(raw_nmap_xml) FROM subgroups ORDER BY id DESC LIMIT 3"`
   → liczba bajtów szyfrogramu przy każdej podgrupie.
4. Limit tempa z flagi: `:!./run.sh scan 127.0.0.1 --max-rate 20 --mode discovery` → `… po 20 pakietów/s`.
5. **Cel spoza zakresu:** `:!./run.sh scan 8.8.8.8; echo "kod=$?"` → `brak celów do skanowania w dozwolonym zakresie`, `kod=1`.
   Żaden pakiet nie zostaje wysłany.
6. Testy (w tym z prawdziwym nmap i lokalnym „serwerem SSH”):
   `:!cargo test -q -p dscan-scanner 2>&1 | grep "test result"` → wszystkie `ok`.

## 13. Import celów z CSV/JSON (I1)

1. `:e docs/examples/cele.csv` — przejrzyj plik (zawiera błędny wiersz i duplikaty).
2. `:!./run.sh import docs/examples/cele.csv --dry-run` →
   `Poprawne cele: 3, odrzucone wiersze: 3`, a niżej `wiersz 5: 'zły cel'`, `wiersz 6 … duplikat wiersza 2`,
   `wiersz 7 … duplikat wiersza 3` (10.10.0.7/24 to po normalizacji ta sama sieć) i `Tryb próbny — nic nie zapisano.`
3. `:!./run.sh import docs/examples/cele.csv` → `Zapisano w bazie: 3 nowych, 0 już istniało.`
4. JSON: `:!./run.sh import docs/examples/cele.json` → 2 poprawne, `wiersz 3: '300.1.1.1'` odrzucony.
5. Ponowny import tego samego pliku → `0 nowych, 2 już istniało.`
6. `:!./run.sh targets list` → tabela celów z grupami i notatkami.
7. Błędy całego pliku: `:!./run.sh import README.md --dry-run` → `nie rozpoznano formatu`;
   plik CSV bez kolumny `target` → `plik CSV musi mieć kolumnę 'target'`.

## 14. Szyfrowanie pól (B2)

1. Notatki w bazie są nieczytelne:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT value, encode(substr(note,1,16), 'hex') FROM targets"`
   → szyfrogram zaczynający się od `01` (wersja formatu) zamiast tekstu notatki.
2. `:!./run.sh targets list` → notatki czytelne (odszyfrowane kluczem z `.env`).
3. **Zły klucz:** `:!DSCAN_ENCRYPTION_KEY=$(./target/release/dscan keys generate) ./run.sh targets list`
   → `nie udało się odszyfrować danych (zły klucz szyfrowania lub uszkodzone dane)`.
4. **Rotacja klucza** (w terminalu `:tabnew | terminal`, bo zmienne muszą przetrwać między poleceniami):
   ```
   NOWY=$(./run.sh keys generate); echo $NOWY
   DSCAN_NEW_ENCRYPTION_KEY=$NOWY ./run.sh keys rotate
   ./run.sh targets list                          # błąd: stary klucz z .env już nie działa
   DSCAN_ENCRYPTION_KEY=$NOWY ./run.sh targets list   # działa
   ```
   Następnie albo wpisz `$NOWY` do `.env` jako `DSCAN_ENCRYPTION_KEY`, albo cofnij rotację:
   `DSCAN_ENCRYPTION_KEY=$NOWY DSCAN_NEW_ENCRYPTION_KEY=<stary klucz z .env> ./run.sh keys rotate`.
5. Testy szyfrowania: `:!cargo test -q -p dscan-crypto 2>&1 | grep "test result"` → `ok`
   (zły klucz, zły kontekst kolumny, zmodyfikowane dane — wszystkie odrzucone).

## 15. Klasyfikacja danych wrażliwych (B4)

1. `:e docs/klasyfikacja-danych.md` → poziomy (sekret / poufne / wewnętrzne), tabela 7 szyfrowanych kolumn
   z uzasadnieniem i tabela danych jawnych z powodem.
2. Zgodność z kodem: `:!cargo test -q -p dscan-db classification 2>&1 | grep "test result"` → `ok`.
   Sprawdź, że test pilnuje dokumentu: usuń w buforze wiersz z `services.banner` (`dd`), zapisz,
   uruchom test ponownie → błąd `nie opisuje services.banner`. Cofnij (`u`, `:w`).

## 16. Wydajny zapis wyników (B5)

1. `:!./run.sh db status` → `[x] 0002 scan progress and indexes`.
2. Test 10 000 hostów + 20 000 usług na bazie z Dockera:
   `:!set -a; . ./.env; set +a; DSCAN_TEST_DATABASE_URL=$DSCAN_DATABASE_URL cargo test -q -p dscan-db --test scan_results -- --nocapture 2>&1 | grep -E "zapis|test result"`
   → `zapis 10 000 hostów i 20 000 usług: …ms` (ok. 1 s lub mniej) i `ok`.
3. Indeksy: `:!docker compose exec -T postgres psql -U dscan -d dscan -c '\di *_idx'`
   → m.in. `hosts_ip_run_idx`, `services_comparison_idx`, `scan_runs_started_idx`.
4. Kod: `:e crates/db/src/results.rs` — `push_values` buduje jeden INSERT dla 1000 wierszy.

## 17. Podgrupy i pula workerów (S4)

1. `:!DSCAN_LIMITS__SUBGROUP_SIZE=32 ./run.sh scan 127.0.0.0/25 --mode discovery --parallel 2 --quiet`
   → `Przebieg #N: 128 adresów w 4 podgrupach; do 2 procesów nmap naraz…`, cztery wiersze `[k/4] podgrupa …`,
   `Przebieg #N zakończony (completed)`.
2. Podgrupy w bazie:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT scan_run_id, sequence_no, addresses, status FROM subgroups ORDER BY id DESC LIMIT 4"`
   → `127.0.0.0/27`, `127.0.0.32/27`, … ze statusem `completed`.
3. Zły rozmiar podgrupy: `:!DSCAN_LIMITS__SUBGROUP_SIZE=100 ./run.sh config validate`
   → `wymagana potęga dwójki`.
4. Bezpiecznik: `:!DSCAN_LIMITS__MAX_ADDRESSES_PER_SCAN=10 ./run.sh scan 127.0.0.0/28 --mode discovery`
   → `skan obejmuje 16 adresów, a limit to 10`.
5. Testy puli (limit równoległości, błąd jednej podgrupy):
   `:!cargo test -q -p dscan-scanner pool 2>&1 | grep "test result"` → `ok`.

## 18. Ograniczanie tempa (S7)

1. `:!./run.sh scan 127.0.0.1 --mode discovery --parallel 4 --max-rate 100 --quiet`
   → `do 4 procesów nmap naraz po 25 pakietów/s` (limit łączny podzielony na procesy).
2. Limit z przepustowości: `:!DSCAN_SCOPE__MAX_BANDWIDTH_KBPS=64 ./run.sh scan 127.0.0.1 --mode discovery --parallel 1 --max-rate 5000 --quiet`
   → `po 108 pakietów/s` (64 kbit/s ÷ 74 B na pakiet).
3. Argument przekazany do nmap: uruchom w terminalu (`:tabnew | terminal`)
   `./run.sh scan 127.0.0.0/28 --parallel 2` i w pierwszej karcie (`1gt`) `:!pgrep -a nmap | grep -o "max-rate [0-9]*"`
   → `max-rate 50` przy każdym procesie.
4. Limiter HTTP (dla przyszłego klienta HTTP): `:!cargo test -q -p dscan-fingerprint 2>&1 | grep "test result"` → `ok`.

## 19. Pomiar czasu i prognoza (S6)

1. Uruchom serwer w terminalu (`:tabnew | terminal`, `./run.sh`), w drugim terminalu (`:tabnew | terminal`):
   `DSCAN_LIMITS__SUBGROUP_SIZE=4 ./run.sh scan 127.0.0.0/28 --parallel 1`
   → po każdej podgrupie `| 25% | pozostało ok. 0:47` itd.
2. W trakcie skanu z pierwszej karty (`1gt`):
   `:!curl -s 'localhost:8080/api/v1/scans?limit=1'`
   → `"status":"running"`, `"progress_percent":25.0`, `"elapsed_seconds":…`, `"estimated_remaining_seconds":…`.
3. Po zakończeniu to samo polecenie → `"status":"completed"`, `"estimated_remaining_seconds":null`.
4. Czasy podgrup w bazie:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT sequence_no, round(EXTRACT(EPOCH FROM finished_at - started_at)::numeric, 1) AS sekundy FROM subgroups ORDER BY id DESC LIMIT 4"`.
5. Nieistniejący przebieg: `:!curl -s localhost:8080/api/v1/scans/999999` → `{"error":"nie znaleziono zasobu"}`.

## Na koniec

`:!docker compose stop` zatrzymuje bazę uruchomioną przez `./run.sh`.
`dscan.toml` i `.env` są w `.gitignore`. Nie usuwaj `.env`, bo jest w nim klucz szyfrowania i hasło bazy.
