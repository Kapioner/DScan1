# Testowanie DScan w Neovimie (zadania 1–45 planu)

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

> **Od etapu 36–45 (C5)** polecenia `scan`, `import`, `export`, `diff`, `sig`, `targets add/remove`,
> `stop` i `resume` działają **przez API**. Przed ich użyciem (także w sekcjach 12–34):
> 1. w osobnej karcie `:tabnew | terminal` uruchom serwer: `./run.sh`,
> 2. zaloguj się raz: `:terminal ./run.sh login --user admin` (hasło: `DSCAN_ADMIN_PASSWORD` z `.env`).
>
> Token trafia do `~/.config/dscan/credentials.json` (uprawnienia 600). Skan i import bez serwera:
> dopisz `--local` (np. `./run.sh scan 127.0.0.1 --local`).

## 1. Workspace i CI (D1)

1. `:!cargo metadata --no-deps --format-version 1 | grep -o '"name":"dscan[a-z-]*"'`
   → 12 crate'ów: `dscan`, `dscan-core`, `dscan-config`, `dscan-db`, `dscan-api`, `dscan-crypto`,
   `dscan-auth`, `dscan-scanner`, `dscan-engine`, `dscan-integrations`, `dscan-fingerprint`, `dscan-web`.
   (Serwer `./run.sh` wymaga teraz zalogowania do API — patrz sekcje 22–24.)
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

## 20. Klient HTTP/HTTPS (H1)

1. Testy na lokalnych serwerach (przekierowania, przekierowanie na obcy host, pętla, limit treści,
   budżet zapytań, certyfikat self-signed):
   `:!cargo test -q -p dscan-fingerprint --test fetch_live 2>&1 | grep "test result"` → `6 passed`.
2. Na żywo: w terminalu (`:tabnew | terminal`) uruchom serwer `./run.sh` (port 8080) oraz w drugim terminalu
   serwer HTTPS z certyfikatem self-signed:
   ```
   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test -keyout /tmp/k.pem -out /tmp/c.pem
   openssl s_server -www -accept 8443 -cert /tmp/c.pem -key /tmp/k.pem
   ```
3. Z pierwszej karty: `:!./run.sh scan 127.0.0.1` (trwa ok. 45 s) →
   ```
   8080/tcp  open  http-proxy
       HTTP 200 „Logowanie · DScan” (przekierowania: 1)
   8443/tcp  open  ssl/http   OpenSSL s_server -www httpd
       HTTP 200 (TLS niezweryfikowany)
   ```
4. Wyłączenie fingerprintingu: `:!DSCAN_HTTP__ENABLED=false ./run.sh scan 127.0.0.1 --quiet` — bez wierszy `HTTP …`.

## 21. Ekstrakcja informacji HTTP (H2)

1. Testy (tytuł, ciasteczka z atrybutami, odporność na złe dane): `:!cargo test -q -p dscan-fingerprint --lib 2>&1 | grep "test result"` → `ok`.
2. Dane w bazie po skanie z sekcji 20:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT s.port, i.status_code, i.title, i.tls_verified, jsonb_array_length(i.redirect_chain) AS przekierowania FROM http_info i JOIN services s ON s.id = i.service_id ORDER BY i.id DESC LIMIT 2"`
   → wiersz 8080 z tytułem i 1 przekierowaniem, wiersz 8443 z `tls_verified = f`.
3. Nagłówki i ciasteczka są zaszyfrowane:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT encode(substr(headers,1,8), 'hex') FROM http_info LIMIT 1"` → szyfrogram od `01`.

## 22. Uwierzytelnianie (A2)

1. Przy pierwszym `./run.sh` (pusta baza użytkowników) w logu: `utworzono administratora 'admin' ze zmiennych środowiskowych`.
   Login i hasło: `:e .env` → `DSCAN_ADMIN_USERNAME`, `DSCAN_ADMIN_PASSWORD`.
2. Bez sesji: `:!curl -s localhost:8080/api/v1/targets` → `{"error":"wymagane zalogowanie"}`.
3. Logowanie API i token (w terminalu, bo zmienne muszą przetrwać):
   ```
   set -a; . ./.env; set +a
   TOKEN=$(curl -s -H 'content-type: application/json' -d "{\"username\":\"$DSCAN_ADMIN_USERNAME\",\"password\":\"$DSCAN_ADMIN_PASSWORD\"}" localhost:8080/api/v1/auth/login | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/auth/me
   curl -s -X POST -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/auth/logout -w '%{http_code}\n'
   curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/auth/me
   ```
   → dane admina, potem `204`, potem `wymagane zalogowanie`.
4. Złe hasło i nieistniejący login dają tę samą odpowiedź `401`.
5. W bazie tylko skrót tokenu: `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT encode(token_hash, 'hex'), expires_at FROM sessions"`.
6. Testy: `:!cargo test -q -p dscan-api 2>&1 | grep "test result"` (z `DSCAN_TEST_DATABASE_URL` także testy logowania na bazie).

## 23. CRUD celów i profili (A5)

W terminalu z `TOKEN` z sekcji 22 (zaloguj się ponownie, jeśli się wylogowałeś):
```
curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"target":"10.10.0.7/24","group":"lab","note":"sieć testowa"}' localhost:8080/api/v1/targets
curl -s -H "authorization: Bearer $TOKEN" 'localhost:8080/api/v1/targets?group=lab'
curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/groups
curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"name":"nocny","mode":"services","target_group":"lab","windows":[{"start":"22:00","end":"06:00"}],"frequency_minutes":1440}' localhost:8080/api/v1/profiles
curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"name":"zly","mode":"services","frequency_minutes":1}' localhost:8080/api/v1/profiles
```
→ cel zapisany jako `10.10.0.0/24` (normalizacja), lista i grupy z liczbą celów, profil `201`,
błędny profil `częstotliwość musi wynosić co najmniej 5 minut`. Ponowne dodanie celu → `409`.
Zmiana i usunięcie: `curl -X PUT … /api/v1/targets/<id> -d '{"group":"prod","note":null}'`, `curl -X DELETE … /api/v1/targets/<id>` → `204`.

## 24. Interfejs WWW (F1)

1. Otwórz w przeglądarce <http://127.0.0.1:8080/> → przekierowanie na stronę logowania.
2. Złe hasło → „Nieprawidłowy login lub hasło.”; poprawne (z `.env`) → pulpit.
3. Menu: Pulpit, Cele, Profile skanów, Użytkownicy (ostatnia pozycja tylko dla roli administracja).
4. Pulpit: tabela przebiegów odświeża się co 5 s — uruchom w terminalu `./run.sh scan 127.0.0.0/28 --parallel 1`
   i obserwuj postęp i „Pozostało” bez przeładowania strony.
5. „Cele” i „Profile skanów” pokazują dane dodane w sekcji 23; „Wyloguj” wraca do logowania.
6. Bez przeglądarki: `:!curl -sI localhost:8080/ | grep -iE "^HTTP|^location"` → `HTTP/1.1 303 See Other`, `location: /login`;
   nagłówki: `:!curl -sI localhost:8080/login | grep -iE "content-security|x-frame"`.
7. Testy: `:!cargo test -q -p dscan-web 2>&1 | grep "test result"` → `ok`.

## 25. Formularz celów w UI (F3)

Zaloguj się w przeglądarce (<http://127.0.0.1:8080/>, dane z `.env`) i otwórz „Cele”.
1. „Dodaj cel”: wpisz `10.30.0.9/24`, grupa `lab` → komunikat „Dodano cel 10.30.0.0/24.” i nowy wiersz w tabeli
   (bez przeładowania strony). Ponownie ten sam → „Cel 10.30.0.0/24 już istnieje.”; `zły cel` → komunikat o błędzie.
2. „Wgraj plik”: wybierz `docs/examples/cele.csv`, zaznacz „tylko sprawdź” → „Poprawne cele: 3, odrzucone wiersze: 3”
   i tabela odrzuconych wierszy 5, 6, 7 z powodami; „Tryb „tylko sprawdź” — nic nie zapisano.”
3. To samo bez zaznaczenia → „Zapisano: … nowych, … już istniało.”
4. „Usuń” przy celu → okno potwierdzenia → „Usunięto cel.”
5. Rola tylko do odczytu nie widzi formularzy ani przycisków „Usuń”.
6. Testy: `:!cargo test -q -p dscan-web 2>&1 | grep "test result"` → `ok`.

## 26. Lokalny DefectDojo (D4)

Wymaga Dockera i ok. 2 GB miejsca; pierwszy start trwa kilka minut.
1. W terminalu (`:tabnew | terminal`): `./scripts/defectdojo-setup.sh` →
   `Gotowe: http://127.0.0.1:8081 …`, `Produkt #1 „DScan lab”, engagement #1 …`.
2. `:e .env` → `DSCAN_DEFECTDOJO_URL`, `DSCAN_DEFECTDOJO_TOKEN`, `DSCAN_DEFECTDOJO_PRODUCT_ID`, `DSCAN_DEFECTDOJO_ENGAGEMENT_ID`.
3. Token działa (w terminalu): `set -a; . ./.env; set +a; curl -s -H "Authorization: Token $DSCAN_DEFECTDOJO_TOKEN" $DSCAN_DEFECTDOJO_URL/api/v2/engagements/ | head -c 300`.
4. W przeglądarce <http://127.0.0.1:8081> (admin / `DEFECTDOJO_ADMIN_PASSWORD`) → produkt „DScan lab”.
5. Ponowne uruchomienie skryptu nie tworzy duplikatów (używa istniejącego produktu i engagementu).
6. Zatrzymanie: `./scripts/defectdojo-setup.sh stop`. Przy błędzie „429 Too Many Requests” (limit Docker Hub)
   dopisz do `.env` `DEFECTDOJO_REGISTRY=registry.defectdojo.com` i uruchom ponownie.

## 27. Porównanie przebiegów (M1)

1. Uruchom w terminalu dodatkowy serwer WWW: `python3 -m http.server 8000 --bind 127.0.0.1` (port 8000 jest w `allowed_ports`).
2. `:!./run.sh scan 127.0.0.1 --quiet` → na końcu `Zmiany #A → #B: …` z `+ 127.0.0.1:8000/tcp  nowa`
   (przy pierwszym skanie po aktualizacji pozostałe usługi mogą być „zmienione” — wcześniejsze przebiegi nie miały odcisków).
3. Zatrzymaj serwer z punktu 1 (`Ctrl+C` w terminalu) i powtórz skan → `- 127.0.0.1:8000/tcp  zniknęła`, inne bez zmian.
4. `:!./run.sh diff A B` (numery z punktów 2–3) → ten sam raport; `:!./run.sh diff 1 999999` → `nie ma przebiegu`.
5. Zmiany w bazie: `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT current_run_id, ip, port, kind FROM changes ORDER BY id DESC LIMIT 5"`.
6. Testy: `:!cargo test -q -p dscan-core compare 2>&1 | grep "test result"` → `ok`.

## 28. Silnik sygnatur (H5)

1. `:!./run.sh sig list` → tabela sygnatur (nginx, Apache, PHP, WordPress, Joomla, Drupal, Panel logowania, DScan).
2. `:e crates/fingerprint/signatures/default.yaml` — format sygnatur (matchery, wagi, wersja).
3. Strona „WordPress” do testu (w terminalu):
   ```
   mkdir -p /tmp/www && echo '<title>Blog</title><meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/a.css">' > /tmp/www/index.html
   cd /tmp/www && python3 -m http.server 8000 --bind 127.0.0.1
   ```
   Z pierwszej karty: `:!./run.sh sig test WordPress --host http://127.0.0.1:8000/` →
   `WordPress 6.4.2 — pewność 90%` i lista dowodów (+50, +40).
4. `:!./run.sh sig test '*' --host http://127.0.0.1:8080/` (serwer DScan) → „Panel logowania” i „DScan” z dowodami.
5. Poza zakresem: `:!./run.sh sig test WordPress --host http://8.8.8.8/` → odmowa.
6. Po `./run.sh scan 127.0.0.1` detekcje są pod usługami (`⚑ WordPress 6.4.2 (90%)`) i w bazie:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT technology, version, confidence FROM detections ORDER BY id DESC LIMIT 5"`.
7. Testy: `:!cargo test -q -p dscan-fingerprint signatures 2>&1 | grep "test result"` → `ok`.

## 29. Bezpieczne sondowanie ścieżek (H6)

1. Przy działającym serwerze z sekcji 28 (`python3 -m http.server` wypisuje każde zapytanie) uruchom
   `:!./run.sh sig test '*' --host http://127.0.0.1:8000/` i spójrz na terminal serwera →
   wyłącznie `GET` na `/`, `/login`, `/admin`, `/version` i ścieżki z sygnatur (np. `/wp-login.php`) — żadnych `POST`.
2. Limit: `:!DSCAN_HTTP__MAX_PROBES_PER_SERVICE=2 ./run.sh sig test '*' --host http://127.0.0.1:8000/` → `(sondy: 2)`.
3. Niebezpieczna ścieżka w konfiguracji: `:!DSCAN_HTTP__PROBE_PATHS='["/../etc"]' ./run.sh config validate` → błąd `niedozwolona ścieżka`.
4. Testy: `:!cargo test -q -p dscan-fingerprint probe 2>&1 | grep "test result"` → `ok`.

## Przygotowanie do sekcji 30–34

W terminalu (`:tabnew | terminal`), jako root lub przez `sudo`:
```
echo "127.0.0.1 staging.lab.local" | sudo tee -a /etc/hosts
openssl req -x509 -newkey rsa:2048 -nodes -days 10 -subj /CN=staging.lab.local -addext "subjectAltName=DNS:staging.lab.local" -keyout /tmp/k.pem -out /tmp/c.pem
openssl s_server -www -accept 8443 -cert /tmp/c.pem -key /tmp/k.pem
```
W drugim terminalu serwer z nagłówkiem debugowania i `robots.txt` (skrypt z repozytorium nie jest potrzebny —
wystarczy dowolny serwer; przykład w Pythonie):
```
mkdir -p /tmp/www && cd /tmp/www
printf 'User-agent: *\nDisallow: /\nDisallow: /admin-old/\n' > robots.txt
echo '<title>Admin Panel - Login</title><input type="password">' > index.html
python3 -m http.server 8001 --bind 127.0.0.1
```

## 30. Startowa baza sygnatur (H7)

1. `:!./run.sh sig list | wc -l` → ok. 40 sygnatur; `:!./run.sh sig list | grep -iE "kamera|hikvision|jenkins|grafana"`.
2. Próbki odpowiedzi rozpoznawane przez sygnatury: `:!cargo test -q -p dscan-fingerprint --test signature_samples 2>&1 | grep "test result"` → `4 passed`.
3. Własny plik sygnatur: utwórz `:e moje-sygnatury.yaml` z treścią
   `- { name: Aplikacja labu, matchers: [ { type: body, pattern: 'Admin Panel', weight: 90 } ] }`, zapisz,
   potem `:!DSCAN_HTTP__SIGNATURES_FILE=moje-sygnatury.yaml ./run.sh sig test 'Aplikacja labu' --host http://127.0.0.1:8001/`
   → `Aplikacja labu — pewność 90%`.

## 31. Pewność i dowody (H8)

1. `:!./run.sh sig test '*' --host http://127.0.0.1:8001/` → każda detekcja z `pewność N%` i listą dowodów `• … (+waga)`.
2. Próg: `:!DSCAN_HTTP__MIN_CONFIDENCE=70 ./run.sh sig test '*' --host http://127.0.0.1:8001/` → zostają tylko detekcje ≥ 70%.
3. W raporcie skanu (sekcja 32) przy `⚑` jest pewność i dowód, np. `⚑ Tryb debugowania (80%: nagłówek x-debug-token)`.

## 32. Środowiska testowe i panele (M6)

1. `:!./run.sh scan staging.lab.local` (nazwa z `/etc/hosts`; `127.0.0.0/8` w `allowed_networks`) →
   pod usługą 8001 m.in. `⚑ Środowisko testowe (60%: nazwa hosta staging.lab.local)`,
   `⚑ Wskazówki w robots.txt (70%: robots.txt blokuje całą witrynę; robots.txt ukrywa: /admin-old/)`,
   `⚑ Panel administracyjny (50%: tytuł „Admin Panel - Login”)`.
2. Testy heurystyk: `:!cargo test -q -p dscan-fingerprint environment 2>&1 | grep "test result"` → `ok`.

## 33. Certyfikat TLS (H3)

1. W raporcie skanu z sekcji 32 pod portem 8443:
   `TLS: CN=staging.lab.local, ważny do …, wygasa za 9 dni, self-signed, sha256WithRSAEncryption`.
2. Certyfikat w bazie jest zaszyfrowany:
   `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT encode(substr(certificate,1,8),'hex') FROM http_info WHERE certificate IS NOT NULL LIMIT 1"`.
3. Testy (odczyt CN/SAN/self-signed z prawdziwego serwera TLS): `:!cargo test -q -p dscan-fingerprint --test fetch_live certificate 2>&1 | grep "test result"`.

## 34. Edycja wyników niezależna od skanu (A6)

W terminalu z `TOKEN` (logowanie jak w sekcji 22) i numerem ostatniego przebiegu `RUN`:
```
curl -s -X PUT -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"ip":"127.0.0.1","port":8001,"protocol":"tcp","field":"product","value":"Panel testowy"}' localhost:8080/api/v1/overrides -w '%{http_code}\n'
curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/scans/$RUN/hosts | python3 -m json.tool | grep -E '"product"|edited_fields' -A1 | head
```
→ `204`, a w wynikach `"product": "Panel testowy"` i `"edited_fields": ["product"]`.
1. Uruchom nowy skan (`./run.sh scan 127.0.0.1 --quiet`) i odczytaj hosty nowego przebiegu → poprawka nadal obowiązuje.
2. W bazie zostaje obserwacja skanera: `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT product FROM services WHERE port = 8001 ORDER BY id DESC LIMIT 1"`.
3. Usunięcie: `curl -s -X DELETE -H "authorization: Bearer $TOKEN" 'localhost:8080/api/v1/overrides?ip=127.0.0.1&port=8001&protocol=tcp&field=product'` → `204`, wartość wraca do zaobserwowanej.
4. Pole usługi bez portu → `400`; rola „odczyt” → `403`.

## Przygotowanie do sekcji 36–45

1. `:!cargo build -q --release` i w osobnej karcie `:tabnew | terminal` → `./run.sh` (serwer z harmonogramem).
   W logu serwera: `DScan działa: http://127.0.0.1:8080/`.
2. Konta testowe ról (w terminalu, raz):
   ```
   ./run.sh user list
   ```
   Do testów ról przyda się drugie konto z rolą `odczyt` — utwórz je w psql (jak w sekcji 22) albo pomiń punkty o roli „odczyt”.
3. Zaloguj się: `:terminal ./run.sh login --user admin` → `Zalogowano jako admin (sesja ważna do …)`.
4. Token do `curl` (w terminalu): `TOKEN=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.config/dscan/credentials.json')))['token'])")`.

## 36. RBAC na każdym endpoincie (A3)

1. Bez logowania (w `:terminal`, bo polecenie zawiera `%`): `curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/targets` → `401`.
2. Z tokenem administratora: `curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/users` → lista kont.
   Rolą `odczyt` ten sam adres → `403`, a `GET /api/v1/targets` → `200`.
3. Testy macierzy ról: `:!cargo test -q -p dscan-api role_permission_matrix 2>&1 | grep "test result"` → `ok`.
4. Tabela uprawnień w kodzie: `:e crates/api/src/auth/rbac.rs` (`WRITE_RULES`; trasa spoza tabeli = tylko administrator).

## 37. CLI jako klient API (C5)

1. `:!ls -l ~/.config/dscan/credentials.json` → `-rw-------`.
2. `:!./run.sh targets add 127.0.0.5 --group lab` → `dodano #N 127.0.0.5`; `:!./run.sh targets remove 127.0.0.5` → `usunięto`.
3. `:!./run.sh sig list | head -3`, `:!./run.sh diff 1 2` — dane z serwera.
4. `:!./run.sh logout` → `Wylogowano`; potem `:!./run.sh diff 1 2` → `brak ważnej sesji — zaloguj się …`. Zaloguj się ponownie.
5. Testy: `:!cargo test -q -p dscan client 2>&1 | grep "test result"` → `ok`.

## 38. Endpointy dashboardu (A8)

`curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/dashboard | python3 -m json.tool | head -40` →
`latest_run`, `active_runs` (postęp, czas, prognoza), `findings` (panele, CI/CD, kamery, środowiska testowe,
TLS niezweryfikowany), `changes`, `technologies`, liczniki `hosts`, `open_services`, `active_hosts`, `inactive_hosts`.

## 39. Harmonogram i okna czasowe (S8)

1. Profil z bazy uruchamiany co 5 minut w oknie obejmującym „teraz” (w terminalu; godziny dopasuj):
   ```
   curl -s -X POST -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"name":"co5min","mode":"discovery","ports":[],"windows":[{"start":"00:00","end":"23:59"}],"frequency_minutes":5}' localhost:8080/api/v1/profiles
   ```
   (profil bez `target_group` skanuje wszystkie cele z bazy — dodaj np. `./run.sh targets add 127.0.0.1`).
2. Do minuty w logu serwera: `harmonogram: …`, a na pulpicie nowy przebieg profilu `co5min`; po 5 minutach kolejny.
3. Okno, które już minęło (np. `"start":"01:00","end":"01:05"`) → profil czeka; ręczny skan profilu TOML z takim
   oknem kończy się błędem `poza oknem czasowym`.
4. Testy decyzji harmonogramu: `:!cargo test -q -p dscan-engine scheduler 2>&1 | grep "test result"` → `ok`.

## 40. Przerwanie po końcu okna i wznowienie (S9)

1. Uruchom dłuższy skan (np. `./run.sh scan 127.0.0.0/28` w `:terminal`) i w drugim terminalu `./run.sh stop N`
   (N = numer przebiegu z pierwszej linii) → skan kończy się stanem `paused`, procesy nmap znikają (`:!pgrep nmap` → nic).
2. `:!./run.sh resume N` → przebieg wraca do `running` i skanuje tylko niedokończone podgrupy; na pulpicie przycisk „Wznów”.
3. Restart serwera w trakcie skanu → przy starcie `wstrzymano przerwane przebiegi: 1`.
4. Testy: `:!cargo test -q -p dscan-scanner stop_interrupts 2>&1 | grep "test result"` i
   `:!cargo test -q -p dscan-engine --test scan_job 2>&1 | grep "test result"` → `ok`.

## 41. Host nieaktywny po K przebiegach (S11)

1. `[stability] inactive_after_missed_runs = 3` w `dscan.toml`.
2. Zaimportuj trzy razy wynik bez hosta, który wcześniej odpowiadał (sekcja 43) → w raporcie importu
   `Hosty nieaktywne: …`, a w dashboardzie rośnie `inactive_hosts`.
3. Historia: `:!docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT ip, status, consecutive_misses FROM host_presence"`.
4. Testy: `:!cargo test -q -p dscan-core presence 2>&1 | grep "test result"` → `ok`.

## 42. Profile w TOML (C4)

1. `:e dscan.toml` → sekcje `[profiles.szybki]`, `[profiles.pelny]`, `[profiles.nocny]` (wzór w `dscan.example.toml`).
2. `:!curl -s -H "authorization: Bearer $TOKEN" localhost:8080/api/v1/scan-profiles` → `["nocny","pelny","szybki"]`.
3. `:!./run.sh scan 127.0.0.1 --profile szybki --quiet` → przebieg zapisany z profilem `szybki`.
4. Nieznany profil: `:!./run.sh scan 127.0.0.1 --profile brak` → błąd `nie ma profilu 'brak' (zdefiniowane w [profiles]: …)`.
5. W UI na pulpicie lista „Profil” w formularzu „Uruchom skan”.

## 43. Import wyników (I2)

1. Zapisz wynik nmap: `:!nmap -sV -p 22,8001 -oX /tmp/wynik.xml 127.0.0.1`.
2. `:!./run.sh import --kind results /tmp/wynik.xml --dry-run` → `Tryb próbny: 1 hostów …`.
3. `:!./run.sh import --kind results /tmp/wynik.xml` → `Przebieg #N …` i `Pierwszy przebieg tego profilu`
   (albo zmiany względem poprzedniego importu). Hosty spoza `[scope]` są wypisane jako pominięte.
4. CSV/JSON: eksport z sekcji 44 można zaimportować z powrotem: `./run.sh export services --format csv -o /tmp/u.csv`,
   potem `./run.sh import --kind results /tmp/u.csv`.
5. Bez serwera: `:!./run.sh import --kind results /tmp/wynik.xml --local`.

## 44. Eksport z filtrami (I3)

1. `:!./run.sh export services --format csv` → nagłówek `ip,hostname,port,…` i wiersz na usługę.
2. Filtry: `:!./run.sh export services --format csv --port 22`, `--state open`, `--technology nginx`, `--run N`.
3. `:!./run.sh export hosts -o /tmp/hosty.json` → `Zapisano … bajtów`; `:!./run.sh export changes --format csv`.
4. Rola `odczyt`: eksport działa, ale bez notatek, a `--edited` → `403`.
5. Testy: `:!cargo test -q -p dscan-api --test results_flow 2>&1 | grep "test result"` → `2 passed`.

## 45. Dashboard w UI (F2)

1. Otwórz `http://127.0.0.1:8080/` i zaloguj się → karty: hosty, otwarte usługi, ważne znaleziska, aktywne/nieaktywne;
   tabele „Trwające skany” (pasek postępu, czas, pozostało), „Najważniejsze znaleziska”, „Zmiany od poprzedniego skanu”,
   „Technologie”. Dane odświeżają się co 10 s.
2. Formularz „Uruchom skan”: cel `127.0.0.1`, profil `szybki` → komunikat `Uruchomiono przebieg #N`; postęp widać w tabelach.
3. Przycisk „Wstrzymaj” przy trwającym przebiegu i „Wznów” przy wstrzymanym.
4. Rola `odczyt` nie widzi formularza ani przycisków.

## Na koniec

`:!docker compose stop` zatrzymuje bazę uruchomioną przez `./run.sh`.
`dscan.toml` i `.env` są w `.gitignore`. Nie usuwaj `.env`, bo jest w nim klucz szyfrowania i hasło bazy.
