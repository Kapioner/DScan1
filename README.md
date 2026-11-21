# DScan

**DScan (Defect Scan)**: narzędzie do skanowania i inwentaryzacji usług sieciowych,
napisane w Rust i uruchamiane natywnie na hoście. Binarka: `dscan`.

> Uwaga: crate o nazwie `dscan` istnieje już na crates.io, a na GitHubie są inne
> projekty o tej nazwie. Nie przeszkadza to w budowaniu i używaniu narzędzia;
> przy ewentualnej publikacji na crates.io trzeba by użyć innej nazwy pakietu.

## Uruchomienie (jedna komenda)

```bash
./run.sh
```

Po chwili interfejs WWW działa pod <http://127.0.0.1:8080/> (API: `/api/v1`). `Ctrl+C` zatrzymuje serwer.
Login i hasło administratora są w pliku `.env` (`DSCAN_ADMIN_USERNAME`, `DSCAN_ADMIN_PASSWORD`) —
konto zakłada `dscan serve` przy pierwszym starcie, gdy w bazie nie ma jeszcze użytkowników.

Co robi skrypt:

1. Przy pierwszym uruchomieniu tworzy `dscan.toml` (kopię `dscan.example.toml`) i `.env`
   z wygenerowanym kluczem szyfrowania, hasłem i adresem bazy oraz kontem administratora (uprawnienia 600).
   Brakujące wpisy dopisuje też do istniejącego `.env`.
2. Uruchamia PostgreSQL w Dockerze (`docker compose up -d postgres`, port `127.0.0.1:5433`).
3. Buduje wersję release (przyrostowo, więc kolejne starty są szybkie).
4. Uruchamia natywną binarkę: domyślnie `dscan serve`, który sam wykonuje migracje bazy.

Inne podkomendy przez ten sam skrypt: `./run.sh config show`, `./run.sh db status`, `./run.sh --help`.

**Wymagania:** Rust (stable) z `cargo`, `bash` (Linux/macOS; na Windows przez WSL), Docker z Compose v2 i nmap (do skanów).
Własna baza zamiast Dockera: w `.env` ustaw `USE_DOCKER_POSTGRES=0` i swój `DSCAN_DATABASE_URL`.

> Plik `.env` zawiera jedyną kopię klucza szyfrowania. Bez niego nie odczytasz zaszyfrowanych
> danych, więc zrób jego kopię zapasową. `dscan.toml` i `.env` są w `.gitignore`.

### Wszystko w kontenerach (opcjonalnie)

```bash
./run.sh config validate
```
```bash
docker compose up --build
```

Pierwsza komenda przygotowuje `.env`, druga buduje obraz (`rust:slim` → `debian:trixie-slim`
z nmap) i uruchamia DScan razem z PostgreSQL. Proces działa jako użytkownik bez roota;
nmap ma CAP_NET_RAW do skanów SYN (`nmap --privileged -sS …`).

## Polecenia (`dscan --help`)

| Polecenie | Tryb | Opis |
|---|---|---|
| `serve` | lokalnie | Interfejs WWW, API i harmonogram skanów; migracje bazy, konto administratora przy pierwszym starcie |
| `login --user NAZWA [--server URL]`, `logout` | API | Logowanie; token w `~/.config/dscan/credentials.json` (uprawnienia 600) |
| `scan CEL… [--profile NAZWA] [--mode discovery\|services] [--quiet] [--local]` | API (`--local`: lokalnie) | Skan nmap celów z `[scope]` w podgrupach z fingerprintingiem HTTP; postęp, zmiany, obecność hostów |
| `stop N`, `resume N` | API | Wstrzymanie trwającego skanu, wznowienie od niedokończonych podgrup |
| `import PLIK [--kind targets\|results] [--format csv\|json\|nmap-xml] [--dry-run] [--local]` | API (`--local`: lokalnie) | Import celów albo wyników skanów (nmap XML, JSON, CSV) |
| `export hosts\|services\|changes [--format json\|csv] [--run N] [--port P] [--state S] [--technology T] [--edited] [-o PLIK]` | API | Eksport z filtrami (uprawnienia według roli) |
| `diff A B` | API | Porównanie dwóch przebiegów: usługi nowe, zniknięte, zmienione |
| `sig list`, `sig test SYGNATURA --host URL` | API | Sygnatury serwera; test sygnatury na usłudze WWW z zakresu |
| `targets add CEL… [--group G]`, `targets remove CEL…` | API | Dodawanie i usuwanie celów |
| `targets check CEL…`, `targets list` | lokalnie | Sprawdzenie celów bez skanowania; cele zapisane w bazie |
| `user create-admin LOGIN`, `user list` | lokalnie | Konto administratora (hasło argon2id), lista użytkowników |
| `keys generate`, `keys rotate` | lokalnie | Nowy klucz; przeszyfrowanie wszystkich pól wrażliwych |
| `config show`, `config validate` | lokalnie | Efektywna konfiguracja (sekrety ukryte), sprawdzenie i ostrzeżenia |
| `db migrate`, `db status` | lokalnie | Migracje schematu bazy |

**Tryb API (C5):** polecenia oznaczone „API” wysyłają żądania do serwera (`./run.sh` w drugim terminalu)
z tokenem z `dscan login`, więc obowiązują je te same role co interfejs WWW. Ścieżkę pliku z tokenem
zmienia zmienna `DSCAN_CREDENTIALS`. `--local` (skan, import) działa bez serwera, bezpośrednio na bazie.

Flaga globalna `-c/--config PLIK` (lub zmienna `DSCAN_CONFIG`) wskazuje plik konfiguracji.
Polecenia administracyjne działające bezpośrednio na bazie (`db migrate`, `user create-admin`,
`keys rotate`, a także `import` i `targets list`) **wymagają klucza szyfrowania**.

### Skanowanie

```bash
./run.sh targets check 10.10.0.0/24 app.lab.local
```
```bash
./run.sh scan 10.10.0.0/22 --parallel 4
```

- Skanowane są **wyłącznie** cele w `[scope] allowed_networks`; pozostałe są pomijane i wypisywane.
  Sieć tylko częściowo dozwolona jest w całości pomijana.
- Domeny są rozwiązywane systemowym DNS; nakładające się cele są scalane (`10.0.0.0/24` + `10.0.0.5` = jeden zakres),
  a adresy są wyliczane strumieniowo, bez trzymania ich w pamięci.
- **Podgrupy (S4):** cele są dzielone na sieci po `limits.subgroup_size` adresów (domyślnie 256 = /24).
  Każda podgrupa to jeden proces nmap; naraz działa najwyżej `limits.max_parallel_nmap` procesów.
  Wynik podgrupy trafia do bazy od razu po jej zakończeniu, a błąd jednej podgrupy nie przerywa reszty.
- **Tempo (S7):** `limits.nmap_max_rate` to limit **łączny**, dzielony między równoległe procesy
  (100 pakietów/s przy 4 procesach = 4 × 25). Dodatkowo nie przekracza przepustowości `scope.max_bandwidth_kbps`
  (szacunek: 74 B na pakiet). Zapytania HTTP (od zadania H1) ogranicza `limits.http_requests_per_second`
  i budżet `limits.http_requests_per_host` na host.
- **Czas (S6):** w terminalu po każdej podgrupie widać postęp i prognozę czasu do końca; w bazie są czasy
  całego przebiegu i każdej podgrupy. Ten sam postęp i prognozę zwraca API `GET /api/v1/scans`.
- Bezpiecznik: skan większy niż `limits.max_addresses_per_scan` (domyślnie 1 048 576 adresów) jest odrzucany.
- `--mode discovery` = `nmap -sn` (tylko aktywne hosty); `--mode services` (domyślnie) = `nmap -sV`
  na portach z `[scope] allowed_ports`. Surowy XML każdej podgrupy jest zapisywany w bazie (zaszyfrowany).
- **Fingerprinting HTTP (H1, H2):** po skanie usług każda usługa WWW (`http`, `http-proxy`, `ssl/http`…)
  jest odpytywana: tytuł strony, kod odpowiedzi, nagłówki, ciasteczka z atrybutami, łańcuch przekierowań.
  Tylko GET, bez wysyłania ciasteczek i haseł, bez systemowego proxy; przekierowania tylko w obrębie hosta.
  Certyfikat HTTPS, który nie przechodzi weryfikacji (np. self-signed), nie blokuje odczytu — wynik jest
  oznaczany „TLS niezweryfikowany”. Nagłówki i ciasteczka trafiają do bazy zaszyfrowane. Wyłączenie: `[http] enabled = false`.
- **Sygnatury (H5):** technologie rozpoznawane są sygnaturami YAML ([`crates/fingerprint/signatures/default.yaml`](crates/fingerprint/signatures/default.yaml)):
  matchery `header`, `cookie`, `body` (regex), `favicon` (hash), `path`; warunek `any`/`all`; wersja z regexu.
  Pewność = suma wag pasujących matcherów (max 100), a każda detekcja ma listę dowodów.
- **Startowa baza sygnatur (H7):** ok. 40 sygnatur — serwery WWW i aplikacyjne, frameworki, CMS-y, panele
  administracyjne (phpMyAdmin, Grafana, Jenkins, Kibana…), IoT/kamery (Hikvision, Dahua, Axis), urządzenia sieciowe.
  Własne sygnatury (np. przykłady od organizatora): plik YAML wskazany w `[http] signatures_file`.
- **Pewność (H8):** każda detekcja ma pewność 0–100 (suma wag dowodów) i listę dowodów; detekcje poniżej
  `[http] min_confidence` (domyślnie 30) są pomijane. Raport skanu i API pokazują dowody.
- **Środowiska testowe i panele (M6):** heurystyki — nazwy hostów (dev/test/staging/uat…), nagłówki debugowania
  (np. `X-Debug-Token`), domyślne strony serwerów, `robots.txt` (blokada całej witryny, ukryte ścieżki), tytuły paneli.
- **Certyfikat TLS (H3):** CN/SAN, wystawca, ważność, algorytm podpisu, SHA-256; oznaczenie wygasłych,
  wygasających w ciągu 30 dni i self-signed. Zapisywany w bazie zaszyfrowany; zmiana certyfikatu = zmiana usługi (M1).
- **Nazwy z `/etc/hosts`:** gdy DNS nie zna domeny, DScan pyta resolver systemu (np. wpisy laboratorium w `/etc/hosts`).
- **Sondowanie ścieżek (H6):** ścieżki z `[http] probe_paths` i z sygnatur (np. `/wp-login.php`) — wyłącznie GET,
  bez formularzy i haseł, najwyżej `max_probes_per_service` na usługę i w budżecie `limits.http_requests_per_host`.
- **Porównanie przebiegów (M1):** każda otwarta usługa ma odcisk (SHA-256 z produktu, wersji, nazwy, kodu i tytułu HTTP,
  stabilnych nagłówków i stanu TLS). Po udanym skanie DScan porównuje go z poprzednim udanym przebiegiem tego samego
  trybu po kluczu (IP, port, protokół): **nowa / zniknęła / zmieniona**. Zmiany są zapisywane w bazie i wypisywane;
  dowolne dwa przebiegi porówna `./run.sh diff A B`.
- **Profile (C4):** nazwane zestawy ustawień w `[profiles.NAZWA]` w `dscan.toml` (tryb, porty, tempo, równoległość,
  rozmiar podgrup, `host_timeout_seconds`, `max_retries`, okna czasowe, ścieżki sond); wybór: `--profile NAZWA` albo lista w UI.
- **Harmonogram (S8):** `dscan serve` co minutę sprawdza profile z bazy (`/api/v1/profiles`): w oknie czasowym
  i po upływie `frequency_minutes` od ostatniego przebiegu startuje skan celów z grupy profilu.
- **Okna i wznawianie (S9):** o końcu okna procesy nmap są zatrzymywane, niedokończone podgrupy wracają do kolejki,
  a przebieg dostaje stan `paused`. Wznowienie: harmonogram w następnym oknie, `dscan resume N` albo przycisk „Wznów” w UI.
  Przebiegi przerwane restartem serwera są przy starcie oznaczane jako wstrzymane.
- **Obecność hostów (S11):** po każdym udanym przebiegu zapisywana jest odpowiedź każdego adresu z zakresu skanu;
  host bez odpowiedzi w `[stability] inactive_after_missed_runs` (K) kolejnych przebiegach dostaje stan „nieaktywny”.
- Wymaga zainstalowanego nmap (`sudo apt install nmap`).

### Import i eksport

```bash
./run.sh import docs/examples/cele.csv --dry-run
```
```bash
./run.sh import --kind results wynik-nmap.xml
```
```bash
./run.sh export services --format csv --technology wordpress -o uslugi.csv
```

**Wyniki (I2):** nmap XML (`-oX`), JSON (format `dscan export hosts`) i CSV (format `dscan export services`)
przechodzą to samo przetwarzanie co skan: przebieg w bazie, obecność hostów i porównanie z poprzednim przebiegiem
tego samego profilu (domyślnie `import`). Hosty spoza `[scope]` są pomijane. **Eksport (I3):** hosty (JSON), usługi
i zmiany (JSON/CSV); filtry `--run`, `--port`, `--state`, `--technology`, `--edited`. Rola tylko do odczytu dostaje
eksport bez notatek operatorów i nie może filtrować po ręcznych poprawkach.

**Cele (I1):**

CSV z nagłówkiem `target` (opcjonalnie `group`, `note`; dopuszczalne `cel`, `grupa`, `notatka`) albo tablica JSON
napisów lub obiektów — przykłady w [`docs/examples/`](docs/examples/). Błędne i powtórzone wiersze trafiają do raportu
z numerem wiersza i powodem; poprawne są zapisywane w bazie (istniejące są pomijane). `--dry-run` niczego nie zapisuje.

### Szyfrowanie i rotacja klucza

Które dane są szyfrowane, a które jawne i dlaczego: [`docs/klasyfikacja-danych.md`](docs/klasyfikacja-danych.md).
Pola wrażliwe (notatki, banery, nagłówki, ciasteczka, certyfikaty, surowy XML, nadpisania) są szyfrowane
AES-256-GCM po stronie aplikacji: losowy nonce dla każdej wartości, nazwa kolumny jako dane uwierzytelniane (AAD),
bajt wersji formatu. Baza widzi tylko szyfrogram.

```bash
NOWY_KLUCZ=$(./run.sh keys generate) && echo "$NOWY_KLUCZ"
```
```bash
DSCAN_NEW_ENCRYPTION_KEY=$NOWY_KLUCZ ./run.sh keys rotate
```

Rotacja działa w jednej transakcji (błąd = brak zmian). Po niej wpisz wypisany nowy klucz
jako `DSCAN_ENCRYPTION_KEY` w `.env` (zachowaj kopię zapasową).
Zmienne podane w linii poleceń mają pierwszeństwo przed wartościami z `.env`.

> Nie usuwaj `.env`: oprócz klucza zawiera hasło bazy w wolumenie Dockera. Nowo wygenerowane hasło
> nie pasowałoby do istniejącej bazy.

## Interfejs WWW

Strony renderowane w Ruście (askama), interakcje przez htmx (wkompilowany w binarkę — działa bez internetu).
Logowanie formularzem, menu zależne od roli (np. „Użytkownicy” tylko dla administracji), pulpit z listą
przebiegów odświeżaną co 5 s (postęp, czas, prognoza), cele i profile skanów.
**Pulpit (F2):** karty (hosty, otwarte usługi, ważne znaleziska, hosty aktywne/nieaktywne), trwające skany z paskiem
postępu, czasem i prognozą, najważniejsze znaleziska (panele administracyjne, CI/CD, kamery, środowiska testowe,
TLS niezweryfikowany), usługi nowe/zniknięte/zmienione od poprzedniego skanu i statystyki technologii — odświeżane co 10 s.
Formularz „Uruchom skan” z wyborem profilu z `[profiles]` oraz przyciski „Wstrzymaj”/„Wznów” (tylko role z `targets:write`).
**Formularz celów (F3):** wpis ręczny, wgranie pliku CSV/JSON z tabelą odrzuconych wierszy (opcja „tylko sprawdź”)
i usuwanie — dostępne dla ról z prawem zapisu; pozostali widzą tylko listę.
Nagłówki bezpieczeństwa: `Content-Security-Policy` (tylko zasoby z własnego serwera), `X-Frame-Options: DENY`.

## API

Wszystko poza `health`, `auth/login` i `openapi.json` wymaga sesji: ciasteczka `dscan_session`
(przeglądarka) albo nagłówka `Authorization: Bearer <token>` (token zwraca logowanie).

**RBAC (A3):** middleware sprawdza uprawnienia **każdego** żądania według jednej tabeli
([`crates/api/src/auth/rbac.rs`](crates/api/src/auth/rbac.rs)); trasa spoza tabeli wymaga roli administratora.

| Rola | Uprawnienia | Co może |
|---|---|---|
| `administracja` | wszystko | także konta użytkowników |
| `dodawanie_usuwanie_modyfikacja` | `targets:write`, `results:write`, `read` | cele, profile, skany, import, sygnatury, poprawki |
| `modyfikacja_odczyt` | `results:write`, `read` | ręczne poprawki wyników, odczyt i eksport |
| `odczyt` | `read` | odczyt, dashboard, eksport bez notatek |

| Endpoint | Opis |
|---|---|
| `GET /api/v1/health` | Stan usługi i połączenia z bazą |
| `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` | Logowanie (`{"username","password"}`), wylogowanie, bieżący użytkownik |
| `GET/POST /api/v1/targets`, `GET/PUT/DELETE /api/v1/targets/{id}` | Cele (filtr `?group=`); PUT zmienia grupę i notatkę |
| `GET /api/v1/groups` | Grupy celów z liczbą celów |
| `GET/POST /api/v1/profiles`, `GET/PUT/DELETE /api/v1/profiles/{id}` | Profile skanów: tryb, grupa celów, porty, okna czasowe, częstotliwość |
| `GET /api/v1/scans?limit=N`, `GET /api/v1/scans/{id}` | Przebiegi: stan, postęp, czas trwania, prognoza do końca |
| `GET /api/v1/scans/{id}/hosts` | Hosty przebiegu z usługami, HTTP i detekcjami (z dowodami), z nałożonymi poprawkami |
| `GET/PUT/DELETE /api/v1/overrides` | Ręczne poprawki wyników (A6): `hostname`, `host_note`, `product`, `version`, `service_name`, `service_note` |
| `POST /api/v1/scans` | Zlecenie skanu `{"targets":[…],"profile":"…","mode":"…"}` → 202 z numerem przebiegu |
| `POST /api/v1/scans/{id}/stop`, `POST /api/v1/scans/{id}/resume` | Wstrzymanie i wznowienie (S9) |
| `GET /api/v1/scans/{id}/changes`, `GET /api/v1/diff?from=A&to=B` | Zmiany przebiegu; porównanie dowolnych dwóch |
| `GET /api/v1/scan-profiles` | Nazwy profili z `[profiles]` (C4) |
| `POST /api/v1/imports/targets`, `POST /api/v1/imports/results` | Import `{"format","content","dry_run"}` (I1, I2) |
| `GET /api/v1/exports/{hosts\|services\|changes}` | Eksport z filtrami `format, run, port, state, technology, edited` (I3) |
| `GET /api/v1/signatures`, `POST /api/v1/signatures/test` | Sygnatury i ich test na usłudze |
| `GET /api/v1/dashboard` | Znaleziska, zmiany, technologie, trwające skany, obecność hostów (A8) |
| `GET /api/v1/users` | Konta (tylko administracja) |
| `GET /api/openapi.json` | Opis API (OpenAPI 3.1), np. do Swagger Editor lub Postmana |

Błędy zwracane są jako JSON `{"error": "..."}` (400, 401, 403, 404, 409, 413).

### Bezpieczeństwo logowania

- Hasła: argon2id. Przy nieznanym loginie też liczony jest skrót, żeby czas odpowiedzi nie zdradzał, które loginy istnieją.
- Sesje w PostgreSQL (przetrwają restart, można je unieważnić); w bazie tylko skrót SHA-256 tokenu.
- Ciasteczko `HttpOnly; SameSite=Strict` (ochrona przed CSRF), `Secure` po ustawieniu `server.secure_cookies = true`.
- Zablokowane konto traci dostęp natychmiast; wygasłe sesje są usuwane przy starcie serwera.

### Ręczne poprawki wyników (A6)

Poprawki są przechowywane osobno od obserwacji, przypięte do adresu (IP, opcjonalnie port i protokół),
a nie do przebiegu, i nakładane przy odczycie. Działają więc także w trakcie skanu i przetrwają kolejne
przebiegi, a porównanie przebiegów (M1) widzi tylko to, co faktycznie zaobserwował skaner.
Poprawione pola są wymienione w `edited_fields`. Zapis wymaga uprawnienia `results:write`
(role: administracja, dodawanie/usuwanie/modyfikacja, modyfikacja i odczyt); wartości są szyfrowane.

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"ip":"10.10.0.5","port":80,"protocol":"tcp","field":"product","value":"Kamera Hikvision"}' \
  http://127.0.0.1:8080/api/v1/overrides
```

## DefectDojo do testów integracji (D4)

```bash
./scripts/defectdojo-setup.sh
```

Uruchamia lokalny DefectDojo 3.5.202 (`compose.defectdojo.yaml`, osobny projekt, http://127.0.0.1:8081),
generuje jego sekrety w `.env`, pobiera token API i tworzy testowy produkt „DScan lab” oraz engagement
„DScan — testy”. Wynik trafia do `.env`: `DSCAN_DEFECTDOJO_URL`, `DSCAN_DEFECTDOJO_TOKEN`,
`DSCAN_DEFECTDOJO_PRODUCT_ID`, `DSCAN_DEFECTDOJO_ENGAGEMENT_ID` (użyje ich eksport w zadaniach I4/I5).
Login do DefectDojo: `admin`, hasło `DEFECTDOJO_ADMIN_PASSWORD` z `.env`. Zatrzymanie: `./scripts/defectdojo-setup.sh stop`.
Przy limicie pobrań Docker Hub: `DEFECTDOJO_REGISTRY=registry.defectdojo.com` w `.env`.

## Konfiguracja

Kolejność ważności: **wartości domyślne < plik TOML < zmienne `DSCAN_*` < flagi CLI**.

- Plik: `dscan.toml` w bieżącym katalogu albo `--config PLIK`. Wszystkie pola opisuje [`dscan.example.toml`](dscan.example.toml).
- Zmienne: `DSCAN_<SEKCJA>__<POLE>`, np. `DSCAN_LIMITS__NMAP_MAX_RATE=50`, `DSCAN_SCOPE__ALLOWED_PORTS='["22","80"]'`.
- Flagi: `--listen ADRES:PORT`, `--max-rate N`, `--parallel N` (w `serve`, `scan`, `config show/validate`).
- **Sekrety tylko ze zmiennych środowiskowych:** `DSCAN_ENCRYPTION_KEY` (64 znaki hex),
  `DSCAN_DATABASE_URL` oraz `DSCAN_ADMIN_USERNAME` / `DSCAN_ADMIN_PASSWORD` (pierwszy administrator). Wpis w TOML jest odrzucany, a `config show` i logi pokazują je zamaskowane.
- Nieznane pola (literówki) kończą się błędem, także w zmiennych `DSCAN_<SEKCJA>__…`.

| Sekcja | Zawartość |
|---|---|
| `[scope]` | dozwolone sieci i porty, limit ruchu (dane od organizatora laboratorium) |
| `[limits]` | łączne tempo nmap, równoległe procesy, rozmiar podgrupy, limit adresów, limity zapytań HTTP |
| `[[schedule.windows]]` | okna czasowe skanowania (`HH:MM`, mogą przechodzić przez północ) |
| `[stability]` | K przebiegów do statusu „nieaktywny”, N ponowień, odstęp ponowień |
| `[server]` | adres nasłuchiwania, limit rozmiaru żądania, ważność sesji, flaga `Secure` ciasteczka |
| `[database]` | rozmiar puli połączeń, timeout połączenia |
| `[http]` | fingerprinting HTTP: włączony, limit czasu, przekierowania, limit treści, User-Agent, sondowane ścieżki |

### Środowisko testowe (D3)

Wartości w sekcji `[scope]` pliku przykładowego są **zastępcze**. Przed pierwszym
skanem wpisz do `dscan.toml` adresację kontenerów laboratorium, dozwolone porty
i limity ruchu z regulaminu organizatora.

## Struktura workspace

| Crate | Katalog | Odpowiedzialność |
|---|---|---|
| `dscan-core` | `crates/core` | Model domeny: `Target`, `Host`, `Service`, `HttpInfo`, `Detection`, `ScanRun`, `Change` (serde) |
| `dscan-config` | `crates/config` | Konfiguracja warstwowa (figment), walidacja, sekrety z env |
| `dscan-db` | `crates/db` | PostgreSQL (sqlx): migracje, `Encrypted<T>`, rotacja klucza, użytkownicy, cele |
| `dscan-crypto` | `crates/crypto` | AES-256-GCM dla pól wrażliwych |
| `dscan-auth` | `crates/auth` | Hasła argon2id, walidacja loginów |
| `dscan-api` | `crates/api` | REST API (axum, tower-http, utoipa): logowanie i sesje, cele, profile, przebiegi |
| `dscan-web` | `crates/web` | Interfejs WWW (askama + htmx): logowanie, menu zależne od roli, pulpit, listy |
| `dscan-scanner` | `crates/scanner` | Cele (parsowanie, DNS, scalanie, zakres), wrapper nmap, podgrupy, pula workerów, tempo |
| `dscan-engine` | `crates/engine` | Przebieg skanu: podgrupy → pula → zapis w bazie, postęp i prognoza (Observer) |
| `dscan-integrations` | `crates/integrations` | Import celów z CSV/JSON |
| `dscan-fingerprint` | `crates/fingerprint` | Klient HTTP/HTTPS (reqwest + rustls), ekstrakcja (scraper), silnik sygnatur YAML, sondowanie ścieżek, limiter |
| `dscan` | `crates/cli` | Binarka `dscan` (clap) |

Schemat bazy (migracje `0001`–`0003`): `targets`, `scan_profiles`, `sessions`,, `scan_runs`, `subgroups`, `hosts`, `services`,
`http_info`, `detections`, `signatures`, `changes`, `overrides`, `users`, `roles`, `audit_log`.
Kolumny z danymi wrażliwymi to `BYTEA` z szyfrogramem AES-256-GCM. Wyniki są zapisywane wsadowo
(INSERT z wieloma wierszami, po 1000): 10 000 hostów z 20 000 usług zapisuje się w ok. 0,6 s.
Indeksy pod porównania przebiegów: `hosts (ip, scan_run_id)`, `services (host_id, port, protocol) INCLUDE (fingerprint_hash, state)`.

## Weryfikacja (to samo robi CI)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Testy na prawdziwej bazie uruchamiają się, gdy ustawiona jest zmienna `DSCAN_TEST_DATABASE_URL`
(każdy test tworzy i usuwa własny schemat). Test wrappera z prawdziwym nmap uruchamia się, gdy nmap jest zainstalowany.

Instrukcja testów ręcznych w Neovimie: [`docs/testowanie-neovim.md`](docs/testowanie-neovim.md).
Plan zadań ze statusami: [`docs/plan_DScan.xlsx`](docs/plan_DScan.xlsx).

## Zasady rozwoju

Wytyczne dla kolejnych etapów: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).
