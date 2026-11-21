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

Po chwili API działa pod <http://127.0.0.1:8080/api/v1/health>. `Ctrl+C` zatrzymuje serwer.

Co robi skrypt:

1. Przy pierwszym uruchomieniu tworzy `dscan.toml` (kopię `dscan.example.toml`) i `.env`
   z wygenerowanym kluczem szyfrowania, hasłem i adresem bazy (uprawnienia 600).
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

| Polecenie | Stan | Opis |
|---|---|---|
| `serve` | działa | Serwer API; łączy się z bazą i wykonuje migracje |
| `scan CEL… [--mode discovery\|services] [--xml PLIK]` | działa (lokalnie) | Skan nmap celów z `[scope]`; wynik w terminalu, surowy XML do pliku |
| `targets check CEL…` | działa | Sprawdza cele bez skanowania: poprawność, DNS, duplikaty, zakres |
| `targets list` | działa | Cele zapisane w bazie (z odszyfrowanymi notatkami) |
| `import PLIK [--dry-run]` | działa | Import celów z CSV/JSON z raportem odrzuconych wierszy |
| `user create-admin LOGIN`, `user list` | działa | Konto administratora (hasło argon2id), lista użytkowników |
| `keys generate`, `keys rotate` | działa | Nowy klucz; przeszyfrowanie wszystkich pól wrażliwych |
| `config show`, `config validate` | działa | Efektywna konfiguracja (sekrety ukryte), sprawdzenie i ostrzeżenia |
| `db migrate`, `db status` | działa | Migracje schematu bazy |
| `targets add/remove`, `export`, `diff`, `sig`, `import --kind results` | zdefiniowane | Mają `--help`; logika powstanie w kolejnych zadaniach planu |

Flaga globalna `-c/--config PLIK` (lub zmienna `DSCAN_CONFIG`) wskazuje plik konfiguracji.
Polecenia administracyjne działające bezpośrednio na bazie (`db migrate`, `user create-admin`,
`keys rotate`, a także `import` i `targets list`) **wymagają klucza szyfrowania**.

### Skanowanie

```bash
./run.sh targets check 10.10.0.0/24 app.lab.local
```
```bash
./run.sh scan 10.10.0.0/24 --xml wynik.xml
```

- Skanowane są **wyłącznie** cele w `[scope] allowed_networks`; pozostałe są pomijane i wypisywane.
  Sieć tylko częściowo dozwolona jest w całości pomijana.
- Domeny są rozwiązywane systemowym DNS; nakładające się cele są scalane (`10.0.0.0/24` + `10.0.0.5` = jeden zakres),
  a adresy są wyliczane strumieniowo, bez trzymania ich w pamięci.
- `--mode discovery` = `nmap -sn` (tylko aktywne hosty); `--mode services` (domyślnie) = `nmap -sV`
  na portach z `[scope] allowed_ports`. Zawsze z `--max-rate` z `[limits]` (lub flagi `--max-rate`).
- Wymaga zainstalowanego nmap (`sudo apt install nmap`). Na razie skan działa lokalnie i nie zapisuje wyników w bazie
  (to zadania S4/B5); po wdrożeniu RBAC (C5) będzie zlecany przez API.

### Import celów

```bash
./run.sh import docs/examples/cele.csv --dry-run
```

CSV z nagłówkiem `target` (opcjonalnie `group`, `note`; dopuszczalne `cel`, `grupa`, `notatka`) albo tablica JSON
napisów lub obiektów — przykłady w [`docs/examples/`](docs/examples/). Błędne i powtórzone wiersze trafiają do raportu
z numerem wiersza i powodem; poprawne są zapisywane w bazie (istniejące są pomijane). `--dry-run` niczego nie zapisuje.

### Szyfrowanie i rotacja klucza

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

## API

| Endpoint | Opis |
|---|---|
| `GET /api/v1/health` | Stan usługi i połączenia z bazą |
| `GET /api/openapi.json` | Opis API (OpenAPI 3.1), np. do Swagger Editor lub Postmana |

Błędy zwracane są jako JSON `{"error": "..."}`. Żądania większe niż `server.max_body_bytes` dostają 413.

## Konfiguracja

Kolejność ważności: **wartości domyślne < plik TOML < zmienne `DSCAN_*` < flagi CLI**.

- Plik: `dscan.toml` w bieżącym katalogu albo `--config PLIK`. Wszystkie pola opisuje [`dscan.example.toml`](dscan.example.toml).
- Zmienne: `DSCAN_<SEKCJA>__<POLE>`, np. `DSCAN_LIMITS__NMAP_MAX_RATE=50`, `DSCAN_SCOPE__ALLOWED_PORTS='["22","80"]'`.
- Flagi: `--listen ADRES:PORT`, `--max-rate N`, `--parallel N` (w `serve`, `scan`, `config show/validate`).
- **Sekrety tylko ze zmiennych środowiskowych:** `DSCAN_ENCRYPTION_KEY` (64 znaki hex) i
  `DSCAN_DATABASE_URL`. Wpis w TOML jest odrzucany, a `config show` i logi pokazują je zamaskowane.
- Nieznane pola (literówki) kończą się błędem, także w zmiennych `DSCAN_<SEKCJA>__…`.

| Sekcja | Zawartość |
|---|---|
| `[scope]` | dozwolone sieci i porty, limit ruchu (dane od organizatora laboratorium) |
| `[limits]` | `nmap --max-rate`, równoległe procesy nmap, limity zapytań HTTP |
| `[[schedule.windows]]` | okna czasowe skanowania (`HH:MM`, mogą przechodzić przez północ) |
| `[stability]` | K przebiegów do statusu „nieaktywny”, N ponowień, odstęp ponowień |
| `[server]` | adres nasłuchiwania API, limit rozmiaru żądania |
| `[database]` | rozmiar puli połączeń, timeout połączenia |

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
| `dscan-api` | `crates/api` | REST API (axum, tower-http, utoipa) |
| `dscan-scanner` | `crates/scanner` | Cele (parsowanie, DNS, scalanie, zakres, iterator adresów) i wrapper nmap |
| `dscan-integrations` | `crates/integrations` | Import celów z CSV/JSON |
| `dscan-fingerprint` | `crates/fingerprint` | Fingerprinting HTTP/TLS i sygnatury, *w przygotowaniu* |
| `dscan-web` | `crates/web` | UI (askama + htmx), *w przygotowaniu* |
| `dscan` | `crates/cli` | Binarka `dscan` (clap) |

Schemat bazy (migracja `0001`): `targets`, `scan_runs`, `subgroups`, `hosts`, `services`,
`http_info`, `detections`, `signatures`, `changes`, `overrides`, `users`, `roles`, `audit_log`.
Kolumny z danymi wrażliwymi to `BYTEA`, przygotowane pod szyfrowanie AES-256-GCM (zadanie B2).

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
