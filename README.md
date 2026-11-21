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

**Wymagania:** Rust (stable) z `cargo`, `bash` (Linux/macOS; na Windows przez WSL) i Docker z Compose v2.
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
| `config show` | działa | Efektywna konfiguracja w TOML, sekrety ukryte |
| `config validate` | działa | Sprawdzenie konfiguracji i ostrzeżenia |
| `db migrate`, `db status` | działa | Migracje schematu bazy |
| `scan`, `targets`, `import`, `export`, `diff`, `sig`, `user`, `keys` | zdefiniowane | Mają pełne `--help`; logika powstanie w kolejnych zadaniach planu |

Flaga globalna `-c/--config PLIK` (lub zmienna `DSCAN_CONFIG`) wskazuje plik konfiguracji.

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
| `dscan-db` | `crates/db` | PostgreSQL (sqlx): pula połączeń, migracje w `crates/db/migrations` |
| `dscan-api` | `crates/api` | REST API (axum, tower-http, utoipa) |
| `dscan-scanner` | `crates/scanner` | Skaner (nmap, podgrupy, limity), *w przygotowaniu* |
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

Testy migracji na prawdziwej bazie uruchamiają się, gdy ustawiona jest zmienna
`DSCAN_TEST_DATABASE_URL` (baza zostanie zmodyfikowana — użyj osobnej, testowej).

Instrukcja testów ręcznych w Neovimie: [`docs/testowanie-neovim.md`](docs/testowanie-neovim.md).
Plan zadań ze statusami: [`docs/plan_DScan.xlsx`](docs/plan_DScan.xlsx).

## Zasady rozwoju

Wytyczne dla kolejnych etapów: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).
