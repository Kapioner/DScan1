<p align="center">
  <img src="docs/img/logo.png" alt="DScan — Smart Scanning" width="220">
</p>

<h1 align="center">DScan — Defect Scan</h1>

<p align="center">
  Skanowanie i inwentaryzacja usług sieciowych z wykrywaniem zmian.<br>
  Jedna binarka w Ruście (<code>dscan</code>): serwer WWW, REST API i CLI, dane w PostgreSQL.
</p>

<p align="center">
  <a href="#szybki-start">Szybki start</a> ·
  <a href="#najważniejsze-funkcje">Funkcje</a> ·
  <a href="#jak-to-działa">Architektura</a> ·
  <a href="#polecenia-cli">CLI</a> ·
  <a href="#api-i-role">API</a> ·
  <a href="#bezpieczeństwo">Bezpieczeństwo</a> ·
  <a href="#dokumentacja">Dokumentacja</a>
</p>

---

## Najważniejsze funkcje

| Obszar | Co daje DScan |
|---|---|
| **Wykrywanie** | nmap (`-sn`/`-sV`) w równoległych podgrupach CIDR, łączny limit tempa, postęp i prognoza czasu |
| **Rozpoznawanie technologii** | HTTP/HTTPS, certyfikaty TLS, favicon (mmh3), ok. 50 sygnatur YAML z pewnością 0–100 i dowodami |
| **Zmiany** | porównanie przebiegów: usługa **nowa / zniknęła / zmieniona**; kod wyjścia `2` = wykryto zmiany |
| **Znaleziska** | ranking najciekawszych usług: panele admina, CI/CD, kamery IoT, środowiska testowe, stare wersje |
| **Harmonogram** | profile skanów, okna czasowe, wstrzymanie i wznowienie od niedokończonych podgrup |
| **Interfejs WWW** | pulpit, hosty, porównanie przebiegów, oś czasu, ręczna edycja wyników, grupy podobnych usług |
| **Import / eksport** | cele z CSV/JSON, wyniki z nmap XML/JSON/CSV, eksport z filtrami, integracja z DefectDojo |
| **Bezpieczeństwo** | tylko dozwolone sieci i porty, bez NSE i exploitów, AES-256-GCM dla danych poufnych, RBAC i audyt |

Skuteczność na laboratorium organizatorów: **31/31 portów, 100% precyzji i czułości, 0 fałszywych zmian**
([analiza](docs/analiza-skutecznosci.md)).

## Szybki start

### Automatycznie (zalecane)

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan
```

```bash
./install.sh
```

Skrypt realizuje całą [instrukcję dla jury](docs/INSTRUKCJA-JURY.md) i pokazuje postęp każdego kroku:

| Krok | Co robi |
|---|---|
| 1. System | wykrywa Linux / macOS / WSL2, sprawdza wolne miejsce (ok. 6 GB) |
| 2. Narzędzia | doinstalowuje brakujące: Git, kompilator C, nmap, Docker + Compose v2, Rust ≥ 1.85 |
| 3. Weryfikacja | wersje narzędzi, dostęp do Dockera (w razie potrzeby dodaje do grupy `docker`) |
| 4. Konfiguracja | `docs/jury/dscan.toml` → `dscan.toml` (zakres `127.0.0.0/8`, port **9080**) |
| 5. Kompilacja | `cargo build --release` z paskiem postępu; `.env` z kluczem szyfrowania i kontem admina |
| 6. Serwer | PostgreSQL w Dockerze, `dscan serve` w tle, czeka na `/api/v1/health` |
| 7. Logowanie | token CLI dla administratora (`~/.config/dscan/credentials.json`) |
| 8. Dane | lista celów, dwa przebiegi demo ze zmianami, ocena trafności |

Na końcu wypisuje adres <http://127.0.0.1:9080/>, login i hasło. Opcje:

| Opcja | Działanie |
|---|---|
| `--lab lab.zip` | scenariusz laboratorium organizatorów: znikająca i powracająca usługa 8787 |
| `--dojo` | lokalny DefectDojo (<http://127.0.0.1:8180/>) i włączenie integracji |
| `--no-install` | tylko sprawdzenie narzędzi, bez instalacji pakietów |
| `--no-demo` | bez danych demo |
| `--force-config` | nadpisanie istniejącego `dscan.toml` konfiguracją dla jury |
| `--stop` | zatrzymanie serwera i bazy |

Skrypt jest idempotentny — ponowne uruchomienie pomija wykonane kroki. Log: `.dscan-install/install.log`.

### Ręcznie

Wymagania: Rust ≥ 1.85, kompilator C, Docker z Compose v2, nmap, `bash` (Linux, macOS, Windows przez WSL2).

```bash
cp docs/jury/dscan.toml dscan.toml
```

```bash
./run.sh
```

`run.sh` przy pierwszym starcie tworzy `.env` (klucz szyfrowania, hasło bazy, konto administratora;
uprawnienia 600), uruchamia PostgreSQL w Dockerze (`127.0.0.1:5433`), buduje wersję release i startuje
`dscan serve` (migracje, konto administratora, harmonogram). Login i hasło:

```bash
grep -E '^DSCAN_ADMIN_(USERNAME|PASSWORD)=' .env
```

W drugim terminalu:

```bash
./run.sh login --user admin
```

```bash
./run.sh import --kind results docs/demo/przebieg-1.xml && ./run.sh import --kind results docs/demo/przebieg-2.xml
```

> **Ważne:** `.env` zawiera jedyną kopię klucza szyfrowania — zrób kopię zapasową. `dscan.toml` i `.env` są w `.gitignore`.
> Własna baza zamiast Dockera: `USE_DOCKER_POSTGRES=0` i własny `DSCAN_DATABASE_URL` w `.env`.

Całość w kontenerach (opcjonalnie): `./run.sh config validate && docker compose up --build`
(obraz `debian:trixie-slim` z nmap, proces bez roota, `CAP_NET_RAW` do skanów SYN).

## Jak to działa

```
            przeglądarka (htmx)          dscan CLI (klient API, token)
                    │                              │
                    ▼                              ▼
   ┌──────────────────────────── dscan serve ─────────────────────────────┐
   │  dscan-web (askama)   dscan-api (axum, RBAC, OpenAPI, audyt)          │
   │                 │              │                                      │
   │                 ▼              ▼                                      │
   │      dscan-engine: przebiegi, harmonogram, podgrupy, import,          │
   │      porównania, obecność hostów, ocena znalezisk, klastry            │
   │        │                │                     │                       │
   │  dscan-scanner     dscan-fingerprint     dscan-integrations           │
   │  (nmap, pula,      (HTTP, TLS, favicon,  (import/eksport, DefectDojo, │
   │   zabezpieczenia)   sygnatury, SimHash)   ewaluacja)                  │
   │        │                                                              │
   │  dscan-db (sqlx, migracje, szyfrowanie pól) ── dscan-crypto (AES-GCM) │
   └──────────────────────────────┬───────────────────────────────────────┘
                                  ▼
                              PostgreSQL
```

### Przebieg skanu

1. **Cele** (IP, CIDR, domeny) → DNS (także `/etc/hosts`) → scalenie → odrzucenie wszystkiego spoza `[scope] allowed_networks`.
2. **Podgrupy** CIDR (domyślnie /24); rozmiar dobierany z przepustowości i czasu pozostałego w oknie.
3. **Pula procesów nmap** (`max_parallel_nmap`), łączny `--max-rate` dzielony między procesy i ograniczony `max_bandwidth_kbps`.
4. **Fingerprinting usług WWW:** strona główna, nagłówki, ciasteczka, przekierowania, certyfikat, favicon,
   bezpieczne sondy ścieżek (tylko GET), sygnatury, heurystyki (staging, debug, panele, niedokończona instalacja), czas odpowiedzi.
5. **Zapis** każdej podgrupy od razu, wsadowo, w transakcji (10 000 hostów z 20 000 usług ≈ 0,6 s); surowy XML zaszyfrowany.
6. **Koniec okna czasowego** → procesy zatrzymane, niedokończone podgrupy wracają do kolejki (stan `paused`).
7. **Po przebiegu:** powtórne pomiary hostów bez odpowiedzi, obecność (host „nieaktywny” po K pominięciach),
   porównanie z poprzednim przebiegiem profilu, opcjonalnie auto-import do DefectDojo.

**Odcisk usługi** (SHA-256 z produktu, wersji, nazwy, kodu i tytułu HTTP, stabilnych nagłówków i stanu TLS)
pozwala odróżnić usługę zmienioną od niezmienionej po kluczu (IP, port, protokół).

### Workspace

| Crate | Odpowiedzialność |
|---|---|
| `dscan-core` | modele domeny (Host, Service, Detection, Change…), porównanie przebiegów, obecność hostów |
| `dscan-config` | konfiguracja TOML + `DSCAN_*` + flagi (figment), walidacja, profile, sekrety |
| `dscan-crypto` | AES-256-GCM z identyfikatorem klucza, HMAC-SHA256 (ślepy indeks), tokeny sesji |
| `dscan-db` | pula PostgreSQL (sqlx), migracje `0001`–`0009`, zapis wsadowy, rotacja kluczy |
| `dscan-scanner` | cele i zakres, podgrupy CIDR, pula nmap z limitem tempa, parser XML, zabezpieczenia |
| `dscan-fingerprint` | klient HTTP(S) (reqwest + rustls), TLS, favicon, silnik sygnatur YAML, SimHash |
| `dscan-engine` | przebiegi, harmonogram, import wyników, dashboard, ocena znalezisk, klastry |
| `dscan-integrations` | import/eksport JSON/CSV, DefectDojo, ewaluacja trafności |
| `dscan-auth` | hasła argon2id, walidacja loginów |
| `dscan-api` | REST API `/api/v1` (axum, utoipa), middleware RBAC, dziennik audytu |
| `dscan-web` | interfejs WWW (askama + htmx wkompilowany w binarkę — działa offline) |
| `dscan` | binarka i podkomendy CLI (clap); większość działa jako klient API |

Wzorce projektowe: Builder (`ConfigLoader`), Command (podkomendy), Strategy (heurystyki, matchery),
Adapter (resolver DNS), Decorator (fingerprinting nad nmap), Observer (postęp skanu, auto-import), Iterator (adresy CIDR).

## Interfejs WWW

| Widok | Zawartość |
|---|---|
| **Pulpit** | karty (hosty, usługi, ważne znaleziska, hosty aktywne/nieaktywne), trwające skany z postępem i prognozą, najciekawsze usługi z uzasadnieniem, zmiany od poprzedniego skanu, statystyki technologii |
| **Hosty** | usługi, HTTP, certyfikat, technologie z dowodami, mapa dostępności w godzinach, tagi, ręczna edycja |
| **Porównanie** | dwa dowolne przebiegi z kolorami: nowe / zniknięte / zmienione |
| **W czasie** | historia usług i hostów między przebiegami |
| **Cele i profile** | wpis ręczny, import CSV/JSON z raportem odrzuconych wierszy, profile i okna czasowe |
| **Sygnatury** | lista, edytor i test sygnatury na usłudze przed zapisem |
| **Użytkownicy, Audyt** | konta, własne role, dziennik zmian (tylko administracja) |

Ręczne poprawki wyników są przechowywane osobno od obserwacji, przypięte do adresu (nie do przebiegu)
i nakładane przy odczycie — przetrwają kolejne skany, a porównanie widzi tylko to, co zaobserwował skaner.
Grupy podobnych usług (SimHash) pozwalają oznaczyć np. „te same 4 kamery” jednym tagiem.

## Polecenia CLI

| Polecenie | Opis |
|---|---|
| `serve` | serwer WWW, API i harmonogram; migracje bazy, konto administratora przy pierwszym starcie |
| `login --user NAZWA [--password-stdin]`, `logout` | logowanie do API; token w pliku z uprawnieniami 600 |
| `scan CEL… [--profile P] [--mode discovery\|services] [--dry-run] [--quiet]` | skan celów z `[scope]`; `--dry-run` pokazuje plan bez wysyłania pakietów |
| `stop N`, `resume N` | wstrzymanie i wznowienie przebiegu |
| `import PLIK [--kind targets\|results] [--dry-run]` | import celów (CSV/JSON) albo wyników (nmap XML, JSON, CSV) |
| `export hosts\|services\|changes [--format json\|csv] [--run N] [--port P] [--technology T]` | eksport z filtrami (uprawnienia według roli) |
| `diff A B` | porównanie dwóch przebiegów |
| `evaluate PLIK [--details]` | trafność względem wyników referencyjnych: precyzja, czułość, F1 |
| `targets add\|remove\|check\|list` | zarządzanie celami, sprawdzenie bez skanowania |
| `sig list`, `sig test SYGNATURA --host URL` | sygnatury i ich test na usłudze z zakresu |
| `dojo import N`, `dojo export N --item IP:PORT/PROTO=Technologia` | wysyłka do DefectDojo |
| `user create-admin`, `user list` | konta (bezpośrednio na bazie) |
| `keys generate\|rotate\|reencrypt\|status` | klucze szyfrowania, rotacja jednorazowa lub stopniowa |
| `config show\|validate\|init`, `db migrate\|status` | konfiguracja i migracje |
| `docs`, `completions SHELL` | dokumentacja CLI (markdown/man) i autouzupełnianie |

Kody wyjścia `scan` i `diff`: **0** brak zmian, **1** błąd, **2** wykryto zmiany (do skryptów i crona).
Polecenia `scan`, `import`, `export`, `diff`, `sig`, `targets add/remove`, `stop`, `resume` działają przez API
z tokenem z `dscan login`, więc obowiązują je te same role co w WWW; `--local` (skan, import) działa bez serwera.
Pełna lista argumentów: [`docs/cli.md`](docs/cli.md) albo `./run.sh --help`.

```bash
./run.sh scan 127.0.0.0/28 --dry-run
```

```bash
./run.sh export services --format csv --technology wordpress -o uslugi.csv
```

## API i role

Wszystko poza `health`, `auth/login` i `openapi.json` wymaga sesji: ciasteczka `dscan_session` (przeglądarka)
albo nagłówka `Authorization: Bearer <token>`. Opis OpenAPI 3.1: `GET /api/openapi.json`.

| Endpoint | Opis |
|---|---|
| `GET /api/v1/health` | stan usługi i połączenia z bazą |
| `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` | sesja |
| `GET/POST /api/v1/targets`, `GET/PUT/DELETE /api/v1/targets/{id}`, `GET /api/v1/groups` | cele i grupy |
| `GET/POST /api/v1/profiles`, `GET/PUT/DELETE /api/v1/profiles/{id}` | profile skanów, okna, częstotliwość |
| `GET/POST /api/v1/scans`, `GET /api/v1/scans/{id}`, `POST …/stop`, `POST …/resume` | przebiegi: postęp, prognoza, sterowanie |
| `GET /api/v1/scans/{id}/hosts`, `GET /api/v1/scans/{id}/changes`, `GET /api/v1/diff?from=A&to=B` | wyniki i zmiany |
| `GET/PUT/DELETE /api/v1/overrides` | ręczne poprawki wyników |
| `POST /api/v1/imports/{targets\|results}`, `GET /api/v1/exports/{hosts\|services\|changes}` | import i eksport |
| `GET /api/v1/signatures`, `POST /api/v1/signatures/test` | sygnatury |
| `GET /api/v1/dashboard`, `GET /api/v1/users` | pulpit; konta (administracja) |

Błędy: JSON `{"error": "..."}` (400, 401, 403, 404, 409, 413).

| Rola | Uprawnienia | Zakres |
|---|---|---|
| `administracja` | `admin`, `targets:write`, `results:write`, `read` | wszystko, konta, role, dziennik audytu |
| `dodawanie_usuwanie_modyfikacja` | `targets:write`, `results:write`, `read` | cele, profile, skany, importy, sygnatury, poprawki |
| `modyfikacja_odczyt` | `results:write`, `read` | poprawki wyników, tagi, DefectDojo, odczyt |
| `odczyt` | `read` | odczyt, pulpit, eksport bez notatek |

Middleware RBAC sprawdza **każde** żądanie według jednej tabeli ([`crates/api/src/auth/rbac.rs`](crates/api/src/auth/rbac.rs));
trasa spoza tabeli wymaga roli administratora. Administrator może tworzyć własne role z tych uprawnień.
Każda zmiana trafia do dziennika audytu (kto, co, kiedy — bez wartości pól poufnych).

## Bezpieczeństwo

### Skaner wykrywa, nie atakuje

Zasady są wymuszone w kodzie ([szczegóły](docs/bezpieczenstwo-skanera.md)):

- nmap tylko `-sn` albo `-sV` — żadnych skryptów NSE (`--script`, `-sC`, `-A`), exploitów, brute force ani prób logowania;
- brak fałszowania źródła i omijania zapór (`-S`, `-D`, `--spoof-mac`, `-f`), zawsze limit `--max-rate`;
- skanowane wyłącznie sieci z `[scope] allowed_networks` i porty z `allowed_ports` (także w profilach);
- HTTP tylko GET, bez haseł, ciasteczek i formularzy, przekierowania w obrębie hosta, limity zapytań na host;
- zależności sprawdzane `cargo audit` w CI.

### Dane

| Poziom | Gdzie | Ochrona |
|---|---|---|
| **Sekret** | tylko `.env` (uprawnienia 600) | klucz szyfrowania, hasła bazy i admina, token DefectDojo — nigdy w bazie ani w logach |
| **Poufne** | kolumny `BYTEA` | AES-256-GCM po stronie aplikacji: notatki, banery, nagłówki, ciasteczka, certyfikaty, surowy XML, poprawki |
| **Wewnętrzne** | kolumny jawne | IP, porty, produkty, tytuły — potrzebne do indeksów, porównań i filtrów; dostęp przez RBAC |

- Losowy nonce dla każdej wartości, nazwa kolumny jako AAD, identyfikator klucza w rekordzie.
- Wyszukiwanie po polach szyfrowanych: ślepy indeks HMAC-SHA256.
- Rotacja klucza w jednej transakcji (`keys rotate`) albo stopniowo, partiami (`keys reencrypt`).
- Hasła argon2id (stały czas także dla nieznanych loginów); w bazie tylko SHA-256 tokenu sesji;
  ciasteczko `HttpOnly; SameSite=Strict`; nagłówki `Content-Security-Policy` i `X-Frame-Options: DENY`.

Uzasadnienie dla każdej kolumny: [`docs/klasyfikacja-danych.md`](docs/klasyfikacja-danych.md).

```bash
NOWY_KLUCZ=$(./run.sh keys generate) && DSCAN_NEW_ENCRYPTION_KEY=$NOWY_KLUCZ ./run.sh keys rotate
```

Po rotacji wpisz nowy klucz jako `DSCAN_ENCRYPTION_KEY` w `.env`.

## Sygnatury technologii

Startowa baza ([`crates/fingerprint/signatures/default.yaml`](crates/fingerprint/signatures/default.yaml)): serwery WWW
i aplikacyjne, frameworki, CMS-y, panele (phpMyAdmin, Grafana, Jenkins, Portainer, Adminer…), CI/CD, IoT i kamery
(Hikvision, Dahua, Axis), urządzenia sieciowe, bazy i brokery. Własne sygnatury: plik w `[http] signatures_file` albo edytor w UI.

```yaml
- name: Jenkins
  category: ci-cd            # wrażliwe: panel-admina, iot-kamera, iot-drukarka, ci-cd, baza-danych
  condition: any             # any — wystarczy jeden matcher; all — wszystkie
  matchers:
    - { type: header, name: X-Jenkins, weight: 60 }
    - { type: cookie, name: JSESSIONID, weight: 10 }
    - { type: body, pattern: 'Dashboard \[Jenkins\]', weight: 40 }
    - { type: favicon, hash: 81586312, weight: 50 }                     # mmh3, jak w Shodanie
    - { type: path, path: /login, status: 200, pattern: 'Jenkins', weight: 30 }
  version: { source: header, name: X-Jenkins, pattern: '([\d.]+)' }
```

Pewność = suma wag pasujących matcherów (max 100); detekcje poniżej `[http] min_confidence` (domyślnie 30) są pomijane.

## Konfiguracja

Kolejność ważności: **wartości domyślne < `dscan.toml` < zmienne `DSCAN_<SEKCJA>__<POLE>` < flagi CLI**.
Wszystkie pola: [`dscan.example.toml`](dscan.example.toml) albo `./run.sh config init`. Nieznane pola kończą się błędem.

| Sekcja | Zawartość |
|---|---|
| `[scope]` | dozwolone sieci i porty, limit przepustowości |
| `[limits]` | tempo nmap, równoległe procesy, rozmiar podgrupy, limit adresów, limity zapytań HTTP |
| `[[schedule.windows]]` | okna czasowe skanowania (`HH:MM`, także przez północ) |
| `[stability]` | K przebiegów do stanu „nieaktywny”, ponowienia |
| `[server]`, `[database]` | adres nasłuchiwania, sesje, flaga `Secure`; pula połączeń |
| `[http]` | fingerprinting: limity czasu, przekierowania, sondy ścieżek, `min_confidence`, własne sygnatury |
| `[defectdojo]`, `[scoring]` | integracja z DefectDojo; wagi rankingu znalezisk |
| `[profiles.NAZWA]` | nazwane zestawy ustawień skanu (`--profile NAZWA` albo lista w UI) |

Przykład: `DSCAN_LIMITS__NMAP_MAX_RATE=50 ./run.sh scan 10.0.0.0/24 --parallel 4`.
Sekrety (`DSCAN_ENCRYPTION_KEY`, `DSCAN_DATABASE_URL`, `DSCAN_ADMIN_*`, `DSCAN_DEFECTDOJO_TOKEN`) tylko ze zmiennych
środowiskowych — wpis w TOML jest odrzucany, a `config show` i logi pokazują je zamaskowane.

## Skuteczność na laboratorium

Laboratorium organizatorów (4 stacki Docker + scenariusz quickstart), szczegóły i odtworzenie: [`docs/analiza-skutecznosci.md`](docs/analiza-skutecznosci.md).

| Miara | Wynik |
|---|---|
| Wykryte otwarte porty (4 stacki) | 31/31 — precyzja i czułość 100% |
| Fałszywe zmiany przy skanie bez zmian | 0 |
| Poprawna nazwa usługi / rozpoznana aplikacja | 20/20 / 20/20 |
| Scenariusz quickstart (zniknięcie i powrót 8787) | zaliczony |
| Czas odpowiedzi przez Toxiproxy (opóźnienie 500 ms) | 71 ms → 1057 ms |
| Test uogólnienia (Grafana, Jenkins, Portainer, MongoDB) | 4/4 rozpoznane |

Przykładowy ranking (stack „vulnerable”): WordPress 4.7 — 135 pkt (niedokończona instalacja, przestarzałe Apache i PHP,
panel logowania), DVWA — 130 pkt, Adminer — 85 pkt, FTP — 30 pkt.

## DefectDojo

```bash
./scripts/defectdojo-setup.sh
```

Uruchamia lokalny DefectDojo (<http://127.0.0.1:8180/>), zapisuje token i identyfikatory w `.env`.
Po włączeniu `[defectdojo] enabled = true`:

```bash
./run.sh dojo import N
```

```bash
./run.sh dojo export N --item "127.0.0.1:8090/tcp=DVWA"
```

`dojo import` wysyła surowy XML nmap (parser „Nmap Scan”), `dojo export` — wybrane obserwacje jako findingi
z dowodami (wartości ciasteczek i tokenów ukryte). Obserwacje można też zaznaczać w widoku hosta.

## Rozwój i testy

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

CI (GitHub Actions): fmt, clippy `-D warnings`, ok. 400 testów (parser nmap, sygnatury, porównania, szyfrowanie,
RBAC dla 4 ról, import/eksport, skala /18 = 16 384 adresów, harmonogram, okna i wznawianie), `cargo audit`, obraz Docker.
Testy na prawdziwej bazie uruchamiają się z `DSCAN_TEST_DATABASE_URL` (każdy test w osobnym schemacie).

Wytyczne rozwoju: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).
Plan zadań ze statusami: [`docs/plan_DScan.xlsx`](docs/plan_DScan.xlsx).

## Dokumentacja

| Dokument | Zawartość |
|---|---|
| [`docs/INSTRUKCJA-JURY.md`](docs/INSTRUKCJA-JURY.md) | uruchomienie od zera krok po kroku, laboratorium, DefectDojo, rozwiązywanie problemów |
| [`docs/architektura.md`](docs/architektura.md) | architektura, przebieg skanu, konfiguracja, format sygnatur, szyfrowanie, role |
| [`docs/cli.md`](docs/cli.md) | wszystkie polecenia i argumenty (generowane: `dscan docs`) |
| [`docs/analiza-skutecznosci.md`](docs/analiza-skutecznosci.md) | wyniki na laboratorium organizatorów i wprowadzone poprawki |
| [`docs/bezpieczenstwo-skanera.md`](docs/bezpieczenstwo-skanera.md) | zasady bezpiecznego skanowania z odnośnikami do kodu |
| [`docs/klasyfikacja-danych.md`](docs/klasyfikacja-danych.md) | które dane są szyfrowane, a które jawne i dlaczego |
| [`docs/testowanie-neovim.md`](docs/testowanie-neovim.md) | testy ręczne wszystkich zadań planu |
| [`docs/prezentacja.md`](docs/prezentacja.md) | slajdy (Marp); demo na żywo: `scripts/demo.sh` |

> Nazwa `dscan` jest zajęta na crates.io — nie przeszkadza to w budowaniu i używaniu narzędzia,
> ale przy publikacji pakietu trzeba by użyć innej nazwy.

## Licencja

[MIT](LICENSE)
