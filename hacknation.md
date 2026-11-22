# DScan - spełnienie wymagań zadania „Attack Surface Intelligence”

Każde wymaganie z treści zadania: jak jest spełnione i jak to sprawdzić.
**[demo]** = widoczne po `./install.sh` (dane z plików), **[skan]** = wymaga skanu na żywo (`scripts/demo.sh --uslugi` albo laboratorium).

## 1. Uruchomienie demo (Linux)

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan && ./install.sh
```

`install.sh` instaluje narzędzia, kompiluje, wgrywa demo (`scripts/demo.sh`), wypisuje adres, login i hasło,
a na końcu uruchamia serwer w tym samym terminalu (zostaw go otwartego). Kolejne starty: `./run.sh`.
Polecenia `scripts/demo.sh` i `./run.sh scan …` uruchamiaj w drugim terminalu.

| Polecenie | Co robi |
|---|---|
| `scripts/demo.sh` | wgrywa demo, zakłada konta ról, ocenia trafność, eksportuje CSV/JSON do `.dscan-demo/` |
| `scripts/demo.sh --uslugi` | jak wyżej + Grafana, Jenkins, Portainer, MongoDB w Dockerze i dwa skany `127.0.0.1` |
| `./install.sh --lab lab.zip` | scenariusz laboratorium: usługa 8787 znika i wraca, 4 skany z kodami wyjścia |

| Konto | Rola | Hasło |
|---|---|---|
| `admin` | administracja | `DSCAN_ADMIN_PASSWORD` w `.env` |
| `demo-operator` | dodawanie, usuwanie, modyfikacja | `DSCAN_DEMO_PASSWORD` w `.env` |
| `demo-modyfikacja` | modyfikacja i odczyt | jw. |
| `demo-odczyt` | odczyt | jw. |

Zawartość demo (`docs/demo/`, sieć `172.20.0.0/24`, 8 hostów): dwa przebiegi nmap. Między nimi:
`+` SSH na `172.20.0.11:2222`, `+` kamera Hikvision `172.20.0.34`, `~` nginx 1.18.0 → 1.24.0 na `172.20.0.10:80`,
`-` MySQL `172.20.0.12:3306`.

## 2. Wyzwanie (wymagania 1-16)

| # | Wymaganie | Jak spełnione | Jak sprawdzić |
|---|---|---|---|
| 1 | Lista IP, CIDR, domen | parser celów: DNS (także `/etc/hosts`), scalanie, normalizacja, zakres `[scope]` | `./run.sh targets check 127.0.0.1 10.10.0.7/24 localhost 'zły cel'`; WWW: **Cele** |
| 2 | Bezpieczny skan discovery | tylko `nmap -sn`/`-sV`, bez NSE, zawsze `--max-rate`, tylko sieci i porty z `[scope]` (`crates/scanner/src/safety.rs`) | `./run.sh scan 8.8.8.8` → odrzucony; [docs/bezpieczenstwo-skanera.md](docs/bezpieczenstwo-skanera.md) |
| 2a | Wielowątkowo, nmap, DefectDojo | pula `max_parallel_nmap` procesów; `dojo import` (XML nmap) i `dojo export` | `./run.sh scan 127.0.0.0/28 --parallel 4` → „do 4 procesów naraz”; rozdział 4 |
| 2b | Czas trwania skanu | postęp, czas i prognoza po każdej podgrupie; czasy w bazie i API | [skan] terminal skanu; WWW: **Pulpit → Trwające skany**; `GET /api/v1/scans` |
| 2c | Optymalne podgrupy | podział CIDR, rozmiar z przepustowości (EWMA) i czasu okna (`crates/engine/src/adaptive.rs`) | `./run.sh scan 127.0.0.0/16 --dry-run` → liczba podgrup i szacowany czas, bez pakietów |
| 3 | Aktywne hosty | `nmap -sn` / `-sV`, obecność hostów w każdym przebiegu | [demo] **Hosty**; [skan] `./run.sh scan 127.0.0.1 --mode discovery` |
| 4 | Identyfikacja usług | `nmap -sV` + weryfikacja HTTP dla usług niejednoznacznych | [demo] **Hosty → host**: produkt i wersja; `./run.sh evaluate docs/demo/referencja.csv` |
| 5 | Tytuł, kod HTTP, nagłówki, ciasteczka, TLS, przekierowania | klient HTTP(S) tylko GET; certyfikat: CN/SAN, ważność, self-signed | [skan] **Hosty → 127.0.0.1** (Grafana: przekierowanie na `/login`, ciasteczka; Jenkins: `X-Jenkins`) |
| 6 | Technologie: CMS, framework, serwer, IoT | ok. 50 sygnatur YAML + produkty nmap; pewność 0-100 z dowodami | [demo] kamery Hikvision, Jetty, nginx, Apache; [skan] Grafana, Jenkins, Portainer, MongoDB |
| 7 | Staging, panel administracyjny | heurystyki: nazwy hostów, nagłówki debug, `robots.txt`, tytuły paneli, kreatory instalacji | [skan] **Pulpit → Najważniejsze znaleziska** (panele Grafana, Jenkins, Portainer) |
| 8 | Porównanie przebiegów | odcisk SHA-256 usługi po kluczu IP, port, protokół | [demo] **Porównanie**; `./run.sh diff 1 2` |
| 9 | Nowe, znikające, zmienione | `+` / `-` / `~`, kolory w WWW, kod wyjścia 2 | [demo] **Pulpit → Zmiany od poprzedniego skanu**; [skan] `--uslugi`: `8083/tcp zniknęła` |
| 10 | Własne sygnatury | edytor w WWW z testem przed zapisem; plik YAML `[http] signatures_file` | WWW: **Sygnatury → Nowa sygnatura → Testuj**; `./run.sh sig test '*' --host http://127.0.0.1:8082/` |
| 11 | Formularz: ręcznie, CSV, JSON, te same reguły | jeden parser dla WWW, API i CLI; raport odrzuconych wierszy | WWW: **Cele** → wpis ręczny i plik `docs/examples/cele.csv` (3 poprawne, 3 odrzucone celowo: błędny wpis i 2 duplikaty) lub `cele.json` |
| 12 | RBAC, tworzenie ról | middleware sprawdza każde żądanie (`crates/api/src/auth/rbac.rs`); własne role z uprawnień | WWW jako `admin`: **Użytkownicy → Nowa rola**; test wszystkich ról na każdym endpoincie: `DSCAN_TEST_DATABASE_URL=… cargo test -p dscan-api --test roles` |
| 13 | 4 role | `administracja`, `dodawanie_usuwanie_modyfikacja`, `modyfikacja_odczyt`, `odczyt` | zaloguj się kontami `demo-*`: różne menu, przyciski i odpowiedzi `403` |
| 14 | Edycja niezależna od skanu, trwała | poprawki przypięte do adresu, nakładane przy odczycie; przetrwają kolejne przebiegi | [demo] **Hosty → host → Zapisz** → znaczek „edytowane ręcznie”; wgraj ponownie `przebieg-2.xml` → poprawka zostaje |
| 15 | Czytelny UI, dashboard znalezisk | menu zależne od roli; Pulpit: znaleziska, ranking ciekawości, zmiany, technologie | [demo] **Pulpit** |
| 16 | Szyfrowanie w spoczynku | AES-256-GCM pól poufnych, klucz tylko w `.env`, rotacja | `docker compose exec -T postgres psql -U dscan -d dscan -c "SELECT encode(substr(raw_nmap_xml,1,16),'hex') FROM subgroups LIMIT 3"` → szyfrogram zamiast XML; [docs/klasyfikacja-danych.md](docs/klasyfikacja-danych.md) |
| - | Harmonogram: okna, częstotliwość, przerwanie i wznowienie | profile z oknami `HH:MM` i częstotliwością; koniec okna → `paused`, wznowienie w kolejnym oknie | WWW: **Profile skanów → Nowy profil**; [skan] `./run.sh stop N`, `./run.sh resume N` |

## 3. Oczekiwany rezultat - zakres minimalny

| Wymaganie | Jak sprawdzić |
|---|---|
| import hostów lub zakresów | WWW **Cele** albo `./run.sh import docs/examples/cele.csv --dry-run` |
| import wyników JSON / CSV | `./run.sh import --kind results .dscan-demo/uslugi.csv` (także `hosty.json`, nmap XML) |
| ponad 10 000 IP | `./run.sh scan 127.0.0.0/16 --dry-run` (65 536 adresów, adresy liczone strumieniowo); test przebiegu /18: `DSCAN_TEST_DATABASE_URL=… cargo test -p dscan-engine --test scale` |
| okno czasowe i częstotliwość | **Profile skanów**; `[[schedule.windows]]` w `dscan.toml` |
| ograniczanie tempa | `--max-rate` (łączny, dzielony między procesy), `max_bandwidth_kbps`, limity HTTP na host |
| aktywne hosty, identyfikacja usług | [demo] **Hosty** |
| zapis do bazy | PostgreSQL; `./run.sh db status` |
| porównanie dwóch skanów | [demo] **Porównanie**, `./run.sh diff 1 2` |
| dashboard najważniejszych zmian | [demo] **Pulpit** |
| eksport JSON / CSV | `./run.sh export services --format csv`; pliki w `.dscan-demo/` |
| role | konta `demo-*` |
| edycja skanów, wyników, konfiguracji | wyniki: strona hosta; profile: **Profile skanów**; cele: **Cele** (dodawanie, usuwanie), grupa i notatka: `PUT /api/v1/targets/{id}` |
| szyfrowanie | wymaganie 16 |

## 4. Zakres mile widziany

| Funkcja | Jak sprawdzić |
|---|---|
| harmonogram cyklicznych skanów | **Profile skanów**: częstotliwość w minutach, uruchamiane przez `dscan serve` |
| różnice zależne od pory dnia | **Hosty → host → Dostępność w godzinach doby**; **W czasie → Aktywność hostów w godzinach** |
| ocena ciekawości | [demo] **Pulpit → Najciekawsze usługi** (punkty z uzasadnieniem) |
| ponowne pomiary hostów niestabilnych | `[stability] unstable_retries`, `retry_delay_seconds`; host nieaktywny po `inactive_after_missed_runs` |
| HTTP/HTTPS fingerprinting, CMS | wymagania 5-6 |
| grupowanie podobnych usług | [skan] **Grupy usług** (SimHash treści stron) → jeden tag dla grupy |
| tagi | **Hosty → host → Tagi** |
| eksport do DefectDojo | `./scripts/defectdojo-setup.sh`, potem `./run.sh dojo import N`, `./run.sh dojo export N --item "IP:PORT/tcp=Technologia"`; WWW: zaznaczenie detekcji na stronie hosta |
| wizualizacja zmian w czasie | [demo] **W czasie** |
| źródła pasywne | `./run.sh import --kind results PLIK --format shodan` lub `--format masscan` |

## 5. Walidacja w laboratorium (rozdział 6 zadania)

| Kryterium | Gdzie udowodnione |
|---|---|
| hosty, usługi, fingerprinting, CMS | [docs/analiza-skutecznosci.md](docs/analiza-skutecznosci.md): 31/31 portów, 20/20 usług i aplikacji |
| nagłówki i ciasteczka | strona hosta: nagłówki, ciasteczka z atrybutami, detekcje z dowodami |
| własne sygnatury | **Sygnatury** (edytor i test) |
| porównanie, hosty niestabilne | quickstart: `./install.sh --lab lab.zip`; obecność hostów, ponowne pomiary |
| bezpieczeństwo skanera | [docs/bezpieczenstwo-skanera.md](docs/bezpieczenstwo-skanera.md) |
| import, eksport, role | rozdziały 2-3 |

## 6. Wymagania formalne

| Wymaganie | Gdzie |
|---|---|
| repozytorium | ten projekt (Rust, 12 modułów w `crates/`) |
| dokumentacja techniczna | [docs/architektura.md](docs/architektura.md), [docs/cli.md](docs/cli.md), PDF: `docs/pdf/` |
| prezentacja do 10 slajdów | [docs/prezentacja.md](docs/prezentacja.md), `docs/pdf/prezentacja.pdf` (10 slajdów) |
| testy | `cargo test --workspace`, CI w `.github/workflows/ci.yml` |
