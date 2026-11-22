<img src="img/logo-mark.png" alt="DScan" width="64" align="right">

# DScan — dokumentacja techniczna (Q6)

DScan (*Defect Scan*) wykrywa hosty i usługi w dozwolonym zakresie sieci, rozpoznaje
technologie, porównuje kolejne przebiegi i pokazuje zmiany. Napisany w Ruście; jedna binarka
`dscan` (serwer WWW + API + CLI), dane w PostgreSQL.

## 1. Architektura

```
            przeglądarka (htmx)          dscan CLI (klient API, token)
                    │                              │
                    ▼                              ▼
   ┌──────────────────────────── dscan serve ─────────────────────────────┐
   │  dscan-web (askama)   dscan-api (axum, RBAC, OpenAPI, audyt)          │
   │                 │              │                                      │
   │                 ▼              ▼                                      │
   │      dscan-engine: ScanService, harmonogram, podgrupy, import,        │
   │      porównania, obecność, ocena znalezisk, klastry                   │
   │        │                │                     │                       │
   │  dscan-scanner     dscan-fingerprint     dscan-integrations           │
   │  (nmap, pula,      (HTTP, TLS, favicon,  (import/eksport, DefectDojo, │
   │   zabezpieczenia)   sygnatury, SimHash)   ewaluacja, źródła pasywne)  │
   │        │                                                              │
   │  dscan-db (sqlx, migracje, szyfrowanie pól) ── dscan-crypto (AES-GCM) │
   └──────────────────────────────┬───────────────────────────────────────┘
                                  ▼
                              PostgreSQL
```

| Crate | Odpowiedzialność |
|---|---|
| `dscan-core` | Modele domeny (Host, Service, Detection, Change…), porównanie przebiegów, obecność i stabilność hostów |
| `dscan-config` | Konfiguracja TOML + zmienne `DSCAN_*` + flagi (figment), walidacja, profile, sekrety |
| `dscan-crypto` | AES-256-GCM z identyfikatorem klucza, HMAC-SHA256 (ślepy indeks), tokeny sesji |
| `dscan-db` | Pula PostgreSQL, migracje, zapis wsadowy, szyfrowane kolumny, rotacja kluczy |
| `dscan-scanner` | Cele i zakres, podgrupy CIDR, pula procesów nmap z limitem tempa, parser XML, zabezpieczenia |
| `dscan-fingerprint` | Klient HTTP(S), certyfikaty TLS, favicon (mmh3), sygnatury YAML, heurystyki środowisk, SimHash |
| `dscan-engine` | Przebiegi (tworzenie, wznawianie, zatrzymanie), harmonogram, import wyników, dashboard, ocena, klastry |
| `dscan-integrations` | Import celów/wyników, eksport JSON/CSV, DefectDojo, ewaluacja trafności, źródła pasywne |
| `dscan-auth` | Hasła argon2id, walidacja loginów |
| `dscan-api` | REST API `/api/v1`, middleware RBAC, dziennik audytu, OpenAPI |
| `dscan-web` | Interfejs WWW (askama + htmx wkompilowany w binarkę) |
| `dscan` (cli) | Podkomendy (wzorzec Command); większość działa jako klient API |

**Wzorce (refactoring.guru):** Builder (`ConfigLoader`), Command (podkomendy), Strategy (heurystyki,
matchery), Adapter (resolver DNS, źródła pasywne), Decorator (fingerprinting nad skanerem nmap),
Observer (postęp skanu, zakończone przebiegi → auto-import DefectDojo), Iterator (adresy CIDR),
Singleton przez `OnceLock` (rejestr własnych sygnatur, sztuczny skrót hasła).

## 2. Przebieg skanu

1. Cele (IP, CIDR, domeny) → DNS → scalenie → odrzucenie wszystkiego spoza `[scope] allowed_networks`.
2. Podział na podgrupy CIDR; rozmiar dobierany z EWMA przepustowości i pozostałego czasu okna (S5).
3. Pula `max_parallel_nmap` procesów `nmap -sV` (albo `-sn`), łączny `--max-rate` dzielony między procesy;
   argumenty sprawdza `check_nmap_args` (bez skryptów NSE).
4. Dla usług WWW: GET strony głównej, certyfikat, favicon, bezpieczne sondy ścieżek, sygnatury,
   heurystyki (staging, debug, panele), SimHash; wyniki `-sV` łączone z detekcjami (H9).
5. Każda podgrupa zapisywana od razu (wsadowo, w transakcji); XML nmap zaszyfrowany.
6. Koniec okna czasowego → procesy zatrzymane, niedokończone podgrupy wracają do kolejki (`paused`).
7. Po udanym przebiegu: powtórne pomiary hostów bez odpowiedzi (S10), obecność (S11),
   porównanie z poprzednim przebiegiem profilu (M1), ewentualnie auto-import do DefectDojo.

## 3. Uruchomienie

```bash
./run.sh                      # serwer WWW + API na http://127.0.0.1:8080 (PostgreSQL w Dockerze)
./run.sh login --user admin   # token dla poleceń CLI
./run.sh scan 172.20.0.0/24 --profile pelny
```

`run.sh` tworzy `dscan.toml` i `.env` (klucz szyfrowania, hasło bazy, konto administratora, uprawnienia 600),
uruchamia PostgreSQL w Dockerze, synchronizuje hasło bazy z `.env` i buduje wersję release.
Bez Dockera: `USE_DOCKER_POSTGRES=0` i własny `DSCAN_DATABASE_URL`. Pełna lista poleceń: [`cli.md`](cli.md).

## 4. Konfiguracja

Kolejność: wartości domyślne < `dscan.toml` < zmienne `DSCAN_<SEKCJA>__<POLE>` < flagi CLI.
`dscan config init` tworzy skomentowany plik ze wszystkimi parametrami, `dscan config show` pokazuje
efektywną konfigurację. Sekcje: `scope`, `limits`, `schedule`, `stability`, `server`, `database`, `http`,
`defectdojo`, `scoring`, `profiles.NAZWA`.

Sekrety wyłącznie w zmiennych środowiskowych (`.env`): `DSCAN_ENCRYPTION_KEY`, `DSCAN_ENCRYPTION_KEY_ID`,
`DSCAN_PREVIOUS_ENCRYPTION_KEYS`, `DSCAN_DATABASE_URL`, `DSCAN_ADMIN_USERNAME/PASSWORD`, `DSCAN_DEFECTDOJO_TOKEN`.

## 5. Format sygnatur

Plik YAML (lista) w `[http] signatures_file` albo pojedyncze sygnatury z edytora w UI (zapisywane w bazie):

```yaml
- name: Jenkins
  category: ci-cd            # kategorie wrażliwe: panel-admina, iot-kamera, iot-drukarka, ci-cd, baza-danych
  condition: any             # any — wystarczy jeden matcher; all — wszystkie
  matchers:
    - { type: header, name: X-Jenkins, weight: 60 }                     # nagłówek (opcjonalnie pattern)
    - { type: cookie, name: JSESSIONID, weight: 10 }                    # ciasteczko (opcjonalnie pattern)
    - { type: body, pattern: 'Dashboard \[Jenkins\]', weight: 40 }      # regex treści strony
    - { type: favicon, hash: 81586312, weight: 50 }                     # mmh3 favicony (jak Shodan)
    - { type: path, path: /login, status: 200, pattern: 'Jenkins', weight: 30 }  # bezpieczna sonda GET
  version: { source: header, name: X-Jenkins, pattern: '([\d.]+)' }
```

Pewność = suma wag pasujących matcherów (max 100); detekcje poniżej `[http] min_confidence` są pomijane.
Każda detekcja ma listę dowodów. Test sygnatury przed zapisem: strona **Sygnatury** albo `dscan sig test`.

## 6. Model szyfrowania

Szczegóły i uzasadnienie klasyfikacji: [`klasyfikacja-danych.md`](klasyfikacja-danych.md).

- Pola poufne (notatki, banery, nagłówki, ciasteczka, certyfikaty, surowy XML, poprawki) — AES-256-GCM
  po stronie aplikacji, losowy nonce, nazwa kolumny jako AAD, identyfikator klucza w rekordzie.
- Wyszukiwanie po polach szyfrowanych: ślepy indeks HMAC-SHA256 (ciasteczka, nagłówki).
- Rotacja: jednorazowa (`keys rotate`, jedna transakcja) albo stopniowa (`keys reencrypt` partiami).
- Hasła: argon2id; sesje: w bazie tylko SHA-256 tokenu; token CLI w pliku z uprawnieniami 600.

## 7. Role i uprawnienia

| Rola | Uprawnienia | Zakres |
|---|---|---|
| `administracja` | `admin`, `targets:write`, `results:write`, `read` | wszystko, konta, role, dziennik audytu |
| `dodawanie_usuwanie_modyfikacja` | `targets:write`, `results:write`, `read` | cele, profile, skany, importy, sygnatury, poprawki |
| `modyfikacja_odczyt` | `results:write`, `read` | poprawki wyników, tagi, DefectDojo, odczyt |
| `odczyt` | `read` | odczyt, dashboard, eksport bez notatek |

Administrator może tworzyć własne role z tych uprawnień. Middleware RBAC sprawdza każde żądanie według
tabeli w `crates/api/src/auth/rbac.rs` (trasa spoza tabeli → tylko administrator). Zmiany trafiają do
dziennika audytu (kto, co, kiedy; bez wartości pól poufnych). Testy: `crates/api/tests/roles.rs`.

## 8. Bezpieczeństwo skanera

[`bezpieczenstwo-skanera.md`](bezpieczenstwo-skanera.md): brak skryptów NSE i prób logowania, limit tempa,
tylko dozwolone sieci i porty, HTTP wyłącznie GET, `cargo audit` w CI.

## 9. Testy

`cargo test --workspace` (z `DSCAN_TEST_DATABASE_URL` — testy na prawdziwej bazie w osobnych schematach):
parser nmap, sygnatury i matchery, porównania, szyfrowanie, RBAC dla 4 ról, import/eksport, test skali /18
(16 384 adresów), harmonogram, okna i wznawianie. CI: fmt, clippy `-D warnings`, testy, `cargo audit`, obraz Docker.

## 10. Demo i dane zapasowe

`scripts/demo.sh` — scenariusz na danych z `docs/demo` (dwa przebiegi z laboratorium i zmianą między nimi,
plik referencyjny do oceny trafności); `scripts/demo.sh --live CEL` — dwa prawdziwe skany.
