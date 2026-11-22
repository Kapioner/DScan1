# DScan - architektura

Jedna binarka `dscan` (serwer WWW + REST API + CLI) w Ruście, dane w PostgreSQL.

## Komponenty

```
 przeglądarka (htmx)          dscan CLI (klient API)
         │                             │
         ▼                             ▼
 ┌───────────────────── dscan serve ──────────────────────┐
 │ dscan-web (askama)    dscan-api (axum, RBAC, audyt)    │
 │      dscan-engine (przebiegi, harmonogram)             │
 │ dscan-scanner  dscan-fingerprint  dscan-integrations   │
 │ dscan-db (sqlx, szyfrowanie) ── dscan-crypto (AES-GCM) │
 └────────────────────────────┬───────────────────────────┘
                              ▼
                         PostgreSQL
```

| Crate | Zadanie |
|---|---|
| `dscan-core` | modele, porównanie przebiegów, obecność hostów |
| `dscan-config` | TOML + `DSCAN_*` + flagi, walidacja, profile, sekrety |
| `dscan-crypto` | AES-256-GCM, HMAC-SHA256 (ślepy indeks), tokeny |
| `dscan-db` | pula, migracje `0001`-`0009`, zapis wsadowy, rotacja kluczy |
| `dscan-scanner` | cele i zakres, podgrupy CIDR, pula nmap, parser XML, zabezpieczenia |
| `dscan-fingerprint` | HTTP(S), TLS, favicon (mmh3), sygnatury YAML, heurystyki, SimHash |
| `dscan-engine` | przebiegi, harmonogram, import, dashboard, ocena znalezisk, klastry |
| `dscan-integrations` | import/eksport, DefectDojo, ewaluacja trafności |
| `dscan-auth` | argon2id, walidacja loginów |
| `dscan-api` | REST `/api/v1`, RBAC, audyt, OpenAPI |
| `dscan-web` | interfejs WWW (htmx wkompilowany - działa offline) |
| `dscan` | podkomendy CLI (clap) |

Wzorce: Builder, Command, Strategy, Adapter, Decorator, Observer, Iterator.

## Przebieg skanu

1. Cele → DNS (także `/etc/hosts`) → scalenie → odrzucenie spoza `[scope] allowed_networks`.
2. Podgrupy CIDR (domyślnie /24), rozmiar dobierany z przepustowości i czasu okna.
3. `max_parallel_nmap` procesów `nmap -sV` / `-sn`; łączny `--max-rate` dzielony między procesy.
4. Usługi WWW: GET, nagłówki, ciasteczka, certyfikat, favicon, sondy ścieżek, sygnatury, heurystyki, czas odpowiedzi.
5. Zapis podgrupy od razu, wsadowo (10 000 hostów + 20 000 usług ≈ 0,6 s); XML zaszyfrowany.
6. Koniec okna → nmap zatrzymany, niedokończone podgrupy wracają do kolejki (`paused`).
7. Po przebiegu: ponowne pomiary, obecność hostów, porównanie z poprzednim przebiegiem, auto-import DefectDojo.

Zmiana usługi = inny odcisk SHA-256 (produkt, wersja, nazwa, kod i tytuł HTTP, stabilne nagłówki, TLS)
przy tym samym kluczu (IP, port, protokół).

## Konfiguracja

Kolejność: domyślne < `dscan.toml` < `DSCAN_<SEKCJA>__<POLE>` < flagi CLI.
Sekcje: `scope`, `limits`, `schedule`, `stability`, `server`, `database`, `http`, `defectdojo`, `scoring`, `profiles.NAZWA`.
Sekrety tylko w `.env`: `DSCAN_ENCRYPTION_KEY`, `DSCAN_ENCRYPTION_KEY_ID`, `DSCAN_PREVIOUS_ENCRYPTION_KEYS`,
`DSCAN_DATABASE_URL`, `DSCAN_ADMIN_USERNAME/PASSWORD`, `DSCAN_DEFECTDOJO_TOKEN`.

## Sygnatury

```yaml
- name: Jenkins
  category: ci-cd          # panel-admina, iot-kamera, iot-drukarka, ci-cd, baza-danych
  condition: any           # any | all
  matchers:
    - { type: header, name: X-Jenkins, weight: 60 }
    - { type: body, pattern: 'Dashboard \[Jenkins\]', weight: 40 }
    - { type: favicon, hash: 81586312, weight: 50 }
    - { type: path, path: /login, status: 200, pattern: 'Jenkins', weight: 30 }
  version: { source: header, name: X-Jenkins, pattern: '([\d.]+)' }
```

Matchery: `header`, `cookie`, `body`, `favicon`, `path`. Pewność = suma wag (max 100), próg `[http] min_confidence`.
Test: strona **Sygnatury** lub `dscan sig test`.

## Szyfrowanie

- Pola poufne: AES-256-GCM, losowy nonce, nazwa kolumny jako AAD, identyfikator klucza w rekordzie.
- Wyszukiwanie: ślepy indeks HMAC-SHA256.
- Rotacja: `keys rotate` (jedna transakcja) lub `keys reencrypt` (partiami).
- Hasła argon2id; w bazie tylko SHA-256 tokenu sesji. Szczegóły: `klasyfikacja-danych`.

## Role

| Rola | Uprawnienia |
|---|---|
| `administracja` | wszystko, konta, role, audyt |
| `dodawanie_usuwanie_modyfikacja` | cele, profile, skany, importy, sygnatury, poprawki |
| `modyfikacja_odczyt` | poprawki, tagi, DefectDojo, odczyt |
| `odczyt` | odczyt i eksport bez notatek |

RBAC sprawdza każde żądanie (`crates/api/src/auth/rbac.rs`); trasa spoza tabeli → tylko administrator.

## Testy

`cargo test --workspace` (z `DSCAN_TEST_DATABASE_URL` - na prawdziwej bazie). CI: fmt, clippy `-D warnings`,
ok. 400 testów (RBAC 4 ról, skala /18), `cargo audit`, obraz Docker.
