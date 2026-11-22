# DScan — klasyfikacja danych

Lista kolumn szyfrowanych: `ENCRYPTED_COLUMNS` w `crates/db/src/columns.rs`.
Test `classification_document_lists_every_encrypted_column` pilnuje zgodności z tym dokumentem.

## Poziomy

| Poziom | Gdzie | Ochrona |
|---|---|---|
| **Sekret** | tylko `.env` (600) | nigdy w bazie, konfiguracji ani logach; maskowany w `config show` |
| **Poufne** | kolumny `BYTEA` | AES-256-GCM po stronie aplikacji |
| **Wewnętrzne** | kolumny jawne | dostęp lokalny do bazy, w API przez RBAC |

## Sekrety

| Sekret | Dlaczego |
|---|---|
| `DSCAN_ENCRYPTION_KEY` | odszyfrowuje wszystkie dane poufne |
| `DSCAN_DATABASE_URL`, `POSTGRES_PASSWORD` | dostęp do całej bazy |
| `DSCAN_ADMIN_PASSWORD` | w bazie tylko skrót argon2id |
| `DSCAN_DEFECTDOJO_TOKEN`, `DEFECTDOJO_*` | dostęp do DefectDojo |

## Dane poufne (szyfrowane)

| Kolumna | Dlaczego |
|---|---|
| `targets.note` | wolny tekst operatorów |
| `subgroups.raw_nmap_xml` | komplet: banery, wersje, nazwy hostów |
| `services.banner` | dokładne wersje oprogramowania |
| `http_info.headers` | nazwy serwerów, tokeny, nagłówki debugowania |
| `http_info.cookies` | identyfikatory sesji |
| `http_info.certificate` | SAN/CN zdradzają nazwy wewnętrzne |
| `overrides.value` | dowolny tekst operatora |

Format: `[wersja 1 B][id klucza 1 B][nonce 12 B][szyfrogram + tag 16 B]`; losowy nonce, nazwa kolumny jako AAD.
Rotacja: `keys rotate` (jedna transakcja) albo `keys reencrypt` partiami (`DSCAN_ENCRYPTION_KEY_ID`,
`DSCAN_PREVIOUS_ENCRYPTION_KEYS`), postęp: `keys status`. Wyszukiwanie: ślepy indeks HMAC-SHA256 (`http_blind_index`).

## Dane jawne

| Dane | Dlaczego jawne |
|---|---|
| `hosts.ip`, `services.port/protocol/state` | klucz porównań, indeksy, filtry |
| `services.name/product/version/cpe` | statystyki technologii (pełny baner szyfrowany) |
| `services.fingerprint_hash` | skrót — nie da się odtworzyć danych |
| `http_info.url/status_code/title/redirect_chain/tls_verified` | filtry i listy w UI |
| `detections.*` | technologie i dowody (bez wartości ciasteczek) |
| `targets.kind/value/target_group` | porównanie z `[scope]` |
| `scan_runs.*`, `subgroups.*` (bez XML), `changes.*`, `scan_profiles.*` | metadane, harmonogram, wznawianie |
| `users.username`, `roles.*` | logowanie i uprawnienia |
| `users.password_hash` | haszowane argon2id (jednokierunkowo) |
| `sessions.token_hash` | tylko SHA-256 tokenu |
| `host_presence.*`, `host_responses.*` | stan aktywny/nieaktywny |
| `audit_log.*` | kto, co, kiedy — bez wartości pól poufnych |

Token CLI: `~/.config/dscan/credentials.json` (0600); `dscan logout` kończy sesję i usuwa plik.
