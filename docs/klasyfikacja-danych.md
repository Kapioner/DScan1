# Klasyfikacja danych wrażliwych (zadanie B4)

Ten dokument opisuje, które dane DScan szyfruje, które przechowuje jawnie i dlaczego.
Lista kolumn szyfrowanych w kodzie to `ENCRYPTED_COLUMNS` w `crates/db/src/columns.rs`.
Test `classification_document_lists_every_encrypted_column` pilnuje, żeby ten dokument
wymieniał każdą z nich.

## Poziomy

| Poziom | Gdzie | Ochrona |
|---|---|---|
| **Sekret** | tylko zmienne środowiskowe (`.env`, uprawnienia 600) | nigdy w bazie, plikach konfiguracji ani logach; w `config show` i logach zamaskowane |
| **Poufne** | baza, kolumny `BYTEA` | szyfrowane po stronie aplikacji AES-256-GCM; baza widzi wyłącznie szyfrogram |
| **Wewnętrzne** | baza, kolumny jawne | dostęp do bazy tylko lokalnie lub w sieci Compose; w API dostęp według ról (RBAC) |

## Sekrety (poza bazą)

| Sekret | Uzasadnienie |
|---|---|
| `DSCAN_ENCRYPTION_KEY` | Klucz AES-256 do pól poufnych. Kto go ma, odczyta wszystkie dane poufne, więc nie może trafić do bazy ani do repozytorium. |
| `DSCAN_DATABASE_URL` / `POSTGRES_PASSWORD` | Hasło do bazy daje dostęp do wszystkich danych wewnętrznych. |
| `DSCAN_ADMIN_PASSWORD` | Hasło pierwszego administratora; w bazie zostaje tylko jego skrót argon2id. |
| `DSCAN_DEFECTDOJO_TOKEN`, `DEFECTDOJO_*` | Token API i sekrety lokalnego DefectDojo (D4) — dostęp do zgłoszeń w DefectDojo. |

## Dane poufne (szyfrowane)

| Kolumna | Co zawiera | Dlaczego szyfrujemy |
|---|---|---|
| `targets.note` | Notatki operatorów do celów | Wolny tekst: łatwo wpisać w nim dane kontaktowe, hasła tymczasowe lub opis infrastruktury. |
| `subgroups.raw_nmap_xml` | Surowy wynik nmap (do DefectDojo) | Zawiera wszystko naraz: banery, wersje, nazwy hostów, wyniki skryptów. |
| `services.banner` | Banery usług | Ujawniają dokładne wersje oprogramowania (gotowa lista celów dla atakującego), czasem nazwy wewnętrzne. |
| `http_info.headers` | Nagłówki odpowiedzi HTTP | Mogą zawierać nazwy wewnętrznych serwerów, identyfikatory sesji (`Set-Cookie`), tokeny i nagłówki debugowania. |
| `http_info.cookies` | Ciasteczka z atrybutami | Identyfikatory sesji pozwalają przejąć zalogowaną sesję. |
| `http_info.certificate` | Certyfikat TLS | Pola SAN/CN zdradzają wewnętrzne nazwy i strukturę organizacji. |
| `overrides.value` | Ręczne poprawki wyników (A6) | Operator może wpisać w nich dowolne poufne informacje (jak w notatkach). |

### Model szyfrowania

- AES-256-GCM (crate `aes-gcm`), klucz wyłącznie ze zmiennej `DSCAN_ENCRYPTION_KEY`.
- Losowy 12-bajtowy nonce dla **każdej** wartości, więc ta sama wartość daje za każdym razem inny szyfrogram.
- Nazwa kolumny (np. `services.banner`) jest danymi uwierzytelnianymi (AAD), więc szyfrogramu
  nie da się przenieść do innej kolumny bez wykrycia.
- Format `[wersja 1 B][nonce 12 B][szyfrogram + tag 16 B]`; bajt wersji pozwoli zmienić format później.
- Rotacja klucza: `dscan keys rotate` przeszyfrowuje wszystkie kolumny z listy w jednej transakcji.

## Dane wewnętrzne (jawne) i uzasadnienie

| Dane | Dlaczego jawne |
|---|---|
| `hosts.ip`, `services.port/protocol/state` | Klucz porównań przebiegów (IP, port, protokół), indeksy, filtry i statystyki. Zaszyfrowanych wartości nie da się indeksować ani porównywać w SQL. |
| `services.name/product/version/cpe` | Statystyki technologii na dashboardzie i wyszukiwanie podatnych wersji. Pełny baner (bogatszy w szczegóły) jest szyfrowany. |
| `services.fingerprint_hash` | Skrót odcisku usługi (do wykrywania zmian); z samego skrótu nie da się odtworzyć danych. |
| `http_info.url/status_code/title`, `redirect_chain` | Filtrowanie i lista hostów w UI. Tytuł strony jest widoczny publicznie dla każdego, kto ją otworzy. |
| `detections.*` | Rozpoznane technologie z pewnością i opisem dowodu; potrzebne do filtrów i oceny znalezisk. Dowody ciasteczek zawierają tylko nazwę ciasteczka, nie wartość (identyfikator sesji). Dowody nagłówków zawierają wartość tylko dla nagłówków wskazanych w sygnaturach (np. `Server`). |
| `targets.kind/value/target_group` | Zakres skanowania musi dać się wyszukiwać i porównywać z `[scope]`. |
| `scan_runs.*`, `subgroups.addresses/status/czasy/error` | Metadane przebiegu: postęp, czasy, prognoza, wznawianie. |
| `changes.*` | Wynik porównania przebiegów: adres, port i skróty odcisków. |
| `users.username`, `users.last_login_at`, `roles.*` | Potrzebne do logowania i sprawdzania uprawnień. |
| `sessions.token_hash` | Tylko skrót SHA-256 tokenu sesji — z niego nie da się odtworzyć tokenu z ciasteczka, więc wyciek bazy nie pozwala przejąć sesji. |
| `scan_profiles.*` | Konfiguracja skanów (grupa celów, porty, okna, częstotliwość); potrzebna harmonogramowi i UI. |
| `http_info.tls_verified` | Czy certyfikat przeszedł weryfikację — cecha znaleziska, nie dana poufna. |
| `users.password_hash` | Nie jest szyfrowane, tylko **haszowane** argon2id (jednokierunkowo, z solą); odszyfrowanie nie jest potrzebne ani możliwe. |
| `host_presence.*`, `host_responses.*` | Stan aktywny/nieaktywny hosta i historia odpowiedzi w przebiegach (S11): adres, licznik pominięć, czasy — potrzebne do filtrów i dashboardu. |
| `scan_runs.mode/profile_id/requested_by` | Kto i jakim profilem zlecił skan — metadane harmonogramu i audytu. |
| `audit_log.*` | Kto, co i kiedy zmienił. Zasada: w `details` nie zapisujemy wartości pól poufnych, tylko nazwy pól. |

## Token CLI (poza bazą)

`dscan login` zapisuje token sesji w `~/.config/dscan/credentials.json` z uprawnieniami **0600**
(tylko właściciel). W bazie jest wyłącznie skrót SHA-256 tokenu. `dscan logout` kończy sesję na serwerze
i usuwa plik; token wygasa też sam po `[server] session_hours`.

## Planowane rozszerzenia

- **B3:** ślepy indeks (HMAC-SHA256) dla pól poufnych, po których trzeba filtrować (np. nazwa ciasteczka).
- **B6:** wersja klucza w każdym rekordzie, co pozwoli rotować klucz stopniowo.
