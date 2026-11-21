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

## Dane poufne (szyfrowane)

| Kolumna | Co zawiera | Dlaczego szyfrujemy |
|---|---|---|
| `targets.note` | Notatki operatorów do celów | Wolny tekst: łatwo wpisać w nim dane kontaktowe, hasła tymczasowe lub opis infrastruktury. |
| `subgroups.raw_nmap_xml` | Surowy wynik nmap (do DefectDojo) | Zawiera wszystko naraz: banery, wersje, nazwy hostów, wyniki skryptów. |
| `services.banner` | Banery usług | Ujawniają dokładne wersje oprogramowania (gotowa lista celów dla atakującego), czasem nazwy wewnętrzne. |
| `http_info.headers` | Nagłówki odpowiedzi HTTP | Mogą zawierać nazwy wewnętrznych serwerów, identyfikatory sesji (`Set-Cookie`), tokeny i nagłówki debugowania. |
| `http_info.cookies` | Ciasteczka z atrybutami | Identyfikatory sesji pozwalają przejąć zalogowaną sesję. |
| `http_info.certificate` | Certyfikat TLS | Pola SAN/CN zdradzają wewnętrzne nazwy i strukturę organizacji. |
| `overrides.value` | Ręczne poprawki wyników | Operator może wpisać w nich dowolne poufne informacje (jak w notatkach). |

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
| `detections.*` | Rozpoznane technologie z pewnością i opisem dowodu; potrzebne do filtrów i oceny znalezisk. Zasada dla silnika sygnatur (H5, H8): dowody zawierają nazwy ciasteczek i nagłówków, nie ich wartości. |
| `targets.kind/value/target_group` | Zakres skanowania musi dać się wyszukiwać i porównywać z `[scope]`. |
| `scan_runs.*`, `subgroups.addresses/status/czasy/error` | Metadane przebiegu: postęp, czasy, prognoza, wznawianie. |
| `changes.*` | Wynik porównania przebiegów: adres, port i skróty odcisków. |
| `users.username`, `roles.*` | Potrzebne do logowania i sprawdzania uprawnień. |
| `users.password_hash` | Nie jest szyfrowane, tylko **haszowane** argon2id (jednokierunkowo, z solą); odszyfrowanie nie jest potrzebne ani możliwe. |
| `audit_log.*` | Kto, co i kiedy zmienił. Zasada: w `details` nie zapisujemy wartości pól poufnych, tylko nazwy pól. |

## Planowane rozszerzenia

- **B3:** ślepy indeks (HMAC-SHA256) dla pól poufnych, po których trzeba filtrować (np. nazwa ciasteczka).
- **B6:** wersja klucza w każdym rekordzie, co pozwoli rotować klucz stopniowo.
