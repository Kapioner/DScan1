# DScan - jak sprawdzić wymagania zadania w panelu WWW

Instrukcja dla jury: instalacja przez `install.sh`, kolejne starty przez `run.sh` (Linux), wszystkie testy w przeglądarce.
Przy każdym teście: gdzie kliknąć, co wpisać i jaki wynik powinien się pojawić. Zrzuty ekranu: `docs/pdf/zrzuty-ekranu.pdf`.

## 1. Uruchomienie

```bash
git clone https://github.com/Kapioner/DScan.git DScan && cd DScan && ./install.sh
```

`install.sh` instaluje brakujące narzędzia, kompiluje aplikację i przygotowuje dane testowe. Na końcu wypisuje
adres, login i hasła, a potem uruchamia serwer w tym samym terminalu. **Terminal zostaw otwarty.**
Kolejne uruchomienia: `./run.sh`. Zatrzymanie: `Ctrl+C`.

Adres panelu: **http://127.0.0.1:9080/**

| Konto | Rola | Hasło |
|---|---|---|
| `admin` | administracja | wypisane na końcu `install.sh` („Hasło”) |
| `demo-operator` | dodawanie, usuwanie, modyfikacja | wypisane na końcu `install.sh` („Konta ról”) |
| `demo-modyfikacja` | modyfikacja i odczyt | jw. |
| `demo-odczyt` | odczyt | jw. |

Co przygotowuje `install.sh`:

- **dane demo** - dwa przebiegi skanu sieci `172.20.0.0/24` (8 hostów) ze zmianami między nimi,
- **usługa do skanu na żywo** - `127.0.0.1:8088` (HTTP) i `127.0.0.1:8089` (HTTPS): panel logowania WordPress,
  przekierowanie, ciasteczka, nagłówki debugowania, intranet „Development” z certyfikatem self-signed.

Pliki do testów importu (w katalogu `DScan`): `docs/examples/cele.csv`, `docs/examples/cele.json`, `docs/demo/przebieg-2.xml`.

## 2. Testy

Testy wykonuj po kolei, zalogowany jako `admin` (chyba że test mówi inaczej).

### A. Dane demo: dashboard i zmiany

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| A1 | **Pulpit** | otwórz po zalogowaniu | karty (hosty, usługi, znaleziska, aktywne/nieaktywne), **Najciekawsze usługi** z punktami i uzasadnieniem, **Technologie** | 15 |
| A2 | **Pulpit → Zmiany od poprzedniego skanu** | przewiń | `Nowe: 3, zniknęły: 1, zmienione: 1`: `+` 172.20.0.11:2222, `+` 172.20.0.34:80 i :554, `−` 172.20.0.12:3306, `~` 172.20.0.10:80 | 8, 9 |
| A3 | **Porównanie** | Starszy przebieg: `#1`, Nowszy: `#2` → **Porównaj** | `nowe: 3, zniknęły: 1, zmienione: 1`; wiersz `172.20.0.10:80/tcp`: `nginx 1.18.0` → `nginx 1.24.0` | 8, 9 |
| A4 | **Hosty** | Przebieg `#2`, Technologia: `Hikvision` → **Filtruj** | `Hostów: 4` - kamery IP (urządzenia IoT) | 3, 4, 6 |
| A5 | **W czasie** | otwórz | wykres hostów i usług w kolejnych przebiegach, aktywność hostów w godzinach doby | zmiany w czasie, pora dnia |

### B. Edycja wyników

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| B1 | **Hosty** → `172.20.0.10` | w sekcji `80/tcp`, pole **Produkt**: wpisz `Serwer WWW firmy` → **Zapisz** | wartość ze znaczkiem „edytowane ręcznie” i przyciskiem „Przywróć wartość ze skanu” | 14 |
| B2 | ten sam host → **Tagi** | wpisz `serwer-www` → **Dodaj tag** | tag przy hoście; **Hosty** → Tag `serwer-www` → **Filtruj** pokazuje ten host | tagi |
| B3 | **Cele → Wgraj wyniki skanu** | plik `docs/demo/przebieg-2.xml` → **Wgraj wyniki** | `Zapisano przebieg #3: 7 hostów, 14 otwartych portów`, `Brak zmian względem przebiegu #2` | import wyników |
| B4 | **Hosty** → Przebieg `#3` → `172.20.0.10` | sprawdź `80/tcp` | produkt nadal `Serwer WWW firmy` ze znaczkiem „edytowane ręcznie” - edycja przetrwała nowy przebieg | 14 |

### C. Cele: formularz ręczny i pliki

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| C1 | **Cele → Dodaj cel** | Cel: `10.10.0.7/24`, Grupa: `lab` → **Dodaj** | `Dodano cel 10.10.0.0/24.` (sieć znormalizowana), cel w tabeli | 1, 11 |
| C2 | **Cele → Dodaj cel** | Cel: `zły cel` → **Dodaj** | komunikat o błędzie: to nie jest adres IP, sieć CIDR ani domena | 1, 11 |
| C3 | **Cele → Wgraj plik** | plik `docs/examples/cele.csv`, zaznacz „tylko sprawdź” → **Wgraj** | `Poprawne cele: 3, odrzucone wiersze: 3`; tabela: wiersz 5 błędny cel, wiersze 6 i 7 duplikaty (celowo) | 1, 11 |
| C4 | **Cele → Wgraj plik** | plik `docs/examples/cele.json`, „tylko sprawdź” → **Wgraj** | `Poprawne cele: 2, odrzucone wiersze: 1` (`300.1.1.1`) | 1, 11 |

### D. Skan na żywo i fingerprinting HTTP/HTTPS

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| D1 | **Pulpit → Uruchom skan** | Cele: `127.0.0.1`, Tryb: `usługi` → **Uruchom** | `Uruchomiono przebieg #N`; w **Trwające skany** pasek postępu, czas i prognoza; skan trwa ok. 15-60 s | 2, 3, 4, czas skanu |
| D2 | **Hosty** → najnowszy przebieg → `127.0.0.1` | sekcja `8088/tcp` | `HTTP 200 „Admin Panel - Login”`, **Przekierowania** `302 …/ → …/admin/`, **Ciasteczka** `PHPSESSID (Path=/, HttpOnly, bez Secure)`, **Nagłówki** m.in. `x-powered-by`, `x-debug-token` | 5 |
| D3 | ta sama strona, sekcja `8089/tcp` | sprawdź **Certyfikat** | `CN=staging.lab.local`, ważność, SAN, `self-signed`, `TLS niezweryfikowany` | 5 |
| D4 | ta sama strona → **Technologie** | sprawdź tabele | `WordPress 4.7` (CMS), `PHP 5.6.40`, `nginx 1.27.5` (serwer), `Panel logowania`, `Panel administracyjny`, `Tryb debugowania`, `Środowisko testowe` - z pewnością w % i dowodami | 6, 7 |
| D5 | **Pulpit** | przewiń | **Najciekawsze usługi**: `127.0.0.1:8088/tcp` ok. 135 pkt (panel, debug, stary PHP i WordPress); **Najważniejsze znaleziska**: panel logowania, tryb debugowania, środowisko testowe, certyfikat | 7, 15 |
| D6 | **Pulpit → Uruchom skan** | ponownie `127.0.0.1`, tryb `usługi` | po skanie **Zmiany**: `Nowe: 0, zniknęły: 0, zmienione: 0` - brak fałszywych zmian | 8 |
| D7 | **Pulpit → Uruchom skan** | Cele: `127.0.0.0/18`, Tryb: `wykrywanie hostów` → **Uruchom** | przebieg 16 384 adresów w 64 podgrupach (tabela **Przebiegi skanów**, kolumna Podgrupy `64/64`); **Hosty** → ten przebieg: `Hostów: 16384` | ponad 10 000 IP, podgrupy |

Test D7 wykonaj na końcu - kolejne widoki domyślnie pokazują najnowszy przebieg.

### E. Własne sygnatury

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| E1 | **Sygnatury → Nowa sygnatura** | wklej YAML poniżej; Testuj na adresie: `http://127.0.0.1:8088/admin/` → **Testuj** | wynik testu: `Panel demo 90%`, dowód `treść pasuje do /Admin Panel/ (+90)` | 10 |
| E2 | ten sam formularz | **Zapisz** | `Zapisano sygnaturę - działa w kolejnych skanach.`, sygnatura na liście; kolejny skan `127.0.0.1` pokazuje `Panel demo` w technologiach | 10 |

```yaml
name: Panel demo
category: panel-admina
condition: any
matchers:
  - { type: body, pattern: 'Admin Panel', weight: 90 }
```

### F. Harmonogram

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| F1 | **Profile skanów → Nowy profil** | Nazwa: `nocny`, Okna czasowe: `22:00-06:00`, Co ile minut: `1440` → **Utwórz** | `Zapisano profil.`; w tabeli: okno `22:00–06:00`, `co 1440 min` | okna czasowe, częstotliwość |
| F2 | **Profile skanów** → rozwiń `Edytuj „nocny”` | Co ile minut: `720` → **Zapisz** | w tabeli `co 720 min` (edycja konfiguracji) | edycja konfiguracji |

Skan przerwany końcem okna dostaje stan `paused` i jest wznawiany w kolejnym oknie (przycisk **Wznów** na Pulpicie).

### G. Eksport i import

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| G1 | **Hosty** → Przebieg `#2` | kliknij `usługi CSV`, `usługi JSON`, `hosty JSON`, `zmiany CSV` | pobrane pliki z wynikami przebiegu | eksport JSON/CSV |
| G2 | **Cele → Wgraj wyniki skanu** | pobrany plik `hosty-…json` albo `uslugi-…csv` → **Wgraj wyniki** | `Zapisano przebieg #N` z liczbą hostów i portów oraz zmianami względem poprzedniego importu | import JSON/CSV |

### H. Role i uprawnienia

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| H1 | **Użytkownicy** | otwórz | konta `admin`, `demo-operator`, `demo-modyfikacja`, `demo-odczyt` z rolami | 13 |
| H2 | **Użytkownicy → Nowa rola** | Nazwa: `audytor`, uprawnienie `read` (zaznaczone) → **Utwórz rolę** | nowa rola na liście, do wyboru przy kontach | 12 |
| H3 | **Audyt** | otwórz | wpisy z testów B1-F1: kto, co, kiedy (edycja, tag, import, skan, sygnatura, profil) | 12 |
| H4 | **Wyloguj** → `demo-odczyt` | przejdź po menu | brak pozycji **Użytkownicy** i **Audyt**, brak formularzy „Uruchom skan”, „Dodaj”, przycisków „Zapisz”; adres `/users` → „Brak dostępu” | 12, 13 |
| H5 | **Wyloguj** → `demo-modyfikacja` | **Hosty** → host | przyciski **Zapisz** (edycja wyników) są, formularza „Uruchom skan” na Pulpicie nie ma | 12, 13 |
| H6 | **Wyloguj** → `demo-operator` | **Pulpit**, **Cele** | może uruchamiać skany i dodawać cele, nie widzi **Użytkownicy** i **Audyt** | 12, 13 |

### I. Bezpieczeństwo danych i skanera

| # | Gdzie | Co zrobić | Oczekiwany wynik | Wymaganie |
|---|---|---|---|---|
| I1 | **Pulpit → Uruchom skan** | Cele: `8.8.8.8` → **Uruchom** | odmowa: cel poza dozwolonym zakresem - skaner nie wysyła pakietów poza `[scope]` | 2, bezpieczeństwo |
| I2 | **Hosty** → `127.0.0.1` → `8088/tcp` | sprawdź ciasteczka i nagłówek `set-cookie` | wartość ciasteczka sesji ukryta (`PHPSESSID=***`) - dane poufne | 16 |
| I3 | **Cele → Dodaj cel** | pole **Notatka** | opis pola: „zapisywana zaszyfrowana” - notatki, banery, nagłówki, ciasteczka, certyfikaty i surowe wyniki nmap są w bazie szyfrowane AES-256-GCM | 16 |

## 3. Podsumowanie: wymaganie → test

| Wymaganie zadania | Testy |
|---|---|
| 1. Lista IP, CIDR, domen | C1-C4 |
| 2. Bezpieczny skan, wielowątkowość, czas skanu, podgrupy | D1, D7, I1 |
| 3. Aktywne hosty | A4, D1, D7 |
| 4. Identyfikacja usług | A3, D2 |
| 5. Tytuł, kod HTTP, nagłówki, ciasteczka, TLS, przekierowania | D2, D3 |
| 6. CMS, framework, serwer, IoT | A4, D4 |
| 7. Staging, panel administracyjny | D4, D5 |
| 8. Porównanie przebiegów | A2, A3, D6 |
| 9. Nowe, znikające, zmienione usługi | A2, A3 |
| 10. Własne sygnatury | E1, E2 |
| 11. Formularz ręczny, CSV, JSON | C1-C4 |
| 12-13. RBAC i 4 role | H1-H6 |
| 14. Edycja trwała między skanami | B1, B4 |
| 15. Czytelny interfejs, dashboard znalezisk | A1, D5 |
| 16. Szyfrowanie danych wrażliwych | I2, I3 |
| Import wyników JSON/CSV, eksport | B3, G1, G2 |
| Ponad 10 000 IP | D7 |
| Okno czasowe, częstotliwość | F1, F2 |
| Ocena ciekawości, tagi, zmiany w czasie, pora dnia | A1, D5, B2, A5 |

Szczegóły techniczne (polecenia, kod źródłowy, testy automatyczne): `docs/hacknation-techniczny.md`.
