# dscan 0.1.0

DScan (Defect Scan): skanowanie i inwentaryzacja usług sieciowych

## `dscan serve`

Uruchamia serwer API (wykonuje też migracje bazy)

| Argument | Opis |
|---|---|
| `--listen` | Adres nasłuchiwania serwera, np. 127.0.0.1:8080 [server.listen] |
| `--max-rate` | Limit pakietów na sekundę dla nmap [limits.nmap_max_rate] |
| `--parallel` | Liczba równoległych procesów nmap [limits.max_parallel_nmap] |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan scan`

Skanuje podane cele programem nmap (tylko cele z [scope])

| Argument | Opis |
|---|---|
| `CEL` | Cele: adresy IP, sieci CIDR lub domeny. Skanowane są tylko cele z [scope] allowed_networks |
| `--profile` | Nazwany profil z [profiles] w dscan.toml (porty, tempo, okna, ponowienia…) |
| `--mode` | Rodzaj skanu (domyślnie z profilu albo `services`) |
| `--quiet` | Nie wypisuj listy hostów na końcu (tylko podsumowanie) |
| `--output` | Format wyniku na stdout (postęp idzie na stderr). Kod wyjścia: 0 — brak zmian, 2 — wykryto zmiany, 1 — błąd |
| `--dry-run` | Tylko plan: liczba adresów, podgrupy i szacowany czas — bez wysyłania pakietów (C8) |
| `--local` | Skan bezpośrednio z tej binarki (bez serwera i RBAC) — wymaga klucza szyfrowania i dostępu do bazy |
| `--listen` | Adres nasłuchiwania serwera, np. 127.0.0.1:8080 [server.listen] |
| `--max-rate` | Limit pakietów na sekundę dla nmap [limits.nmap_max_rate] |
| `--parallel` | Liczba równoległych procesów nmap [limits.max_parallel_nmap] |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan targets`

Zarządza listą celów skanowania

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan targets list`

Wyświetla cele zapisane w bazie (wymaga klucza szyfrowania — notatki są szyfrowane)

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan targets check`

Sprawdza cele bez skanowania: poprawność, DNS, duplikaty, zakres [scope]

| Argument | Opis |
|---|---|
| `CEL` |  |
| `--show` | Ile pierwszych adresów pokazać |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan targets add`

Dodaje cele (IP, CIDR, domeny) przez API — wymaga `dscan login`

| Argument | Opis |
|---|---|
| `CEL` |  |
| `--group` | Grupa, do której trafią cele |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan targets remove`

Usuwa cele (po wartości) przez API — wymaga `dscan login`

| Argument | Opis |
|---|---|
| `CEL` |  |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan import`

Importuje cele lub wyniki skanów z pliku

| Argument | Opis |
|---|---|
| `PLIK` | Plik do zaimportowania: cele (CSV z kolumną `target`, tablica JSON) albo wyniki (nmap XML, JSON z `dscan export hosts`, CSV z `dscan export services`) |
| `--kind` | Co zawiera plik |
| `--format` | Format pliku, jeśli nie wynika z rozszerzenia |
| `--dry-run` | Tylko sprawdza plik i pokazuje raport — nic nie zapisuje w bazie |
| `--local` | Zapis bezpośrednio do bazy (bez serwera i RBAC) — wymaga klucza szyfrowania |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan export`

Eksportuje hosty, usługi lub zmiany do pliku

| Argument | Opis |
|---|---|
| `SCOPE` | Co eksportować |
| `--format` | Format pliku |
| `-o, --output` | Plik wynikowy (domyślnie standardowe wyjście) |
| `--run` | Numer przebiegu (domyślnie ostatni zakończony) |
| `--port` | Tylko usługi na tym porcie |
| `--state` | Tylko usługi w tym stanie (open, closed, filtered) |
| `--technology` | Tylko usługi z technologią (fragment nazwy, np. wordpress) |
| `--edited` | Tylko wyniki z ręcznymi poprawkami (wymaga roli z results:write) |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan diff`

Porównuje dwa przebiegi skanu

| Argument | Opis |
|---|---|
| `PRZEBIEG_A` | Numer starszego przebiegu |
| `PRZEBIEG_B` | Numer nowszego przebiegu |
| `--output` | Format wyniku. Kod wyjścia: 0 — brak zmian, 2 — są zmiany, 1 — błąd |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan sig`

Zarządza sygnaturami technologii

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan sig list`

Wyświetla wbudowane sygnatury

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan sig test`

Sprawdza sygnaturę na adresie usługi WWW (tylko w zakresie [scope])

| Argument | Opis |
|---|---|
| `SYGNATURA` | Nazwa sygnatury (np. WordPress); „*” = wszystkie |
| `--host` | Adres usługi, np. http://10.0.0.5:80/ (host musi być adresem IP z [scope]) |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan user`

Zarządza użytkownikami

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan user create-admin`

Tworzy konto administratora bezpośrednio w bazie (wymaga klucza szyfrowania)

| Argument | Opis |
|---|---|
| `LOGIN` | Login: 3–64 znaki, małe litery a-z, cyfry oraz . _ - |
| `--password-stdin` | Czyta hasło z pierwszej linii standardowego wejścia (do skryptów) zamiast pytać w terminalu |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan user list`

Wyświetla użytkowników

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan config`

Wyświetla i sprawdza konfigurację

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan config show`

Wypisuje efektywną konfigurację (TOML) z ukrytymi sekretami

| Argument | Opis |
|---|---|
| `--listen` | Adres nasłuchiwania serwera, np. 127.0.0.1:8080 [server.listen] |
| `--max-rate` | Limit pakietów na sekundę dla nmap [limits.nmap_max_rate] |
| `--parallel` | Liczba równoległych procesów nmap [limits.max_parallel_nmap] |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan config validate`

Sprawdza konfigurację i wypisuje ostrzeżenia

| Argument | Opis |
|---|---|
| `--listen` | Adres nasłuchiwania serwera, np. 127.0.0.1:8080 [server.listen] |
| `--max-rate` | Limit pakietów na sekundę dla nmap [limits.nmap_max_rate] |
| `--parallel` | Liczba równoległych procesów nmap [limits.max_parallel_nmap] |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan config init`

Tworzy skomentowany dscan.toml ze wszystkimi parametrami

| Argument | Opis |
|---|---|
| `PLIK` | Ścieżka pliku |
| `--force` | Nadpisz istniejący plik |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan db`

Zarządza bazą danych (migracje)

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan db migrate`

Wykonuje zaległe migracje schematu bazy (wymaga klucza szyfrowania)

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan db status`

Pokazuje, które migracje są już zastosowane

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan keys`

Zarządza kluczami szyfrowania

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan keys rotate`

Przeszyfrowuje dane wrażliwe nowym kluczem

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan keys generate`

Wypisuje nowy losowy klucz (64 znaki hex)

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan docs`

Generuje dokumentację CLI (markdown albo strona man)

| Argument | Opis |
|---|---|
| `--format` |  |
| `-o, --output` | Plik wynikowy (domyślnie standardowe wyjście) |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan completions`

Wypisuje skrypt autouzupełniania dla powłoki (bash, zsh, fish…)

| Argument | Opis |
|---|---|
| `SHELL` | Powłoka: bash, zsh, fish, elvish, powershell |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan dojo`

Wysyła wyniki i obserwacje do DefectDojo

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan dojo import`

Wysyła surowe wyniki nmap przebiegu (parser „Nmap Scan”)

| Argument | Opis |
|---|---|
| `PRZEBIEG` |  |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan dojo export`

Wysyła wybrane obserwacje jako findingi informacyjne z dowodami

| Argument | Opis |
|---|---|
| `PRZEBIEG` |  |
| `--item` | Obserwacja `IP:PORT/PROTOKÓŁ=Technologia`, np. `10.0.0.5:8080/tcp=Jenkins` (można powtórzyć) |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan evaluate`

Mierzy trafność wykrywania względem wyników referencyjnych

| Argument | Opis |
|---|---|
| `PLIK` | Plik z wynikami referencyjnymi (.xml z nmap, .json, .csv) |
| `--run` | Przebiegi do oceny (można powtórzyć); domyślnie dwa ostatnie zakończone |
| `--details` | Pokaż listy pominiętych i nadmiarowych hostów i usług |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan login`

Loguje do serwera API i zapisuje token w pliku użytkownika

| Argument | Opis |
|---|---|
| `-u, --user` | Nazwa użytkownika |
| `--server` | Adres serwera (domyślnie z [server] listen w dscan.toml) |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan logout`

Wylogowuje i usuwa zapisany token

| Argument | Opis |
|---|---|
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan stop`

Wstrzymuje trwający skan na serwerze

| Argument | Opis |
|---|---|
| `PRZEBIEG` | Numer przebiegu |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

## `dscan resume`

Wznawia wstrzymany skan na serwerze

| Argument | Opis |
|---|---|
| `PRZEBIEG` | Numer przebiegu |
| `-c, --config` | Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje) |

