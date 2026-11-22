# DScan - polecenia CLI

Uruchamianie: `./run.sh <polecenie>` (wczytuje `.env`). Opcja globalna: `-c, --config PLIK`.
**API** = wymaga serwera i `dscan login`; **lokalnie** = bezpośrednio na bazie.
Pełny opis generuje `dscan docs`.

## Serwer i sesja

| Polecenie | Opcje | Opis |
|---|---|---|
| `serve` | `--listen`, `--max-rate`, `--parallel` | WWW, API, harmonogram, migracje |
| `login` | `-u/--user`, `--server`, `--password-stdin` | token w `~/.config/dscan/credentials.json` (600) |
| `logout` | - | koniec sesji, usunięcie tokenu |

## Skanowanie (API)

| Polecenie | Opcje | Opis |
|---|---|---|
| `scan CEL…` | `--profile`, `--mode discovery\|services`, `--quiet`, `--output`, `--dry-run`, `--local`, `--max-rate`, `--parallel` | skan celów z `[scope]` |
| `stop N` / `resume N` | - | wstrzymanie / wznowienie przebiegu |
| `diff A B` | `--output` | porównanie dwóch przebiegów |

Kody wyjścia `scan` i `diff`: **0** brak zmian, **1** błąd, **2** zmiany.

## Dane

| Polecenie | Opcje | Opis |
|---|---|---|
| `import PLIK` | `--kind targets\|results`, `--format csv\|json\|nmap-xml`, `--dry-run`, `--local` | cele lub wyniki |
| `export hosts\|services\|changes` | `--format json\|csv`, `-o`, `--run`, `--port`, `--state`, `--technology`, `--edited` | eksport z filtrami |
| `evaluate PLIK` | `--run` (wielokrotnie), `--details` | precyzja, czułość, F1 względem referencji |
| `targets add CEL…` | `--group` | dodanie celów (API) |
| `targets remove CEL…` | - | usunięcie celów (API) |
| `targets check CEL…` | `--show N` | walidacja, DNS, zakres - bez skanu |
| `targets list` | - | cele w bazie (lokalnie) |

## Sygnatury i integracje

| Polecenie | Opcje | Opis |
|---|---|---|
| `sig list` | - | lista sygnatur |
| `sig test SYGNATURA` | `--host URL` | test na usłudze z zakresu (`*` = wszystkie) |
| `dojo import N` | - | surowy XML nmap do DefectDojo |
| `dojo export N` | `--item IP:PORT/PROTO=Technologia` | obserwacje jako findingi |

## Administracja (lokalnie)

| Polecenie | Opcje | Opis |
|---|---|---|
| `user create-admin LOGIN` | `--password-stdin` | konto administratora |
| `user list` | - | użytkownicy |
| `keys generate` | - | nowy klucz (64 hex) |
| `keys rotate` | - | przeszyfrowanie jednym ruchem (`DSCAN_NEW_ENCRYPTION_KEY`) |
| `keys reencrypt` | `--batch` | rotacja stopniowa, partiami |
| `keys status` | - | liczba rekordów na klucz |
| `config show\|validate` | `--listen`, `--max-rate`, `--parallel` | efektywna konfiguracja, ostrzeżenia |
| `config init PLIK` | `--force` | skomentowany `dscan.toml` |
| `db migrate\|status` | - | migracje |
| `docs` | `--format`, `-o` | dokumentacja (markdown / man) |
| `completions SHELL` | - | autouzupełnianie: bash, zsh, fish, elvish, powershell |
