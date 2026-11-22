# DScan - instrukcja uruchomienia

## 1. Wymagania

| Element | Wersja |
|---|---|
| System | Linux (Ubuntu 22.04+ / Debian 12+), macOS 13+, Windows 10/11 z WSL2 |
| Rust + Cargo | ≥ 1.85 |
| Docker + Compose v2 | Docker 24+ |
| nmap | 7.80+ |
| Git, kompilator C | dowolne |
| Wolne miejsce | ok. 6 GB |

## 2. Instalacja automatyczna (Linux)

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan && ./install.sh
```

`install.sh` wykonuje kolejno, pokazując postęp każdego kroku:

1. sprawdzenie systemu i wolnego miejsca,
2. instalację brakujących narzędzi (Git, kompilator C, nmap, Docker, Rust),
3. weryfikację wersji i dostępu do Dockera,
4. utworzenie `dscan.toml` z `docs/konfiguracja/dscan.toml`,
5. kompilację z paskiem postępu i utworzenie `.env` z sekretami,
6. start PostgreSQL i serwera DScan (na czas logowania i importu demo),
7. logowanie administratora w CLI,
8. załadowanie danych demo, konta ról, ocenę trafności (`scripts/demo.sh`).

Na końcu wypisuje adres interfejsu WWW, login i hasło, a potem uruchamia serwer w tym samym terminalu
(jak `./run.sh`): terminal zostaje otwarty, widać logi serwera, `Ctrl+C` kończy. Log instalacji: `.dscan-install/install.log`.

| Opcja | Działanie |
|---|---|
| `--lab PLIK` | scenariusz laboratorium z archiwum `lab.zip` (rozdział 5a) |
| `--dojo` | lokalny DefectDojo (rozdział 6) |
| `--no-install` | tylko sprawdzenie narzędzi |
| `--no-demo` | bez danych demo |
| `--force-config` | zastąpienie istniejącego `dscan.toml` (kopia: `dscan.toml.bak`) |
| `--background` | serwer w tle, skrypt się kończy |
| `--stop` | zatrzymanie serwera uruchomionego z `--background` i bazy |

## 3. Uruchomienie przez run.sh

```bash
./run.sh
```

`run.sh` wypisuje każdy krok:

| Krok | Co robi |
|---|---|
| `[1/4] Konfiguracja` | tworzy `dscan.toml` i `.env` (klucz szyfrowania, hasło bazy, konto admina; uprawnienia 600) |
| `[2/4] Baza danych` | uruchamia PostgreSQL w Dockerze (`127.0.0.1:5433`) |
| `[3/4] Kompilacja` | buduje wersję release z postępem `Building N/M`; bez zmian w kodzie - pomija |
| `[4/4] Start serwera` | migracje, konto administratora, harmonogram; wypisuje adres WWW |

Serwer działa do `Ctrl+C`. Jeśli serwer już działa na porcie z `dscan.toml`, `run.sh` wypisuje jego adres.
Inne polecenia: `./run.sh <polecenie>` (np. `./run.sh scan 127.0.0.1`), lista: `./run.sh --help`.

Instalacja narzędzi ręcznie (Ubuntu / Debian):

```bash
sudo apt-get update && sudo apt-get install -y git curl build-essential pkg-config nmap ca-certificates
```

```bash
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker "$USER"
```

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source "$HOME/.cargo/env"
```

Po `usermod` wyloguj się i zaloguj ponownie. macOS: `xcode-select --install`, `brew install git nmap`,
Docker Desktop. Windows: `wsl --install -d Ubuntu`, Docker Desktop z *WSL integration*.

## 4. Logowanie i dane demo

| Cel | Polecenie |
|---|---|
| login i hasło | `grep -E '^DSCAN_ADMIN_(USERNAME\|PASSWORD)=' .env` |
| interfejs WWW | adres z `[server] listen` w `dscan.toml` (domyślnie http://127.0.0.1:9080/) |
| token CLI | `./run.sh login --user admin` |
| dane demo, konta ról, ocena, eksport | `scripts/demo.sh` (serwer musi działać) |
| demo + skan na żywo usług w Dockerze | `scripts/demo.sh --uslugi` (zatrzymanie: `scripts/demo.sh --stop`) |
| ręczny import demo | `./run.sh import --kind results docs/demo/przebieg-1.xml`, potem `przebieg-2.xml` |

Dane demo to dwa przebiegi ze zmianą (nowy SSH, inna wersja nginx, brak MySQL, nowa kamera).
Konta ról: `demo-operator`, `demo-modyfikacja`, `demo-odczyt`, hasło `DSCAN_DEMO_PASSWORD` w `.env`.
Sprawdzanie wymagań zadania krok po kroku: `hacknation.md`.
Widoki: **Pulpit**, **Hosty**, **Porównanie**, **W czasie**.

## 5. Laboratorium

```bash
unzip lab.zip -d ../lab && cd ../lab
```

### 5a. Znikająca usługa

| Polecenie | Wynik |
|---|---|
| `bash quickstart.sh up && ../DScan/run.sh scan 127.0.0.1` | porty 2223, 3001, 5673, 8787, 15673 |
| `bash quickstart.sh change && ../DScan/run.sh scan 127.0.0.1 --quiet` | `- 127.0.0.1:8787/tcp zniknęła`, kod 2 |
| `bash quickstart.sh up && ../DScan/run.sh scan 127.0.0.1 --quiet` | `+ 127.0.0.1:8787/tcp nowa`, kod 2 |
| `../DScan/run.sh scan 127.0.0.1 --quiet` | `brak zmian`, kod 0 |

Kody wyjścia: **0** brak zmian, **1** błąd, **2** zmiany. Skan hosta: ok. 1-2 min (sondy `nmap -sV`).

### 5b. Pozostałe stacki

Uruchamiaj po jednym (poprzedni: `down`). Nakładki dla hostów bez IPv6: `N=../DScan/docs/analiza-lab/nakladki-compose`.

| Stack | Uruchomienie |
|---|---|
| custom-network | `docker compose -f docker-compose-custom-network.yml up -d` |
| modern | `docker compose -f docker-compose-modern.yml -f $N/docker-compose-modern.ipv4.yml up -d` |
| vulnerable | `docker compose -f docker-compose-vulnerable.yml -f $N/docker-compose-vulnerable.ipv4.yml up -d` |
| modern-proxy | `cp -n .env.example .env`, w `.env`: `ENABLE_LATENCY=true`, `LATENCY_MS=500`, potem `docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d` |

Po ok. 60 s: `../DScan/run.sh scan 127.0.0.1`. Toxiproxy z Docker Hub: `-f $N/docker-compose-modern-proxy.dockerhub.yml`.

### 5c. Przydatne polecenia

| Polecenie | Wynik |
|---|---|
| `./run.sh scan 127.0.0.0/28 --dry-run` | plan skanu bez wysyłania pakietów |
| `./run.sh export services --format csv --technology wordpress` | eksport usług |
| `./run.sh diff 1 2` | porównanie przebiegów |
| `./run.sh evaluate docs/analiza-lab/wzorce/vulnerable.csv --details` | trafność względem wzorca |

## 6. DefectDojo

```bash
./scripts/defectdojo-setup.sh
```

W `dscan.toml` ustaw `[defectdojo] enabled = true` i uruchom serwer ponownie. `N` = numer przebiegu:

```bash
./run.sh dojo import N && ./run.sh dojo export N --item "127.0.0.1:8090/tcp=DVWA"
```

Panel: http://127.0.0.1:8180/ (login `admin`, hasło `DEFECTDOJO_ADMIN_PASSWORD` w `.env`).

## 7. Zatrzymanie

| Co | Polecenie |
|---|---|
| serwer (`install.sh`, `run.sh`) | `Ctrl+C` w jego terminalu, baza: `docker compose stop` |
| serwer w tle (`install.sh --background`) | `./install.sh --stop` |
| laboratorium | `docker compose -f <stack>.yml down` |
| DefectDojo | `./scripts/defectdojo-setup.sh stop` |

## 8. Problemy

| Objaw | Rozwiązanie |
|---|---|
| `permission denied` przy `docker` | wyloguj się i zaloguj po `usermod -aG docker` |
| `password authentication failed` | uruchamiaj przez `./run.sh` (synchronizuje hasło bazy z `.env`) |
| `brak ważnej sesji` | `./run.sh login --user admin` (token ważny 12 h) |
| `brak celów w dozwolonym zakresie` | cel spoza `[scope] allowed_networks` |
| `poza oknem czasowym` | usuń `[[schedule.windows]]` z `dscan.toml` albo skanuj w oknie |
| `address already in use` | zmień `[server] listen` w `dscan.toml` |
| port `tcpwrapped` | kontener nie wystartował - `docker compose logs`, nakładki z 5b |
