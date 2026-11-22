# DScan — instrukcja dla jury

Od czystego systemu do działającego skanera z danymi demo i skanami laboratorium.

## 1. Wymagania

| Element | Wersja |
|---|---|
| System | Ubuntu 22.04+ / Debian 12+, macOS 13+, Windows 10/11 z WSL2 |
| Rust + Cargo | ≥ 1.85 |
| Docker + Compose v2 | Docker 24+ |
| nmap | 7.80+ |
| Git, kompilator C | dowolne |
| Wolne miejsce | ok. 6 GB |

## 2. Instalacja automatyczna (zalecana)

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan && ./install.sh
```

Skrypt instaluje brakujące narzędzia, kompiluje DScan, uruchamia bazę i serwer w tle, loguje
administratora i ładuje dane demo. Na końcu wypisuje adres **http://127.0.0.1:9080/**, login i hasło.

| Opcja | Działanie |
|---|---|
| `--lab ../lab.zip` | dodatkowo scenariusz laboratorium (krok 5a) |
| `--dojo` | dodatkowo DefectDojo (krok 6) |
| `--stop` | zatrzymanie serwera i bazy |

Po `./install.sh` przejdź od razu do kroku 5.

## 3. Instalacja ręczna

Ubuntu / Debian:

```bash
sudo apt-get update && sudo apt-get install -y git curl build-essential pkg-config nmap ca-certificates
```

```bash
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker "$USER"
```

Wyloguj się i zaloguj ponownie (grupa `docker`), potem Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source "$HOME/.cargo/env"
```

- **macOS:** `xcode-select --install`, `brew install git nmap`, Docker Desktop, Rust jak wyżej.
- **Windows:** `wsl --install -d Ubuntu`, Docker Desktop z *WSL integration*, dalej jak Ubuntu (bez Dockera).

## 4. Uruchomienie ręczne

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan && cp docs/jury/dscan.toml dscan.toml
```

```bash
./run.sh
```

Pierwsza kompilacja trwa kilka minut. Gotowe przy komunikacie
`DScan działa: http://127.0.0.1:9080/`. Terminal zostaw otwarty, dalej pracuj w drugim.

Login i hasło administratora:

```bash
grep -E '^DSCAN_ADMIN_(USERNAME|PASSWORD)=' .env
```

```bash
./run.sh login --user admin
```

Dane demo (dwa przebiegi ze zmianą: nowy SSH, inna wersja nginx, brak MySQL, nowa kamera):

```bash
./run.sh import --kind results docs/demo/przebieg-1.xml && ./run.sh import --kind results docs/demo/przebieg-2.xml
```

```bash
./run.sh evaluate docs/demo/referencja.csv --details
```

W przeglądarce: **Pulpit**, **Hosty**, **Porównanie**, **W czasie**.

## 5. Laboratorium organizatorów

```bash
unzip lab.zip -d ../lab && cd ../lab
```

### 5a. Znikająca usługa (quickstart)

| Polecenie | Oczekiwany wynik |
|---|---|
| `bash quickstart.sh up && ../DScan/run.sh scan 127.0.0.1` | porty 2223, 3001, 5673, 8787, 15673 |
| `bash quickstart.sh change && ../DScan/run.sh scan 127.0.0.1 --quiet` | `- 127.0.0.1:8787/tcp zniknęła`, kod 2 |
| `bash quickstart.sh up && ../DScan/run.sh scan 127.0.0.1 --quiet` | `+ 127.0.0.1:8787/tcp nowa`, kod 2 |
| `../DScan/run.sh scan 127.0.0.1 --quiet` | `brak zmian`, kod 0 |

Kody wyjścia: **0** brak zmian, **1** błąd, **2** zmiany. Skan hosta: ok. 1–2 min (sondy `nmap -sV`).

### 5b. Pozostałe stacki (po jednym, poprzedni zatrzymaj `down`)

Nakładki dla hostów bez IPv6: `N=../DScan/docs/analiza-lab/nakladki-compose`.

| Stack | Uruchomienie |
|---|---|
| custom-network | `docker compose -f docker-compose-custom-network.yml up -d` |
| modern | `docker compose -f docker-compose-modern.yml -f $N/docker-compose-modern.ipv4.yml up -d` |
| vulnerable | `docker compose -f docker-compose-vulnerable.yml -f $N/docker-compose-vulnerable.ipv4.yml up -d` |
| modern-proxy | `cp -n .env.example .env`, w `.env`: `ENABLE_LATENCY=true`, `LATENCY_MS=500`, potem `docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d` |

Po starcie (ok. 60 s): `../DScan/run.sh scan 127.0.0.1`. Toxiproxy z Docker Hub zamiast ghcr.io:
dodaj `-f $N/docker-compose-modern-proxy.dockerhub.yml`.

### 5c. Przydatne polecenia

| Polecenie | Wynik |
|---|---|
| `../DScan/run.sh scan 127.0.0.0/28 --dry-run` | plan skanu bez wysyłania pakietów |
| `../DScan/run.sh export services --format csv --technology wordpress` | eksport usług |
| `../DScan/run.sh diff 1 2` | porównanie przebiegów |
| `../DScan/run.sh evaluate ../DScan/docs/analiza-lab/wzorce/vulnerable.csv --details` | trafność względem wzorca |

## 6. DefectDojo (opcjonalnie)

```bash
./scripts/defectdojo-setup.sh
```

Ustaw `[defectdojo] enabled = true` w `dscan.toml`, zrestartuj `./run.sh`. `N` = numer przebiegu:

```bash
./run.sh dojo import N && ./run.sh dojo export N --item "127.0.0.1:8090/tcp=DVWA"
```

Panel: http://127.0.0.1:8180/ (login `admin`, hasło `DEFECTDOJO_ADMIN_PASSWORD` w `.env`).

## 7. Zatrzymanie

| Co | Polecenie |
|---|---|
| Serwer i baza (po `install.sh`) | `./install.sh --stop` |
| Serwer (po `./run.sh`) | `Ctrl+C`, potem `docker compose stop` |
| Laboratorium | `docker compose -f <stack>.yml down` |
| DefectDojo | `./scripts/defectdojo-setup.sh stop` |

## 8. Problemy

| Objaw | Rozwiązanie |
|---|---|
| `permission denied` przy `docker` | wyloguj się i zaloguj po `usermod -aG docker` |
| `password authentication failed` | uruchamiaj przez `./run.sh` (synchronizuje hasło bazy) |
| `brak ważnej sesji` | `./run.sh login --user admin` (token ważny 12 h) |
| `brak celów w dozwolonym zakresie` | cel spoza `[scope] allowed_networks` — zabezpieczenie |
| `poza oknem czasowym` | skopiuj `docs/jury/dscan.toml` (bez okien czasowych) |
| `address already in use` | zmień `[server] listen` w `dscan.toml` |
| port `tcpwrapped` | kontener nie wystartował — `docker compose logs`, nakładki z 5b |
