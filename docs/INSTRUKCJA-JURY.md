<p align="center">
  <img src="img/logo.png" alt="DScan — Smart Scanning" width="220">
</p>

# DScan — uruchomienie od zera (instrukcja dla jury)

Instrukcja prowadzi od czystego systemu do działającego skanera z danymi i przykładowymi skanami
laboratorium organizatorów. Każdy blok poleceń można skopiować w całości.

| Krok | Co robimy | Czas |
|---|---|---|
| [1](#1-wymagania) | Wymagania | — |
| [2](#2-instalacja-narzędzi) | Instalacja: Git, kompilator C, nmap, Docker, Rust | 10–15 min |
| [3](#3-pobranie-repozytorium) | Pobranie repozytorium | 1 min |
| [4](#4-konfiguracja-i-pierwsze-uruchomienie) | Konfiguracja i pierwsze uruchomienie (`./run.sh`) | 5–10 min (pierwsza kompilacja) |
| [5](#5-logowanie) | Logowanie (WWW i CLI) | 1 min |
| [6](#6-załadowanie-danych) | Załadowanie danych: cele i zapasowe wyniki demo | 2 min |
| [7](#7-przykładowe-skany-laboratorium-organizatorów) | Przykładowe skany laboratorium organizatorów | 10–20 min |
| [8](#8-opcjonalnie-defectdojo) | Opcjonalnie: DefectDojo | 10 min |
| [9](#9-zatrzymanie-i-sprzątanie) | Zatrzymanie i sprzątanie | 1 min |
| [10](#10-rozwiązywanie-problemów) | Rozwiązywanie problemów | — |

---

## 1. Wymagania

| Element | Wersja | Do czego |
|---|---|---|
| System | Linux (Ubuntu 22.04+/Debian 12+), macOS 13+, Windows 10/11 z **WSL2** | — |
| Git | dowolna | pobranie kodu |
| Kompilator C (`build-essential` / Xcode CLT) | dowolna | kompilacja biblioteki kryptograficznej |
| Rust + Cargo | **1.85 lub nowszy** (stable) | kompilacja DScan |
| Docker + Docker Compose v2 | Docker 24+ | baza PostgreSQL, laboratorium, DefectDojo |
| nmap | 7.80+ | skanowanie |
| Wolne miejsce | ok. 6 GB (obrazy laboratorium i kompilacja) | — |

DScan nie wymaga OpenSSL ani lokalnie zainstalowanego PostgreSQL — bazę uruchamia w Dockerze.

## 2. Instalacja narzędzi

### Ubuntu / Debian

```bash
sudo apt-get update && sudo apt-get install -y git curl build-essential pkg-config nmap ca-certificates
```

Docker (oficjalny skrypt instalacyjny Dockera; instaluje też wtyczkę Compose v2):

```bash
curl -fsSL https://get.docker.com | sudo sh
```

Uruchamianie Dockera bez `sudo` (po tym poleceniu **wyloguj się i zaloguj ponownie**):

```bash
sudo usermod -aG docker "$USER"
```

Rust (oficjalny instalator rustup, domyślne odpowiedzi):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source "$HOME/.cargo/env"
```

### macOS

Narzędzia Xcode (kompilator C) i [Homebrew](https://brew.sh):

```bash
xcode-select --install
```

```bash
brew install git nmap
```

Docker: zainstaluj i uruchom [Docker Desktop](https://www.docker.com/products/docker-desktop/).
Rust: to samo polecenie `rustup` co dla Linuksa (powyżej).

### Windows

1. W PowerShell jako administrator: `wsl --install -d Ubuntu`, potem restart.
2. Zainstaluj [Docker Desktop](https://www.docker.com/products/docker-desktop/) i włącz
   *Settings → Resources → WSL integration → Ubuntu*.
3. Dalsze kroki wykonuj w terminalu **Ubuntu (WSL)** według sekcji „Ubuntu / Debian” (bez instalacji Dockera).

### Sprawdzenie

```bash
git --version && cargo --version && docker --version && docker compose version && nmap --version | head -1
```

Wszystkie polecenia powinny wypisać wersje (`cargo` ≥ 1.85, `docker compose` v2).

## 3. Pobranie repozytorium

```bash
git clone https://github.com/Kapioner/DScan1.git DScan
```

```bash
cd DScan
```

## 4. Konfiguracja i pierwsze uruchomienie

Gotowa konfiguracja dla jury (zakres `127.0.0.1` i sieć danych demo, porty laboratorium, skanowanie
przez całą dobę, serwer na porcie **9080**, bo 8080/8081 zajmuje laboratorium):

```bash
cp docs/jury/dscan.toml dscan.toml
```

Start jedną komendą:

```bash
./run.sh
```

Skrypt przy pierwszym uruchomieniu:

1. tworzy `.env` z kluczem szyfrowania, hasłem bazy i kontem administratora (uprawnienia 600),
2. uruchamia PostgreSQL w Dockerze (`127.0.0.1:5433`) i ustawia mu hasło z `.env`,
3. kompiluje DScan w trybie release (**pierwsza kompilacja trwa kilka minut**, kolejne starty — sekundy),
4. uruchamia serwer: migracje bazy, konto administratora, harmonogram.

Gotowe, gdy w terminalu pojawi się:

```text
INFO DScan działa: http://127.0.0.1:9080/ (API: /api/v1, Ctrl+C kończy)
```

**Zostaw ten terminal otwarty** — kolejne kroki wykonuj w **drugim terminalu**, w katalogu `DScan`.

## 5. Logowanie

Login i hasło administratora (wygenerowane w kroku 4):

```bash
grep -E '^DSCAN_ADMIN_(USERNAME|PASSWORD)=' .env
```

**Przeglądarka:** <http://127.0.0.1:9080/> — zaloguj się tymi danymi.

**Wiersz poleceń** (polecenia `scan`, `import`, `export`, `diff` działają przez API, z tokenem):

```bash
./run.sh login --user admin
```

Wpisz hasło z `.env`. Token trafia do `~/.config/dscan/credentials.json` (uprawnienia 600).

## 6. Załadowanie danych

### 6a. Lista celów z pliku (CSV/JSON)

```bash
./run.sh import docs/examples/cele.csv --dry-run
```

Tryb próbny pokazuje poprawne i odrzucone wiersze z powodem. Cele można też dodać ręcznie:

```bash
./run.sh targets add 127.0.0.1 --group laboratorium
```

### 6b. Zapasowe wyniki demo (bez sieci laboratorium)

Dwa przebiegi z laboratorium ze zmianą między nimi (nowy port SSH, zmieniona wersja nginx,
zniknięta baza MySQL, dodatkowa kamera):

```bash
./run.sh import --kind results docs/demo/przebieg-1.xml
```

```bash
./run.sh import --kind results docs/demo/przebieg-2.xml
```

Drugi import wypisze zmiany względem pierwszego. Ocena trafności względem pliku referencyjnego:

```bash
./run.sh evaluate docs/demo/referencja.csv --details
```

Cały scenariusz demo z pauzami między krokami: `scripts/demo.sh`.

W przeglądarce zobacz teraz **Pulpit** (najciekawsze usługi z uzasadnieniem, zmiany, technologie),
**Hosty** (szczegóły, edycja wyników, tagi), **Porównanie** (dwa przebiegi z kolorami) i **W czasie**.

## 7. Przykładowe skany laboratorium organizatorów

Rozpakuj `lab.zip` od organizatorów **obok** katalogu `DScan` i przejdź do niego w drugim terminalu:

```bash
unzip lab.zip -d ../lab && cd ../lab
```

> Na hostach bez IPv6 (część maszyn wirtualnych i WSL) Nginx Proxy Manager i Adminer nie startują.
> Naprawiają to nakładki z repozytorium: `../DScan/docs/analiza-lab/nakladki-compose/` (użyte niżej).

### 7a. Scenariusz organizatorów: znikająca i powracająca usługa

```bash
bash quickstart.sh up
```

Skan 1 — oczekiwane porty 2223, 3001, 5673, 8787, 15673 (Gitea, RabbitMQ, nginx):

```bash
../DScan/run.sh scan 127.0.0.1
```

Zatrzymanie usługi HTTP na 8787 i skan 2 — DScan wypisze `- 127.0.0.1:8787/tcp zniknęła`, kod wyjścia 2:

```bash
bash quickstart.sh change && ../DScan/run.sh scan 127.0.0.1 --quiet; echo "kod wyjścia: $?"
```

Przywrócenie i skan 3 — `+ 127.0.0.1:8787/tcp nowa`:

```bash
bash quickstart.sh up && ../DScan/run.sh scan 127.0.0.1 --quiet; echo "kod wyjścia: $?"
```

Skan bez zmian — `brak zmian`, kod wyjścia 0:

```bash
../DScan/run.sh scan 127.0.0.1 --quiet; echo "kod wyjścia: $?"
```

Kody wyjścia (do skryptów i crona): **0** brak zmian, **1** błąd, **2** wykryto zmiany.
Jeden skan hosta trwa ok. 1–2 minut (tyle zajmują sondy wersji `nmap -sV`).

### 7b. Pozostałe stacki

Uruchamiaj po jednym stacku (zatrzymaj poprzedni). Każdy skan pokazuje zmiany względem poprzedniego.

Pełna sieć custom-network (dochodzą httpbin i PostgreSQL):

```bash
docker compose -f docker-compose-custom-network.yml up -d && sleep 30 && ../DScan/run.sh scan 127.0.0.1
```

Stack „modern” (WordPress, phpMyAdmin, Redis, Nginx Proxy Manager):

```bash
docker compose -f docker-compose-custom-network.yml down
```

```bash
docker compose -f docker-compose-modern.yml -f ../DScan/docs/analiza-lab/nakladki-compose/docker-compose-modern.ipv4.yml up -d && sleep 60 && ../DScan/run.sh scan 127.0.0.1
```

Stack „vulnerable” (stary WordPress 4.7, Adminer, DVWA, FTP) — zobacz na Pulpicie ranking najciekawszych usług:

```bash
docker compose -f docker-compose-modern.yml down
```

```bash
docker compose -f docker-compose-vulnerable.yml -f ../DScan/docs/analiza-lab/nakladki-compose/docker-compose-vulnerable.ipv4.yml up -d && sleep 60 && ../DScan/run.sh scan 127.0.0.1
```

Stack „modern-proxy” z opóźnieniem Toxiproxy (DScan pokazuje czas odpowiedzi usługi):

```bash
docker compose -f docker-compose-vulnerable.yml down && cp -n .env.example .env
```

```bash
sed -i 's/^ENABLE_LATENCY=.*/ENABLE_LATENCY=true/; s/^LATENCY_MS=.*/LATENCY_MS=500/' .env
```

```bash
docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d && sleep 60 && ../DScan/run.sh scan 127.0.0.1
```

> Jeśli obraz `ghcr.io/shopify/toxiproxy` nie daje się pobrać, dodaj
> `-f ../DScan/docs/analiza-lab/nakladki-compose/docker-compose-modern-proxy.dockerhub.yml`
> (ten sam program z Docker Hub).

### 7c. Inne przydatne polecenia

Plan skanu bez wysyłania pakietów (adresy, podgrupy, szacowany czas):

```bash
../DScan/run.sh scan 127.0.0.0/28 --dry-run
```

Eksport usług z technologią do CSV:

```bash
../DScan/run.sh export services --format csv --technology wordpress
```

Porównanie dwóch dowolnych przebiegów (numery z Pulpitu albo z wyniku skanu):

```bash
../DScan/run.sh diff 1 2
```

Ocena trafności względem wzorców dla stacków laboratorium:

```bash
../DScan/run.sh evaluate ../DScan/docs/analiza-lab/wzorce/vulnerable.csv --details
```

Pełna lista poleceń: [`cli.md`](cli.md) albo `./run.sh --help`.

## 8. Opcjonalnie: DefectDojo

W katalogu `DScan` (pierwszy start pobiera obrazy i wykonuje migracje — kilka minut):

```bash
./scripts/defectdojo-setup.sh
```

Skrypt zapisuje token API w `.env` (`DSCAN_DEFECTDOJO_TOKEN`). Włącz integrację w `dscan.toml`
(`[defectdojo] enabled = true`) i uruchom ponownie serwer (`Ctrl+C`, potem `./run.sh`).
Następnie wyślij przebieg ze skanu stacka „vulnerable” — `N` to numer z wyniku skanu
(„Przebieg #N”) albo z Pulpitu:

```bash
./run.sh dojo import N
```

```bash
./run.sh dojo export N --item "127.0.0.1:8090/tcp=DVWA" --item "127.0.0.1:8089/tcp=Adminer"
```

DefectDojo: <http://127.0.0.1:8180/> (login `admin`, hasło `DEFECTDOJO_ADMIN_PASSWORD` w `.env`).
Obserwacje można też zaznaczać w widoku hosta i wysyłać przyciskiem.

## 9. Zatrzymanie i sprzątanie

- Serwer DScan: `Ctrl+C` w pierwszym terminalu.
- Laboratorium (w katalogu `lab`): `docker compose -f <plik-stacka>.yml down`.
- Baza DScan: `docker compose stop` w katalogu `DScan` (dane zostają w wolumenie).
- DefectDojo: `./scripts/defectdojo-setup.sh stop`.

## 10. Rozwiązywanie problemów

| Objaw | Rozwiązanie |
|---|---|
| `permission denied` przy `docker` | Wyloguj się i zaloguj po `usermod -aG docker` (krok 2) albo użyj `sudo`. |
| `password authentication failed for user "dscan"` | Uruchamiaj przez `./run.sh` — skrypt synchronizuje hasło bazy z `.env`. |
| `brak ważnej sesji — zaloguj się` | `./run.sh login --user admin` (token wygasa po 12 h). |
| `brak celów w dozwolonym zakresie [scope]` | Cel spoza `allowed_networks` w `dscan.toml` — to zabezpieczenie, nie błąd. |
| `teraz jest poza oknem czasowym` | Używasz `dscan.example.toml` z oknem 22:00–06:00 — skopiuj `docs/jury/dscan.toml` (krok 4). |
| `address already in use` przy starcie | Port 9080 zajęty — zmień `[server] listen` w `dscan.toml`. |
| Port widoczny jako `tcpwrapped` | Kontener usługi nie wystartował (np. brak IPv6) — `docker compose logs`, nakładki z kroku 7. |
| Brak programu nmap | `sudo apt-get install nmap` / `brew install nmap`. |

Więcej: [`architektura.md`](architektura.md) (budowa i bezpieczeństwo),
[`analiza-skutecznosci.md`](analiza-skutecznosci.md) (wyniki na laboratorium organizatorów).
