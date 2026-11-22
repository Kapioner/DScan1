#!/usr/bin/env bash
# DScan - automatyczna instalacja i uruchomienie (kroki opisane w docs/uruchomienie.md).
#
#   ./install.sh                 instalacja narzędzi, kompilacja, start serwera, logowanie, dane demo
#   ./install.sh --lab lab.zip   dodatkowo scenariusz laboratorium (znikająca i powracająca usługa)
#   ./install.sh --dojo          dodatkowo lokalny DefectDojo
#   ./install.sh --stop          zatrzymanie serwera DScan i bazy
#   ./install.sh --help          wszystkie opcje
#
# Skrypt jest idempotentny: ponowne uruchomienie pomija to, co już zrobione.
# Szczegółowy log każdego kroku: .dscan-install/install.log
set -euo pipefail

cd "$(dirname "$0")"
REPO_DIR="$(pwd)"

STATE_DIR=".dscan-install"
LOG_FILE="$STATE_DIR/install.log"
SERVER_LOG="$STATE_DIR/server.log"
PID_FILE="$STATE_DIR/server.pid"
MIN_RUST="1.85"

# --- opcje ----------------------------------------------------------------------------------

OPT_INSTALL=1
OPT_DEMO=1
OPT_LAB=""
OPT_DOJO=0
OPT_FORCE_CONFIG=0
OPT_STOP=0

usage() {
    cat << 'EOF'
Użycie: ./install.sh [opcje]

  --lab PLIK|KATALOG   uruchom scenariusz laboratorium (lab.zip albo rozpakowany katalog)
  --dojo               uruchom lokalny DefectDojo i włącz integrację
  --no-install         nie instaluj pakietów systemowych (tylko sprawdź, czy są)
  --no-demo            nie ładuj zapasowych danych demo
  --force-config       zastąp istniejący dscan.toml konfiguracją lokalną (kopia: dscan.toml.bak)
  --stop               zatrzymaj serwer DScan uruchomiony przez ten skrypt oraz bazę
  -h, --help           ta pomoc
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --lab) OPT_LAB="${2:?--lab wymaga ścieżki do lab.zip albo katalogu}"; shift ;;
        --dojo) OPT_DOJO=1 ;;
        --no-install) OPT_INSTALL=0 ;;
        --no-demo) OPT_DEMO=0 ;;
        --force-config) OPT_FORCE_CONFIG=1 ;;
        --stop) OPT_STOP=1 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "Nieznana opcja: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

mkdir -p "$STATE_DIR"
: >> "$LOG_FILE"

# --- wygląd i postęp ------------------------------------------------------------------------

if [ -t 1 ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
    TTY=1
else
    B=""; DIM=""; R=""; G=""; Y=""; C=""; N=""
    TTY=0
fi

SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
STEP=0
TOTAL_STEPS=8
[ -n "$OPT_LAB" ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[ "$OPT_DOJO" = 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
START_TIME=$(date +%s)

bar() { # bar PROCENT SZEROKOŚĆ
    local pct=$1 width=$2 filled i out=""
    filled=$((pct * width / 100))
    for ((i = 0; i < filled; i++)); do out+="█"; done
    out+="$DIM"
    for ((i = filled; i < width; i++)); do out+="░"; done
    printf '%s%s%s' "$G" "$out" "$N"
}

step() {
    STEP=$((STEP + 1))
    local pct=$(((STEP - 1) * 100 / TOTAL_STEPS))
    printf '\n%s[%d/%d]%s %s %3d%%  %s%s%s\n' "$B$C" "$STEP" "$TOTAL_STEPS" "$N" "$(bar "$pct" 24)" "$pct" "$B" "$*" "$N"
    printf '\n===== [%d/%d] %s (%s) =====\n' "$STEP" "$TOTAL_STEPS" "$*" "$(date '+%F %T')" >> "$LOG_FILE"
}

ok() { printf '      %s✔%s %s\n' "$G" "$N" "$*"; }
info() { printf '      %s•%s %s\n' "$C" "$N" "$*"; }
warn() { printf '      %s!%s %s\n' "$Y" "$N" "$*"; }
fail() {
    printf '\n      %s✘ %s%s\n' "$R$B" "$*" "$N" >&2
    printf '      Szczegóły: %s\n' "$LOG_FILE" >&2
    exit 1
}

elapsed() { # elapsed START → "1 min 05 s"
    local s=$(($(date +%s) - $1))
    if [ "$s" -ge 60 ]; then printf '%d min %02d s' $((s / 60)) $((s % 60)); else printf '%d s' "$s"; fi
}

# run "opis" polecenie… - wykonuje polecenie z animacją, wyjście trafia do logu.
run() {
    local label="$1"; shift
    local started pid code=0 i=0
    started=$(date +%s)
    echo "\$ $*" >> "$LOG_FILE"
    if [ "$TTY" = 1 ]; then
        "$@" >> "$LOG_FILE" 2>&1 < /dev/null &
        pid=$!
        while kill -0 "$pid" 2> /dev/null; do
            printf '\r      %s%s%s %s %s(%s)%s ' "$C" "${SPIN[i++ % ${#SPIN[@]}]}" "$N" "$label" "$DIM" "$(elapsed "$started")" "$N"
            sleep 0.1
        done
        wait "$pid" || code=$?
        printf '\r\033[K'
    else
        "$@" >> "$LOG_FILE" 2>&1 < /dev/null || code=$?
    fi
    if [ "$code" -ne 0 ]; then
        printf '      %s✘%s %s (kod %d)\n' "$R" "$N" "$label" "$code"
        echo "      --- ostatnie linie logu ---"
        tail -n 20 "$LOG_FILE" | sed 's/^/      │ /'
        fail "Krok nie powiódł się: $label"
    fi
    ok "$label ${DIM}($(elapsed "$started"))${N}"
}

# --- pomocnicze -----------------------------------------------------------------------------

have() { command -v "$1" > /dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

version_ge() { # version_ge 1.86.0 1.85 → prawda
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

env_value() { # env_value NAZWA → wartość z .env
    sed -n "s/^$1=//p" .env 2> /dev/null | tail -n1
}

server_port() {
    local listen
    listen="$(sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' dscan.toml 2> /dev/null | head -n1)"
    echo "${listen##*:}"
}

health_ok() {
    curl -fsS --max-time 2 "http://127.0.0.1:$(server_port)/api/v1/health" > /dev/null 2>&1
}

# Liczba przebiegów profilu (domyślnie „import”) na serwerze (przez API, z tokenem zapisanym przez `dscan login`).
server_run_count() {
    local creds token
    creds="${DSCAN_CREDENTIALS:-${XDG_CONFIG_HOME:-$HOME/.config}/dscan/credentials.json}"
    token="$(sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' "$creds" 2> /dev/null | head -n1)"
    curl -fsS --max-time 5 -H "Authorization: Bearer $token" \
        "http://127.0.0.1:$(server_port)/api/v1/scans?limit=100" 2> /dev/null \
        | grep -o "\"profile\":\"${1:-import}\"" | wc -l | tr -d ' '
}

OS="unknown"
detect_os() {
    case "$(uname -s)" in
        Darwin) OS="macos" ;;
        Linux)
            if grep -qi microsoft /proc/version 2> /dev/null; then OS="wsl"; else OS="linux"; fi
            ;;
    esac
}

# --- zatrzymanie ----------------------------------------------------------------------------

stop_all() {
    echo "${B}Zatrzymywanie DScan${N}"
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2> /dev/null; then
        kill -INT "$(cat "$PID_FILE")" 2> /dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$(cat "$PID_FILE")" 2> /dev/null || break
            sleep 0.2
        done
        kill -TERM "$(cat "$PID_FILE")" 2> /dev/null || true
        ok "Serwer DScan zatrzymany"
    else
        info "Serwer DScan uruchomiony przez install.sh nie działa"
    fi
    rm -f "$PID_FILE"
    if have docker; then
        docker compose stop > /dev/null 2>&1 && ok "Baza PostgreSQL zatrzymana (dane zostają w wolumenie)" || true
    fi
    if [ "$OPT_DOJO" = 1 ]; then
        ./scripts/defectdojo-setup.sh stop || true
    fi
}

if [ "$OPT_STOP" = 1 ]; then
    stop_all
    exit 0
fi

# --- start ----------------------------------------------------------------------------------

detect_os
cat << EOF

${B}  ____  ____                  ${N}
${B} |  _ \\/ ___|  ___ __ _ _ __  ${N}   ${B}DScan - instalacja i uruchomienie${N}
${B} | | | \\___ \\ / __/ _\` | '_ \\ ${N}   system: ${OS}, katalog: ${REPO_DIR}
${B} | |_| |___) | (_| (_| | | | |${N}   log: ${LOG_FILE}
${B} |____/|____/ \\___\\__,_|_| |_|${N}
EOF

# ===== 1. Wymagania ==========================================================================
step "Sprawdzenie systemu"

case "$OS" in
    linux | wsl) ok "System: $(. /etc/os-release 2> /dev/null && echo "${PRETTY_NAME:-Linux}" || echo Linux)" ;;
    macos) ok "System: macOS $(sw_vers -productVersion 2> /dev/null || true)" ;;
    *) fail "Nieobsługiwany system $(uname -s). Na Windows uruchom skrypt w WSL2 (Ubuntu)." ;;
esac
[ "$OS" = wsl ] && info "WSL wykryty - Docker powinien pochodzić z Docker Desktop (WSL integration)."

free_kb=$(df -Pk . | awk 'NR == 2 {print $4}')
if [ "${free_kb:-0}" -lt $((6 * 1024 * 1024)) ]; then
    warn "Wolne miejsce: $((free_kb / 1024 / 1024)) GB - zalecane ok. 6 GB (kompilacja i obrazy)."
else
    ok "Wolne miejsce: $((free_kb / 1024 / 1024)) GB"
fi
if [ -n "$SUDO" ] && ! have sudo; then
    fail "Brak sudo - uruchom skrypt jako root albo zainstaluj sudo."
fi

# ===== 2. Instalacja narzędzi ================================================================
step "Instalacja narzędzi (Git, kompilator C, nmap, Docker, Rust)"

install_linux_packages() {
    local missing=()
    have git || missing+=(git)
    have curl || missing+=(curl)
    have cc || missing+=(build-essential)
    have pkg-config || missing+=(pkg-config)
    have nmap || missing+=(nmap)
    have unzip || missing+=(unzip)
    [ -f /etc/ssl/certs/ca-certificates.crt ] || missing+=(ca-certificates)
    if [ "${#missing[@]}" -eq 0 ]; then
        ok "Pakiety systemowe już zainstalowane"
        return
    fi
    have apt-get || fail "Brak apt-get. Zainstaluj ręcznie: ${missing[*]} (instrukcja: docs/uruchomienie.md)."
    [ "$OPT_INSTALL" = 1 ] || fail "Brakuje: ${missing[*]} (uruchom bez --no-install)."
    [ -n "$SUDO" ] && info "Może pojawić się pytanie o hasło sudo."
    $SUDO true
    run "apt-get update" $SUDO apt-get update
    run "Instalacja: ${missing[*]}" $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

install_docker_linux() {
    if have docker; then
        ok "Docker: $(docker --version 2> /dev/null | sed 's/Docker version //')"
    else
        [ "$OS" = wsl ] && fail "Brak Dockera w WSL. Zainstaluj Docker Desktop i włącz Settings → Resources → WSL integration → Ubuntu."
        [ "$OPT_INSTALL" = 1 ] || fail "Brak Dockera (uruchom bez --no-install)."
        local installer="$STATE_DIR/get-docker.sh"
        run "Pobranie instalatora Dockera" curl -fsSL https://get.docker.com -o "$installer"
        run "Instalacja Dockera (get.docker.com)" $SUDO sh "$installer"
        rm -f "$installer"
    fi
    if ! docker compose version > /dev/null 2>&1 && ! $SUDO docker compose version > /dev/null 2>&1; then
        [ "$OPT_INSTALL" = 1 ] || fail "Brak Docker Compose v2."
        run "Instalacja Docker Compose v2" bash -c "$SUDO apt-get install -y docker-compose-plugin || $SUDO apt-get install -y docker-compose-v2"
    fi
    # Usługa Dockera (systemd) - w WSL i kontenerach może jej nie być.
    if [ "$OPT_INSTALL" = 1 ] && ! $SUDO docker info > /dev/null 2>&1; then
        info "Uruchamiam usługę Dockera…"
        { $SUDO systemctl enable --now docker || $SUDO service docker start; } >> "$LOG_FILE" 2>&1 \
            || warn "Nie udało się uruchomić usługi Dockera automatycznie (sprawdzę w kroku 3)."
    fi
}

install_macos() {
    if ! xcode-select -p > /dev/null 2>&1; then
        xcode-select --install || true
        fail "Zainstaluj narzędzia Xcode (otwarte okno instalatora) i uruchom ./install.sh ponownie."
    fi
    ok "Narzędzia Xcode (kompilator C)"
    have brew || fail "Brak Homebrew - zainstaluj ze strony https://brew.sh i uruchom ponownie."
    local missing=()
    have git || missing+=(git)
    have nmap || missing+=(nmap)
    if [ "${#missing[@]}" -gt 0 ]; then
        [ "$OPT_INSTALL" = 1 ] || fail "Brakuje: ${missing[*]}."
        run "brew install ${missing[*]}" brew install "${missing[@]}"
    else
        ok "git i nmap już zainstalowane"
    fi
    have docker || fail "Brak Dockera - zainstaluj i uruchom Docker Desktop: https://www.docker.com/products/docker-desktop/"
    ok "Docker: $(docker --version | sed 's/Docker version //')"
}

install_rust() {
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    if have cargo; then
        local current
        current="$(rustc --version | awk '{print $2}')"
        if version_ge "$current" "$MIN_RUST"; then
            ok "Rust $current"
            return
        fi
        have rustup || fail "Rust $current jest starszy niż $MIN_RUST, a rustup nie jest dostępny - zaktualizuj Rust."
        run "Aktualizacja Rust ($current → stable)" rustup update stable
        rustup default stable >> "$LOG_FILE" 2>&1
    else
        [ "$OPT_INSTALL" = 1 ] || fail "Brak Rust/Cargo (uruchom bez --no-install)."
        local installer="$STATE_DIR/rustup-init.sh"
        run "Pobranie instalatora rustup" curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$installer"
        run "Instalacja Rust (rustup, stable)" sh "$installer" -y --profile minimal
        rm -f "$installer"
        . "$HOME/.cargo/env"
    fi
    ok "Rust $(rustc --version | awk '{print $2}')"
}

case "$OS" in
    linux | wsl)
        install_linux_packages
        install_docker_linux
        ;;
    macos) install_macos ;;
esac
install_rust

# ===== 3. Weryfikacja ========================================================================
step "Weryfikacja narzędzi i dostępu do Dockera"

for tool in git cargo nmap docker curl; do
    have "$tool" || fail "Brak programu: $tool"
done
ok "git $(git --version | awk '{print $3}'), cargo $(cargo --version | awk '{print $2}'), $(nmap --version | head -n1 | awk '{print "nmap", $3}')"

if ! docker info > /dev/null 2>&1; then
    if [ "$OS" != macos ] && $SUDO docker info > /dev/null 2>&1; then
        # Docker działa, ale bieżący użytkownik nie jest w grupie docker.
        if ! id -nG "$USER" | grep -qw docker; then
            run "Dodanie użytkownika $USER do grupy docker" $SUDO usermod -aG docker "$USER"
        fi
        if [ -z "${DSCAN_INSTALL_REEXEC:-}" ] && have sg; then
            info "Ponowne uruchomienie skryptu z grupą docker (bez wylogowania)…"
            export DSCAN_INSTALL_REEXEC=1
            args=()
            [ -n "$OPT_LAB" ] && args+=(--lab "$OPT_LAB")
            [ "$OPT_DOJO" = 1 ] && args+=(--dojo)
            [ "$OPT_DEMO" = 0 ] && args+=(--no-demo)
            [ "$OPT_FORCE_CONFIG" = 1 ] && args+=(--force-config)
            exec sg docker -c "$(printf '%q ' "$REPO_DIR/install.sh" --no-install "${args[@]}")"
        fi
        fail "Brak uprawnień do Dockera. Wyloguj się i zaloguj ponownie (grupa docker), potem uruchom ./install.sh."
    fi
    fail "Docker nie odpowiada - uruchom Docker Desktop / usługę docker i spróbuj ponownie."
fi
docker compose version > /dev/null 2>&1 || fail "Brak Docker Compose v2 (polecenie 'docker compose')."
ok "Docker działa, $(docker compose version --short 2> /dev/null | sed 's/^/Compose v/')"

# ===== 4. Konfiguracja =======================================================================
step "Konfiguracja (dscan.toml i .env z sekretami)"

if [ ! -f dscan.toml ]; then
    cp docs/konfiguracja/dscan.toml dscan.toml
    ok "Utworzono dscan.toml z docs/konfiguracja/dscan.toml (zakres 127.0.0.0/8 i 172.20.0.0/24)"
elif [ "$OPT_FORCE_CONFIG" = 1 ] || cmp -s dscan.toml dscan.example.toml; then
    # Niezmieniony plik przykładowy ma okno skanowania 22:00-06:00 i zakres tylko 172.20.0.0/24.
    cp dscan.toml dscan.toml.bak
    cp docs/konfiguracja/dscan.toml dscan.toml
    ok "Zastąpiono dscan.toml konfiguracją lokalną (poprzedni plik: dscan.toml.bak)"
else
    ok "Używam istniejącego dscan.toml (konfiguracja lokalna: --force-config)"
fi
PORT="$(server_port)"
[ -n "$PORT" ] || fail "Nie znaleziono [server] listen w dscan.toml."
ok "Serwer będzie nasłuchiwał na porcie $PORT"

# ===== 5. Kompilacja =========================================================================
step "Kompilacja DScan (release - pierwsza trwa kilka minut)"

compile() {
    local total done_count pct started code=0 pid line
    total=$(grep -c '^name = ' Cargo.lock || echo 400)
    started=$(date +%s)
    echo "\$ cargo build --release -p dscan" >> "$LOG_FILE"
    cargo build --release -p dscan --color never > "$STATE_DIR/build.log" 2>&1 < /dev/null &
    pid=$!
    while kill -0 "$pid" 2> /dev/null; do
        if [ "$TTY" = 1 ]; then
            done_count=$(grep -c '^ *Compiling ' "$STATE_DIR/build.log" 2> /dev/null || true)
            pct=$((done_count * 100 / total))
            [ "$pct" -gt 99 ] && pct=99
            line="$(grep '^ *Compiling ' "$STATE_DIR/build.log" 2> /dev/null | tail -n1 | awk '{print $2}')"
            printf '\r\033[K      %s %3d%%  %s%s · %s%s' "$(bar "$pct" 30)" "$pct" "$DIM" "$(elapsed "$started")" "${line:-przygotowanie…}" "$N"
        fi
        sleep 0.5
    done
    wait "$pid" || code=$?
    [ "$TTY" = 1 ] && printf '\r\033[K'
    cat "$STATE_DIR/build.log" >> "$LOG_FILE"
    if [ "$code" -ne 0 ]; then
        tail -n 25 "$STATE_DIR/build.log" | sed 's/^/      │ /'
        fail "Kompilacja nie powiodła się."
    fi
    ok "Zbudowano target/release/dscan ${DIM}($(elapsed "$started"))${N}"
}
compile
# run.sh tworzy .env (klucz szyfrowania, hasło bazy, konto administratora) przy pierwszym wywołaniu.
run "Utworzenie .env i sprawdzenie konfiguracji" ./run.sh config validate
ok "Sekrety w .env (uprawnienia 600) - zrób kopię zapasową, zawiera jedyny klucz szyfrowania"

# ===== 6. Baza i serwer ======================================================================
step "Uruchomienie bazy PostgreSQL i serwera DScan"

start_server() {
    if health_ok; then
        ok "Serwer już działa na http://127.0.0.1:$PORT/"
        return
    fi
    run "Start PostgreSQL w Dockerze (127.0.0.1:5433)" ./run.sh db status
    echo "===== start serwera $(date '+%F %T') =====" >> "$SERVER_LOG"
    if have setsid; then
        setsid nohup ./run.sh serve >> "$SERVER_LOG" 2>&1 < /dev/null &
    else
        nohup ./run.sh serve >> "$SERVER_LOG" 2>&1 < /dev/null &
    fi
    echo $! > "$PID_FILE"
    local started i=0
    started=$(date +%s)
    until health_ok; do
        kill -0 "$(cat "$PID_FILE")" 2> /dev/null || {
            tail -n 20 "$SERVER_LOG" | sed 's/^/      │ /'
            fail "Serwer zakończył działanie - log: $SERVER_LOG"
        }
        [ $(($(date +%s) - started)) -gt 180 ] && fail "Serwer nie odpowiada po 3 min - log: $SERVER_LOG"
        [ "$TTY" = 1 ] && printf '\r      %s%s%s Oczekiwanie na serwer %s(%s)%s ' "$C" "${SPIN[i++ % ${#SPIN[@]}]}" "$N" "$DIM" "$(elapsed "$started")" "$N"
        sleep 0.3
    done
    [ "$TTY" = 1 ] && printf '\r\033[K'
    ok "Serwer działa: http://127.0.0.1:$PORT/ (PID $(cat "$PID_FILE"), log: $SERVER_LOG)"
}
start_server

# ===== 7. Logowanie ==========================================================================
step "Logowanie administratora (CLI)"

ADMIN_USER="$(env_value DSCAN_ADMIN_USERNAME)"
ADMIN_PASS="$(env_value DSCAN_ADMIN_PASSWORD)"
ADMIN_USER="${ADMIN_USER:-admin}"
[ -n "$ADMIN_PASS" ] || fail "Brak DSCAN_ADMIN_PASSWORD w .env."
login_admin() {
    printf '%s\n' "$ADMIN_PASS" | ./run.sh login --user "$ADMIN_USER" --password-stdin \
        --server "http://127.0.0.1:$PORT"
}
run "Logowanie jako $ADMIN_USER (token w ~/.config/dscan/credentials.json)" login_admin

# ===== 8. Dane ===============================================================================
step "Załadowanie danych (cele i zapasowe wyniki demo)"

run "Sprawdzenie listy celów docs/examples/cele.csv (--dry-run)" ./run.sh import docs/examples/cele.csv --dry-run
if ./run.sh targets add 127.0.0.1 --group laboratorium >> "$LOG_FILE" 2>&1; then
    ok "Dodano cel 127.0.0.1 (grupa laboratorium)"
else
    info "Cel 127.0.0.1 już istnieje"
fi
if [ "$OPT_DEMO" = 0 ]; then
    info "Pominięto dane demo (--no-demo)"
elif [ "$(server_run_count)" -gt 0 ]; then
    ok "Dane demo już są na serwerze (przebiegi importu: $(server_run_count))"
else
    import_first() { ./run.sh import --kind results docs/demo/przebieg-1.xml | tee "$STATE_DIR/demo-1.txt"; }
    import_second() { ./run.sh import --kind results docs/demo/przebieg-2.xml | tee "$STATE_DIR/demo-2.txt"; }
    run "Import przebiegu demo 1 (nmap XML)" import_first
    run "Import przebiegu demo 2 - porównanie z pierwszym" import_second
    for f in "$STATE_DIR/demo-1.txt" "$STATE_DIR/demo-2.txt"; do
        grep -E '^Przebieg #|^Poza zakresem' "$f" | sed 's/^/        /' || true
    done
    [ "$(server_run_count)" -gt 0 ] || fail "Import demo nie utworzył przebiegów - sprawdź [scope] w dscan.toml i $LOG_FILE."
    info "Zmiany wykryte między przebiegami demo:"
    grep -E '^ *[-+~] ' "$STATE_DIR/demo-2.txt" | head -n 10 | sed 's/^/      /' || true
fi
if ./run.sh evaluate docs/demo/referencja.csv > "$STATE_DIR/evaluate.txt" 2>&1; then
    ok "Ocena trafności względem docs/demo/referencja.csv:"
    grep -E '^Przebieg|^  (hosty|usługi) ' "$STATE_DIR/evaluate.txt" | head -n 6 | sed 's/^/        /' || true
else
    warn "Ocena trafności niedostępna (szczegóły: $STATE_DIR/evaluate.txt)"
fi

# ===== 9. (opcjonalnie) Laboratorium =========================================================
if [ -n "$OPT_LAB" ]; then
    step "Scenariusz laboratorium (znikająca usługa 8787)"
    LAB_DIR="$OPT_LAB"
    if [ -f "$OPT_LAB" ]; then
        LAB_DIR="$(cd "$(dirname "$REPO_DIR")" && pwd)/lab"
        run "Rozpakowanie $OPT_LAB → $LAB_DIR" unzip -oq "$OPT_LAB" -d "$LAB_DIR"
        # Archiwum może mieć katalog nadrzędny.
        [ -f "$LAB_DIR/quickstart.sh" ] || LAB_DIR="$(dirname "$(find "$LAB_DIR" -name quickstart.sh | head -n1)")"
    fi
    [ -f "$LAB_DIR/quickstart.sh" ] || fail "Nie znaleziono quickstart.sh w $LAB_DIR."
    LAB_DIR="$(cd "$LAB_DIR" && pwd)"

    lab_scan() { # lab_scan "opis" oczekiwany_kod
        local label="$1" expected="$2" code=0 started
        started=$(date +%s)
        info "$label - skan trwa ok. 1-2 min…"
        (cd "$LAB_DIR" && "$REPO_DIR/run.sh" scan 127.0.0.1 --quiet) >> "$LOG_FILE" 2>&1 < /dev/null || code=$?
        if [ "$code" = "$expected" ]; then
            ok "$label: kod wyjścia $code (oczekiwany) ${DIM}($(elapsed "$started"))${N}"
        elif [ "$code" = 1 ]; then
            fail "$label: błąd skanu (kod 1)"
        else
            warn "$label: kod wyjścia $code (oczekiwany $expected)"
        fi
    }
    run "quickstart.sh up" bash -c "cd '$LAB_DIR' && bash quickstart.sh up"
    lab_scan "Skan 1 - porty 2223, 3001, 5673, 8787, 15673" 2
    run "quickstart.sh change (zatrzymanie usługi 8787)" bash -c "cd '$LAB_DIR' && bash quickstart.sh change"
    lab_scan "Skan 2 - 127.0.0.1:8787/tcp zniknęła" 2
    run "quickstart.sh up (przywrócenie 8787)" bash -c "cd '$LAB_DIR' && bash quickstart.sh up"
    lab_scan "Skan 3 - 127.0.0.1:8787/tcp nowa" 2
    lab_scan "Skan 4 - brak zmian" 0
    info "Pozostałe stacki laboratorium: docs/uruchomienie.md."
fi

# ===== 10. (opcjonalnie) DefectDojo ==========================================================
if [ "$OPT_DOJO" = 1 ]; then
    step "DefectDojo (pierwszy start pobiera obrazy - kilka minut)"
    run "Uruchomienie DefectDojo i pobranie tokenu API" ./scripts/defectdojo-setup.sh
    if grep -q '^enabled = false' dscan.toml; then
        sed -i.bak '/^\[defectdojo\]/,/^\[/ s/^enabled = false/enabled = true/' dscan.toml && rm -f dscan.toml.bak
        ok "Włączono [defectdojo] enabled = true w dscan.toml"
    fi
    if [ -f "$PID_FILE" ]; then
        info "Restart serwera DScan z integracją DefectDojo…"
        kill -INT "$(cat "$PID_FILE")" 2> /dev/null || true
        for _ in $(seq 1 50); do health_ok || break; sleep 0.2; done
        rm -f "$PID_FILE"
        start_server
        run "Ponowne logowanie" login_admin
    else
        warn "Serwer nie był uruchomiony przez install.sh - zrestartuj go ręcznie, aby włączyć integrację."
    fi
    ok "DefectDojo: http://127.0.0.1:8180/ (login admin, hasło DEFECTDOJO_ADMIN_PASSWORD w .env)"
fi

# ===== podsumowanie ==========================================================================
printf '\n%s[%d/%d]%s %s 100%%  %sGotowe w %s%s\n' "$B$G" "$TOTAL_STEPS" "$TOTAL_STEPS" "$N" "$(bar 100 24)" "$B" "$(elapsed "$START_TIME")" "$N"
cat << EOF

  ${B}Interfejs WWW:${N}  http://127.0.0.1:${PORT}/
  ${B}Login:${N}          ${ADMIN_USER}
  ${B}Hasło:${N}          ${ADMIN_PASS}   ${DIM}(też w .env: DSCAN_ADMIN_PASSWORD)${N}

  ${B}Zobacz w przeglądarce:${N} Pulpit · Hosty · Porównanie · W czasie

  ${B}Serwer pracuje w tle.${N} Kolejne uruchomienia (np. po restarcie komputera): ${B}./run.sh${N}

  ${B}Dalej w terminalu:${N}
    ./run.sh scan 127.0.0.1               skan (kod wyjścia: 0 brak zmian, 2 zmiany, 1 błąd)
    ./run.sh scan 127.0.0.0/28 --dry-run  plan skanu bez wysyłania pakietów
    ./run.sh export services --format csv eksport usług
    ./run.sh diff 1 2                     porównanie dwóch przebiegów
    ./run.sh --help                       wszystkie polecenia

  ${B}Zatrzymanie:${N}    ./install.sh --stop
  ${B}Logi:${N}           ${SERVER_LOG}, ${LOG_FILE}
EOF
