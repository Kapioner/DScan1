#!/usr/bin/env bash
# Uruchamia DScan jedną komendą:  ./run.sh [podkomenda dscan i argumenty]
#
#   ./run.sh                  → dscan serve (interfejs WWW i API, adres z [server] listen)
#   ./run.sh config show      → dowolna inna podkomenda
#
# Kroki (wypisywane na stderr):
#   1. konfiguracja: dscan.toml (kopia docs/konfiguracja/dscan.toml) i .env z sekretami,
#   2. baza PostgreSQL w Dockerze (tylko dla poleceń, które jej używają),
#   3. kompilacja wersji release (tylko gdy kod się zmienił, z paskiem postępu cargo),
#   4. uruchomienie binarki.
#
# Przy pierwszym uruchomieniu (lub gdy czegoś brakuje):
#   - tworzy dscan.toml z docs/konfiguracja/dscan.toml,
#   - uzupełnia .env: klucz szyfrowania, hasło i adres bazy, konto administratora (uprawnienia 600).
# Za każdym razem: wczytuje .env, w razie potrzeby uruchamia PostgreSQL w Dockerze,
# buduje wersję release (przyrostowo) i startuje natywną binarkę.
#
# Własna baza zamiast Dockera: ustaw w .env  USE_DOCKER_POSTGRES=0  i własny DSCAN_DATABASE_URL.
set -euo pipefail

cd "$(dirname "$0")"

CONFIG_FILE="dscan.toml"
ENV_FILE=".env"
BINARY="target/release/dscan"
DEFAULT_CONFIG="docs/konfiguracja/dscan.toml"
COMMAND="${1:-serve}"
STEP_PREFIX=""
[ "$COMMAND" = "serve" ] && STEP_PREFIX="[3/4] "

log() {
    echo "[run.sh] $*" >&2
}

# Kroki wypisujemy przy starcie serwera; przy innych poleceniach tylko to, co trwa dłużej.
step() {
    if [ "$COMMAND" = "serve" ]; then
        echo "[run.sh] [$1/4] $2" >&2
    fi
}

server_port() {
    local listen
    listen="$(sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$CONFIG_FILE" | head -n1)"
    echo "${listen##*:}"
}

random_hex() {
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

create_config_if_missing() {
    if [ ! -f "$CONFIG_FILE" ]; then
        cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
        log "Utworzono $CONFIG_FILE (zakres 127.0.0.0/8 i 172.20.0.0/24). Wszystkie opcje: dscan.example.toml"
    fi
}

# Dopisuje zmienną do .env tylko wtedy, gdy jeszcze jej tam nie ma.
ensure_env_var() {
    local name="$1" value="$2"
    if ! grep -q "^${name}=" "$ENV_FILE"; then
        echo "${name}=${value}" >> "$ENV_FILE"
        log "Dodano ${name} do $ENV_FILE"
    fi
}

# Eksportuje zmienne z .env. Zmienna już ustawiona (np. podana przed ./run.sh
# w linii poleceń) ma pierwszeństwo przed wartością z pliku.
load_env() {
    local name value
    while IFS='=' read -r name value; do
        case "$name" in
            '' | '#'*) continue ;;
        esac
        if [ -z "${!name+x}" ]; then
            export "$name=$value"
        fi
    done < "$ENV_FILE"
}

prepare_env_file() {
    (umask 077 && touch "$ENV_FILE")
    ensure_env_var DSCAN_ENCRYPTION_KEY "$(random_hex 32)"
    ensure_env_var POSTGRES_USER dscan
    ensure_env_var POSTGRES_PASSWORD "$(random_hex 16)"
    ensure_env_var POSTGRES_DB dscan
    ensure_env_var POSTGRES_PORT 5433
    ensure_env_var USE_DOCKER_POSTGRES 1
    # Konto tworzone przez `dscan serve` przy pierwszym starcie (gdy w bazie nie ma użytkowników).
    if ! grep -q "^DSCAN_ADMIN_PASSWORD=" "$ENV_FILE"; then
        ensure_env_var DSCAN_ADMIN_USERNAME admin
        ensure_env_var DSCAN_ADMIN_PASSWORD "$(random_hex 12)"
        log "Logowanie do interfejsu WWW: login i hasło w $ENV_FILE (DSCAN_ADMIN_USERNAME, DSCAN_ADMIN_PASSWORD)."
    fi
    load_env
    local expected_url="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
    ensure_env_var DSCAN_DATABASE_URL "$expected_url"
    load_env
    # Baza z Dockera: adres musi zgadzać się z POSTGRES_* (np. po ręcznej zmianie hasła w .env).
    if [ "${USE_DOCKER_POSTGRES}" = "1" ] && [ "${DSCAN_DATABASE_URL}" != "$expected_url" ]; then
        local tmp
        tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
        grep -v "^DSCAN_DATABASE_URL=" "$ENV_FILE" > "$tmp" || true
        echo "DSCAN_DATABASE_URL=${expected_url}" >> "$tmp"
        chmod 600 "$tmp"
        mv "$tmp" "$ENV_FILE"
        export DSCAN_DATABASE_URL="$expected_url"
        log "Poprawiono DSCAN_DATABASE_URL w $ENV_FILE (zgodnie z POSTGRES_*)."
    fi
}

# Polecenia korzystające z bazy (serve jest domyślne).
command_needs_database() {
    case "${1:-serve}" in
        serve | db | user | targets | import | keys | scan) return 0 ;;
        *) return 1 ;;
    esac
}

# Skan wymaga programu nmap na hoście.
warn_if_nmap_missing() {
    if [ "${1:-}" = "scan" ] && ! command -v nmap > /dev/null 2>&1; then
        log "Brak programu nmap - zainstaluj go (np. sudo apt install nmap / brew install nmap)."
    fi
}

start_database() {
    if [ "${USE_DOCKER_POSTGRES}" != "1" ]; then
        return
    fi
    if ! command -v docker > /dev/null 2>&1; then
        log "Brak Dockera - zakładam, że PostgreSQL pod DSCAN_DATABASE_URL już działa."
        log "(Zainstaluj Dockera albo ustaw w $ENV_FILE USE_DOCKER_POSTGRES=0 i własny adres bazy.)"
        return
    fi
    if [ -z "$(docker compose ps --status running --quiet postgres 2> /dev/null)" ]; then
        log "Uruchamiam PostgreSQL w Dockerze (pierwszy raz pobiera obraz)..."
        docker compose up -d --wait postgres
    else
        step 2 "Baza PostgreSQL działa"
    fi
    sync_database_credentials
}

# POSTGRES_PASSWORD działa tylko przy pierwszym utworzeniu wolumenu. Jeśli .env ma inne hasło
# (np. odtworzony plik albo nowy klon repozytorium przy starym wolumenie), logowanie się nie uda -
# dlatego ustawiamy hasło roli zgodnie z .env. Wewnątrz kontenera psql łączy się przez gniazdo
# lokalne, które nie wymaga hasła.
sync_database_credentials() {
    local psql=(docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -qtA -U "$POSTGRES_USER" -d postgres)
    if ! "${psql[@]}" -c "ALTER ROLE \"${POSTGRES_USER}\" WITH PASSWORD '${POSTGRES_PASSWORD}'" > /dev/null 2>&1; then
        log "Nie można ustawić hasła roli ${POSTGRES_USER} w kontenerze bazy - wolumen utworzono"
        log "prawdopodobnie z inną nazwą użytkownika. Jeśli dane w bazie nie są potrzebne:"
        log "  docker compose down -v && ./run.sh"
        return
    fi
    if [ "$("${psql[@]}" -c "SELECT 1 FROM pg_database WHERE datname = '${POSTGRES_DB}'")" != "1" ]; then
        "${psql[@]}" -c "CREATE DATABASE \"${POSTGRES_DB}\" OWNER \"${POSTGRES_USER}\"" > /dev/null
        log "Utworzono bazę ${POSTGRES_DB}."
    fi
}

# Drugi serwer nie wystartuje na zajętym porcie - wtedy tylko wskazujemy adres działającego.
exit_if_server_running() {
    [ "$COMMAND" = "serve" ] || return 0
    local port
    port="$(server_port)"
    if [ -n "$port" ] && command -v curl > /dev/null 2>&1 \
        && curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/v1/health" > /dev/null 2>&1; then
        log "DScan działa już na http://127.0.0.1:${port}/ - otwórz ten adres w przeglądarce."
        log "Serwer w tle (install.sh --background) zatrzymuje: ./install.sh --stop"
        exit 0
    fi
}

# Kompilacja tylko wtedy, gdy binarki nie ma albo źródła są nowsze (kolejne starty bez czekania).
build_if_needed() {
    if [ -x "$BINARY" ] \
        && [ -z "$(find crates Cargo.toml Cargo.lock -newer "$BINARY" -print -quit 2> /dev/null)" ]; then
        step 3 "Kompilacja: bez zmian w kodzie, pomijam"
        return
    fi
    if [ -x "$BINARY" ]; then
        log "${STEP_PREFIX}Kompilacja zmienionego kodu..."
    else
        log "${STEP_PREFIX}Pierwsza kompilacja DScan - trwa kilka minut, postęp poniżej (Building N/M)..."
    fi
    cargo build --release -p dscan
    touch "$BINARY"
}

step 1 "Konfiguracja: $CONFIG_FILE i $ENV_FILE"
create_config_if_missing
exit_if_server_running
prepare_env_file
if command_needs_database "$COMMAND"; then
    step 2 "Baza danych PostgreSQL"
    start_database
fi
warn_if_nmap_missing "$@"
build_if_needed

if [ "$#" -eq 0 ]; then
    set -- serve
fi
if [ "$COMMAND" = "serve" ]; then
    step 4 "Start serwera: migracje bazy, konto administratora, harmonogram"
    log "Interfejs WWW: http://127.0.0.1:$(server_port)/ (login i hasło w $ENV_FILE, Ctrl+C kończy)"
fi
exec "$BINARY" "$@"
