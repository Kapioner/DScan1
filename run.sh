#!/usr/bin/env bash
# Uruchamia DScan jedną komendą:  ./run.sh [podkomenda dscan i argumenty]
#
#   ./run.sh                  → dscan serve (API na http://127.0.0.1:8080)
#   ./run.sh config show      → dowolna inna podkomenda
#
# Przy pierwszym uruchomieniu (lub gdy czegoś brakuje):
#   - tworzy dscan.toml z dscan.example.toml,
#   - uzupełnia .env: klucz szyfrowania, hasło i adres bazy (uprawnienia 600).
# Za każdym razem: wczytuje .env, w razie potrzeby uruchamia PostgreSQL w Dockerze,
# buduje wersję release (przyrostowo) i startuje natywną binarkę.
#
# Własna baza zamiast Dockera: ustaw w .env  USE_DOCKER_POSTGRES=0  i własny DSCAN_DATABASE_URL.
set -euo pipefail

cd "$(dirname "$0")"

CONFIG_FILE="dscan.toml"
ENV_FILE=".env"
BINARY="target/release/dscan"

log() {
    echo "[run.sh] $*" >&2
}

random_hex() {
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

create_config_if_missing() {
    if [ ! -f "$CONFIG_FILE" ]; then
        cp dscan.example.toml "$CONFIG_FILE"
        log "Utworzono $CONFIG_FILE — uzupełnij sekcję [scope] danymi od organizatora."
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
    load_env
    ensure_env_var DSCAN_DATABASE_URL \
        "postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
    load_env
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
        log "Brak programu nmap — zainstaluj go (np. sudo apt install nmap / brew install nmap)."
    fi
}

start_database() {
    if [ "${USE_DOCKER_POSTGRES}" != "1" ]; then
        return
    fi
    if ! command -v docker > /dev/null 2>&1; then
        log "Brak Dockera — zakładam, że PostgreSQL pod DSCAN_DATABASE_URL już działa."
        log "(Zainstaluj Dockera albo ustaw w $ENV_FILE USE_DOCKER_POSTGRES=0 i własny adres bazy.)"
        return
    fi
    if [ -n "$(docker compose ps --status running --quiet postgres 2> /dev/null)" ]; then
        return
    fi
    log "Uruchamiam PostgreSQL (docker compose)…"
    docker compose --progress quiet up -d --wait postgres
}

create_config_if_missing
prepare_env_file
if command_needs_database "$@"; then
    start_database
fi
warn_if_nmap_missing "$@"
cargo build --release --quiet -p dscan

if [ "$#" -eq 0 ]; then
    set -- serve
fi
exec "$BINARY" "$@"
