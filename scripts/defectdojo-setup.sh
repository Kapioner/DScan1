#!/usr/bin/env bash
# Lokalny DefectDojo do testów integracji (zadanie D4) - jedną komendą:
#
#   ./scripts/defectdojo-setup.sh          uruchamia DefectDojo i przygotowuje dane testowe
#   ./scripts/defectdojo-setup.sh stop     zatrzymuje kontenery (dane zostają)
#
# Przy pierwszym uruchomieniu dopisuje do .env sekrety DefectDojo, a po starcie:
#   - pobiera token API administratora      → DSCAN_DEFECTDOJO_TOKEN
#   - tworzy produkt „DScan lab”            → DSCAN_DEFECTDOJO_PRODUCT_ID
#   - tworzy engagement „DScan - testy”     → DSCAN_DEFECTDOJO_ENGAGEMENT_ID
# Pierwszy start (pobranie obrazów, migracje DefectDojo) trwa kilka minut.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE=".env"
COMPOSE=(docker compose -f compose.defectdojo.yaml --env-file "$ENV_FILE")
PRODUCT_NAME="DScan lab"
ENGAGEMENT_NAME="DScan - testy"

log() {
    echo "[defectdojo] $*" >&2
}

random_hex() {
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# Ustawia zmienną w .env (dopisuje albo podmienia istniejącą).
set_env_var() {
    local name="$1" value="$2"
    if grep -q "^${name}=" "$ENV_FILE"; then
        sed -i "s|^${name}=.*|${name}=${value}|" "$ENV_FILE"
    else
        echo "${name}=${value}" >> "$ENV_FILE"
    fi
}

ensure_secret() {
    grep -q "^$1=" "$ENV_FILE" || set_env_var "$1" "$2"
}

env_value() {
    grep "^$1=" "$ENV_FILE" | cut -d= -f2-
}

prepare_secrets() {
    (umask 077 && touch "$ENV_FILE")
    ensure_secret DEFECTDOJO_ADMIN_PASSWORD "$(random_hex 12)"
    ensure_secret DEFECTDOJO_DB_PASSWORD "$(random_hex 16)"
    ensure_secret DEFECTDOJO_SECRET_KEY "$(random_hex 32)"
    ensure_secret DEFECTDOJO_AES_KEY "$(random_hex 16)"
    # 8180, bo 8081 zajmuje phpMyAdmin w laboratorium organizatorów.
    ensure_secret DEFECTDOJO_PORT "${DEFECTDOJO_PORT:-8180}"
}

wait_for_api() {
    local url="$1"
    log "Czekam na DefectDojo pod $url (pierwszy start: migracje bazy, kilka minut)…"
    for _ in $(seq 1 120); do
        if curl -sf -o /dev/null "$url/login"; then
            return 0
        fi
        sleep 5
    done
    log "DefectDojo nie odpowiada - sprawdź: docker compose -f compose.defectdojo.yaml logs initializer"
    exit 1
}

# Wartość pola z odpowiedzi JSON (bez dodatkowych narzędzi poza python3).
json_field() {
    python3 -c "import sys, json; data = json.load(sys.stdin); print($1)"
}

fetch_token() {
    local url="$1"
    for _ in $(seq 1 60); do
        local response
        response=$(curl -s -X POST "$url/api/v2/api-token-auth/" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"admin\", \"password\": \"$(env_value DEFECTDOJO_ADMIN_PASSWORD)\"}")
        if token=$(echo "$response" | json_field "data['token']" 2> /dev/null); then
            echo "$token"
            return 0
        fi
        sleep 5   # konto admina tworzy initializer - może jeszcze nie istnieć
    done
    log "Nie udało się pobrać tokenu API."
    exit 1
}

# Zwraca id istniejącego obiektu o nazwie albo tworzy nowy.
find_or_create() {
    local url="$1" token="$2" endpoint="$3" query="$4" body="$5"
    local existing
    existing=$(curl -s -H "Authorization: Token $token" "$url/api/v2/$endpoint/?$query" \
        | json_field "data['results'][0]['id'] if data['count'] else ''")
    if [ -n "$existing" ]; then
        echo "$existing"
        return 0
    fi
    curl -s -X POST -H "Authorization: Token $token" -H "Content-Type: application/json" \
        -d "$body" "$url/api/v2/$endpoint/" | json_field "data['id']"
}

setup() {
    prepare_secrets
    "${COMPOSE[@]}" up -d
    local url="http://127.0.0.1:$(env_value DEFECTDOJO_PORT)"
    wait_for_api "$url"

    local token product engagement today
    token=$(fetch_token "$url")
    product=$(find_or_create "$url" "$token" products "name=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("'"$PRODUCT_NAME"'"))')" \
        "{\"name\": \"$PRODUCT_NAME\", \"description\": \"Wyniki skanów DScan\", \"prod_type\": 1}")
    today=$(date +%F)
    engagement=$(find_or_create "$url" "$token" engagements "product=$product" \
        "{\"name\": \"$ENGAGEMENT_NAME\", \"product\": $product, \"target_start\": \"$today\", \"target_end\": \"$(date -d '+1 year' +%F)\", \"engagement_type\": \"CI/CD\", \"status\": \"In Progress\"}")

    set_env_var DSCAN_DEFECTDOJO_URL "$url"
    set_env_var DSCAN_DEFECTDOJO_TOKEN "$token"
    set_env_var DSCAN_DEFECTDOJO_PRODUCT_ID "$product"
    set_env_var DSCAN_DEFECTDOJO_ENGAGEMENT_ID "$engagement"
    log "Gotowe: $url (login admin, hasło DEFECTDOJO_ADMIN_PASSWORD w $ENV_FILE)."
    log "Produkt #$product „$PRODUCT_NAME”, engagement #$engagement; token zapisany jako DSCAN_DEFECTDOJO_TOKEN."
}

case "${1:-setup}" in
    setup) setup ;;
    stop) "${COMPOSE[@]}" stop ;;
    *) echo "użycie: $0 [setup|stop]" >&2; exit 2 ;;
esac
