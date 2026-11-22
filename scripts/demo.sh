#!/usr/bin/env bash
# Demo DScan: wgrywa dane demo, zakłada konta dla wszystkich ról i wypisuje, co gdzie sprawdzić.
# Wymaga działającego serwera (./run.sh albo ./install.sh). Można uruchamiać wielokrotnie.
#
#   scripts/demo.sh            dane demo z plików (dwa przebiegi nmap ze zmianą, sieć 172.20.0.0/24)
#   scripts/demo.sh --uslugi   dodatkowo skan na żywo usług z docs/demo/uslugi.compose.yml (Docker)
#   scripts/demo.sh --stop     zatrzymanie usług z --uslugi
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE_USLUGI="docs/demo/uslugi.compose.yml"
OUT_DIR=".dscan-demo"
mkdir -p "$OUT_DIR"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

env_value() { sed -n "s/^$1=//p" .env 2> /dev/null | tail -n1; }
port() { sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' dscan.toml | head -n1 | sed 's/.*://'; }

if [ "${1:-}" = "--stop" ]; then
    docker compose -f "$COMPOSE_USLUGI" down
    exit 0
fi

[ -f dscan.toml ] && [ -f .env ] || { echo "Brak dscan.toml/.env - uruchom najpierw ./run.sh albo ./install.sh."; exit 1; }
URL="http://127.0.0.1:$(port)"
curl -fsS --max-time 3 "$URL/api/v1/health" > /dev/null 2>&1 \
    || { echo "Serwer nie odpowiada pod $URL - uruchom ./run.sh w osobnym terminalu."; exit 1; }

ADMIN_USER="$(env_value DSCAN_ADMIN_USERNAME)"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="$(env_value DSCAN_ADMIN_PASSWORD)"

say "1. Logowanie administratora ($ADMIN_USER)"
printf '%s\n' "$ADMIN_PASS" | ./run.sh login --user "$ADMIN_USER" --password-stdin --server "$URL"
CREDS="${DSCAN_CREDENTIALS:-${XDG_CONFIG_HOME:-$HOME/.config}/dscan/credentials.json}"
TOKEN="$(sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' "$CREDS" | head -n1)"
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

say "2. Dane demo: dwa przebiegi nmap (docs/demo/przebieg-1.xml, przebieg-2.xml)"
imports="$(api "$URL/api/v1/scans?limit=200" | grep -o '"profile":"import"' | wc -l | tr -d ' ' || true)"
if [ "$imports" -gt 0 ]; then
    info "Już wgrane (przebiegi importu: $imports)."
else
    ./run.sh import --kind results docs/demo/przebieg-1.xml
    ./run.sh import --kind results docs/demo/przebieg-2.xml | tee "$OUT_DIR/zmiany.txt"
fi

say "3. Konta dla ról (RBAC)"
DEMO_PASS="$(env_value DSCAN_DEMO_PASSWORD)"
if [ -z "$DEMO_PASS" ]; then
    DEMO_PASS="demo-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "DSCAN_DEMO_PASSWORD=$DEMO_PASS" >> .env
fi
roles="$(api "$URL/api/v1/roles")"
for pair in odczyt:demo-odczyt modyfikacja_odczyt:demo-modyfikacja dodawanie_usuwanie_modyfikacja:demo-operator; do
    role="${pair%%:*}" user="${pair##*:}"
    id="$(printf '%s' "$roles" | grep -o "\"id\":[0-9]*,\"name\":\"$role\"" | grep -o '[0-9]*' | head -n1 || true)"
    if [ -z "$id" ]; then
        info "brak roli $role - pomijam"
        continue
    fi
    if api -o /dev/null -X POST "$URL/api/v1/users" \
        -d "{\"username\":\"$user\",\"password\":\"$DEMO_PASS\",\"role_id\":$id}" 2> /dev/null; then
        info "utworzono $user (rola $role)"
    else
        info "$user (rola $role) już istnieje"
    fi
done

say "4. Trafność względem referencji (docs/demo/referencja.csv)"
./run.sh evaluate docs/demo/referencja.csv | tee "$OUT_DIR/ocena.txt"

say "5. Eksport usług do CSV i JSON"
./run.sh export services --format csv -o "$OUT_DIR/uslugi.csv"
./run.sh export hosts -o "$OUT_DIR/hosty.json"

if [ "${1:-}" = "--uslugi" ]; then
    say "6. Skan na żywo: Grafana :3000, Jenkins :8082, Portainer :8083, MongoDB :8084"
    docker compose -f "$COMPOSE_USLUGI" up -d
    info "Czekam 60 s na start usług..."
    sleep 60
    set +e
    ./run.sh scan 127.0.0.1 | tee "$OUT_DIR/skan-1.txt"
    info "Zatrzymuję Portainer i skanuję ponownie (oczekiwane: 127.0.0.1:8083/tcp zniknęła, kod 2)."
    docker compose -f "$COMPOSE_USLUGI" stop portainer
    ./run.sh scan 127.0.0.1 --quiet | tee "$OUT_DIR/skan-2.txt"
    echo "kod wyjścia: ${PIPESTATUS[0]}"
    set -e
fi

say "Gotowe"
cat << EOF
   Interfejs WWW:  $URL/
   Administrator:  $ADMIN_USER / $ADMIN_PASS
   Konta ról:      demo-operator, demo-modyfikacja, demo-odczyt / $DEMO_PASS
   Pliki wynikowe: $OUT_DIR/ (zmiany, ocena, eksport CSV/JSON)
   Co sprawdzić:   hacknation.md
EOF
