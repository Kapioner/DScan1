#!/usr/bin/env bash
# Uruchamia DScan jedną komendą:  ./run.sh [argumenty dla dscan]
#
# Przy pierwszym uruchomieniu:
#   - tworzy dscan.toml z dscan.example.toml,
#   - generuje klucz szyfrowania i zapisuje go w .env (uprawnienia 600).
# Za każdym razem: wczytuje .env, buduje wersję release (przyrostowo) i startuje binarkę.
set -euo pipefail

cd "$(dirname "$0")"

CONFIG_FILE="dscan.toml"
ENV_FILE=".env"
BINARY="target/release/dscan"

create_config_if_missing() {
    if [ ! -f "$CONFIG_FILE" ]; then
        cp dscan.example.toml "$CONFIG_FILE"
        echo "[run.sh] Utworzono $CONFIG_FILE — uzupełnij sekcję [scope] danymi od organizatora." >&2
    fi
}

generate_hex_key() {
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

create_env_if_missing() {
    if [ ! -f "$ENV_FILE" ]; then
        (umask 077 && echo "DSCAN_ENCRYPTION_KEY=$(generate_hex_key)" > "$ENV_FILE")
        echo "[run.sh] Wygenerowano klucz szyfrowania w $ENV_FILE — zrób jego kopię zapasową." >&2
    fi
}

load_env() {
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
}

create_config_if_missing
create_env_if_missing
load_env
cargo build --release --quiet -p dscan
exec "$BINARY" "$@"
