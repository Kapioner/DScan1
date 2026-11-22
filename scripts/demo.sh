#!/usr/bin/env bash
# Demo DScan (Q8): import → zmiany → edycja → role → eksport, na danych zapasowych
# z docs/demo (dwa przebiegi z laboratorium 172.20.0.0/24 i zmianą między nimi).
# Działa bez sieci laboratorium. Wymaga działającego serwera (./run.sh w drugim terminalu)
# i zalogowania: ./run.sh login --user admin
#
#   scripts/demo.sh            - dane zapasowe (import dwóch przebiegów)
#   scripts/demo.sh --live CEL - dwa prawdziwe skany CEL z przerwą na zmianę w laboratorium
set -euo pipefail
cd "$(dirname "$0")/.."

dscan() { ./run.sh "$@"; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
pause() { [ -t 0 ] && read -r -p "   [Enter] dalej… " _ || true; }

if [ "${1:-}" = "--live" ]; then
    target="${2:?podaj cel, np. 172.20.0.0/24}"
    step "1. Pierwszy skan ($target)"
    dscan scan "$target" --quiet || true
    echo "Wprowadź zmianę w laboratorium (np. uruchom nową usługę), potem Enter."
    pause
    step "2. Drugi skan - kod wyjścia 2 oznacza wykryte zmiany"
    set +e; dscan scan "$target" --quiet; code=$?; set -e
    echo "kod wyjścia: $code"
else
    step "1. Import pierwszego przebiegu (nmap XML)"
    dscan import --kind results docs/demo/przebieg-1.xml
    pause
    step "2. Import drugiego przebiegu - porównanie z pierwszym"
    dscan import --kind results docs/demo/przebieg-2.xml
fi
pause

step "3. Najciekawsze usługi i zmiany: Pulpit w interfejsie WWW (adres z [server] listen)"
step "4. Eksport usług z technologią nginx (CSV)"
dscan export services --format csv --technology nginx
pause

step "5. Trafność względem referencji organizatora (Q1)"
dscan evaluate docs/demo/referencja.csv --details || true
pause

step "6. W przeglądarce: edycja wyniku (Hosty → host → Zapisz), role (Użytkownicy), dziennik (Audyt)"
echo "Gotowe."
