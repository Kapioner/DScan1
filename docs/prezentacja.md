---
marp: true
title: DScan — Defect Scan
paginate: true
---

# DScan — Defect Scan

Inwentaryzacja usług sieciowych z wykrywaniem zmian

- jedna binarka w Ruście: serwer WWW + API + CLI, PostgreSQL
- uruchomienie jedną komendą: `./run.sh`

---

## Problem i cel

- Co działa w sieci laboratorium, w jakiej wersji i **co się zmieniło** od ostatniego skanu?
- Ograniczenia: tylko dozwolone sieci i porty, limit ruchu, okna czasowe
- Wynik: lista hostów i usług, technologie z pewnością i dowodami, najciekawsze znaleziska

---

## Architektura

- `scanner` — nmap w podgrupach CIDR, pula procesów, łączny limit tempa, zabezpieczenia (bez NSE)
- `fingerprint` — HTTP/TLS, favicon (mmh3), ~40 sygnatur YAML, heurystyki staging/debug/panele
- `engine` — przebiegi, harmonogram, wstrzymanie i wznowienie, porównania, ocena, klastry
- `api` + `web` — REST z RBAC i audytem, interfejs htmx; CLI jako klient API
- `db` + `crypto` — szyfrowanie pól AES-256-GCM, ślepy indeks, rotacja kluczy

---

## Demo 1: import → skan

- `./run.sh import --kind results docs/demo/przebieg-1.xml`
- `./run.sh scan 172.20.0.0/24 --profile pelny` — postęp, prognoza czasu
- `--dry-run`: adresy, podgrupy i szacowany czas bez wysyłania pakietów

---

## Demo 2: zmiany

- drugi przebieg → usługi **nowe / zniknięte / zmienione** (kolory w porównaniu dwóch skanów)
- kod wyjścia 2 = wykryto zmiany (cron, skrypty)
- dashboard: najciekawsze usługi z uzasadnieniem (stara wersja, panel admina, nowy port…)

---

## Demo 3: edycja i grupy

- widok hosta: usługi, HTTP, certyfikat, technologie z dowodami, mapa dostępności w godzinach
- edycja wyniku → znaczek „edytowane ręcznie”, poprawka przetrwa kolejne skany
- grupy podobnych usług (SimHash): „te same 4 kamery” → jeden tag dla całej grupy

---

## Demo 4: role

- 4 role wbudowane + własne role z zestawu uprawnień
- „odczyt” nie edytuje, nie uruchamia skanów, eksportuje bez notatek
- każda zmiana w dzienniku audytu: kto, co i kiedy

---

## Demo 5: eksport i integracje

- eksport JSON/CSV z filtrami: `export services --technology nginx --format csv`
- DefectDojo: import surowego XML nmap + wybrane obserwacje jako findingi z dowodami
- ocena trafności względem referencji: `dscan evaluate referencja.csv` → precyzja, czułość, F1

---

## Bezpieczeństwo i jakość

- tylko GET, bez logowania i exploitów; zakres i porty wymuszone w kodzie
- sekrety tylko w `.env`; dane poufne szyfrowane, hasła argon2id
- CI: fmt, clippy `-D warnings`, ~400 testów (w tym RBAC 4 ról i skala /18), `cargo audit`

---

## Podsumowanie

- pełny cykl: import → skan → zmiany → edycja → role → eksport
- działa offline (htmx i wykresy wkompilowane), dane zapasowe do demo: `docs/demo`
- dokumentacja: `docs/architektura.md`, `docs/cli.md`, `docs/klasyfikacja-danych.md`
