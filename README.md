<p align="center">
  <img src="docs/img/logo.png" alt="DScan — Smart Scanning" width="220">
</p>

<h1 align="center">DScan — Defect Scan</h1>

<p align="center">
  Skanowanie i inwentaryzacja usług sieciowych z wykrywaniem zmian.<br>
  Jedna binarka w Ruście (<code>dscan</code>): serwer WWW, REST API i CLI, dane w PostgreSQL.
</p>

<p align="center">
  <a href="docs/pdf/INSTRUKCJA-JURY.pdf"><b>Instrukcja dla jury (PDF)</b></a> ·
  <a href="#szybki-start">Szybki start</a> ·
  <a href="#dokumentacja">Dokumentacja</a>
</p>

---

## Najważniejsze funkcje

| Obszar | Co daje DScan |
|---|---|
| **Wykrywanie** | nmap (`-sn`/`-sV`) w równoległych podgrupach CIDR, łączny limit tempa, postęp i prognoza czasu |
| **Technologie** | HTTP/HTTPS, certyfikaty TLS, favicon, ok. 50 sygnatur YAML z pewnością 0–100 i dowodami |
| **Zmiany** | usługa **nowa / zniknęła / zmieniona** między przebiegami; kod wyjścia `2` = zmiany |
| **Znaleziska** | ranking: panele admina, CI/CD, kamery IoT, środowiska testowe, stare wersje |
| **Harmonogram** | profile, okna czasowe, wstrzymanie i wznowienie od niedokończonych podgrup |
| **Interfejs WWW** | pulpit, hosty, porównanie, oś czasu, ręczna edycja wyników, grupy podobnych usług |
| **Import / eksport** | cele CSV/JSON, wyniki nmap XML/JSON/CSV, eksport z filtrami, DefectDojo |
| **Bezpieczeństwo** | tylko dozwolone sieci i porty, bez NSE, AES-256-GCM dla danych poufnych, RBAC i audyt |

Na laboratorium organizatorów: **31/31 portów, 100% precyzji i czułości, 0 fałszywych zmian**.

## Szybki start

```bash
git clone https://github.com/Kapioner/DScan1.git DScan && cd DScan && ./install.sh
```

`install.sh` z paskiem postępu: instaluje brakujące narzędzia (Git, kompilator C, nmap, Docker, Rust ≥ 1.85),
kompiluje DScan, uruchamia PostgreSQL i serwer w tle, loguje administratora i ładuje dane demo.
Na końcu wypisuje **http://127.0.0.1:9080/**, login i hasło.

| Opcja | Działanie |
|---|---|
| `--lab lab.zip` | scenariusz laboratorium (znikająca usługa 8787) |
| `--dojo` | lokalny DefectDojo z integracją |
| `--no-install` / `--no-demo` | bez instalacji pakietów / bez danych demo |
| `--keep-config` | zostawia własny `dscan.toml` (domyślnie zastępowany konfiguracją dla jury, kopia w `dscan.toml.bak`) |
| `--stop` | zatrzymanie serwera i bazy |

Ręcznie (wymaga Rust, Docker, nmap):

```bash
cp docs/jury/dscan.toml dscan.toml && ./run.sh
```

`run.sh` tworzy `.env` (klucz szyfrowania, hasło bazy, konto admina; 600), startuje PostgreSQL w Dockerze,
buduje release i uruchamia `dscan serve`. Hasło admina: `grep DSCAN_ADMIN_ .env`.

> `.env` zawiera jedyną kopię klucza szyfrowania — zrób kopię zapasową.

## Użycie

```bash
./run.sh login --user admin
```

| Polecenie | Wynik |
|---|---|
| `./run.sh scan 127.0.0.1` | skan z fingerprintingiem i listą zmian |
| `./run.sh scan 10.0.0.0/24 --dry-run` | plan: adresy, podgrupy, czas — bez pakietów |
| `./run.sh import --kind results wynik.xml` | import wyników nmap |
| `./run.sh export services --format csv --technology nginx` | eksport z filtrem |
| `./run.sh diff 1 2` | porównanie przebiegów |
| `./run.sh evaluate referencja.csv` | precyzja, czułość, F1 |
| `./run.sh dojo export N --item "IP:PORT/tcp=DVWA"` | finding w DefectDojo |

Kody wyjścia: **0** brak zmian, **1** błąd, **2** zmiany. Wszystkie polecenia: [CLI (PDF)](docs/pdf/cli.pdf).

## Architektura

```
 przeglądarka (htmx)          dscan CLI (klient API)
         │                             │
         ▼                             ▼
 ┌───────────────────── dscan serve ──────────────────────┐
 │ dscan-web (askama)    dscan-api (axum, RBAC, audyt)    │
 │      dscan-engine (przebiegi, harmonogram)             │
 │ dscan-scanner  dscan-fingerprint  dscan-integrations   │
 │ dscan-db (sqlx, szyfrowanie) ── dscan-crypto (AES-GCM) │
 └────────────────────────────┬───────────────────────────┘
                              ▼
                         PostgreSQL
```

Przebieg: cele → zakres `[scope]` → podgrupy CIDR → pula `nmap -sV` → fingerprinting WWW → zapis wsadowy
→ porównanie z poprzednim przebiegiem. Szczegóły: [Architektura (PDF)](docs/pdf/architektura.pdf).

## Bezpieczeństwo

- nmap tylko `-sn`/`-sV`, bez NSE, exploitów i logowania; zawsze `--max-rate`;
- wyłącznie sieci i porty z `[scope]`; HTTP tylko GET;
- dane poufne (notatki, banery, nagłówki, ciasteczka, certyfikaty, XML) szyfrowane AES-256-GCM, rotacja kluczy;
- hasła argon2id, sesje jako SHA-256, 4 role RBAC + własne, dziennik audytu.

Szczegóły: [Bezpieczeństwo (PDF)](docs/pdf/bezpieczenstwo-skanera.pdf), [Klasyfikacja danych (PDF)](docs/pdf/klasyfikacja-danych.pdf).

## Rozwój

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

CI: fmt, clippy, ok. 400 testów, `cargo audit`, obraz Docker. Wytyczne: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).

## Dokumentacja

| Dokument | PDF | Źródło |
|---|---|---|
| Instrukcja dla jury | [PDF](docs/pdf/INSTRUKCJA-JURY.pdf) | [md](docs/INSTRUKCJA-JURY.md) |
| Architektura | [PDF](docs/pdf/architektura.pdf) | [md](docs/architektura.md) |
| Polecenia CLI | [PDF](docs/pdf/cli.pdf) | [md](docs/cli.md) |
| Skuteczność na laboratorium | [PDF](docs/pdf/analiza-skutecznosci.pdf) | [md](docs/analiza-skutecznosci.md) |
| Bezpieczeństwo skanera | [PDF](docs/pdf/bezpieczenstwo-skanera.pdf) | [md](docs/bezpieczenstwo-skanera.md) |
| Klasyfikacja danych | [PDF](docs/pdf/klasyfikacja-danych.pdf) | [md](docs/klasyfikacja-danych.md) |
| Testy ręczne | [PDF](docs/pdf/testy-reczne.pdf) | [md](docs/testy-reczne.md) |
| Prezentacja | [PDF](docs/pdf/prezentacja.pdf) | [md](docs/prezentacja.md) |

PDF-y generuje `node scripts/docs-pdf.mjs` (pandoc + Chromium).

## Licencja

[MIT](LICENSE)
