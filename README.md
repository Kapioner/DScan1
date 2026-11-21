# Sztygar

Narzędzie do skanowania i inwentaryzacji usług sieciowych, napisane w Rust
i uruchamiane natywnie na hoście. Binarka: `sztygar`.

> Nazwa: *sztygar* to górniczy nadzorca w kopalni, czyli ktoś, kto zna każdy chodnik.
> Sprawdzone kolizje (2026-11): brak crate'a `sztygar` na crates.io; na GitHubie
> tylko jedno niezwiązane repozytorium (aplikacja React). Nazwa `dscan` była zajęta.

## Struktura workspace

| Crate | Katalog | Odpowiedzialność |
|---|---|---|
| `sztygar-core` | `crates/core` | Model domeny: `Target`, `Host`, `Service`, `HttpInfo`, `Detection`, `ScanRun`, `Change` (serde) |
| `sztygar-config` | `crates/config` | Konfiguracja: TOML + zmienne `SZTYGAR_*`, walidacja, klucz szyfrowania z env |
| `sztygar-scanner` | `crates/scanner` | Skaner (nmap, podgrupy, limity), *w przygotowaniu* |
| `sztygar-fingerprint` | `crates/fingerprint` | Fingerprinting HTTP/TLS i sygnatury, *w przygotowaniu* |
| `sztygar-api` | `crates/api` | REST API (axum) + RBAC, *w przygotowaniu* |
| `sztygar-web` | `crates/web` | UI (askama + htmx), *w przygotowaniu* |
| `sztygar` | `crates/cli` | Binarka `sztygar` |

## Uruchomienie

```bash
cp sztygar.example.toml sztygar.toml     # i uzupełnij wartości od organizatora
export SZTYGAR_ENCRYPTION_KEY=$(openssl rand -hex 32)
cargo run --release
```

Na razie program wypisuje efektywną konfigurację (`sztygar [PLIK]`); podkomendy pojawią się w zadaniu C2.

## Konfiguracja

Kolejność ważności: **wartości domyślne < plik TOML < zmienne środowiskowe**.

- Plik: `sztygar.toml` w bieżącym katalogu (lub ścieżka podana jako argument). Wszystkie pola opisuje [`sztygar.example.toml`](sztygar.example.toml).
- Zmienne: `SZTYGAR_<SEKCJA>__<POLE>`, np. `SZTYGAR_LIMITS__NMAP_MAX_RATE=50`,
  `SZTYGAR_SCOPE__ALLOWED_PORTS='["22","80"]'`.
- **Klucz szyfrowania** podaje się wyłącznie przez `SZTYGAR_ENCRYPTION_KEY` (64 znaki hex). Wpis w TOML jest odrzucany, a klucz nigdy nie jest wypisywany.
- Nieznane pola (literówki) kończą się błędem.

| Sekcja | Zawartość |
|---|---|
| `[scope]` | dozwolone sieci i porty, limit ruchu (dane od organizatora laboratorium) |
| `[limits]` | `nmap --max-rate`, równoległe procesy nmap, limity zapytań HTTP |
| `[[schedule.windows]]` | okna czasowe skanowania (`HH:MM`, mogą przechodzić przez północ) |
| `[stability]` | K przebiegów do statusu „nieaktywny”, N ponowień, odstęp ponowień |

### Środowisko testowe (D3)

Wartości w sekcji `[scope]` pliku przykładowego są **zastępcze**. Przed pierwszym
skanem wpisz do `sztygar.toml` adresację kontenerów laboratorium, dozwolone porty
i limity ruchu z regulaminu organizatora.

## Weryfikacja (to samo robi CI)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Instrukcja testów ręcznych w Neovimie: [`docs/testowanie-neovim.md`](docs/testowanie-neovim.md).

## Zasady rozwoju

Wytyczne dla kolejnych etapów: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).
