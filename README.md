# DScan

Narzędzie do skanowania i inwentaryzacji usług sieciowych, napisane w Rust
i uruchamiane natywnie na hoście. Binarka: `dscan`.

> Nazwa: **DScan** = *Defect Scan*.
> Uwaga: crate o nazwie `dscan` istnieje już na crates.io, a na GitHubie są inne
> projekty o tej nazwie. Nie przeszkadza to w budowaniu i używaniu narzędzia;
> przy ewentualnej publikacji na crates.io trzeba by użyć innej nazwy pakietu.

## Struktura workspace

| Crate | Katalog | Odpowiedzialność |
|---|---|---|
| `dscan-core` | `crates/core` | Model domeny: `Target`, `Host`, `Service`, `HttpInfo`, `Detection`, `ScanRun`, `Change` (serde) |
| `dscan-config` | `crates/config` | Konfiguracja: TOML + zmienne `DSCAN_*`, walidacja, klucz szyfrowania z env |
| `dscan-scanner` | `crates/scanner` | Skaner (nmap, podgrupy, limity), *w przygotowaniu* |
| `dscan-fingerprint` | `crates/fingerprint` | Fingerprinting HTTP/TLS i sygnatury, *w przygotowaniu* |
| `dscan-api` | `crates/api` | REST API (axum) + RBAC, *w przygotowaniu* |
| `dscan-web` | `crates/web` | UI (askama + htmx), *w przygotowaniu* |
| `dscan` | `crates/cli` | Binarka `dscan` |

## Uruchomienie (jedna komenda)

```bash
./run.sh
```

Skrypt przy pierwszym uruchomieniu tworzy `dscan.toml` (kopia `dscan.example.toml`)
i generuje klucz szyfrowania w `.env`. Potem za każdym razem wczytuje `.env`,
buduje wersję release (przyrostowo, więc szybko) i uruchamia binarkę.
Argumenty przekazuje dalej: `./run.sh inny.toml`.

> Plik `.env` z kluczem jest jedyną kopią klucza. Bez niego nie odczytasz zaszyfrowanych danych,
> więc zrób jego kopię zapasową. Oba pliki (`dscan.toml`, `.env`) są w `.gitignore`.

Wymagania: Rust (stable) z `cargo` oraz `bash` (Linux/macOS; na Windows przez WSL lub Git Bash).

Ręcznie, bez skryptu:

```bash
cargo run --release -- dscan.toml
```

Na razie program wypisuje efektywną konfigurację; podkomendy pojawią się w zadaniu C2.

## Konfiguracja

Kolejność ważności: **wartości domyślne < plik TOML < zmienne środowiskowe**.

- Plik: `dscan.toml` w bieżącym katalogu (lub ścieżka podana jako argument). Wszystkie pola opisuje [`dscan.example.toml`](dscan.example.toml).
- Zmienne: `DSCAN_<SEKCJA>__<POLE>`, np. `DSCAN_LIMITS__NMAP_MAX_RATE=50`,
  `DSCAN_SCOPE__ALLOWED_PORTS='["22","80"]'`.
- **Klucz szyfrowania** podaje się wyłącznie przez `DSCAN_ENCRYPTION_KEY` (64 znaki hex). Wpis w TOML jest odrzucany, a klucz nigdy nie jest wypisywany.
- Nieznane pola (literówki) kończą się błędem.

| Sekcja | Zawartość |
|---|---|
| `[scope]` | dozwolone sieci i porty, limit ruchu (dane od organizatora laboratorium) |
| `[limits]` | `nmap --max-rate`, równoległe procesy nmap, limity zapytań HTTP |
| `[[schedule.windows]]` | okna czasowe skanowania (`HH:MM`, mogą przechodzić przez północ) |
| `[stability]` | K przebiegów do statusu „nieaktywny”, N ponowień, odstęp ponowień |

### Środowisko testowe (D3)

Wartości w sekcji `[scope]` pliku przykładowego są **zastępcze**. Przed pierwszym
skanem wpisz do `dscan.toml` adresację kontenerów laboratorium, dozwolone porty
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
