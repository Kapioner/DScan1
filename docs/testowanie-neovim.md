# Testowanie etapu D1/C1/D3/D5/S1 w Neovimie

Aplikacja: **DScan** (*Defect Scan*), binarka `dscan`.

Wszystkie polecenia wykonujesz w Neovimie otwartym w katalogu głównym repozytorium:

```bash
cd DScan && nvim .
```

`:!polecenie` uruchamia polecenie powłoki i pokazuje wynik. `:terminal` otwiera
pełny terminal (wyjście z trybu wpisywania: `Ctrl-\ Ctrl-n`).

## 1. Workspace i CI (D1)

1. `:!cargo metadata --no-deps --format-version 1 | grep -o '"name":"dscan[a-z-]*"'`
   → 7 crate'ów: `dscan`, `dscan-core`, `dscan-config`, `dscan-scanner`,
   `dscan-fingerprint`, `dscan-api`, `dscan-web`.
2. `:!cargo fmt --all -- --check` → brak wyjścia.
3. `:!cargo clippy --workspace --all-targets -- -D warnings` → bez ostrzeżeń.
4. `:!cargo test --workspace 2>&1 | grep "test result"` → każdy wiersz `ok`, 0 failed.
5. `:e .github/workflows/ci.yml` i sprawdź trzy kroki: fmt, clippy, test.
   Po wypchnięciu na GitHub zobacz zakładkę **Actions**: zadanie „CI” ma być zielone.

## 2. Nazwa (C1) i uruchomienie jedną komendą

1. `:!cargo build --release && ls target/release/dscan` → plik binarny `dscan` istnieje.
2. **Pierwsze uruchomienie:** usuń lokalne pliki, żeby zasymulować świeże repo:
   `:!rm -f dscan.toml .env`, potem `:!./run.sh`. Oczekiwane:
   - komunikaty `[run.sh] Utworzono dscan.toml...` i `[run.sh] Wygenerowano klucz...`,
   - pierwsza linia wyjścia `DScan v0.1.0`, a niżej `Klucz szyfrowania: ustawiony (wartość ukryta)`.
3. **Kolejne uruchomienie:** `:!./run.sh` → bez komunikatów `[run.sh]`, ten sam wynik.
4. `:e .env` → jedna linia `DSCAN_ENCRYPTION_KEY=` i 64 znaki hex. `:!ls -l .env` → uprawnienia `-rw-------`.
5. Przekazywanie argumentów: `:!./run.sh brak.toml` → `Błąd: plik konfiguracyjny nie istnieje: brak.toml`.

## 3. Konfiguracja: plik, env, klucz (D5)

1. `:!cp dscan.example.toml dscan.toml`, a potem `:e dscan.toml`.
2. `:!cargo run -q --release` → wypisuje `Plik konfiguracji: dscan.toml`, `Klucz szyfrowania: brak`
   i wartości z pliku (np. `nmap_max_rate: 100`).
3. **Plik nadpisuje wartości domyślne:** w buforze zmień `nmap_max_rate = 100` na `25`, zapisz (`:w`),
   uruchom `:!cargo run -q --release | grep nmap_max_rate` → `25`.
4. **Env nadpisuje plik:** `:!DSCAN_LIMITS__NMAP_MAX_RATE=50 cargo run -q --release | grep nmap_max_rate` → `50`.
5. **Klucz tylko z env i ukryty:**
   `:!DSCAN_ENCRYPTION_KEY=$(openssl rand -hex 32) cargo run -q --release | grep Klucz`
   → `ustawiony (wartość ukryta)`. W wyjściu nie może pojawić się wartość klucza.
6. **Klucz w TOML jest odrzucany:** dopisz na początku pliku (`gg`, `O`)
   `encryption_key = "aa"`, zapisz, uruchom `:!cargo run -q --release`
   → `Błąd: ... unknown field: found 'encryption_key'`. Cofnij zmianę (`u`, `:w`).
7. **Literówka w polu:** zmień `nmap_max_rate` na `nmap_maxrate`, zapisz, uruchom → błąd `unknown field`. Cofnij.
8. **Walidacja wartości** (po każdej próbie cofnij zmianę przez `u` i `:w`):
   - port `"70000"` w `allowed_ports` → `niepoprawny zakres portów '70000'`,
   - `end = "25:00"` w oknie → `niepoprawna godzina '25:00'`,
   - `max_parallel_nmap = 0` → `ustawienie 'limits.max_parallel_nmap' musi być większe od zera`,
   - `allowed_networks = ["10.0.0.0/33"]` → błąd parsowania sieci.
9. **Zły klucz:** `:!DSCAN_ENCRYPTION_KEY=abc cargo run -q --release` → `oczekiwano 64 znaków hex`.
10. **Brak wskazanego pliku:** `:!cargo run -q --release -- brak.toml` → `plik konfiguracyjny nie istnieje`.

## 4. Środowisko testowe (D3)

1. `:e dscan.toml` i w sekcji `[scope]` wpisz dane od organizatora:
   `allowed_networks` (sieć kontenerów), `allowed_ports`, `max_bandwidth_kbps`;
   w `[limits]` wpisz `nmap_max_rate` zgodny z regulaminem.
2. `:!cargo run -q --release` → wartości z regulaminu widoczne w wyjściu, brak błędów.
3. Sprawdź, czy kontenery laboratorium odpowiadają (poza Neovimem albo przez `:terminal`), np.:
   `ping -c1 <adres-kontenera>`. **Nie skanuj nmapem** niczego spoza dozwolonej listy.

## 5. Model domeny (S1)

1. `:!cargo test -p dscan-core` → wszystkie testy `ok`.
2. Przejrzyj typy: `:e crates/core/src/models/mod.rs`. Na nazwie typu `gd`
   (z LSP rust-analyzer) przenosi do definicji, a `K` pokazuje dokumentację.
3. Szybki test serializacji JSON w osobnym buforze nie jest potrzebny, bo pokrywają ją testy
   `*_survives_json_round_trip` i `change_kind_serializes_as_snake_case`.
   Pojedynczy test uruchomisz tak: `:!cargo test -p dscan-core round_trip`.

## Na koniec

`:!rm dscan.toml`, jeśli nie chcesz zostawiać lokalnej konfiguracji (plik i tak jest w `.gitignore`).
`.env` z kluczem zostaw — `./run.sh` będzie go używać przy każdym starcie.
