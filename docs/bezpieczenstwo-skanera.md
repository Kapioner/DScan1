# Bezpieczeństwo skanera (Q5)

DScan wykrywa i inwentaryzuje usługi — nie atakuje ich. Zasady są wymuszone w kodzie, nie tylko opisane.

| Zasada | Gdzie w kodzie |
|---|---|
| nmap tylko `-sn` (hosty) albo `-sV` (usługi); żadnych skryptów NSE (`--script`, `-sC`, `-A`), więc brak exploitów, brute force i prób logowania | `crates/scanner/src/safety.rs` (`check_nmap_args` przed każdym uruchomieniem nmap) |
| Brak fałszowania źródła i omijania zapór (`-S`, `-D`, `--spoof-mac`, `-f`, `--data`, `--badsum`) | jw. |
| Zawsze limit tempa `--max-rate` dzielony między procesy i ograniczony przepustowością `[scope] max_bandwidth_kbps` | `crates/engine/src/options.rs`, `check_nmap_args` |
| Skanowane wyłącznie cele z `[scope] allowed_networks`; sieć częściowo poza zakresem jest pomijana | `crates/scanner/src/targets` |
| Porty profili (TOML i baza) muszą mieścić się w `[scope] allowed_ports` | `crates/engine/src/launch.rs` (`ports_within`) |
| HTTP: tylko GET, bez wysyłania haseł i ciasteczek, bez formularzy, przekierowania tylko w obrębie hosta, limit zapytań na host i globalny | `crates/fingerprint/src/client.rs`, `probe.rs` (`is_safe_probe_path`), `rate_limit.rs` |
| Sondowane ścieżki: bez `..`, bez parametrów zapytania, najwyżej `max_probes_per_service` | `crates/fingerprint/src/probe.rs` |
| Powtórne pomiary (S10) tylko znanych hostów, z odstępem i limitem prób | `crates/engine/src/retry.rs` |
| Zależności sprawdzane `cargo audit` w CI (baza RustSec) | `.github/workflows/ci.yml`, zadanie `audit` |

Ręcznie: `cargo install cargo-audit && cargo audit`.
