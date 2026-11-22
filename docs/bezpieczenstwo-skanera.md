# DScan — bezpieczeństwo skanera

DScan wykrywa usługi, nie atakuje ich. Zasady są wymuszone w kodzie.

| Zasada | Kod |
|---|---|
| nmap tylko `-sn` / `-sV`; bez NSE (`--script`, `-sC`, `-A`) — brak exploitów, brute force, logowania | `crates/scanner/src/safety.rs` (`check_nmap_args`) |
| bez fałszowania źródła i omijania zapór (`-S`, `-D`, `--spoof-mac`, `-f`, `--data`, `--badsum`) | jw. |
| zawsze `--max-rate`, dzielony między procesy i ograniczony `max_bandwidth_kbps` | `crates/engine/src/options.rs` |
| tylko sieci z `[scope] allowed_networks`; sieć częściowo poza zakresem pomijana | `crates/scanner/src/targets` |
| porty profili w `[scope] allowed_ports` | `crates/engine/src/launch.rs` (`ports_within`) |
| HTTP tylko GET, bez haseł, ciasteczek, formularzy; przekierowania w obrębie hosta; limity zapytań | `crates/fingerprint/src/client.rs`, `probe.rs`, `rate_limit.rs` |
| ścieżki sond bez `..` i parametrów, max `max_probes_per_service` | `crates/fingerprint/src/probe.rs` |
| ponowne pomiary tylko znanych hostów, z limitem prób | `crates/engine/src/retry.rs` |
| `cargo audit` w CI | `.github/workflows/ci.yml` |
