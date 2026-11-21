# DScan

Aplikacja w Rust rozwijana etapami, uruchamiana natywnie na hoście.

## Wymagania

- Rust (stable) z `cargo`

## Uruchomienie

```bash
cargo run --release
```

## Weryfikacja

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
cargo build --release
```

## Zasady rozwoju

Wytyczne dla kolejnych etapów: [`.claude/skills/rust-senior-engineer/SKILL.md`](.claude/skills/rust-senior-engineer/SKILL.md).
