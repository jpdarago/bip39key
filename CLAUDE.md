# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bip39key generates deterministic OpenPGP (EdDSA/ECDH Curve25519) and OpenSSH (Ed25519) keys from BIP39 or Electrum mnemonic seed phrases. It uses Argon2id to expand the seed entropy, with the user ID as salt. An optional passphrase can be combined via concatenation (`-c`, preferred) or XOR (legacy) before key derivation.

## Build & Development

This project uses [Nix](https://nixos.org/) with [devenv](https://devenv.sh/) for development tooling. Enter the dev environment with `devenv shell`.

```bash
cargo build --release       # Build release binary (required before tests)
cargo clippy -- -D warnings # Lint
cargo fmt --all -- --check  # Format check
cargo fmt                   # Auto-format
devenv test                 # Run integration tests (builds release + runs test/test.py)
python3 test/test.py        # Run integration tests directly (requires release build)
```

There are no Rust unit tests. All tests are integration tests in `test/test.py` (Python/unittest) that build the release binary, then exercise it end-to-end against GPG and ssh-keygen. Golden test files (`test/message-*.gpg`) contain encrypted messages that must decrypt correctly with known seed/passphrase combos.

## Pre-commit Hooks

devenv configures git hooks for `rustfmt`, `clippy`, and `black` (Python formatter).

## Architecture

- **`main.rs`** — CLI entry point (clap). Parses args, reads seed (stdin/file/interactive prompt), gets passphrase, generates keys, writes output.
- **`keys.rs`** — Core key derivation. `Keys::new_with_concat` (preferred) and `Keys::new_with_xor` (legacy) run Argon2id to expand seed+passphrase into 64 bytes, split into sign key (first 32) and encrypt key (last 32). `KeySettings` holds all derivation parameters.
- **`pgp.rs`** — OpenPGP v4 packet serialization. Handles packet encoding, MPI format, S2K passphrase encryption (AES-256-CFB), self-signatures, subkey binding signatures, and ASCII armor output. Implements RFC 4880 directly without external PGP libraries.
- **`ssh.rs`** — OpenSSH private/public key serialization. Handles the `openssh-key-v1` format with optional AES-256-CTR encryption via bcrypt-pbkdf.
- **`seed.rs`** — BIP39 and Electrum seed phrase parsing/validation. Includes interactive prompt with autocomplete and Levenshtein-based typo suggestions. Wordlist bundled from `resources/bip39.txt`, overridable via `WORDLIST_BIP39` env var.
- **`passphrase.rs`** — Passphrase input via pinentry subprocess (configurable with `BIP39_PINENTRY` env var) or interactive terminal prompt.
- **`console.rs`** — Terminal detection and `console_logln!` macro that suppresses output when not on a TTY. `NO_INTERACTIVE_OUTPUT=1` forces non-interactive mode.
- **`types.rs`** — Type aliases (`Result<T>`, `ByteCursor`).

## Key Design Details

- The default creation timestamp is the Bitcoin genesis block (1231006505). GPG treats this as part of the key fingerprint, so it must remain consistent.
- PGP packet construction follows GPG's actual behavior, not always the RFC spec (see S2K implementation note from passphrase2pgp).
- Curve25519 encrypt keys require clamping per RFC 7748. Sign keys use Ed25519 directly.
