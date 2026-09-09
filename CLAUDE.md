# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bip39key generates deterministic OpenPGP (EdDSA/ECDH Curve25519) and OpenSSH (Ed25519) keys from BIP39 or Electrum mnemonic seed phrases. It uses Argon2id to expand the seed entropy, with the user ID as salt. An optional passphrase can be combined via concatenation (`-c`, preferred) or XOR (legacy) before key derivation.

## Build & Development

This project uses [Nix](https://nixos.org/) with [devenv](https://devenv.sh/) for development tooling. Enter the dev environment with `devenv shell`.

```bash
cargo build --release                    # Build release binary
cargo clippy --all-targets -- -D warnings # Lint (test code included)
cargo fmt --all -- --check               # Format check
cargo fmt                                # Auto-format
cargo test --release                     # Run the whole suite
cargo test --release --lib               # Unit and property tests only (fast)
cargo test --release --test integration  # Integration tests only
devenv test                              # Run the whole suite (via devenv)
```

Tests come in two layers. `tests/integration.rs` exercises the binary end-to-end against GPG and ssh-keygen; these are slow, because each one pays for a real Argon2id derivation (4.0s on the default config, 1.6s on RFC 9106). Golden test files (`test/message-*.gpg`) contain encrypted messages that must decrypt correctly with known seed/passphrase combos.

Unit and property tests live in `#[cfg(test)]` modules inside the library (`src/pgp.rs`, `src/ssh.rs`, `src/seed.rs`, `src/passphrase.rs`) and run in microseconds, since they test the pure encoders rather than key derivation. `proptest` covers packet length headers, MPI encoding, the armor CRC-24, and the OpenSSH length-prefix framing and padding. Prefer adding coverage here when the behavior under test does not need a derived key.

### Golden vectors

`test/golden/*.golden` pins the exact bytes bip39key produces for each
combination of flags, covering both PGP and SSH across every algorithm, seed
format, subkey layout, and timestamp setting. Passphrase-protected secret
output is not pinned (S2K and bcrypt draw a random salt each run); those
combinations pin the deterministic *public* key instead, which still detects
any change in how the passphrase feeds derivation.

**A diff in `test/golden/` is a breaking change, not a test failure to fix.**
Those bytes are the keys existing users regenerate from their seed phrase. To
add a new vector, add it to the `golden_vectors!` table and run
`BIP39KEY_UPDATE_GOLDEN=1 cargo test --release --test integration`; only
regenerate existing files when the change in key material is itself the
intended, released change.

### Receipt tests

`receipt.rs` and `html_receipt.rs` have unit tests in the library.
`receipt::tests::test_encode_golden` pins the exact receipt string and its
checksum, so any change to the receipt format must bump the receipt version.

## Pre-commit Hooks

devenv configures git hooks for `rustfmt` and `clippy`.

## Architecture

- **`lib.rs`** — Library root. The modules below live here so tests can exercise them in process; `main.rs` is a thin wrapper over it.
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
