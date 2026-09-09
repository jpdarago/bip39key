# Generate an OpenPGP/OpenSSH key from a BIP39 mnemonic

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![build](https://github.com/jpdarago/bip39key/actions/workflows/rust.yml/badge.svg)

> :warning: **Disclaimer:** This software was not written by a cryptography
> expert. It is provided as-is, with no warranty or guarantee of correctness or
> security. **Use at your own risk.** You are strongly advised to review the code
> and understand its limitations before using it to generate keys for any
> purpose.

> :warning: **Breaking change in v2.0:** The default key derivation algorithm
> will change from `xor` to `hkdf`. If you have existing keys generated without
> the `--algorithm` flag, they were created with `xor`. To ensure you can always
> regenerate them, pass `--algorithm xor` explicitly. New keys should use
> `--algorithm hkdf`.

Generates a cryptographical key from a [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic (and, optionally, a
passphrase).

It can generate either

* An OpenPGP EdDSA signing key + ECCDH encryption key, both using Curve25519.
* An OpenPGP EdDSA signing key with Curve25519.
* An OpenSSH key using EdDSA with Curve25519.

In all cases the tool requires a User ID in [RFC 2822](https://datatracker.ietf.org/doc/html/rfc2822) format.

When providing a passphrase, the tool will use it to generate the key together
with the seed from the BIP39 mnemonic and the user id, and will also encrypt the 
resulting OpenPGP/OpenSSH keys with the provided passphrase.

The creation timestamp for the OpenPGP keys is set to the Bitcoin genesis block
timestamp (1231006505 in seconds from Unix epoch). GPG considers this part of
the key so it is important to keep it consistent. We use that timestamp because
it's easy to retrieve, and it's not zero (which can trigger bad corner cases in
GPG).

## Usage

```
Usage: bip39key [OPTIONS]

Options:
  -u, --user-id <USER_ID>
          RFC 2822 of the user, e.g. "User <user@email.com>".
          Required unless --from-receipt is set
  -i, --input-filename <INPUT_FILENAME>
          Filename from which to read the mnemonic words
  -o, --output-filename <OUTPUT_FILENAME>
          Filename where to output the keys, if not present then write to stdout
  -d, --creation-timestamp <CREATION_TIMESTAMP>
          Creation timestamp (as unix timestamp in seconds). If unset, uses the genesis block (1231006505)
  -y, --expiration-timestamp <EXPIRATION_TIMESTAMP>
          Creation timestamp (as unix timestamp in seconds). If unset, the keys do not expire
  -j, --just-signkey
          Only output the sign key for PGP
  -f, --format <FORMAT>
          Output format: SSH or PGP [default: pgp] [possible values: pgp, ssh]
  -a, --armor
          Output as armored
  -k, --public-key
          Output the public key
  -p, --passphrase <PASSPHRASE>
          Optional passphrase. If set, -e/--pinentry must not be set. See README.md for details
  -e, --pinentry
          Request passphrase with pinentry. See README.md for details
  -s, --seed-format <SEED_FORMAT>
          Seed Format: BIP39, Electrum [default: bip39] [possible values: bip39, electrum]
  -g, --algorithm <ALGORITHM>
          Key derivation algorithm: xor (legacy default), concat, hkdf (recommended for new keys).
          Use --algorithm hkdf for new keys. Defaults to xor for backward compatibility.
          [default: xor] [possible values: xor, concat, hkdf]
  -r, --use-rfc9106-settings
          Use RFC 9106 settings for Argon2id
  -b, --authorization-for-sign-key
          Add authorization capability to the sign key
      --auth-subkey
          Generate a separate authentication subkey (requires --algorithm hkdf)
  -n, --skip-passphrase-for-key-material
          Do not add the passphrase as extra entropy. If set, the passphrase will only be
          used to encrypt the PGP or SSH key contents, and the key material itself will be
          generated from the seed and the user id
      --output-receipt <FILE>
          Write an HTML recovery receipt to this file. The receipt records the derivation
          parameters, key fingerprints, and build provenance — but no secrets — so the key
          can be regenerated from the mnemonic later
      --from-receipt <FILE>
          Regenerate a key from a receipt file (HTML receipt or raw receipt string). The
          receipt supplies the user ID and all derivation parameters; only the mnemonic
          (and passphrase, if used) is prompted. The regenerated key's fingerprint is
          checked against the receipt. Cannot be combined with flags the receipt already
          supplies
  -h, --help
          Print help
  -V, --version
          Print version
```

## Recovery receipts

A receipt is a self-contained HTML disaster-recovery document for a generated
key. It records everything needed to regenerate the key — user ID, seed
format, derivation algorithm, Argon2id parameters, timestamps, key structure —
plus the key fingerprints, a QR code of the compact receipt string, and build
provenance (version, git commit, binary SHA-256, reproducible build
instructions). It contains **no secrets**: the mnemonic, passphrase, and key
material are never written to it, so it is safe to store in cloud storage,
email, or print. It does tell anyone who reads it exactly how the key was
derived (and whether a passphrase was involved), so the mnemonic must stay
secret on its own; the receipt is a recovery aid, not a second factor.

Generate a key and its receipt:

```sh
bip39key -g hkdf -u "Alice <alice@example.com>" -i seed.txt -o key.gpg \
    --output-receipt receipt.html
```

Years later, regenerate the same key from the receipt and the mnemonic:

```sh
bip39key --from-receipt receipt.html -o key.gpg
```

The receipt supplies the user ID and every derivation flag; only the mnemonic
(and passphrase, if one was used) is needed. Flags the receipt already covers
(`-u`, `-g`, `-s`, `-r`, `-b`, `-j`, `-f`, `-d`, `-y`, `-n`, `--auth-subkey`)
are rejected alongside `--from-receipt` rather than silently ignored. The
regenerated key's fingerprint is checked against the one stored in the
receipt, so entering the wrong seed phrase or passphrase fails loudly instead
of silently producing a different key. If the receipt file is lost but the
receipt string (or its QR code) was saved elsewhere, `--from-receipt` also
accepts a file containing just the receipt string, e.g.
`bip39key:1:bip39:withpass:hkdf:Alice <alice@example.com>:ABCD`. A bare
receipt string carries no fingerprint, so that path prints a warning and
cannot verify the result; compare the printed fingerprint yourself. User IDs
must not contain `:` when a receipt is written, since the receipt string is
colon-separated.

## Why BIP39

[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) is a
mnemonic code for the generation of deterministic wallets for Bitcoin and other
cryptocurrencies. This format consists of a few words (up to 24) from a special
dictionary that contains no ambiguous characters or words than can be
confused with each other. It also includes a checksum to ensure that it
was backed up properly.

Using a BIP39 mnemonic instead of a passphrase allows for easier, safer backups
(because of the checksum and dictionary design) and ensures a consistent amount
of entropy is provided. A passphrase's entropy depends on the algorithm used
to generate the passphrase, and the passphrase length. Too short a passphrase
can make the resulting key weak.

## Wordlist source

The binary bundles the BIP39 english wordlist, available in the repo in [resources/bip39.txt](`https://github.com/jpdarago/bip39key/blob/main/resources/bip39.txt`).

If you want to override the wordlist, you can use the env var `WORDLIST_BIP39`.

IMPORTANT: It must be in the same format as the one above (one word per line).

## Entropy source

The BIP39 seed is expanded from 128/256 bits to 512 bits using Argon2id, with
the User ID as the salt.

Optionally, you can provide a passphrase. The `--algorithm` flag controls how
the seed and passphrase are combined:

* **`xor`** (current default) — Applies Argon2id separately to the seed and
  passphrase, then XORs the results.
* **`concat`** — Concatenates the seed and passphrase, applies Argon2id, and
  splits the output at a fixed offset into sign and encrypt keys.
* **`hkdf`** (recommended for new keys) — Concatenates the seed and passphrase,
  applies Argon2id, then uses HKDF-Expand (RFC 5869) with distinct info strings
  (`bip39key-sign-v1` and `bip39key-encrypt-v1`) to derive independent sign and
  encrypt keys. This provides proper domain separation between key types.

The passphrase is also used to encrypt the OpenPGP and SSH files themselves. If
you want to keep that encryption but not use the passphrase as additional entropy,
then pass the `--skip-passphrase-for-key-material/-n` option.

> :warning: The `xor` algorithm has a weakness: if an attacker obtains your
> passphrase and output key, they can recover the hashed seed via XOR and
> attempt to brute force the input phrase. While this is very difficult due to
> 128 bits of entropy and Argon2id's computational cost, both `concat` and
> `hkdf` avoid this issue entirely.

## Installing shell completions and manpage

Building the project generates shell completions and a manpage automatically
(in `completions/` and `man/`). Below are instructions for installing them.

### NixOS

If you package bip39key in a Nix derivation, add the completions and manpage
to the install phase:

```nix
postInstall = ''
  installShellCompletion --bash completions/bip39key.bash
  installShellCompletion --zsh completions/bip39key.zsh
  installManPage man/bip39key.1
'';
```

For a standalone install without a derivation:

```bash
# Bash
cp completions/bip39key.bash ~/.local/share/bash-completion/completions/bip39key

# Zsh
cp completions/bip39key.zsh ~/.local/share/zsh/site-functions/_bip39key

# Manpage
sudo cp man/bip39key.1 /run/current-system/sw/share/man/man1/
# Or add to your home-manager or NixOS configuration instead.
```

### Debian/Ubuntu

```bash
# Bash
sudo cp completions/bip39key.bash /usr/share/bash-completion/completions/bip39key

# Zsh
sudo cp completions/bip39key.zsh /usr/share/zsh/vendor-completions/_bip39key

# Manpage
sudo cp man/bip39key.1 /usr/local/share/man/man1/
sudo mandb
```

### macOS

```bash
# Bash (requires bash-completion from Homebrew)
cp completions/bip39key.bash $(brew --prefix)/etc/bash_completion.d/bip39key

# Zsh
cp completions/bip39key.zsh $(brew --prefix)/share/zsh/site-functions/_bip39key

# Manpage
cp man/bip39key.1 /usr/local/share/man/man1/
```

## Running tests

Tests are Rust integration tests that exercise the binary end-to-end against GPG
and ssh-keygen. They require `gpg` and `ssh-keygen` to be installed.

```bash
cargo test --release --test integration
```

If using [Nix](https://nixos.org/) with [devenv](https://devenv.sh), you can also run `devenv test`.

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out!
