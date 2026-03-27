# Generate an OpenPGP/OpenSSH key from a BIP39 mnemonic

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![build](https://github.com/jpdarago/bip39key/actions/workflows/rust.yml/badge.svg)

Generates a cryptographical key from a [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic (and, optionally, a
passphrase).

It can generate either

* An OpenPGP EdDSA signing key + ECCDH encryption key, both using Curve25519.
* An OpenPGP EdDSA signing key with Curve25519.
* An OpenSSH key using EdDSA with Curve25519.

In all cases the tool requires a User ID in [RFC 2822](https://datatracker.ietf.org/doc/html/rfc2822) format.

When providing a passphrase, the tool will use it to generate the key together
with the seed from the BIP39 mnemonic and the user id, and will also encrypt the 
resulting OpenPGP/OpenSSH keys with  the provided passphrase.

The creation timestamp for the OpenPGP keys is set to the Bitcoin genesis block
timestamp (1231006505 in seconds from Unix epoch). GPG considers this part of
the key so it is important to keep it consistent. We use that timestamp because
it's easy to retrieve, and it's not zero (which can trigger bad corner cases in
GPG).

## Usage

```
Usage: bip39key [OPTIONS] --user-id <USER_ID>

Options:
  -u, --user-id <USER_ID>
          RFC 2822 of the user, e.g. "User <user@email.com>"
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
  -n, --skip-passphrase-for-key-material
          Do not add the passphrase as extra entropy. If set, the passphrase will only be
          used to encrypt the PGP or SSH key contents, and the key material itself will be
          generated from the seed and the user id
  -h, --help
          Print help
  -V, --version
          Print version
```

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

> :warning: **Breaking change in v2.0:** The default algorithm will change from
> `xor` to `hkdf`. If you have existing keys generated without `--algorithm`,
> they were created with `xor`. To ensure you can always regenerate them, pass
> `--algorithm xor` explicitly. New keys should use `--algorithm hkdf`.

The passphrase is also used to encrypt the OpenPGP and SSH files themselves. If
you want to keep that encryption but not use the passphrase as additional entropy,
then pass the `--skip-passphrase-for-key-material/-n` option.

> :warning: The `xor` algorithm has a weakness: if an attacker obtains your
> passphrase and output key, they can recover the hashed seed via XOR and
> attempt to brute force the input phrase. While this is very difficult due to
> 128 bits of entropy and Argon2id's computational cost, both `concat` and
> `hkdf` avoid this issue entirely.

## Running tests.

This project uses the https://nixos.org/ package manager with https://devenv.sh, 
once you install those you can run the tests with `devenv test`.

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out!
