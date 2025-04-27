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
with the seed from the BIP39 mnemonic, and will also encrypt the resulting OpenPGP/OpenSSH keys with
the provided passphrase.

The creation timestamp for the OpenPGP keys is set to the Bitcoin genesis block
timestamp (1231006505 in seconds from Unix epoch). GPG considers this part of
the key so it is important to keep it consistent. We use that timestamp because
it's easy to retrieve, and it's not zero (which can trigger bad corner cases in
GPG).

## Usage

> :warning: New users of `bip39key` should use `-c` option.

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
  -c, --use-concatenation
          Use a hash of the concatenation of key and password instead of XOR of the hashes
  -q, --interactive
          Request seed phrase through an interactive CLI prompt
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

## Entropy source

The BIP39 seed is expanded from 128/256 bits to 512 bits using Argon2id, with
the User ID as the salt.

Optionally, you can provide a passphrase. `bip39key` will then:

1. If using the `--use-concatenate/-c` option, it will concatenate the seed
with the passphrase, and then apply Argon2id to the result to produce the
key.
2. Apply Argon2id to the seed, then to the passphrase, and then XOR both buffers.

> :warning:: You should prefer to use the `-c` option: with the XOR algorithm,
> if the attacker gets your passphrase and output key, they can get the hashed seed
> through an XOR and then attempt to brute force the input phrase. It is very hard
> to do due to 128 bits of the input and the CPU intensive properties of Argon2id,
> but concatenating both is better since the input phrase is no longer in any well
> known format that could have been precomputed.

## Running tests.

Ensure that `gpg` and `ssh-keygen` are installed.

You can then use [`pipenv`](https://pipenv.pypa.io/en/latest/) to run the tests.

```sh
$ pipenv run ./test/test.py
```

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out!
