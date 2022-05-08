# Generate an OpenPGP/OpenSSH key from a BIP39 mnemonic

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![build](https://github.com/jpdarago/bip39key/actions/workflows/rust.yml/badge.svg)

> :warning: **EXPERIMENTAL:** Do not use for anything serious (like your actual production keys!).

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

```
USAGE:
    bip39key [OPTIONS] --user-id <USER_ID>

OPTIONS:
    -a, --armor
            Output as armored

    -f, --format <FORMAT>
            Output format: SSH or PGP [default: pgp] [possible values: pgp, ssh]

    -h, --help
            Print help information

    -j, --just-signkey
            Only output the sign key for PGP

    -o, --output-filename <OUTPUT_FILENAME>
            Filename where to output the keys, if not present then write to stdout

    -p, --passphrase <PASSPHRASE>
            Optional passphrase. See README.md for details

    -t, --timestamp <TIMESTAMP>
            Timestamp (in seconds) for the dates. If unset, use the default 1231006505

    -u, --user-id <USER_ID>
            RFC 2822 of the user, e.g. "User <user@email.com>"

    -V, --version
            Print version information
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

Optionally, you can provide a passphrase. `bip39key`
will generate a second buffer from that passphrase using Argon2id and then XOR
that buffer against the 512 bits buffer generated from the seed.

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out!
