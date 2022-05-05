# Generate an OpenPGP/OpenSSH key from a BIP39 mnemonic

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![build](https://github.com/jpdarago/bip39key/actions/workflows/rust.yml/badge.svg)

> :warning: **EXPERIMENTAL:** Do not use for anything serious (like your actual production keys!).

Generates a cryptographical key from a BIP39 key.

It can generate either

* An OpenPGP EdDSA signing key + ECCDH encryption key, both using Curve25519.
* An OpenPGP EdDSA signing key with Curve25519.
* An OpenSSH key using EdDSA with Curve25519.

In all cases requires a User ID in [RFC 2822](https://datatracker.ietf.org/doc/html/rfc2822) format.

## Why BIP39

[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) is a
mnemonic code for the generation of deterministic wallets. This format consists
of a few words (up to 24) from a special dictionary that contains no ambiguous
characters or words than can be confused with each other. It also includes a
checksum to ensure that it was written on paper properly.

Using a BIP39 mnemonic instead of a passphrase allows for easier, safer backups
(because of the checksum and dictionary design) and ensures a consistent amount
of entropy is provided to the program. A passphrase's entropy depends on the
algorithm used to generate the passphrase, and the passphrase length. Too short
a passphrase can make the resulting key weak.

## Entropy source

The BIP39 seed is expanded from 128/256 bits to 512 bits using Argon2id, with
the User ID as the salt.

Optionally, you can provide a passphrase. `bip39key`
will generate a second buffer from that passphrase using Argon2id and then XOR
that buffer against the 512 bits buffer generated from the seed.

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out!
