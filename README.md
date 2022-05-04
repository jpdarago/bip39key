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

## Entropy source

The BIP39 seed is expanded from 128/256 bits to 512 bits using Argon2id, with
the User ID as the salt.

## Acknowledgements

A very significant part of the implementation is based on [passphrase2pgp](https://github.com/skeeto/passphrase2pgp).

Check that project out! It has a lot more functionality than this project at the
moment.
