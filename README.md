# bip39pgp - Generate an OpenPGP key from a BIP39 mnemonic

> :warning: **EXPERIMENTAL:** Do not use for anything serious (like your actual production keys!).

Generates an OpenPGP EdDSA signing key and ECCDH encryption subkey from a BIP39
mnemonic.

## Caveats

* Requires an RFC 2822 User Id provided with the `-u` flag.
* Sets the creation timestamp (and all timestamps) to the Bitcoin genesis block.
* Expands entropy with one call of Argon with default settings.
