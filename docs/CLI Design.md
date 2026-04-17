# CLI Design

**Parent:** [[bip39key v2 Design Doc]]

---

## Philosophy

v1's flat flag namespace grew to 16+ flags with hidden deprecated aliases and mutually exclusive combinations that aren't enforced. v2 uses subcommands to group related functionality and eliminate ambiguity.

---

## Subcommand Overview

```
bip39key <subcommand> [options]
```

| Subcommand | Purpose |
|---|---|
| `generate` | Generate a key pair (default if no subcommand given) |
| `verify` | Check that a seed produces an expected fingerprint |
| `receipt` | Decode and display a receipt string |

Running `bip39key` with no subcommand is equivalent to `bip39key generate`.

---

## `generate`

The primary command. Produces a private or public key.

### Required

| Flag | Description |
|---|---|
| `-u, --user-id <ID>` | RFC 2822 user identity, e.g. `"Alice <alice@example.com>"` |

### Derivation

| Flag | Default | Description |
|---|---|---|
| `--algorithm <alg>` | `hkdf` | `hkdf` or `concat` |
| `--seed-format <fmt>` | `bip39` | `bip39` or `electrum` |
| `--no-passphrase-derivation` | off | Passphrase only encrypts the output file, not the key material |

### Timestamps

| Flag | Default | Description |
|---|---|---|
| `--created <unix>` | `1231006505` | Key creation timestamp (Bitcoin genesis) |
| `--expires <unix>` | none | Key expiration timestamp |

### Output

| Flag | Default | Description |
|---|---|---|
| `-f, --format <fmt>` | `pgp` | `pgp` or `ssh` (`age` planned for v2.1) |
| `-a, --armor` | off | ASCII armor output (PGP only) |
| `-k, --public-key` | off | Output public key instead of private |
| `-o, --output <file>` | stdout | Write to file |

### Input

| Flag | Default | Description |
|---|---|---|
| `-i, --input <file>` | stdin/prompt | Read seed from file |
| `-p, --passphrase <pass>` | prompted | Provide passphrase on command line |
| `-e, --pinentry` | off | Use pinentry program for passphrase |

### PGP-specific

| Flag | Default | Description |
|---|---|---|
| `--sign-only` | off | Omit encryption subkey |
| `--authorize` | off | Add authorization capability to sign key |

### Receipt integration

| Flag | Description |
|---|---|
| `--from-receipt <string>` | Parse receipt and set all derivation flags. Overrides individual flags. |

---

## `verify`

Derives the key and compares the fingerprint without outputting any secret material.

```
bip39key verify -u "Alice <alice@example.com>" --fingerprint "67EA E069 ..."
```

| Flag | Description |
|---|---|
| `-u, --user-id <ID>` | Required. User identity. |
| `--fingerprint <fp>` | Expected PGP fingerprint or SSH public key hash. |
| `--from-receipt <string>` | Use receipt for derivation parameters. |
| `-f, --format <fmt>` | `pgp` or `ssh` (determines fingerprint format). |

Exit codes:
- `0` -- fingerprint matches.
- `1` -- fingerprint does not match.
- `2` -- error (bad seed, missing input, etc.).

---

## `receipt`

Decodes a receipt string and prints human-readable derivation parameters.

```
bip39key receipt "bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:7B2F:A3B7"
```

Output:
```
Version:      2
Algorithm:    HKDF (with domain separation)
Seed format:  BIP39
Argon2id:     RFC 9106 (2 GiB memory, 1 iteration, 4 lanes)
Created:      2009-01-03T18:15:05Z (Bitcoin genesis)
Expires:      never
Auth cap:     no
Passphrase:   used in key derivation
Checksum:     A3B7 (valid)
```

---

## Flag Elimination Summary

| v1 flag | v2 equivalent | Notes |
|---|---|---|
| `-c, --use-concatenation` | `--algorithm concat` | Redundant with `--algorithm` |
| `-r, --use-rfc9106-settings` | default behavior | RFC 9106 is the only option |
| `-t, --timestamp` | `--created` | Clearer name |
| `-q, --interactive` | auto-detected | Unnecessary flag |
| `-b, --authorization-for-sign-key` | `--authorize` | Shorter, clearer |
| `-g, --algorithm xor` | removed | Use v1.5.0 tag for XOR keys |
| `-n, --skip-passphrase-for-key-material` | `--no-passphrase-derivation` | Clearer name |
| `-j, --just-signkey` | `--sign-only` | Clearer name |
| `-s, --seed-format` | `--seed-format` | Kept, same name |
| `-d, --creation-timestamp` | `--created` | Shorter |
| `-y, --expiration-timestamp` | `--expires` | Shorter |
