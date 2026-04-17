# Receipt System

**Parent:** [[bip39key v2 Design Doc]]

---

## Problem

Key material depends on ~8 parameters: algorithm, seed format, Argon2id settings, timestamps, passphrase role, authorization capability, and user ID. Forgetting any one produces a different key. Users generating a key today may need to recover it years later.

---

## Receipt Format

A compact, versioned, human-readable string emitted to stderr after every key generation.

```
bip39key:<version>:<algorithm>:<seed_format>:<created>:<expires>:<auth>:<pass_role>:<uid_hash>:<checksum>
```

### Fields

| Field | Values | Description |
|---|---|---|
| `version` | `2` | Receipt format version. Implicitly determines Argon2id params (v2 = RFC 9106). |
| `algorithm` | `hkdf`, `concat` | Key derivation algorithm |
| `seed_format` | `bip39`, `electrum` | Mnemonic format |
| `created` | Unix timestamp | Key creation time |
| `expires` | Unix timestamp or `0` | Expiration (0 = never) |
| `auth` | `auth`, `noauth` | Authorization capability on sign key |
| `pass_role` | `withpass`, `nopass`, `passonly` | How passphrase is used |
| `uid_hash` | 4 hex chars | Truncated SHA-256 of the user-id string |
| `checksum` | 4 hex chars | Truncated SHA-256 of all preceding fields |

Argon2id parameters are not in the receipt because they are fixed per version. Version `2` always means RFC 9106 (2 GiB / 1 iter / 4 lanes).

### User-ID Hash

The `uid_hash` field is the first 2 bytes (4 hex chars) of `SHA-256(user_id)`. Users usually remember their name and email, but the hash catches typos, encoding differences (e.g., trailing whitespace, different capitalization), and copy-paste errors. When `--from-receipt` is used, the tool computes the hash of the provided `--user-id` and warns if it doesn't match the receipt.

### Passphrase Role Values

| Value | Meaning |
|---|---|
| `withpass` | Passphrase is concatenated with seed before Argon2id (default when passphrase provided) |
| `nopass` | No passphrase was used |
| `passonly` | Passphrase only encrypts output (`--no-passphrase-derivation`) |

---

## Examples

Default generation with passphrase:
```
bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:7B2F:A3B7
```

Electrum seed, no passphrase:
```
bip39key:2:hkdf:electrum:1231006505:0:noauth:nopass:7B2F:F1C2
```

Custom timestamps, authorization, passphrase not in derivation:
```
bip39key:2:hkdf:bip39:1700000000:1800000000:auth:passonly:7B2F:8D4E
```

---

## Checksum

The checksum is the first 4 hex characters (2 bytes) of SHA-256 over the colon-joined preceding fields (including `uid_hash`):

```
SHA-256("bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:7B2F") -> first 2 bytes -> hex
```

This catches single-character transcription errors with high probability (~1/65536 false positive rate). Hex was chosen over base32 for simplicity -- the receipt already uses hex for `uid_hash`, so there's one fewer encoding to explain.

---

## Receipt Decoding

`bip39key receipt <string>` validates the checksum and prints a human-readable summary:

```
$ bip39key receipt "bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:7B2F:A3B7"

bip39key Derivation Receipt
  Version:      2
  Algorithm:    HKDF (with domain separation)
  Seed format:  BIP39
  Argon2id:     RFC 9106 (2 GiB memory, 1 iteration, 4 lanes)
  Created:      2009-01-03T18:15:05Z (Bitcoin genesis block)
  Expires:      never
  Auth cap:     no
  Passphrase:   included in key derivation
  User-ID hash: 7B2F
  Checksum:     A3B7 (valid)
```

---

## User Experience

After key generation, the receipt is displayed in two forms:

### 1. QR Code (primary)

A QR code is rendered directly in the terminal using Unicode block characters. The user scans it with their phone camera. This is the primary flow for air-gapped machines where file export is impractical.

```
$ bip39key generate -u "Alice <alice@example.com>" -a > key.asc

Deriving key material (this may take a moment)...
PGP fingerprint: 67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F

Derivation receipt (scan or save with your seed backup):

  ██████████████████████████████
  ██ ▄▄▄▄▄ █ ▀▄█▀▄█ ▄▄▄▄▄ ██
  ██ █   █ █▀▄▀▄▀██ █   █ ██
  ██ ▀▀▀▀▀ █ ▀ █▀██ ▀▀▀▀▀ ██
  ██████████████████████████████

  bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:A3B7
```

The QR encodes the same receipt string shown below it. Scanning produces a string the user can paste into `--from-receipt` later.

Implementation: use the `qr2term` crate (or similar) to render QR codes as terminal Unicode. No image files, no GUI dependencies.

### 2. Text string (fallback)

The receipt string is always printed to stderr below the QR code. Users who can't scan (e.g., no phone in the air-gapped room) can hand-copy it. The format is designed to be short and unambiguous:

- Under 70 characters for default settings.
- ASCII-only, colon-separated.
- Checksummed to catch transcription errors.

---

## `--from-receipt`

Parses a receipt and sets all derivation flags:

```
bip39key generate --from-receipt "bip39key:2:hkdf:..." -u "User <user@email.com>"
```

- The user ID is NOT in the receipt (it's part of the key identity, not a derivation parameter to forget). A truncated hash of the user-id is included for verification -- if the provided `--user-id` doesn't match the `uid_hash`, the tool prints a warning and asks for confirmation.
- If individual flags conflict with the receipt, the command fails with an error rather than silently choosing one.
- The passphrase is never in the receipt -- it's prompted or provided via `-p`/`-e`.

---

## Why Receipts Are NOT Embedded in Key Output

Embedding the receipt in PGP armor comments, SSH key comments, or PGP notation subpackets would mean it gets published alongside the public key. An attacker who knows the algorithm, seed format, and that no passphrase was used has a narrower search space. The receipt is not secret per se -- but it shouldn't be broadcast to the world attached to the key.

The receipt is meant to be stored alongside the seed backup (same metal plate, same safe), not distributed with the key.

---

## Physical Backup

The receipt is designed to be:
- **Scannable** -- QR code displayed in terminal, scan with phone.
- **Under 70 characters** -- fits on a single line of a metal backup plate if hand-copying.
- **ASCII-only** -- no encoding ambiguity.
- **Checksummed** -- catches transcription errors.

Recommended practice: scan the QR code to your phone, then store the receipt text alongside your seed phrase on metal or paper.

---

## v2-Only Feature

Receipts are a v2-only feature. v1 has no receipt support. Users who need to regenerate v1 keys should use the `v1.5.0` git tag and must remember their original flags.

---

## Related

- [[bip39key v2 Design Doc]] -- overall v2 design
- [[CLI Design]] -- `receipt` subcommand and `--from-receipt` flag
- [[Migration Guide]] -- using receipts during v1->v2 migration
