# bip39key v2 Design Doc

**Status:** Draft
**Author:** JP
**Date:** 2026-04-10

---

## Motivation

bip39key v1.x grew organically, accumulating flags and backward-compatible defaults that make the tool harder to use correctly. The biggest risks are not cryptographic attacks -- they are users who generate a key, lose track of which flags they used, and can never regenerate it.

v2 is a clean break that:
1. Defaults to the safest derivation ([[HKDF Key Derivation|HKDF]] + sane [[Argon2id Parameters|Argon2id]] defaults).
2. Eliminates dangerous flag combinations.
3. Introduces a [[Receipt System|receipt system]] so key recovery is practical.

v2 offers **no backward compatibility** with v1. Users who need to regenerate v1 keys should use the v1.5.0 release (tagged in the repo). See [[Backward Compatibility]].

---

## Design Principles

- **Pit of success.** The default invocation should produce the most secure key with the least input.
- **No silent footguns.** If a flag combination is dangerous or unusual, refuse it or require explicit opt-in.
- **Recoverable by design.** Every key generation emits enough metadata to recreate the key years later given the seed and passphrase.
- **One way to do each thing.** Remove flag aliases, deprecated options, and redundant paths.

---

## Breaking Changes from v1

| v1 behavior | v2 behavior |
|---|---|
| Default algorithm: `xor` | Only `hkdf` or `concat`. XOR is gone. |
| Default Argon2id: 64MB / 32 iter / 8 lanes | [[Argon2id Parameters|RFC 9106 fixed]]: 2GB / 1 iter / 4 lanes. Not configurable. |
| `-c` flag for concat | `--algorithm concat` |
| `-t` flag for timestamp | `--created` |
| `-q` interactive flag | Auto-detected from TTY |
| Passphrase combined via flag choice | Always concatenated before Argon2id |
| No receipt | Receipt (QR + text) emitted on every generation |

**There is no migration path within v2.** v1 keys cannot be regenerated with the v2 binary. Users needing v1 keys should build from the `v1.5.0` git tag. See [[Backward Compatibility]].

---

## CLI Architecture

v2 moves to a subcommand-based CLI. See [[CLI Design]] for full details.

```
bip39key generate [options]     # Generate a new key (default subcommand)
bip39key verify [options]       # Verify seed matches a known fingerprint
bip39key receipt <string>       # Decode and display a receipt
```

### `generate` options

```
REQUIRED:
  -u, --user-id <ID>            RFC 2822 user ID (e.g., "Name <email>")

DERIVATION:
  --algorithm <alg>              hkdf (default) | concat
  --seed-format <fmt>            bip39 (default) | electrum
  --no-passphrase-derivation     Passphrase only encrypts output, not key material

TIMESTAMPS:
  --created <unix>               Creation time (default: Bitcoin genesis 1231006505)
  --expires <unix>               Expiration time (default: none)

OUTPUT:
  -f, --format <fmt>             pgp (default) | ssh
  -a, --armor                    ASCII armor (PGP only)
  -k, --public-key               Output public key only
  -o, --output <file>            Output file (default: stdout)

INPUT:
  -i, --input <file>             Read seed from file
  -p, --passphrase <pass>        Passphrase (prompted if omitted on TTY)
  -e, --pinentry                 Use pinentry for passphrase

PGP-SPECIFIC:
  --sign-only                    Omit encryption subkey
  --authorize                    Add authorization capability to sign key
```

### What's removed

- `--use-rfc9106-settings` / `-r` -- RFC 9106 is now the only option.
- `--use-concatenation` / `-c` -- Replaced by `--algorithm concat`.
- `--timestamp` / `-t` -- Use `--created`.
- `--interactive` / `-q` -- Auto-detected from TTY.
- `--algorithm xor` -- Removed entirely. Use v1.5.0 tag for XOR keys.
- `-b` short flag for authorize -- Use `--authorize` (long form only for rare options).

---

## Key Derivation

See [[HKDF Key Derivation]] for the full derivation pipeline.

```
seed_bytes = decode_mnemonic(mnemonic, seed_format)
input      = seed_bytes || passphrase_bytes    # always concatenate
prk        = Argon2id(input, salt=user_id, params=RFC_9106, output=64)
sign_key   = HKDF-Expand-SHA256(prk, info="bip39key-sign-v2",    len=32)
encrypt_key= HKDF-Expand-SHA256(prk, info="bip39key-encrypt-v2", len=32)
```

Note the info strings change from `v1` to `v2` because the Argon2id parameters change, which means the PRK is different. This provides clean domain separation between v1 and v2 key material even if the same seed/passphrase/user-id are used.

---

## Argon2id Parameters

See [[Argon2id Parameters]] for rationale.

| Parameter | v1 default | v2 default (RFC 9106) |
|---|---|---|
| Memory | 64 MiB | 2 GiB |
| Iterations | 32 | 1 |
| Parallelism | 8 | 4 |
| Hash length | 64 bytes | 64 bytes |

The v1 parameters were chosen early in development and are significantly below modern recommendations. The RFC 9106 "first recommended option" (2 GiB memory, 1 iteration, 4 lanes) is designed for high-value secrets on modern hardware and is already implemented behind `--use-rfc9106-settings` in v1.5.0.

**Why 2 GiB is appropriate here:** bip39key generates long-lived identity keys from a memorized seed. This is exactly the high-value, infrequent-use scenario that RFC 9106 targets. The derivation runs once (at generation time) and once more on rare recovery. A few seconds of computation and 2 GiB of RAM is a negligible cost compared to the lifetime value of the key.

Argon2id parameters are fixed to RFC 9106 and not user-configurable. This eliminates a class of recovery failures -- users can never forget which Argon2id settings they used. See [[Argon2id Parameters]] for rationale.

---

## Receipt System

See [[Receipt System]] for the full specification.

After every key generation, bip39key v2 displays a QR code in the terminal and prints the receipt string to stderr:

```
bip39key:2:hkdf:bip39:1231006505:0:noauth:withpass:7B2F:A3B7
```

The QR code encodes this same string. On an air-gapped machine, the user scans the QR with their phone -- no file export needed. The text string is a fallback for hand-copying.

The receipt encodes every parameter that affects key derivation. Given the receipt + seed + passphrase + user-id, the key can be deterministically rebuilt:

```
bip39key generate --from-receipt "bip39key:2:hkdf:..." -u "User <user@email.com>"
```

---

## Backward Compatibility

**v2 has no v1 compatibility.** The v2 binary cannot regenerate v1 keys. See [[Backward Compatibility]] for the full rationale.

Users who need to regenerate v1 keys should build from the `v1.5.0` git tag. The v1 codebase is frozen at that tag -- no new features, only critical security fixes if needed.

---

## Migration Path

See [[Migration Guide]] for the full walkthrough. Summary:

1. **Regenerate your v1 key** from the `v1.5.0` tag if you still need it.
2. **Generate a new v2 key** with `bip39key generate -u "..."`. Save the receipt.
3. **Cross-sign** the v2 public key with the v1 key to establish trust continuity.
4. **Set an expiration** on the v1 key and transition contacts to the v2 key.

---

## Resolved Decisions

- **Age format:** Deferred to v2.1.
- **Receipt checksum:** 4 hex characters (truncated SHA-256).
- **Receipt user-id hash:** Yes -- receipt includes a truncated hash of the user-id for verification. Users usually remember their name and email, but a hash catches typos and encoding differences.
- **v1 compatibility:** None. v1 lives as the `v1.5.0` git tag. v2 is a clean codebase with no v1 code.

---

## Related Pages

- [[CLI Design]]
- [[HKDF Key Derivation]]
- [[Argon2id Parameters]]
- [[Receipt System]]
- [[Backward Compatibility]]
- [[Migration Guide]]
