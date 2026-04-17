# HKDF Key Derivation

**Parent:** [[bip39key v2 Design Doc]]

---

## Overview

v2 always uses HKDF-Expand (RFC 5869) to derive individual keys from the Argon2id output. This provides proper domain separation between the sign key and encrypt key, preventing any cross-key attacks.

---

## Derivation Pipeline

```
                     ┌─────────────┐
                     │  BIP39 seed │
                     │  (entropy)  │
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ passphrase  │  (if provided)
                     └──────┬──────┘
                            │
                   seed_bytes || passphrase_bytes
                            │
              ┌─────────────▼─────────────┐
              │       Argon2id            │
              │  input: seed||passphrase  │
              │  salt:  user_id           │
              │  params: RFC 9106         │
              │  output: 64 bytes (PRK)   │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │                           │
     ┌────────▼────────┐       ┌──────────▼──────────┐
     │  HKDF-Expand    │       │  HKDF-Expand        │
     │  SHA-256        │       │  SHA-256             │
     │  info: sign-v2  │       │  info: encrypt-v2   │
     │  len: 32        │       │  len: 32             │
     └────────┬────────┘       └──────────┬───────────┘
              │                           │
     ┌────────▼────────┐       ┌──────────▼──────────┐
     │  Ed25519 sign   │       │  X25519 encrypt     │
     │  key (32 bytes) │       │  key (32 bytes,     │
     │                 │       │  clamped per 7748)  │
     └─────────────────┘       └─────────────────────┘
```

---

## Info Strings

| Key type | v1 info string | v2 info string |
|---|---|---|
| Sign | `bip39key-sign-v1` | `bip39key-sign-v2` |
| Encrypt | `bip39key-encrypt-v1` | `bip39key-encrypt-v2` |

The version suffix changes because v2 uses different Argon2id parameters by default, producing a different PRK. Even if someone accidentally uses v2 defaults with a v1 info string, they'd get the wrong key. The version bump makes this explicit and prevents confusion.

---

## Why HKDF Instead of Splitting

v1's `xor` and `concat` algorithms split the 64-byte Argon2id output directly:
- First 32 bytes -> sign key
- Last 32 bytes -> encrypt key

This is sound if Argon2id's output is uniformly random, but it has a subtle weakness: the sign and encrypt keys are derived from adjacent portions of the same hash, so they share a security boundary. A theoretical weakness in Argon2id that leaks partial state could compromise both keys simultaneously.

HKDF-Expand with distinct info strings ensures:
1. **Domain separation** -- each key is derived independently from the PRK.
2. **Extensibility** -- new key types (e.g., `bip39key-age-v2`) can be added without changing the derivation of existing keys.
3. **Standard construction** -- HKDF is a well-analyzed, NIST-approved (SP 800-56C) construction.

---

## Argon2id as HKDF-Extract Substitute

Strictly, HKDF consists of Extract (HMAC-based) + Expand. Here we use Argon2id in place of Extract:

- Argon2id is a memory-hard KDF that produces a pseudo-random key (PRK) from a password-like input.
- Its output is indistinguishable from random to an attacker who can't afford the memory cost.
- We feed this PRK directly to HKDF-Expand, skipping HKDF-Extract.

This is cryptographically sound because HKDF-Expand only requires its input to be a pseudo-random key of sufficient entropy, which Argon2id provides. This is the same pattern recommended by the `hkdf` crate's `from_prk()` method.

---

## Future Key Types

The HKDF approach makes it trivial to derive additional key types from the same seed:

| Use case | Proposed info string |
|---|---|
| Age encryption | `bip39key-age-v2` |
| Second sign key | `bip39key-sign-v2-1` (index-based) |
| Authentication | `bip39key-auth-v2` |

These can be added in point releases without breaking existing keys, since each info string produces independent key material.

---

## Related

- [[Argon2id Parameters]] -- the parameters feeding Argon2id
- [[Receipt System]] -- receipts encode which algorithm was used
- [[bip39key v2 Design Doc]] -- overall v2 design
