# memo2key Prior Art

**Parent:** [[memo2key Design]]
**Date:** 2026-04-18

---

## Overview

A survey of tools that deterministically derive OpenPGP/SSH/age keys from mnemonics or passphrases, focused on what memo2key should adopt, avoid, or learn from.

---

## Tools Surveyed

### passphrase2pgp (skeeto, Go, ~228 stars)

The original inspiration for bip39key. Derives Ed25519 PGP keys from a passphrase via Argon2id (1 GB, 8 passes). Supports PGP, SSH, X.509, and Signify output. Uses the User ID as the Argon2id salt.

**Interesting decisions:**
- **`--check` flag:** Validates the generated Key ID matches an expected value, catching passphrase typos before import. Simple and effective.
- **Emergency SSH pattern:** Derive SSH keys on the spot without storing them on disk. The key exists only in memory for the duration of the session.
- **Signing-first philosophy:** Wellons is openly skeptical of PGP encryption but considers signing (especially Git commits) to lack practical alternatives.

**Problems to avoid:**
- **Epoch-0 creation date** causes GnuPG to mishandle expiration dates. bip39key's Bitcoin genesis timestamp was a direct fix for this. memo2key keeps the genesis timestamp.
- **No receipt.** Recovery requires remembering the exact passphrase and userid. No backup metadata of any kind.

### mnemonikey (kklash, Go, ~84 stars)

Derives PGP keys from a 128-bit random seed encoded as a mnemonic. Uses Argon2id + HKDF (two-stage). The most complete backup story of any existing tool.

**Features to adopt:**

- **Self-contained recovery phrase:** Embeds the creation timestamp, version number, and a checksum directly in the mnemonic. You don't need to remember anything beyond the phrase. memo2key's receipt achieves the same goal via a different mechanism (HTML file with embedded receipt string).
- **Subkey cycling:** Compromised subkeys can be revoked and new ones derived at incremented indices (0-65535 per key type), all recoverable from the single phrase. This is the killer feature for long-lived identities. See [[#Subkey Cycling]].
- **Version numbers in the phrase:** Provides forward-compatibility guarantees. The version determines the derivation parameters. Exactly the approach memo2key takes.

**Decisions to skip:**

- **Custom 4096-word wordlist:** Breaks BIP39 compatibility for a marginal density gain (12 bits/word vs 11). Not worth fragmenting the ecosystem.
- **PGP-only output:** No SSH or age support.

### keyfork (Distrust, Rust, AGPL)

An organizational key management toolchain using BIP-32 hierarchical deterministic derivation with a persistent agent process. The only tool with a published NCC Group security audit (April 2024, all findings low-severity, all fixed).

**Features to adopt:**

- **Shamir's Secret Sharing for the mnemonic:** Splits the seed M-of-N for organizational or family recovery. See [[#Shamir's Secret Sharing]].

**Decisions to skip:**

- **Agent architecture:** Overkill for a run-once CLI tool. The agent makes sense for keyfork's organizational use case (provisioning smartcards, managing infrastructure keys) but adds complexity memo2key doesn't need.
- **BIP-32 derivation:** HD key derivation is the right choice for cryptocurrency wallets but unnecessarily complex for PGP/SSH keys where you don't need thousands of child keys.

### 1seed (oeo, Rust, ~7 stars)

Derives age keys, SSH keys, Ed25519 signing keys, site-specific passwords, UUIDs, and raw bytes from a single seed. Uses HKDF-SHA256 for derivation and scrypt (~1 GB) for passphrases.

**Features to adopt:**

- **Realms:** Namespace derivations — same seed, different realm = different keys. See [[#Realms]].

**Decisions to skip:**

- **OS keychain storage:** Seeds stored in Secure Enclave/TPM/Secret Service. Not portable, not appropriate for air-gapped workflows.
- **Kitchen-sink scope:** Generating passwords, UUIDs, and random bytes dilutes the tool's identity. memo2key should do one thing well.

### summitto/pgp-key-generation (C++, ~42 stars)

Derives PGP keys using libsodium's BLAKE2-based KDF. Supports Ed25519, Curve25519, NIST P-256, and RSA. Audited by Radically Open Security (November 2019).

**Features to adopt:**

- **Dice-roll entropy:** Accepts 100 dice rolls (~256+ bits) combined with system randomness. See [[#Dice-Roll Entropy]].

**Problems to avoid:**

- **Inactive since 2021.** C++ codebase is harder to audit than Rust alternatives.
- **Three-piece recovery:** Requires timestamp + mnemonic + passphrase. The timestamp is not embedded in the phrase, creating the exact recovery failure mode memo2key's receipt is designed to prevent.

### deterministic-pgp-keys (Rust crate, ~downloads unknown)

Derives PGP keys from a BIP39 seed via HKDF.

**The cautionary tale:** Broke key compatibility between minor crate versions (0.3.x → 0.4.x → 0.5.x). Keys generated on an older version cannot be regenerated on a newer one. For a deterministic key tool, this defeats the entire purpose. This is exactly the failure mode memo2key's receipt system and version-pinned derivation are designed to prevent.

### Other tools

- **gpg-hd** (Python, ~40 stars): BIP-39 seed to PGP keys with `--card` flag for direct YubiKey provisioning. Simplest hardware-token workflow.
- **ssh-keydgen** (Go, ~44 stars): Argon2-based SSH key derivation with `--aa` flag to add keys directly to ssh-agent. Only SSH, inactive since 2018.
- **age-keygen-deterministic** (Rust, ~40 stars, archived): Passphrase to age keys via Argon2id + HMAC-SHA256. Created because the official age project rejected deterministic key generation. Now archived, recommends `batchpass` plugin instead.
- **micro-key-producer** (TypeScript, ~73 stars): Library (not CLI) supporting SSH, PGP, SLIP10, WebCrypto, Tor v3, BLS, OTP, X.509. Includes a lightweight GPG-free Git signing tool.

---

## Features to Adopt

### Subkey Cycling

**From:** mnemonikey

When a subkey is compromised, the user revokes it and derives a new one at the next index — without changing the primary key or the mnemonic. With HKDF this is trivial:

```
sign_key_0     = HKDF-Expand(prk, info="memo2key-sign-v2:0",    len=32)
sign_key_1     = HKDF-Expand(prk, info="memo2key-sign-v2:1",    len=32)
encrypt_key_0  = HKDF-Expand(prk, info="memo2key-encrypt-v2:0", len=32)
```

The receipt would include the subkey index when non-zero:

```
memo2key:2:bip39:withpass:subkeys=1:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

This is valuable for long-lived identities where the primary key represents a persistent identity but subkeys may need rotation. The primary certification key never changes — only subkeys cycle.

**Priority:** High. This is a unique capability that directly supports the backup story — one mnemonic, one receipt, unlimited subkey rotations.

### Realms

**From:** 1seed

Same seed, different realm = different keys. Maps cleanly to HKDF info strings:

```
sign_key = HKDF-Expand(prk, info="memo2key-sign-v2:personal:0", len=32)
sign_key = HKDF-Expand(prk, info="memo2key-sign-v2:work:0",     len=32)
```

This lets someone use one mnemonic for multiple identities without the keys being mathematically related. The realm would appear in the receipt:

```
memo2key:2:bip39:withpass:realm=work:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

**Priority:** Medium. Useful but adds a parameter to remember. The receipt captures it, but it's still another knob. Consider for v2.1.

### Shamir's Secret Sharing

**From:** keyfork

Split the mnemonic M-of-N for disaster recovery across multiple custodians (family members, safe deposit boxes, trusted friends). Could be standalone subcommands:

```
memo2key split --threshold 2 --shares 3
memo2key combine
```

These operate on the seed itself, independent of key derivation. The receipt doesn't change — it still refers to the original seed. Splitting is a storage strategy, not a derivation parameter.

**Priority:** Medium. Strong organizational use case. Could ship as a follow-up since it's orthogonal to key generation.

### Dice-Roll Entropy

**From:** summitto

Accept physical dice rolls as an entropy source for users who don't trust system RNG:

```
memo2key generate -u "..." --dice
Enter 100 dice rolls (1-6): 3541262514...
```

The rolls are mixed with system randomness (never used alone) to generate the BIP39 seed. This builds trust with paranoid users and is the right approach for air-gapped ceremonies.

**Priority:** Low. Niche use case, but cheap to implement and good for credibility.

### Inline Fingerprint Check

**From:** passphrase2pgp

During recovery (not first generation), verify the fingerprint matches before writing output:

```
$ memo2key generate --from-receipt receipt.html --expect-fingerprint "67EA E069 ..."
```

If the derived fingerprint doesn't match (wrong seed, wrong passphrase, corrupted receipt), abort before producing a key file. This catches errors before the user imports a wrong key onto a Yubikey.

The `verify` subcommand already does this, but `--expect-fingerprint` makes it a single step. The fingerprint is already in the HTML receipt, so `--from-receipt` could check it automatically.

**Priority:** High. Directly prevents the worst recovery failure mode: silently generating the wrong key.

---

## Decisions to Skip

| Feature | Source | Why skip |
|---|---|---|
| Custom wordlist | mnemonikey | Breaks BIP39 compatibility for marginal density gain |
| Agent architecture | keyfork | Overkill for run-once CLI tool |
| X.509/Signify output | passphrase2pgp | Too niche for memo2key's backup-focused mission |
| OS keychain storage | 1seed | Not portable, wrong for air-gapped workflows |
| Kitchen-sink derivation | 1seed | Passwords, UUIDs, random bytes dilute the tool's identity |
| BIP-32 HD derivation | keyfork | Unnecessary complexity for PGP/SSH keys |
| RSA key support | summitto | Ed25519/X25519 is the right default; RSA adds complexity |

---

## Lessons Learned

1. **Version stability is non-negotiable.** deterministic-pgp-keys broke compatibility across minor versions, defeating its entire purpose. memo2key's version-pinned receipt format exists to prevent this.
2. **The creation timestamp is a footgun.** passphrase2pgp's epoch-0 choice causes GnuPG bugs. summitto requires users to remember it separately. memo2key defaults to the Bitcoin genesis block and omits it from the receipt when default.
3. **Demand for deterministic age keys is real.** age upstream rejected the feature, spawning multiple third-party tools (all now archived or unmaintained). memo2key can serve this demand with a first-party, maintained implementation.
4. **Hardware token provisioning is table stakes.** gpg-hd's `--card` flag and keyfork's smartcard support show that "generate → import to Yubikey" is the primary workflow, not an edge case. memo2key should document this workflow prominently even if it doesn't automate the `ykman` step.
5. **GnuPG has wanted this since 2003.** The upstream feature request (T169) has been open for 23 years. There is clearly sustained demand that the ecosystem hasn't met.

---

## Related

- [[memo2key Design]] — overall design
- [[HKDF Key Derivation]] — derivation pipeline (subkey cycling extends this)
