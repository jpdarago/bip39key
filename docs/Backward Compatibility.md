# Backward Compatibility

**Parent:** [[bip39key v2 Design Doc]]

---

## No v1 Compatibility in v2

v2 is a clean break. The v2 binary **cannot regenerate v1 keys**. There is no `bip39key v1` subcommand, no legacy codepath, and no v1 flag aliases.

Users who need to regenerate v1 keys should build from the `v1.5.0` git tag.

---

## Why No Compatibility

Carrying v1 code in the v2 binary has costs:

1. **Maintenance burden.** Two CLI parsers, two derivation codepaths, two sets of tests. Every change must be validated against both.
2. **User confusion.** A `v1` subcommand suggests v1 is a supported workflow. It's not -- it's a frozen legacy path that will bitrot.
3. **Security surface.** The v1 XOR algorithm has a known weakness (attacker with passphrase + output can recover hashed seed). Shipping it in v2 means shipping known-weak code.
4. **Cleaner codebase.** v2 can be written from scratch with better structure, without working around v1's flag parser and derivation logic.

The `v1.5.0` tag is immutable in git. It will always be buildable. This is a stronger guarantee than a compatibility subcommand that might subtly drift over time.

---

## What Changes Between v1 and v2

| Aspect | v1 | v2 |
|---|---|---|
| Algorithm | xor (default), concat, hkdf | hkdf (default), concat |
| Argon2id | 64 MiB / 32 / 8 (configurable via `-r`) | RFC 9106 fixed (2 GiB / 1 / 4) |
| HKDF info strings | `*-v1` | `*-v2` |
| Passphrase combining | xor/concat/hkdf via flag | Always concat before Argon2id |
| Receipt | none | QR + text on every generation |
| Fingerprint display | added in v1.5.0 | always shown |
| CLI style | flat flags | subcommands |

---

## Testing Strategy

v1 golden test files (`test/message-*.gpg`) stay in the repo for reference but are not run by the v2 test suite. They can be used to verify the `v1.5.0` tag still builds correctly.

New golden test files for v2:
- `test/message-v2-hkdf.gpg`
- `test/message-v2-hkdf-passphrase.gpg`

---

## Related

- [[bip39key v2 Design Doc]] -- overall design
- [[Migration Guide]] -- upgrading from v1 to v2
