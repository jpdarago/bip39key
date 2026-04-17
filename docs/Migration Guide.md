# Migration Guide

**Parent:** [[bip39key v2 Design Doc]]

---

## Who Needs to Migrate

**You don't need to migrate if:**
- You're generating a new key for the first time -- just use `bip39key generate`.

**You should consider migrating if:**
- You used the default `xor` algorithm (security weakness: attacker with passphrase + output can recover hashed seed).
- You used v1 Argon2id defaults and want stronger brute-force protection.
- You want the benefits of the [[Receipt System|receipt system]] for future recovery.

---

## Prerequisites

v2 cannot regenerate v1 keys. Before migrating, make sure you can still build and run v1:

```bash
git checkout v1.5.0
cargo build --release
```

Keep this binary around (or note the tag) until you've completed the migration.

---

## Step-by-Step Migration

### 1. Identify Your v1 Key Parameters

Build from the `v1.5.0` tag and try regenerating your key. If you don't remember your flags, try the common combinations:

```bash
# Default (xor, v1 Argon2id, genesis timestamp)
./bip39key-v1 -u "Your Name <you@example.com>" -k

# With concatenation
./bip39key-v1 -u "Your Name <you@example.com>" -c -k

# With RFC 9106 Argon2id
./bip39key-v1 -u "Your Name <you@example.com>" -r -k

# With HKDF
./bip39key-v1 -u "Your Name <you@example.com>" -g hkdf -k
```

Compare each fingerprint against your known key:
```
gpg --fingerprint "Your Name"
```

Once you find the match, **write down the exact flags** alongside your seed backup.

### 2. Generate Your v2 Key

```
bip39key generate -u "Your Name <you@example.com>" -a
```

Scan the receipt QR code with your phone, or copy the receipt text. Store it with your seed backup.

### 3. Cross-Sign (PGP)

Establish trust continuity between your v1 and v2 keys:

```bash
# Import both keys
gpg --import v1-key.asc
gpg --import v2-key.asc

# Sign v2 key with v1 key
gpg --default-key <v1-fingerprint> --sign-key <v2-fingerprint>

# Sign v1 key with v2 key
gpg --default-key <v2-fingerprint> --sign-key <v1-fingerprint>

# Export and publish
gpg --armor --export <v2-fingerprint> | # upload to keyserver or distribute
```

### 4. Transition Period

- Set an expiration on your v1 key if it doesn't already have one.
- Update your key in any services, repositories, or documentation.
- Keep both keys active during the transition.

### 5. Archive v1

After contacts and services have updated:
- Keep the v1 flags written down with your seed backup (you may need them to decrypt old messages).
- Stop publishing the v1 public key.

---

## Related

- [[bip39key v2 Design Doc]] -- overall design
- [[Receipt System]] -- receipt format and usage
- [[Backward Compatibility]] -- why v2 has no v1 compat
