# memo2key Design

**Status:** Draft
**Date:** 2026-04-18

---

## Motivation

bip39key works, but recovery is fragile. Users generate a key, load it onto a Yubikey, and three years later need to regenerate — but can't remember which flags they used. The mnemonic is the backup, but the mnemonic alone isn't enough.

memo2key is a rewrite with one driving principle: **the backup story is the product.** Daily security is handled by hardware (Yubikeys, secure enclaves). memo2key's job is to make regeneration foolproof.

The tool lives in a separate repository under a new name to avoid breaking existing bip39key users.

---

## Design Principles

1. **One artifact to save.** After key generation, the user gets an HTML receipt file. That file plus the mnemonic (plus passphrase if used) is everything needed to regenerate the key, forever.
2. **No knobs that affect derivation.** The fewer parameters, the fewer things to forget. Version number pins the algorithm, Argon2id settings, and key structure. There is no `--algorithm` flag.
3. **The receipt contains no secrets.** Safe to store in Google Drive, email to yourself, print and pin to the wall.
4. **`--from-receipt` is the recovery path.** The same tool that generates the key reads the receipt to regenerate it. Recovery from an HTML receipt automatically verifies the fingerprint — wrong seed or passphrase is caught before output is written.
5. **Secrets are never command-line arguments.** Passphrases are always prompted interactively or via pinentry, never passed as flags. This avoids shell history leaks and eliminates a class of backup confusion ("was the passphrase part of the command I ran?").

---

## Receipt

The receipt is the core of memo2key. It is a compact string that encodes every non-secret parameter needed to regenerate a key.

### Format

```
memo2key:2:<seed_format>:<pass_role>:[<key=value options>:]<userid>:<checksum>
```

**Default (the common case):**
```
memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

**With realm:**
```
memo2key:2:bip39:withpass:realm=work:Alice Smith <alice@company.com>:D1F9
```

**After subkey cycling:**
```
memo2key:2:bip39:withpass:subkeys=1:Satoshi Nakamoto <satoshin@gmx.com>:C4E2
```

**With custom timestamps (rare, discouraged):**
```
memo2key:2:bip39:withpass:created=1744948062:expires=1745554397:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

### Fields

| Field | Position | Values | Description |
|---|---|---|---|
| tool | 1 | `memo2key` | Tool identifier |
| version | 2 | `2` | Pins algorithm (hkdf), Argon2id (RFC 9106), key structure (cert+sign+encrypt+auth) |
| seed_format | 3 | `bip39`, `electrum` | Mnemonic format |
| pass_role | 4 | `withpass`, `nopass` | Whether a passphrase was used in key derivation |
| options | 5..n | `key=value` pairs | Only present if non-default. See below. |
| userid | n+1 | RFC 2822 string | Full user identity, used as Argon2id salt |
| checksum | last | 4 hex chars | Truncated SHA-256 of all preceding fields |

### Optional `key=value` fields

All optional fields are omitted when at their default value. The common case has no optional fields at all.

| Key | Default | Description |
|---|---|---|
| `realm` | *(none)* | Namespace for key isolation. See [[#Realms]]. |
| `subkeys` | `0` | Subkey generation index. See [[#Subkey Cycling]]. |
| `created` | `1231006505` | Creation timestamp (Bitcoin genesis). |
| `expires` | `0` | Expiration timestamp (0 = never). |

### What version 2 implies

These are not in the receipt because the version number determines them:

- **Algorithm:** HKDF-Expand with domain-separated info strings (the only algorithm)
- **Argon2id:** RFC 9106 (2 GiB memory, 1 iteration, 4 lanes), not configurable
- **Key structure:** Certification key + three subkeys (sign, encrypt, auth), always derived
- **HKDF info strings:** `memo2key-cert-v2`, `memo2key-sign-v2:<realm>:<index>`, `memo2key-encrypt-v2:<realm>:<index>`, `memo2key-auth-v2:<realm>:<index>`

### Passphrase role

| Value | Meaning |
|---|---|
| `withpass` | Passphrase concatenated with seed before Argon2id. Also encrypts output file. |
| `nopass` | No passphrase used at all |

During generation, if the user provides a passphrase, the tool asks interactively:

```
Use passphrase for key derivation? [Y/n]
```

- **Y (default):** Passphrase feeds into Argon2id alongside the seed. Receipt records `withpass`.
- **n:** Passphrase only encrypts the output file. Key material depends only on the seed. Receipt records `nopass`.

During recovery with `--from-receipt`, the receipt's `withpass`/`nopass` field determines behavior automatically — no question asked.

### Why timestamps are omitted by default

The creation timestamp defaults to the Bitcoin genesis block (1231006505). The expiration defaults to never. These are omitted from the receipt when they are the defaults for two reasons:

1. **Discourages changing them.** If users see a timestamp field, they'll set a custom one. Then they'll forget it. Then their backup breaks.
2. **Shorter receipt.** The common case should be the compact case.

Custom timestamps are supported (some organizations require expiration dates) but their presence in the receipt is a visible signal that this key has non-standard settings.

### Why the full userid is in the receipt

The userid is the Argon2id salt. Without it, the key cannot be regenerated. Earlier designs included only a truncated hash of the userid (for typo detection), requiring the user to provide `-u` separately during recovery. This created a two-piece backup (receipt + userid) with a failure mode: the user saves the receipt but forgets the exact userid.

Including the full userid makes the receipt self-contained. The user needs exactly two things: the receipt and the mnemonic. Nothing else.

### Checksum

The checksum is the first 4 hex characters (2 bytes) of SHA-256 over the colon-joined preceding fields:

```
SHA-256("memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>") -> first 2 bytes -> hex
```

This catches transcription errors with ~1/65536 false positive rate. Hex is used for consistency (no extra encoding to explain).

### Parsing rules

1. Split on `:` delimiter
2. Fields 0-3 are fixed: tool, version, seed format, pass role
3. Last field is always the checksum (4 hex characters)
4. Second-to-last field is the userid (the full RFC 2822 string; must not contain colons)
5. Any fields between position 4 and the userid are `key=value` option overrides

---

## HTML Receipt File

The receipt is delivered as a self-contained HTML file, generated automatically alongside every key.

### What the HTML contains

- **The receipt string** in large monospace text
- **A QR code** (inline SVG) encoding the receipt string
- **Human-readable summary** of what each field means and what parameters are pinned by the version
- **Key fingerprint** for the generated key
- **Recovery command** — the exact `memo2key generate --from-receipt <file>` invocation needed to regenerate the key
- **Verify command** — a copy-pasteable `memo2key verify --from-receipt <file>` with the fingerprint pre-filled, so the user can test their backup immediately
- **Generation date** for the user's reference (not part of the receipt, not used in derivation)

### What the HTML does NOT contain

- The mnemonic
- The passphrase
- The private key
- Any secret material

The file is safe to store in Google Drive, Dropbox, email, or any cloud service.

### Machine-readable embedding

The receipt string is embedded in a `<code>` element with a data attribute for reliable extraction:

```html
<code data-memo2key-receipt="memo2key:2:bip39:withpass:Satoshi Nakamoto &lt;satoshin@gmx.com&gt;:A3B7">
  memo2key:2:bip39:withpass:Satoshi Nakamoto &lt;satoshin@gmx.com&gt;:A3B7
</code>
```

The fingerprint is similarly embedded:

```html
<code data-memo2key-fingerprint="67EAE06904766020FB5B41B314B8857D6EFD7E9F">
  67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F
</code>
```

`--from-receipt` parses the receipt attribute when given an HTML file. During recovery, the fingerprint is verified automatically. See [[#Inline Fingerprint Verification]].

### Properties

- **Self-contained** — inline CSS, inline SVG for QR, no external dependencies
- **Viewable anywhere** — any browser on any device
- **Searchable** — "memo2key" or the user's email will find it in Drive/Dropbox
- **Printable** — print from browser for paper backup
- **Durable** — even if the HTML structure is corrupted, the receipt string appears as plain text and can be extracted manually

---

## Key Derivation

### Key hierarchy

memo2key separates the **certification key** (identity, permanent) from **subkeys** (workers, can cycle):

```
seed_bytes   = decode_mnemonic(mnemonic, seed_format)
input        = seed_bytes || passphrase_bytes                         # if withpass
prk          = Argon2id(input, salt=user_id, params=RFC_9106, output=64)

cert_key     = HKDF-Expand-SHA256(prk, info="memo2key-cert-v2",                   len=32)
sign_key     = HKDF-Expand-SHA256(prk, info="memo2key-sign-v2:<realm>:<index>",    len=32)
encrypt_key  = HKDF-Expand-SHA256(prk, info="memo2key-encrypt-v2:<realm>:<index>", len=32)
auth_key     = HKDF-Expand-SHA256(prk, info="memo2key-auth-v2:<realm>:<index>",    len=32)
```

Where `<realm>` defaults to empty string and `<index>` defaults to `0`. For the common case (no realm, no cycling), the info strings are:

```
memo2key-cert-v2
memo2key-sign-v2::0
memo2key-encrypt-v2::0
memo2key-auth-v2::0
```

The certification key has no realm or index — it is the permanent identity anchor. Subkeys are the workers that live on hardware tokens and can be rotated.

If `nopass`: input = seed_bytes, no encryption on output.

### Output formats

| Format | What's produced | Key material used |
|---|---|---|
| `pgp` (default) | OpenPGP cert key + sign/encrypt/auth subkeys | cert_key, sign_key, encrypt_key, auth_key |
| `ssh` | OpenSSH Ed25519 key | sign_key |
| `age` | age X25519 key | encrypt_key |

The age format reuses the encrypt key since age is an encryption tool. The SSH format uses the sign key since SSH keys are used for authentication/signing. All keys are always derived regardless of output format — the format only controls serialization.

---

## Subkey Cycling

**Inspired by:** mnemonikey

When a subkey is compromised (e.g., Yubikey stolen), the user revokes the compromised subkeys and derives new ones at the next index — without changing the primary certification key. The identity and trust chain are unbroken.

### How it works

All subkeys cycle together (single index). If a Yubikey is stolen, all subkeys on it are compromised, so independent per-key-type cycling adds complexity without benefit.

```
# Index 0 (initial)
sign_key     = HKDF-Expand(prk, info="memo2key-sign-v2::0",    len=32)
encrypt_key  = HKDF-Expand(prk, info="memo2key-encrypt-v2::0", len=32)
auth_key     = HKDF-Expand(prk, info="memo2key-auth-v2::0",    len=32)

# Index 1 (after compromise)
sign_key     = HKDF-Expand(prk, info="memo2key-sign-v2::1",    len=32)
encrypt_key  = HKDF-Expand(prk, info="memo2key-encrypt-v2::1", len=32)
auth_key     = HKDF-Expand(prk, info="memo2key-auth-v2::1",    len=32)

# Certification key: unchanged
cert_key     = HKDF-Expand(prk, info="memo2key-cert-v2",       len=32)
```

### Workflow

```
# Day 1: generate key, load onto Yubikey
$ memo2key generate -u "Satoshi Nakamoto <satoshin@gmx.com>" -o key.gpg
# => cert key + subkeys at index 0
# => key-receipt.html (no subkeys= field, index 0 is default)

# Year 3: Yubikey stolen, need new subkeys
$ memo2key generate --from-receipt key-receipt.html --cycle-subkeys -o key-new.gpg
# => same cert key + new subkeys at index 1
# => key-new-receipt.html (includes subkeys=1)
# => user revokes old subkeys in GPG, imports new key
```

The primary key fingerprint never changes. Contacts don't need to re-verify the identity. The new receipt replaces the old one.

### Receipt

The subkey index appears in the receipt only when non-zero:

```
memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>:A3B7           # index 0
memo2key:2:bip39:withpass:subkeys=1:Satoshi Nakamoto <satoshin@gmx.com>:C4E2  # index 1
```

---

## Realms

**Inspired by:** 1seed

Same seed, different realm = completely independent keys. The realm is a namespace in the HKDF info strings, producing keys that are mathematically unrelated — knowing one reveals nothing about the other.

### How it works

```
# Personal identity
cert_key = HKDF-Expand(prk, info="memo2key-cert-v2:personal",            len=32)
sign_key = HKDF-Expand(prk, info="memo2key-sign-v2:personal:0",          len=32)

# Work identity (different userid, same seed)
cert_key = HKDF-Expand(prk, info="memo2key-cert-v2:work",                len=32)
sign_key = HKDF-Expand(prk, info="memo2key-sign-v2:work:0",              len=32)
```

### Use cases

- Personal vs work keys from the same mnemonic
- Multiple organizational identities
- Testing vs production environments

### Workflow

```
$ memo2key generate -u "Alice <alice@personal.com>" -o personal.gpg
# => default realm (omitted from receipt)

$ memo2key generate -u "Alice Smith <alice@company.com>" --realm work -o work.gpg
# => realm=work in receipt
```

Each realm gets its own receipt. The user stores multiple HTML files but protects only one mnemonic.

### Receipt

The realm appears in the receipt only when specified:

```
memo2key:2:bip39:withpass:Alice <alice@personal.com>:A3B7                          # no realm
memo2key:2:bip39:withpass:realm=work:Alice Smith <alice@company.com>:D1F9           # work realm
```

### Realm + subkey cycling

Realms and subkey indices compose naturally:

```
memo2key:2:bip39:withpass:realm=work:subkeys=2:Alice Smith <alice@company.com>:E5A1
```

Info string: `memo2key-sign-v2:work:2`

---

## Inline Fingerprint Verification

**Inspired by:** passphrase2pgp's `--check` flag

During recovery from an HTML receipt, the tool automatically verifies the derived fingerprint matches the one stored in the receipt. This prevents the worst recovery failure: silently generating the wrong key and importing it onto a Yubikey.

### From HTML receipt (automatic)

```
$ memo2key generate --from-receipt key-receipt.html -o key.gpg
Reading receipt... ✓ checksum valid
Enter mnemonic: ****
Enter passphrase: ****
Deriving key (this takes a moment)...
Fingerprint: 67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F
✓ Matches receipt fingerprint
Writing key to key.gpg
```

If the fingerprint doesn't match:

```
Fingerprint: A105 31F7 669D DD0F A50B  0A00 656C 5848 0711 970B
✗ DOES NOT match receipt fingerprint
  Expected: 67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F
Aborting. Your seed or passphrase may be wrong.
```

No output file is written. The user knows immediately that something is wrong.

### From raw receipt string (explicit)

Raw receipt strings don't contain the fingerprint, so verification requires `--expect-fingerprint`:

```
$ memo2key generate --from-receipt "memo2key:2:..." --expect-fingerprint "67EA E069 ..." -o key.gpg
```

Without `--expect-fingerprint`, the key is generated without verification (with a warning).

### Verify subcommand

For testing a backup without producing output:

```
$ memo2key verify --from-receipt key-receipt.html
# Fingerprint auto-extracted from HTML

$ memo2key verify --from-receipt "memo2key:2:..." --fingerprint "67EA E069 ..."
# Fingerprint provided explicitly
```

Exit codes: 0 = match, 1 = mismatch, 2 = error.

---

## Recovery Flow

### From HTML file (primary)

```
$ memo2key generate --from-receipt memo2key-receipt.html -o key.gpg
```

The tool reads the HTML, extracts the receipt and fingerprint, validates the checksum, prompts for the mnemonic and passphrase (if `withpass`), derives the key, verifies the fingerprint matches, and writes the output.

### From receipt string (fallback)

```
$ memo2key generate --from-receipt "memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>:A3B7"
```

If the argument doesn't look like a file path (or the file doesn't exist), it's parsed as a raw receipt string.

---

## Generation Flow

```
$ memo2key generate -u "Satoshi Nakamoto <satoshin@gmx.com>" -o key.gpg
```

1. Prompt for mnemonic (or read from `-i` file / stdin)
2. Prompt for passphrase via interactive prompt or pinentry
3. If passphrase provided, ask: "Use passphrase for key derivation? [Y/n]"
4. Derive keys, serialize output
5. Produce two files:
   - `key.gpg` — the private key (import to Yubikey, then delete)
   - `key-receipt.html` — the receipt (upload to Drive)
6. Print receipt to stderr as QR code + text (for air-gapped machines)
7. Print verify command to stderr so the user can test their backup immediately

The receipt file name is derived from the output file name (`<basename>-receipt.html`). If outputting to stdout, the receipt HTML is written to `memo2key-receipt.html` in the current directory.

---

## CLI Design

### `generate` (default subcommand)

```
REQUIRED:
  -u, --user-id <ID>              RFC 2822 user identity

INPUT:
  -i, --input <file>              Read seed from file (default: stdin/prompt)
  -e, --pinentry                  Use pinentry for passphrase (default: interactive prompt)

OUTPUT:
  -f, --format <fmt>              pgp (default) | ssh | age
  -a, --armor                     ASCII armor (PGP only)
  -k, --public-key                Output public key only
  -o, --output <file>             Output file (default: stdout)

DERIVATION:
  --seed-format <fmt>             bip39 (default) | electrum
  --realm <name>                  Key realm for namespace isolation

TIMESTAMPS (rarely needed):
  --created <unix>                Creation time (default: Bitcoin genesis)
  --expires <unix>                Expiration time (default: never)

RECOVERY:
  --from-receipt <file-or-string> Regenerate from a receipt
  --cycle-subkeys                 Derive subkeys at the next index (use after compromise)
  --expect-fingerprint <fp>       Abort if derived fingerprint doesn't match (raw receipts only)
```

### `verify`

```
memo2key verify --from-receipt <file-or-string> [--fingerprint <fp>]
```

Fingerprint is optional when the receipt is an HTML file (extracted automatically). Required when the receipt is a raw string.

### `receipt`

```
memo2key receipt <file-or-string>
```

Decodes a receipt and prints a human-readable summary. Validates the checksum.

### What's NOT in the CLI

| Removed | Why |
|---|---|
| `-p, --passphrase` | Secrets never on command line. Always prompted interactively or via pinentry. |
| `--algorithm` | Only hkdf. No choice to make. |
| `--sign-only` | All keys (cert, sign, encrypt, auth) always derived. |
| `--authorize` / `-b` | Auth key always derived via HKDF. Not optional. |
| `--no-passphrase-derivation` | Replaced by interactive "Use passphrase for key derivation?" prompt. |
| `-c, --use-concatenation` | concat algorithm removed entirely. |
| `-r, --use-rfc9106-settings` | RFC 9106 is the only option. |

---

## What's Different from bip39key

| bip39key v1 | memo2key |
|---|---|
| 3 algorithms (xor, concat, hkdf) | hkdf only, no `--algorithm` flag |
| Configurable Argon2id params | Fixed RFC 9106, not configurable |
| Auth capability optional (`-b`) | Always derived via HKDF |
| Encryption subkey optional (`-j`) | Always derived |
| No separate certification key | Cert key + subkeys (cert never cycles) |
| No subkey cycling | Subkeys rotate at indexed generations |
| Single key namespace | Realms for independent identities from one seed |
| `-p` passphrase on command line | Passphrase always prompted interactively |
| No receipt | HTML receipt generated automatically |
| No fingerprint verification on recovery | Automatic verification from HTML receipt |
| Recovery = remember your flags | Recovery = `--from-receipt` |
| Flat CLI with 16+ flags | Subcommands, fewer flags |
| No verify command | `verify` is a core subcommand |
| PGP and SSH only | PGP, SSH, and age |
| Same repo, same binary name | Separate repo, new name |

---

## Related

- [[memo2key Prior Art]] — survey of similar tools and features adopted
- [[bip39key v2 Design Doc]] — earlier v2 design (within bip39key repo)
- [[HKDF Key Derivation]] — derivation pipeline details
- [[Argon2id Parameters]] — why RFC 9106
