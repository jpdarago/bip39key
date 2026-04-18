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
4. **`--from-receipt` is the recovery path.** The same tool that generates the key reads the receipt to regenerate it.
5. **Secrets are never command-line arguments.** Passphrases are always prompted interactively or via pinentry, never passed as flags. This avoids shell history leaks and eliminates a class of backup confusion ("was the passphrase part of the command I ran?").

---

## Receipt

The receipt is the core of memo2key. It is a compact string that encodes every non-secret parameter needed to regenerate a key.

### Format

```
memo2key:2:<seed_format>:<pass_role>:<userid>:<checksum>
```

**With default timestamps (the common case):**
```
memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

**With custom timestamps (rare, discouraged):**
```
memo2key:2:bip39:withpass:created=1744948062:expires=1745554397:Satoshi Nakamoto <satoshin@gmx.com>:A3B7
```

### Fields

| Field | Position | Values | Description |
|---|---|---|---|
| tool | 1 | `memo2key` | Tool identifier |
| version | 2 | `2` | Pins algorithm (hkdf), Argon2id (RFC 9106), key structure (sign+encrypt+auth) |
| seed_format | 3 | `bip39`, `electrum` | Mnemonic format |
| pass_role | 4 | `withpass`, `nopass` | Whether a passphrase was used in key derivation |
| timestamps | 5..n | `created=<unix>`, `expires=<unix>` | Only present if non-default. Omitted = genesis block creation, no expiration |
| userid | n+1 | RFC 2822 string | Full user identity, used as Argon2id salt |
| checksum | last | 4 hex chars | Truncated SHA-256 of all preceding fields |

### What version 2 implies

These are not in the receipt because the version number determines them:

- **Algorithm:** HKDF-Expand with domain-separated info strings (the only algorithm)
- **Argon2id:** RFC 9106 (2 GiB memory, 1 iteration, 4 lanes), not configurable
- **Key structure:** Three keys always derived — sign, encrypt, auth
- **HKDF info strings:** `memo2key-sign-v2`, `memo2key-encrypt-v2`, `memo2key-auth-v2`

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
5. Any fields between position 4 and the userid are `key=value` timestamp overrides

---

## HTML Receipt File

The receipt is delivered as a self-contained HTML file, generated automatically alongside every key.

### What the HTML contains

- **The receipt string** in large monospace text
- **A QR code** (inline SVG) encoding the receipt string
- **Human-readable summary** of what each field means and what parameters are pinned by the version
- **Key fingerprint** for the generated key
- **Recovery command** — the exact `memo2key generate --from-receipt <file>` invocation needed to regenerate the key
- **Verify command** — a copy-pasteable `memo2key verify --from-receipt <file> --fingerprint <fp>` with the fingerprint pre-filled, so the user can test their backup immediately
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

`--from-receipt` parses the receipt attribute when given an HTML file. `verify` extracts both.

### Properties

- **Self-contained** — inline CSS, inline SVG for QR, no external dependencies
- **Viewable anywhere** — any browser on any device
- **Searchable** — "memo2key" or the user's email will find it in Drive/Dropbox
- **Printable** — print from browser for paper backup
- **Durable** — even if the HTML structure is corrupted, the receipt string appears as plain text and can be extracted manually

---

## Recovery Flow

### From HTML file (primary)

```
$ memo2key generate --from-receipt memo2key-receipt.html -o key.gpg
```

The tool reads the HTML, extracts the receipt from the `data-memo2key-receipt` attribute, validates the checksum, prompts for the mnemonic and passphrase (if `withpass`), and regenerates the key.

### From receipt string (fallback)

```
$ memo2key generate --from-receipt "memo2key:2:bip39:withpass:Satoshi Nakamoto <satoshin@gmx.com>:A3B7"
```

If the argument doesn't look like a file path (or the file doesn't exist), it's parsed as a raw receipt string.

### Verification

```
$ memo2key verify --from-receipt memo2key-receipt.html
```

When given an HTML receipt file, the fingerprint is extracted automatically. The tool derives the key, compares the fingerprint, and reports the result without outputting secret material.

```
$ memo2key verify --from-receipt "memo2key:2:..." --fingerprint "67EA E069 ..."
```

When given a raw receipt string, the fingerprint must be provided explicitly.

Exit codes: 0 = match, 1 = mismatch, 2 = error.

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

TIMESTAMPS (rarely needed):
  --created <unix>                Creation time (default: Bitcoin genesis)
  --expires <unix>                Expiration time (default: never)

RECOVERY:
  --from-receipt <file-or-string> Regenerate from a receipt
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
| `--sign-only` | All three keys (sign, encrypt, auth) always derived. |
| `--authorize` / `-b` | Auth key always derived via HKDF. Not optional. |
| `--no-passphrase-derivation` | Replaced by interactive "Use passphrase for key derivation?" prompt. |
| `-c, --use-concatenation` | concat algorithm removed entirely. |
| `-r, --use-rfc9106-settings` | RFC 9106 is the only option. |

---

## Key Derivation

```
seed_bytes   = decode_mnemonic(mnemonic, seed_format)
input        = seed_bytes || passphrase_bytes     # if withpass
prk          = Argon2id(input, salt=user_id, params=RFC_9106, output=64)
sign_key     = HKDF-Expand-SHA256(prk, info="memo2key-sign-v2",    len=32)
encrypt_key  = HKDF-Expand-SHA256(prk, info="memo2key-encrypt-v2", len=32)
auth_key     = HKDF-Expand-SHA256(prk, info="memo2key-auth-v2",    len=32)
```

All three keys are always derived. The sign key always carries the authentication capability. The version number in the info strings changes from `v1` to `v2` because the Argon2id parameters differ, producing a different PRK.

If `nopass`: input = seed_bytes, no encryption on output.

### Output formats

| Format | What's produced | Key material used |
|---|---|---|
| `pgp` (default) | OpenPGP EdDSA sign key + ECDH encrypt subkey + auth capability | sign_key, encrypt_key, auth_key |
| `ssh` | OpenSSH Ed25519 key | sign_key |
| `age` | age X25519 key | encrypt_key |

The age format reuses the encrypt key since age is an encryption tool. The SSH format uses the sign key since SSH keys are used for authentication/signing. All three keys are always derived regardless of output format — the format only controls serialization.

---

## What's Different from bip39key

| bip39key v1 | memo2key |
|---|---|
| 3 algorithms (xor, concat, hkdf) | hkdf only, no `--algorithm` flag |
| Configurable Argon2id params | Fixed RFC 9106, not configurable |
| Auth capability optional (`-b`) | Always derived via HKDF |
| Encryption subkey optional (`-j`) | Always derived |
| `-p` passphrase on command line | Passphrase always prompted interactively |
| No receipt | HTML receipt generated automatically |
| Recovery = remember your flags | Recovery = `--from-receipt` |
| Flat CLI with 16+ flags | Subcommands, 10 flags total |
| No verify command | `verify` is a core subcommand |
| PGP and SSH only | PGP, SSH, and age |
| Same repo, same binary name | Separate repo, new name |

---

## Related

- [[bip39key v2 Design Doc]] — earlier v2 design (within bip39key repo)
- [[HKDF Key Derivation]] — derivation pipeline details
- [[Argon2id Parameters]] — why RFC 9106
