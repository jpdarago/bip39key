# Future Work

This document tracks planned improvements, research directions, and aspirational goals for `bip39key`. It is organized by theme and roughly ordered by impact within each section.

---

## 1. Recovery Safety

The single biggest risk with `bip39key` is not an attack — it's a user who can't regenerate their key because they forgot which flags they used. Every feature in this section aims to make that scenario impossible.

### 1.1 Derivation Receipt

**Problem:** Key material depends on `--algorithm`, `--seed-format`, `--use-rfc9106-settings`, `--skip-passphrase-for-key-material`, `--creation-timestamp`, `--expiration-timestamp`, `--authorization-for-sign-key`, and the user ID. Forgetting any one of these produces a different key.

**Proposal:** After key generation, print a compact versioned receipt string to stderr that encodes every derivation-affecting parameter:

```
bip39key:v1:hkdf:bip39:argon2default:genesis:noauth:withpass
```

A corresponding `--from-receipt <string>` flag would parse the receipt and set all derivation flags automatically. The user only needs to store the receipt alongside their seed phrase.

**Design considerations:**
- The receipt must be versioned so future parameter additions don't break old receipts.
- It should be short enough to write on a physical card (under 80 characters).
- It must NOT contain the seed, passphrase, or any secret material.
- Consider encoding as a QR code for easy scanning.
- Consider a checksum (CRC or similar) appended to the receipt to catch transcription errors.

### 1.2 Verify Mode

**Problem:** Users may want to confirm that a seed phrase + flags produce the expected key without writing a full private key to disk.

**Proposal:** A `--verify <fingerprint>` flag that derives the key, computes the PGP fingerprint or SSH public key hash, compares it against the provided value, and exits with success/failure. No private key is written anywhere.

**Use cases:**
- "I found my seed backup. Does it still produce the right key?"
- "I'm about to use this key for something important. Let me double-check."
- Automated monitoring: a cron job that verifies the seed still produces the expected fingerprint.

### 1.3 Dry Run / Fingerprint-Only Mode

**Problem:** Sometimes you want to see what fingerprint a set of parameters would produce without outputting any secret material.

**Proposal:** `--dry-run` outputs only the public key fingerprint (PGP) or public key (SSH) to stdout. Combine with `--verify` for a complete "check without risk" workflow.

### 1.4 Parameter Embedding in Key Output

For cases where the user still has the key file but not the receipt:

- **SSH keys:** Encode derivation parameters in the key comment field (after the public key base64). SSH ignores comments, so this is backward-compatible.
- **PGP armor:** Add a custom `Comment:` header in the ASCII armor block with the derivation receipt string.
- **PGP notation:** Store parameters in a notation data subpacket on the self-signature.

This is a secondary defense — the receipt is the primary one, since this only helps if you still have the key file.

---

## 2. Backup Strategies

Inspiration from the cryptocurrency world, where seed phrase backup is a deeply studied problem.

### 2.1 Shamir's Secret Sharing (SLIP-0039 / SSKR)

**What it is:** Split a secret into N shares such that any K of them (threshold) can reconstruct the original, but K-1 shares reveal nothing. Defined in SLIP-0039 for BIP-39 compatible mnemonics, and in SSKR (Sharded Secret Key Reconstruction) by Blockchain Commons.

**How it applies to bip39key:**
- The BIP-39 seed phrase (or the entropy bytes) could be split into Shamir shares before being passed to `bip39key`.
- `bip39key` itself could offer `--shamir-split K N` to split the seed into shares at generation time, and `--shamir-combine` to reconstruct from shares at recovery time.
- Each share is itself a mnemonic (SLIP-0039 uses its own wordlist), so it's human-readable and checksummed.

**Tradeoffs:**
- Adds complexity — users must understand threshold schemes.
- SLIP-0039 uses a different wordlist than BIP-39, which can cause confusion.
- Shares must be stored in separate physical locations to be useful.
- The reconstruction step is a single point of failure: if the software doing reconstruction is compromised, all shares are exposed simultaneously.

**Technical details (SLIP-0039):**
- Operates on the entropy bytes (128 or 256 bits), not the mnemonic words directly.
- Uses GF(256) arithmetic (byte-level Shamir) rather than GF(p) for simpler implementation.
- Shares are encoded using a dedicated 1024-word wordlist (not BIP-39's). Each share includes: 15-bit identifier (ties shares to the same split), 5-bit iteration exponent, group index/threshold/count, member index/threshold, the share value, and a 30-bit RS1024 checksum (much stronger than BIP-39's 4/8-bit SHA-256 checksum — detects up to 3 substitution errors).
- The master secret is encrypted with a passphrase before splitting using a Feistel-like round function derived from PBKDF2-HMAC-SHA256 (parameterized by the iteration exponent). Even reconstructing all shares without the passphrase yields nothing.
- Supports **two-level group thresholds**: e.g., "any 2 of {family group 2-of-3, lawyer group 1-of-1, safe-deposit group 1-of-1}".
- Implementations: Trezor firmware (native), trezorlib Python, Hermit (Unchained Capital CLI).

**Technical details (SSKR):**
- Defined in BCR-2020-011. Uses SSS over GF(256) like SLIP-0039 but encodes shares in CBOR/UR (Uniform Resources) format.
- UR encoding (`ur:sskr/...`) is designed for animated QR codes — a large payload is split into multiple QR frames with fountain codes (rateless erasure coding) so scanning can begin at any frame.
- Uses ByteWords encoding (256-word list, each word uniquely identified by first and last letters).
- Key difference: SSKR does not encrypt the secret before splitting; passphrase protection is left to the layer above.
- Reference implementations in C (`bc-sskr`), Swift, Java, Rust (`bc-sskr-rust`).

**Standards:**
- [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) — Shamir's Secret Sharing for mnemonic codes.
- [SSKR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md) — Blockchain Commons' take, uses CBOR encoding, supports two-level groups.

### 2.2 Seed XOR (Coldcard Approach)

**What it is:** XOR the seed entropy with one or more random masks. Each mask is itself a valid BIP-39 mnemonic. To recover, XOR all parts together. Simpler than Shamir but always requires ALL parts (no threshold).

**How it applies to bip39key:**
- Could offer `--seed-xor-split N` to split into N parts (each a valid BIP-39 mnemonic).
- Recovery: `--seed-xor-combine` takes N mnemonics and XORs them.
- Advantage: each part looks like a normal BIP-39 phrase (plausible deniability, compatible with existing metal backup products).
- Disadvantage: no threshold — lose one part, lose everything. This is strictly worse than Shamir for fault tolerance but simpler to understand.
- **Security note:** XOR shares are not information-theoretically independent. If an attacker has n-1 of n shares plus the ability to test candidate seeds (e.g., against a known public key fingerprint), they can brute-force the last share. With SSS, t-1 shares yield zero information regardless.

### 2.3 Physical / Metal Backup Guidance

**What it is:** Products like Cryptosteel Capsule, Billfodl, Blockplate, and SeedSigner engrave or stamp seed words onto metal plates that survive fire, flood, and corrosion.

**How it applies to bip39key:**
- The derivation receipt (Section 1.1) should be short enough to stamp onto metal alongside the seed words.
- Document recommended physical backup practices in a guide:
  - Store seed and receipt on metal, not paper.
  - Store in a fireproof location.
  - Consider geographic distribution (different physical sites).
  - Use tamper-evident bags/seals to detect unauthorized access.
- Consider generating a printable "backup card" (PDF/SVG) with the seed words, receipt string, fingerprint, and a QR code — designed to be printed on an air-gapped machine and then stored physically.

### 2.4 Social Recovery

**What it is:** Designate trusted contacts ("guardians") who each hold a share of your secret. Recovery requires a threshold of guardians to cooperate. Popularized by Argent wallet and Vitalik Buterin's writings on social recovery wallets.

**How it applies to bip39key:**
- This is essentially Shamir (Section 2.1) with a social protocol layer on top.
- Not directly implementable in a CLI tool, but `bip39key` could produce Shamir shares that users distribute to guardians manually.
- The tool could output shares in a format that includes instructions for the guardian ("If [user] asks you to help recover their key, provide this code: ...").

### 2.5 Dead Man's Switch / Timelock

**What it is:** Automatically release key material (or shares of it) if the owner doesn't check in within a specified period. Used in estate planning for crypto assets.

**How it applies to bip39key:**
- Out of scope for the CLI tool itself, but worth documenting as a practice.
- Users could store encrypted Shamir shares in a service with a dead man's switch (e.g., a scheduled email, a smart contract, a trusted third-party escrow).
- The PGP key's expiration timestamp (`--expiration-timestamp`) already provides a weaker form of this: the key becomes invalid after a date, signaling to others that the owner may be unavailable.

### 2.6 Codex32 / BIP-93 (Manually Verifiable Backups)

**What it is:** A Shamir's Secret Sharing scheme for BIP-32 master seeds using a Bech32-like encoding. Includes a BCH error-correcting code that can detect up to 8 errors or correct up to 4. Crucially, it is designed for **manual computation** — shares can be generated and verified with pen, paper, and lookup tables, requiring no electronic device.

**How it applies to bip39key:**
- Codex32 shares could serve as an alternative backup format for the seed entropy.
- The BCH error correction is strictly stronger than BIP-39's checksum and could catch transcription errors that BIP-39 would miss.
- The pen-and-paper verifiability means users can confirm their backup is valid without trusting any software.
- Presented by Andrew Poelstra et al. Still a relatively new proposal but gaining traction.

### 2.7 Hierarchical / Multi-Key Derivation

**What it is:** BIP-32/BIP-44 define hierarchical deterministic (HD) wallets where a single seed produces a tree of keys. Each branch can be independently shared or rotated.

**How it applies to bip39key:**
- Currently, `bip39key` derives exactly one sign key and one encrypt key from a seed.
- A future version could support deriving multiple key pairs from a single seed using different derivation paths (e.g., `--key-index N`).
- Use case: rotate your encryption subkey without changing your signing key, using the same seed.
- The HKDF approach already partially enables this — different info strings produce different keys. We could expose this as a user-facing parameter.
- **SLIP-0021** defines symmetric key derivation from a master seed using HMAC-SHA512 with label-based paths (strings, not indices): `Node = HMAC-SHA512(Key=parent_key, Data=0x00 || label)`. Left 32 bytes = derived key, right 32 bytes = chain key for further derivation. Example path: `m/"bip39key"/"sign"/"v1"`. This could provide a standardized HD-like derivation for `bip39key`.
- **Gordian architecture** (Blockchain Commons) defines interoperable formats (Gordian Envelope, dCBOR) and visual verification tools (LifeHash — generates distinct abstract images from hashes for visual fingerprint comparison). These could complement bip39key's output formats.

---

## 3. Key Generation Hardening

### 3.1 Memory Protection

**Current state:** Secret key bytes live in `Vec<u8>` and `[u8; 32]` arrays on the heap and stack. They are not zeroed after use, not locked in memory, and may be swapped to disk or included in core dumps.

**Improvements:**

#### 3.1.1 Zeroize Secrets After Use
- Use the [`zeroize`](https://crates.io/crates/zeroize) crate (v1.8+) to overwrite secret buffers when they go out of scope. It uses `write_volatile` + compiler fence to prevent dead-store elimination.
- Apply `Zeroize` derive macro or manual `zeroize()` calls to: `SignKey.private_key`, `EncryptKey.private_key`, `KeySettings.seed`, `KeySettings.passphrase`, Argon2id output buffers, HKDF output buffers, and all intermediate `Vec<u8>` holding key material.
- Use [`secrecy`](https://crates.io/crates/secrecy) crate's `Secret<T>` wrapper for types that should never be accidentally logged or displayed. `Secret<T>` implements `Debug`/`Display` as `[REDACTED]`, preventing accidental `println!("{:?}", settings)` leaks.
- Wrap intermediate buffers in `Zeroizing<Vec<u8>>`:
  ```rust
  use zeroize::Zeroizing;
  fn run_argon(...) -> Result<Zeroizing<Vec<u8>>> {
      Ok(Zeroizing::new(argon2::hash_raw(bytes, user_id.as_bytes(), &config)?))
  }
  ```

**Specific buffers needing zeroize in the current codebase:**

| Variable | Location | Type |
|---|---|---|
| Seed bytes | `KeySettings.seed` | `Vec<u8>` |
| Passphrase | `KeySettings.passphrase` | `Option<String>` |
| Argon2id output | `run_argon()` return | `Vec<u8>` |
| HKDF output | `hkdf_expand()` return | `Vec<u8>` |
| Concatenated seed+pass | `new_with_concat`/`new_with_hkdf` local | `Vec<u8>` |
| Sign key bytes | `SignKey.private_key` | `[u8; 32]` |
| Encrypt key bytes | `EncryptKey.private_key` | `[u8; 32]` |
| `input` in `SignKey::new` | stack local | `[u8; 32]` |
| `normalized_key` in `EncryptKey::new` | stack local | `[u8; 32]` |

#### 3.1.2 Lock Memory (mlock)
- Call `mlock(2)` on buffers containing secrets to prevent them from being swapped to disk.
- On Linux: `libc::mlock(ptr, len)`. On macOS: same syscall.
- Also call `madvise(MADV_DONTDUMP)` to exclude secret pages from core dumps.
- Consider `mprotect` to mark secret pages as non-readable when not actively needed (defense in depth against Spectre-style reads).
- Disable ptrace and core dumps at process start:
  ```rust
  // At the very start of main():
  unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0); }
  ```
  This also prevents `/proc/PID/mem` reads by other processes of the same UID. Already standard practice in `gpg-agent` and `ssh-agent`.
- **Note on mlockall:** `mlockall(MCL_CURRENT | MCL_FUTURE)` would lock all pages, but Argon2id with RFC 9106 settings allocates ~2 GiB — this will fail on most systems. Use targeted `mlock` on specific buffers instead.
- Default `RLIMIT_MEMLOCK` is typically 64KB for unprivileged users on Linux. May need to be raised via `/etc/security/limits.conf` or `setcap cap_ipc_lock`.

#### 3.1.3 Guard Pages
- Allocate secrets in a region bounded by guard pages (no-access pages) to catch buffer overflows/underflows.
- The [`memsec`](https://crates.io/crates/memsec) or [`secrets`](https://crates.io/crates/secrets) crates provide guarded heap allocations.

### 3.2 Side-Channel Resistance

#### 3.2.1 Constant-Time Operations
- The [`subtle`](https://crates.io/crates/subtle) crate provides constant-time comparison (`ConstantTimeEq`), conditional selection (`ConditionallySelectable`), and `Choice` type that wraps a `u8` to prevent boolean short-circuiting. Already a transitive dependency via `ed25519-dalek`.
- **ed25519-dalek (v2.1):** Uses `curve25519-dalek` backend with multiple options:
  - `u64_backend` — portable, uses `subtle` for constant-time ops.
  - `simd_backend` — AVX2/AVX512, also constant-time.
  - `fiat_backend` — uses Fiat Cryptography formally verified field arithmetic.
  - **Recommendation:** Enable the `fiat` feature for formally verified constant-time field arithmetic: `ed25519-dalek = { version = "2.1.0", features = ["fiat_u64_backend"] }`.
  - Signing is constant-time: the nonce is deterministic (RFC 8032) and scalar multiplication uses a fixed-time ladder.
- **x25519-dalek:** Uses the Montgomery ladder which is inherently constant-time (same operations regardless of scalar bits). The clamping in `EncryptKey::new` uses bitwise operations (constant-time, good).
- **AES (for PGP S2K and SSH encryption):** The `aes` crate (v0.8) uses AES-NI hardware instructions when available (constant-time by design) and a bitsliced software fallback (`fixslice`) that avoids T-table lookups. No vulnerable T-table implementation is used.
- The XOR operation in `new_with_xor` is inherently constant-time (byte-by-byte XOR of fixed-length buffers), but the iterator chain should be verified not to short-circuit.
- Argon2id is designed to be side-channel resistant — the "id" variant combines data-independent (Argon2i, first pass) and data-dependent (Argon2d, subsequent passes) memory access patterns.

#### 3.2.2 Avoid Secret-Dependent Branching
- Review all code paths where secret data influences control flow.
- The Curve25519 clamping in `EncryptKey::new` uses bitwise operations (constant-time, good).
- BIP-39 checksum validation in the `bip39` crate may leak timing information about the seed — but this runs before key derivation and the seed is not itself secret from the user, so this is acceptable.

### 3.3 Process Isolation

#### 3.3.1 Seccomp Filtering
- After reading input and before starting key derivation, install a seccomp-bpf filter that restricts syscalls to only those needed.
- This limits the damage from a hypothetical code execution vulnerability in a dependency.
- The [`seccompiler`](https://crates.io/crates/seccompiler) crate (from AWS Firecracker) provides a Rust-native BPF compiler. Also: [`syscallz`](https://crates.io/crates/syscallz) (simpler API), [`libseccomp`](https://crates.io/crates/libseccomp) (bindings).

**Required syscalls during key derivation phase:**
- `read`, `write`, `writev` — I/O
- `mmap`, `munmap`, `mprotect`, `mlock` — memory management (Argon2id allocates large buffers)
- `brk` — heap management
- `futex` — threading (Argon2id uses parallelism)
- `clone3`, `set_robust_list`, `rseq` — thread creation
- `getrandom` — for S2K salt and SSH salt
- `close`, `exit_group`, `sigaltstack` — cleanup
- `rt_sigaction`, `rt_sigprocmask` — signal handling

**Practical concern:** The seccomp filter must be applied after all initialization (argument parsing, file opens, pinentry subprocess communication) and before key derivation. This requires restructuring `main()` into phases.

#### 3.3.2 Namespace Isolation
- Linux namespaces can isolate the key generation process:
  - **Network namespace** — prevents network access during key gen.
  - **PID namespace** — hides other processes.
- Most practical as a wrapper: `unshare --net --pid --fork -- bip39key [args]`.
- A `--paranoid` flag could use `clone()` with `CLONE_NEWNET` to drop network access before derivation.

#### 3.3.3 Disable Ptrace
- Call `prctl(PR_SET_DUMPABLE, 0)` early in `main()` — see Section 3.1.2 above.

#### 3.3.4 Terminal Security
- **Seed input echo vulnerability:** The `inquire` crate's `Password` prompt disables echo for passphrases, but the seed prompt in `seed.rs` uses `Text` which **echoes the seed words to the terminal**. This is a significant exposure — anyone seeing the screen (or screen recording/sharing) captures the seed. The seed prompt should use a non-echoing input or pinentry.
- Consider clearing the terminal scrollback after sensitive input is entered (`\x1b[3J` CSI sequence).
- Detect if running inside a screen sharing session (e.g., check for `DISPLAY` + known screen sharing processes) and warn the user.
- Consider extending the pinentry approach (`BIP39_PINENTRY`) to also handle seed input, isolating it from the terminal entirely.

### 3.4 Entropy Considerations

#### 3.4.1 Where bip39key Uses Randomness
The key derivation is fully deterministic from the seed — but randomness IS used in two places:
- **`pgp.rs:109`**: `OsRng.fill_bytes(&mut salt_and_iv)` — 8 bytes of S2K salt + 16 bytes of AES-256-CFB IV for PGP passphrase encryption.
- **`ssh.rs:79`**: `OsRng.fill_bytes(&mut randbuf)` — 16 bytes of bcrypt-pbkdf salt + 4 bytes of check value for SSH passphrase encryption.

These are non-deterministic by design (different ciphertext each time, same plaintext). This is correct — the S2K salt and IV must be random. But it means:
- If `OsRng` fails or returns low-entropy data, the passphrase encryption is weakened (the key material itself is unaffected since it comes from the deterministic derivation).
- `OsRng` uses the `getrandom()` syscall on modern Linux (5.6+), which blocks until the CRNG is initialized. This is the correct behavior.
- Consider a startup health check:
  ```rust
  let mut test = [0u8; 32];
  getrandom::getrandom(&mut test).expect("getrandom failed");
  assert!(test != [0u8; 32], "getrandom returned all zeros");
  ```

**Entropy starvation on VMs:** On freshly booted VMs with no hardware RNG, the kernel CRNG may not be initialized. Mitigations: ensure `virtio-rng` is enabled, use `haveged` or `rng-tools`. For air-gapped VMs, boot and wait for CRNG initialization before running `bip39key`.

#### 3.4.2 Air-Gapped Generation
- Document a recommended workflow for air-gapped key generation:
  1. Boot a Tails/amnesic USB or dedicated offline machine.
  2. Build `bip39key` from source (or verify a reproducible build hash).
  3. Generate the key, write to a USB or QR code.
  4. Shut down the machine (Tails wipes RAM automatically).
- Consider a `--paranoid` flag that:
  - Refuses to run if a network interface is up.
  - Checks for virtualization (reading `/sys/class/dmi/id/product_name`, checking for hypervisor CPUID bit).
  - Warns if running under a debugger.

### 3.5 Randomness for Non-Deterministic Components

While the key derivation is deterministic, the passphrase encryption uses random salts/IVs. To allow fully reproducible output (useful for testing and verification):

**Proposal:** A `--deterministic-encryption` flag (hidden, for testing only) that derives the S2K salt and IV from the key material using HKDF with a distinct info string, instead of using `OsRng`. This would make the entire output byte-for-byte reproducible from seed + flags.

**Warning:** This trades encryption salt randomness for reproducibility. It should only be used for verification workflows, never for production keys, and should be clearly documented as such.

---

## 4. Key Validation and Verification

### 4.1 Round-Trip Test at Generation Time

**Problem:** A bug in PGP/SSH serialization could produce a key file that looks valid but can't actually be used.

**Proposal:** After generating a key, optionally perform a round-trip test:
1. Generate a random challenge message.
2. Sign it with the generated key.
3. Verify the signature with the public key.
4. If using PGP with an encryption subkey, encrypt the challenge to the public key and decrypt with the private key.
5. If any step fails, refuse to output the key and report the error.

A `--self-test` flag would enable this. It adds a few milliseconds but provides strong confidence that the serialized key actually works.

### 4.2 Golden Test Vectors for HKDF

**Current state:** The `test_gpg_raw_hkdf` test checks that an HKDF-derived key can be imported into GPG, but doesn't verify decryption of a golden ciphertext. The xor and concat tests do have golden encrypted messages (`test/message-*.gpg`).

**Action:** Create golden test files for HKDF:
1. Generate a key with known seed + user ID + `--algorithm hkdf`.
2. Encrypt a known message to that key using GPG.
3. Commit the encrypted message as `test/message-hkdf.gpg`.
4. Add a test that decrypts it and verifies the plaintext.

This catches regressions in the actual key material, not just the serialization format.

### 4.3 Cross-Implementation Verification

**Problem:** bip39key's PGP implementation is hand-rolled (not using an external PGP library). Subtle bugs in packet construction could produce keys that work in some GPG versions but not others.

**Improvements:**
- Test against multiple GPG versions (2.2.x, 2.4.x) in CI.
- Test key import with Sequoia PGP (a Rust PGP implementation) as an independent verification.
- Test SSH key import with multiple OpenSSH versions.
- Consider fuzzing the PGP packet construction with known-good parsers.

### 4.4 Fingerprint Display and Comparison

**Current state:** The tool outputs the full key but doesn't display the fingerprint.

**Proposal:** Always print the key fingerprint (PGP) or public key hash (SSH) to stderr after generation. This gives the user a value they can write down and later use with `--verify`.

Format:
```
PGP fingerprint: 67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F
SSH public key: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 5. Build and Distribution Security

### 5.1 Reproducible Builds

**Current state:** The project uses Nix with devenv, which is a good foundation for reproducibility.

**Improvements:**
- Publish the Nix derivation hash for each release so users can verify they built the same binary.
- Add CI that builds on multiple platforms and compares hashes.
- Document the exact `nix build` command and expected hash in each release's notes.
- Ensure deterministic Rust compilation:
  ```nix
  SOURCE_DATE_EPOCH = "1231006505"; # Bitcoin genesis
  CARGO_INCREMENTAL = "0";
  RUSTFLAGS = "--remap-path-prefix=${src}=/build";
  ```
- Use `crane` or `naersk` for Nix-native Cargo builds that capture `Cargo.lock` exactly.
- Verification workflow: build twice on independent machines, compare SHA-256. Rust is generally reproducible when paths and timestamps are controlled.

### 5.2 Dependency Auditing

**Current state:** No automated dependency auditing.

**Improvements:**
- Add `cargo audit` to CI to check for known vulnerabilities in the RustSec advisory database.
- Add `cargo vet` (Mozilla's supply chain verification) or `cargo deny` for license/ban/duplicate checks.
- Run `cargo supply-chain` to list all crate authors and identify bus-factor risks.
- Pin dependency versions in `Cargo.lock` (already done) and review updates carefully.

**Specific dependency concerns:**

| Crate | Concern | Recommendation |
|---|---|---|
| `rust-argon2` (v2.1) | Not the RustCrypto `argon2` crate. Less audited. | Switch to RustCrypto `argon2` (v0.5) — more actively maintained, uses `zeroize` internally. |
| `tiny-bip39` (v1.0) | Unmaintained since 2021. | Evaluate the `bip39` crate as a replacement. |
| `x25519-dalek` | v2.0.0-rc3 is a release candidate. | Update to v2.0.1 (stable). |
| `inquire` (v0.6) | Large TUI framework, big dependency tree. | Consider `rpassword` for just password input. |
| `base64` (v0.13) | Old version. | Update to v0.22 (current). |
| `lazy_static` | No longer needed. | Replace with `std::sync::OnceLock` (stable since Rust 1.70; already used in `console.rs`). |

### 5.3 Binary Signing

- Sign release binaries with a known PGP key (ideally one generated by `bip39key` itself!).
- Publish signatures alongside binaries on GitHub Releases.
- Consider using sigstore/cosign for keyless signing tied to the CI identity.

---

## 6. UX Improvements

### 6.1 Shell Completions

- Use clap's built-in `clap_complete` to generate shell completions for bash, zsh, and fish.
- Distribute as part of the Nix package.

### 6.2 Version Bump

- `Cargo.toml` currently says `1.4.4` despite the latest tag being `v1.5.0`. Keep these in sync. Consider a release script or CI check that verifies the tag matches `Cargo.toml`.

### 6.3 Structured Error Messages

- Current error handling uses `expect("Could not build keys")` which panics. Use proper error propagation and user-friendly messages.
- Exit codes: define specific exit codes for different failure modes (bad seed, bad passphrase, serialization error, self-test failure).

### 6.4 Progress Indication

- Argon2id with RFC 9106 settings can take several seconds. Show a progress spinner or "Deriving key (this may take a moment)..." message.

### 6.5 Subcommand Architecture

As the tool grows, the flat flag namespace gets unwieldy. Consider moving to subcommands:

```
bip39key generate --algorithm hkdf --user-id "..."
bip39key verify --fingerprint "..." --user-id "..."
bip39key split --shamir 2 3 --user-id "..."
bip39key combine --shamir --user-id "..."
bip39key receipt --decode "bip39key:v1:hkdf:..."
```

This would be a breaking change (v2.0 material) but would make the tool more discoverable and extensible.

---

## 7. Cryptographic Improvements

### 7.1 OpenPGP v5 / v6 Support

- The current implementation generates OpenPGP v4 keys.
- RFC 9580 defines OpenPGP v6 with modern cryptographic choices (AEAD for encryption, improved fingerprints using SHA-256, argon2 as a native S2K).
- As GPG and Sequoia adopt v6, consider adding `--pgp-version 6` support.

### 7.2 Additional Key Types

- **Ed448 / X448:** Larger curve for higher security margin (224-bit security vs Ed25519's 128-bit).
- **Post-quantum hybrid keys:** As PQ standards mature (ML-KEM, ML-DSA), consider hybrid key generation that combines a classical and post-quantum key. OpenPGP post-quantum drafts are in progress.

### 7.3 Age Encryption Support

- [age](https://age-encryption.org/) is a simpler alternative to PGP for file encryption, designed by Filippo Valsorda. No key management, no configuration — a single opinionated design (~4000 lines in the Go reference).
- Uses X25519 key agreement, HKDF-SHA256 key derivation, ChaCha20-Poly1305 payload encryption.
- Public keys are `age1...` (Bech32-encoded), private keys are `AGE-SECRET-KEY-1...`.
- `bip39key` could output age-compatible keys (`--format age`), since the encryption key we already derive (Curve25519 scalar) is exactly what age's X25519 needs. The [`rage`](https://crates.io/crates/rage) crate (Rust age implementation) could facilitate the encoding.
- Age does NOT support signing (by design — use `minisign` or `signify` for that), key certification, subkeys, or expiration.
- This would lower the barrier for users who find PGP too complex but only need encryption.

### 7.4 S2K Modernization

- The current PGP S2K uses iterated-and-salted SHA-256 (S2K type 3), which is the best available in OpenPGP v4 but weak by modern standards.
- OpenPGP v6 supports Argon2 as an S2K mechanism. When v6 support is added, use Argon2 for passphrase protection of the key file itself.
- For SSH, the current bcrypt-pbkdf with 512 rounds is reasonable but could be made configurable.

---

## 8. Documentation and Guides

### 8.1 Threat Model Document

Write an explicit threat model:
- What attacks does `bip39key` protect against? (Seed phrase backup, deterministic regeneration, passphrase-based encryption at rest.)
- What attacks does it NOT protect against? (Compromised machine, keylogger during seed entry, quantum computers, side channels in the current implementation.)
- What are the trust boundaries? (The tool trusts the OS entropy source, the Rust compiler, the dependency tree.)

### 8.2 Key Ceremony Guide

A step-by-step guide for generating a high-value key:

1. **Prepare the environment:**
   - Boot an air-gapped machine (WiFi/Bluetooth hardware disabled in BIOS) with an amnesic OS:
     - **Tails:** RAM-only filesystem, secrets never touch persistent storage, GPG pre-installed.
     - **NixOS live USB:** Build a minimal ISO with just `bip39key` and `gnupg`, networking disabled.
     - **Raspberry Pi Zero** (no-WiFi model) with SD card.
   - Verify the `bip39key` binary hash against the published reproducible build hash.

2. **Generate the seed:**
   - Use a hardware random source, dice rolls (BIP-39 wordlist + 11-bit mapping), or a dedicated device like SeedSigner.
   - Verify the BIP-39 checksum.

3. **Generate the key:**
   - Run `bip39key --algorithm hkdf --user-id "..." -p <passphrase>`.
   - Record the derivation receipt (once implemented, Section 1.1).
   - Note the PGP fingerprint printed to stderr (once implemented, Section 4.4).

4. **Verify the key:**
   - Regenerate on the same machine and compare fingerprints (`--verify`, once implemented).
   - Import into GPG, encrypt+decrypt a test message.

5. **Export:**
   - Export the public key via QR code (`--qr`, once implemented) or USB sneakernet. Avoid using the network.
   - Consider using `qr2term` crate to render the public key as a terminal QR code, avoiding file I/O entirely.

6. **Optionally import to hardware token:**
   - Import PGP key into GPG, then move to YubiKey: `gpg --edit-key <uid>` → `keytocard`.
   - The YubiKey becomes the daily-use device; the seed phrase is the long-term backup.
   - Delete the soft copy: `gpg --delete-secret-keys <uid>`.

7. **Back up the seed:**
   - Store the seed phrase and derivation receipt on metal (Cryptosteel, Billfodl, Blockplate).
   - Optionally split with Shamir shares (SLIP-0039/SSKR) and distribute to guardians.
   - Store in geographically distributed, physically secure locations.
   - Use tamper-evident bags/seals to detect unauthorized access.

8. **Shut down:** Tails wipes RAM automatically. For other OSes, power off (not sleep/hibernate).

### 8.3 Migration Guide

For users upgrading from v1 (xor default) to v2 (hkdf default):
- How to identify which algorithm your existing key uses.
- How to regenerate with the explicit `--algorithm xor` flag.
- Whether and how to migrate to HKDF (generate a new key, re-sign, update key servers).

---

## 9. Operational Improvements

### 9.1 CI Enhancements

- Run integration tests on macOS and Linux (currently CI has had macOS GPG issues).
- Add Windows CI (if feasible with GPG/ssh-keygen availability).
- Add clippy + rustfmt + cargo audit as required checks.
- Test against multiple GPG versions.

### 9.2 Release Automation

- Automate the release process: tag → build → test → sign → publish GitHub Release.
- Include checksums and signatures in the release.
- Auto-generate changelog from commit messages.

### 9.3 Nix Flake Publishing

- Publish the flake to a public binary cache so users can `nix run github:jpdarago/bip39key` without building from source.
- This also provides reproducible builds by default.

---

## 10. Prioritized Implementation Order

Roughly ordered by impact-to-effort ratio, grouped into phases:

**Phase 1 — Low-hanging fruit (hours each):**
1. Add `zeroize` as a direct dependency, apply `ZeroizeOnDrop` to key structs, wrap intermediates in `Zeroizing<Vec<u8>>`. (Section 3.1.1)
2. Add `prctl(PR_SET_DUMPABLE, 0)` at process start. One line. (Section 3.1.2)
3. ~~Bump `Cargo.toml` version to match the latest tag. (Section 6.2)~~
4. ~~Add `cargo audit` to CI. (Section 5.2)~~
5. Always print fingerprint to stderr after key generation. (Section 4.4)
6. Fix seed input echo — use non-echoing prompt for seed words. (Section 3.3.4)

**Phase 2 — Significant features (days each):**
7. Derivation receipt: encode, print, and `--from-receipt` parsing. (Section 1.1)
8. `--verify` mode for fingerprint comparison without key output. (Section 1.2)
9. Golden test vectors for HKDF algorithm. (Section 4.2)
10. Switch from `rust-argon2` to RustCrypto `argon2`. (Section 5.2)
11. `mlock` on sensitive buffers. (Section 3.1.2)
12. `--self-test` round-trip verification. (Section 4.1)

**Phase 3 — Larger efforts (weeks):**
13. Subcommand architecture for v2.0. (Section 6.5)
14. SSKR/SLIP-0039 Shamir splitting. (Section 2.1)
15. Age output format. (Section 7.3)
16. Seccomp filtering. (Section 3.3.1)
17. OpenPGP v6 support. (Section 7.1)
18. Threat model and key ceremony documentation. (Sections 8.1, 8.2)

**Phase 4 — Aspirational:**
19. Multi-key derivation / SLIP-0021. (Section 2.7)
20. Post-quantum hybrid keys. (Section 7.2)
21. Codex32/BIP-93 backup format. (Section 2.6)
