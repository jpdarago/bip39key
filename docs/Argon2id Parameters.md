# Argon2id Parameters

**Parent:** [[bip39key v2 Design Doc]]

---

## v1 vs v2 Defaults

| Parameter | v1 default | v2 default | Source |
|---|---|---|---|
| Memory | 64 MiB | 2 GiB | RFC 9106 first recommendation |
| Iterations (time cost) | 32 | 1 | RFC 9106 first recommendation |
| Parallelism (lanes) | 8 | 4 | RFC 9106 first recommendation |
| Output length | 64 bytes | 64 bytes | Unchanged |
| Variant | Argon2id | Argon2id | Unchanged |
| Version | 0x13 | 0x13 | Unchanged |
| Salt | user_id bytes | user_id bytes | Unchanged |

---

## Why Change Defaults

The v1 defaults (64 MiB / 32 iterations / 8 lanes) were chosen early in development. They provide decent protection but are well below what modern hardware can handle for a high-value, infrequent operation like key generation.

RFC 9106 Section 4 recommends:
- **First option (high-memory):** 2 GiB memory, 1 iteration, 4 lanes -- for environments where memory is abundant.
- **Second option (low-memory):** 64 MiB memory, 3 iterations, 4 lanes -- for memory-constrained environments.

bip39key generates long-lived identity keys. Users run it once at generation time and perhaps once more years later at recovery time. The 2 GiB / 1 iteration profile is the right choice:

- **Memory-hardness is the primary defense.** ASICs and GPUs are bottlenecked by memory bandwidth, not compute. 2 GiB requires the attacker to provision 2 GiB per parallel attempt, making large-scale brute force prohibitively expensive.
- **1 iteration is sufficient at 2 GiB.** The RFC's analysis shows that at high memory settings, additional iterations add minimal security because the memory cost already dominates.
- **4 lanes match typical consumer hardware.** Most machines have at least 4 cores. Using 4 lanes keeps derivation time reasonable (~2-5 seconds on modern hardware).

---

## No Custom Parameters

v2 Argon2id parameters are **fixed to RFC 9106** and not user-configurable. There are no `--argon2-*` flags.

**Why:** Every configurable parameter is something the user can forget. Argon2id settings directly affect key material -- using the wrong values produces a completely different key with no way to detect the error. Fixing the parameters to a single well-known standard eliminates this entire class of recovery failure.

Users who need v1's parameters (64 MiB / 32 iter / 8 lanes) must build from the `v1.5.0` git tag. v1 parameters are a v1 concern.

**What if RFC 9106 becomes outdated?** A future v3 can adopt new parameters with a new version number and new HKDF info strings (`*-v3`). The receipt version field distinguishes which parameter set was used.

---

## Timing Benchmarks

Approximate derivation times (for reference, not commitments):

| Hardware | v1 (64 MiB / 32 iter) | v2 (2 GiB / 1 iter) |
|---|---|---|
| Modern x86_64 (16 GB RAM) | ~1-2s | ~2-5s |
| Raspberry Pi 4 (4 GB RAM) | ~5-10s | ~15-30s |
| Raspberry Pi 4 (2 GB RAM) | ~5-10s | OOM (use v1.5.0 tag) |

v2 should print a progress message to stderr when derivation begins: `Deriving key material (this may take a moment)...`

---

## Crate Migration

v1 uses `rust-argon2` (v2.0.0), which is not the RustCrypto `argon2` crate. The RustCrypto version:
- Is more actively maintained.
- Uses `zeroize` internally for secret buffers.
- Has better API ergonomics for configuration.
- Is the de facto standard in the Rust ecosystem.

v2 should migrate to `argon2` (RustCrypto, currently v0.5.x). This is a code change only -- the Argon2id algorithm and output are identical given the same parameters.

---

## Related

- [[HKDF Key Derivation]] -- what happens after Argon2id
- [[Receipt System]] -- receipts encode which parameter set was used
- [[bip39key v2 Design Doc]] -- overall v2 design
