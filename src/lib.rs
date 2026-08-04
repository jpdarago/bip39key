//! Deterministic OpenPGP and OpenSSH key generation from BIP39/Electrum
//! mnemonic seed phrases.
//!
//! The binary in `main.rs` is a thin CLI wrapper over this library. The split
//! exists so tests can exercise seed decoding, key derivation, and packet
//! serialization in process, rather than only end to end through the binary.

// `#[macro_use]` makes console_logln! visible to the modules below;
// `#[macro_export]` in console.rs makes it visible to the binary.
#[macro_use]
pub mod console;

pub mod cli;
pub mod html_receipt;
pub mod keys;
pub mod passphrase;
pub mod pgp;
pub mod receipt;
pub mod seed;
pub mod ssh;
pub mod types;
