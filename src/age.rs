//! age (https://age-encryption.org) X25519 identity and recipient output.
//!
//! The X25519 key comes from its own HKDF-Expand info string
//! (`bip39key-age-v1`), so it is independent of the OpenPGP encryption subkey:
//! leaking one does not leak the other. This needs `--algorithm hkdf`; xor and
//! concat only produce the 64 bytes the sign and encrypt keys already use.
//!
//! The encoding is Bech32 (BIP 173, not Bech32m), as specified by age:
//!
//! - recipient: HRP `age`, lowercase, e.g. `age1...`
//! - identity: HRP `age-secret-key-`, uppercase, e.g. `AGE-SECRET-KEY-1...`
//!
//! age identity files have no passphrase protection, so the secret output is
//! always plaintext.

use crate::keys::*;
use crate::types::*;

use anyhow::Context;
use bech32::{Bech32, Hrp};
use std::io::Write;

const RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("age");
const IDENTITY_HRP: Hrp = Hrp::parse_unchecked("age-secret-key-");

fn age_key(keys: &Keys) -> Result<&EncryptKey> {
    keys.age_key
        .as_ref()
        .context("age output needs the age key, which is only derived with --algorithm hkdf")
}

/// The `age1...` recipient string for the derived age key.
pub fn recipient(keys: &Keys) -> Result<String> {
    Ok(bech32::encode_lower::<Bech32>(
        RECIPIENT_HRP,
        &age_key(keys)?.public_key,
    )?)
}

/// The `AGE-SECRET-KEY-1...` identity string for the derived age key.
pub fn identity(keys: &Keys) -> Result<String> {
    Ok(bech32::encode_upper::<Bech32>(
        IDENTITY_HRP,
        &age_key(keys)?.private_key,
    )?)
}

/// Write an age identity file. Unlike age-keygen this has no `# created:`
/// line, so the output stays deterministic.
pub fn output_secret<W: Write>(keys: &Keys, out: &mut W) -> Result<()> {
    writeln!(out, "# public key: {}", recipient(keys)?)?;
    writeln!(out, "{}", identity(keys)?)?;
    Ok(())
}

/// Write the age recipient, as `age-keygen -y` prints it.
pub fn output_public<W: Write>(keys: &Keys, out: &mut W) -> Result<()> {
    writeln!(out, "{}", recipient(keys)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::primitives::decode::CheckedHrpstring;
    use proptest::prelude::*;

    /// Decode with a strict Bech32 (not Bech32m) checksum check, returning the
    /// HRP and data bytes.
    fn decode_bech32(s: &str) -> (Hrp, Vec<u8>) {
        let checked = CheckedHrpstring::new::<Bech32>(s).expect("not valid Bech32");
        (checked.hrp(), checked.byte_iter().collect())
    }

    fn keys_with_age_key(secret: &[u8; 32]) -> Keys {
        Keys {
            user_id: UserId {
                user_id: String::new(),
            },
            sign_key: SignKey::new(secret, DEFAULT_CREATION_TIMESTAMP, None, false).unwrap(),
            encrypt_key: None,
            auth_key: None,
            age_key: Some(EncryptKey::new(secret, DEFAULT_CREATION_TIMESTAMP, None).unwrap()),
            passphrase: None,
        }
    }

    #[test]
    fn missing_age_key_is_an_error() {
        let mut keys = keys_with_age_key(&[7; 32]);
        keys.age_key = None;
        assert!(recipient(&keys).is_err());
        assert!(identity(&keys).is_err());
    }

    proptest! {
        #[test]
        fn age_output_encodes_the_age_key(secret in any::<[u8; 32]>()) {
            let keys = keys_with_age_key(&secret);
            let age_key = keys.age_key.as_ref().unwrap();

            let recipient = recipient(&keys).unwrap();
            prop_assert!(recipient.starts_with("age1"));
            prop_assert_eq!(&recipient, &recipient.to_lowercase());
            let (hrp, data) = decode_bech32(&recipient);
            prop_assert_eq!(hrp, RECIPIENT_HRP);
            prop_assert_eq!(data, age_key.public_key.to_vec());

            let identity = identity(&keys).unwrap();
            prop_assert!(identity.starts_with("AGE-SECRET-KEY-1"));
            prop_assert_eq!(&identity, &identity.to_uppercase());
            let (hrp, data) = decode_bech32(&identity);
            prop_assert_eq!(hrp, IDENTITY_HRP);
            prop_assert_eq!(data, age_key.private_key.to_vec());
        }
    }
}
