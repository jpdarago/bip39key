//! age (https://age-encryption.org) X25519 identity and recipient output.
//!
//! The X25519 key comes from its own HKDF-Expand info string
//! (`bip39key-age-v1`), so it is independent of the OpenPGP encryption subkey:
//! leaking one does not leak the other. This needs `--algorithm hkdf`; xor and
//! concat only produce the 64 bytes the sign and encrypt keys already use. The
//! encoding is Bech32 (BIP 173, not
//! Bech32m), as specified by age:
//!
//! - recipient: HRP `age`, lowercase, e.g. `age1...`
//! - identity: HRP `age-secret-key-`, uppercase, e.g. `AGE-SECRET-KEY-1...`
//!
//! age identity files have no passphrase protection, so the secret output is
//! always plaintext.

use crate::keys::*;
use crate::types::*;

use anyhow::Context;
use std::io::Write;

const RECIPIENT_HRP: &str = "age";
const IDENTITY_HRP: &str = "age-secret-key-";

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut result: Vec<u8> = bytes.iter().map(|b| b >> 5).collect();
    result.push(0);
    result.extend(bytes.iter().map(|b| b & 31));
    result
}

/// Regroup 8-bit bytes into 5-bit groups, zero-padding the last group.
fn to_base32(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        result.push(((acc << (5 - bits)) & 31) as u8);
    }
    result
}

/// Encode `data` as lowercase Bech32 (BIP 173) with the given lowercase HRP.
/// age keys exceed BIP 173's 90 character limit, which age itself ignores.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let values = to_base32(data);
    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&values);
    checksum_input.extend_from_slice(&[0; 6]);
    let checksum = polymod(&checksum_input) ^ 1;

    let mut result = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    result.push_str(hrp);
    result.push('1');
    for value in values {
        result.push(CHARSET[value as usize] as char);
    }
    for i in 0..6 {
        result.push(CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    result
}

fn age_key(keys: &Keys) -> Result<&EncryptKey> {
    keys.age_key
        .as_ref()
        .context("age output needs the age key, which is only derived with --algorithm hkdf")
}

/// The `age1...` recipient string for the derived age key.
pub fn recipient(keys: &Keys) -> Result<String> {
    Ok(bech32_encode(RECIPIENT_HRP, &age_key(keys)?.public_key))
}

/// The `AGE-SECRET-KEY-1...` identity string for the derived age key.
pub fn identity(keys: &Keys) -> Result<String> {
    Ok(bech32_encode(IDENTITY_HRP, &age_key(keys)?.private_key).to_uppercase())
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
    use proptest::prelude::*;

    /// Decode a Bech32 string, checking the checksum, and return its HRP and
    /// data bytes. Only used to round-trip the encoder.
    fn bech32_decode(s: &str) -> (String, Vec<u8>) {
        let s = s.to_lowercase();
        let sep = s.rfind('1').expect("no separator");
        let (hrp, rest) = (&s[..sep], &s[sep + 1..]);
        let values: Vec<u8> = rest
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).expect("bad char") as u8)
            .collect();
        let mut checksum_input = hrp_expand(hrp);
        checksum_input.extend_from_slice(&values);
        assert_eq!(polymod(&checksum_input), 1, "bad checksum");
        let data = &values[..values.len() - 6];
        let mut bytes = Vec::new();
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &v in data {
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes.push(((acc >> bits) & 0xff) as u8);
            }
        }
        assert!(bits < 5, "too much padding");
        assert_eq!(acc & ((1 << bits) - 1), 0, "non-zero padding");
        (hrp.to_string(), bytes)
    }

    #[test]
    fn bip173_valid_checksums() {
        // Valid Bech32 strings from BIP 173. Each must carry a checksum that
        // verifies, which exercises polymod and hrp_expand independently of
        // the encoder.
        for s in [
            "A12UEL5L",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ] {
            let lower = s.to_lowercase();
            let sep = lower.rfind('1').unwrap();
            let values: Vec<u8> = lower[sep + 1..]
                .bytes()
                .map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8)
                .collect();
            let mut input = hrp_expand(&lower[..sep]);
            input.extend_from_slice(&values);
            assert_eq!(polymod(&input), 1, "{s}");
        }
    }

    #[test]
    fn bip173_encode_empty_data() {
        assert_eq!(bech32_encode("a", &[]), "a12uel5l");
    }

    proptest! {
        #[test]
        fn bech32_round_trips(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let encoded = bech32_encode(RECIPIENT_HRP, &data);
            let (hrp, decoded) = bech32_decode(&encoded);
            prop_assert_eq!(hrp, RECIPIENT_HRP);
            prop_assert_eq!(decoded, data);
        }

        #[test]
        fn age_output_encodes_the_age_key(secret in any::<[u8; 32]>()) {
            let age_key = EncryptKey::new(&secret, DEFAULT_CREATION_TIMESTAMP, None).unwrap();
            let sign_key = SignKey::new(&secret, DEFAULT_CREATION_TIMESTAMP, None, false).unwrap();
            let expected_public = age_key.public_key;
            let expected_private = age_key.private_key;
            let keys = Keys {
                user_id: UserId { user_id: String::new() },
                sign_key,
                encrypt_key: None,
                auth_key: None,
                age_key: Some(age_key),
                passphrase: None,
            };

            let recipient = recipient(&keys).unwrap();
            prop_assert!(recipient.starts_with("age1"));
            prop_assert_eq!(bech32_decode(&recipient).1, expected_public.to_vec());

            let identity = identity(&keys).unwrap();
            prop_assert!(identity.starts_with("AGE-SECRET-KEY-1"));
            prop_assert_eq!(&identity, &identity.to_uppercase());
            prop_assert_eq!(bech32_decode(&identity).1, expected_private.to_vec());
        }
    }
}
