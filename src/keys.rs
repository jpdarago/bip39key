use crate::types::*;
use hkdf::Hkdf;
use sha2::Sha256;

/// Default key creation time: the timestamp of the Bitcoin genesis block. Any
/// timestamp would work but this one is fairly recent, well established, and
/// stored in a decentralized database. GPG includes it in the fingerprint, so
/// it must never change.
pub const DEFAULT_CREATION_TIMESTAMP: i64 = 1231006505;

pub struct UserId {
    pub user_id: String,
}

pub struct SignKey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub signing_key: ed25519_dalek::SigningKey,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
    pub use_authorization_for_sign_key: bool,
}

impl SignKey {
    pub fn new(
        secret_key_bytes: &[u8],
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
        use_authorization_for_sign_key: bool,
    ) -> Result<SignKey> {
        let mut input = [0u8; 32];
        input.copy_from_slice(secret_key_bytes);
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&input);
        Ok(SignKey {
            creation_timestamp_secs,
            expiration_timestamp_secs,
            use_authorization_for_sign_key,
            public_key: secret_key.verifying_key().to_bytes(),
            private_key: secret_key.to_bytes(),
            signing_key: secret_key,
        })
    }
}

pub struct EncryptKey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
}

pub struct AuthKey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
}

impl EncryptKey {
    pub fn new(
        secret_key_bytes: &[u8],
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
    ) -> Result<EncryptKey> {
        // Clamp the secret key bytes per Curve25519 specification.
        // See https://datatracker.ietf.org/doc/html/rfc7748#section-5 for more information.
        let mut normalized_key = [0u8; 32];
        normalized_key.copy_from_slice(secret_key_bytes);
        normalized_key[0] &= 248;
        normalized_key[31] &= 127;
        normalized_key[31] |= 64;
        let encrypt_secret_key: x25519_dalek::StaticSecret = normalized_key.into();
        let encrypt_public_key = x25519_dalek::PublicKey::from(&encrypt_secret_key);
        Ok(EncryptKey {
            creation_timestamp_secs,
            expiration_timestamp_secs,
            public_key: encrypt_public_key.to_bytes(),
            private_key: encrypt_secret_key.to_bytes(),
        })
    }
}

impl AuthKey {
    pub fn new(
        secret_key_bytes: &[u8],
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
    ) -> Result<AuthKey> {
        let mut input = [0u8; 32];
        input.copy_from_slice(secret_key_bytes);
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&input);
        Ok(AuthKey {
            creation_timestamp_secs,
            expiration_timestamp_secs,
            public_key: secret_key.verifying_key().to_bytes(),
            private_key: secret_key.to_bytes(),
        })
    }
}

pub struct Keys {
    pub user_id: UserId,
    pub sign_key: SignKey,
    pub encrypt_key: Option<EncryptKey>,
    pub auth_key: Option<AuthKey>,
    /// X25519 key for age output. Only derived with HKDF, under its own info
    /// string, so it is independent of the PGP encryption subkey.
    pub age_key: Option<EncryptKey>,
    pub passphrase: Option<String>,
}

fn run_argon(bytes: &[u8], user_id: &str, use_rfc9106_settings: bool) -> Result<Vec<u8>> {
    let config = if use_rfc9106_settings {
        let mut result = argon2::Config::rfc9106();
        result.hash_length = 64;
        result
    } else {
        argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 64 * 1024,
            time_cost: 32,
            lanes: 8,
            secret: &[],
            ad: &[],
            hash_length: 64,
        }
    };
    Ok(argon2::hash_raw(bytes, user_id.as_bytes(), &config)?)
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| anyhow::anyhow!("HKDF-Expand: invalid PRK: {e}"))?;
    let mut output = vec![0u8; length];
    hkdf.expand(info, &mut output)
        .map_err(|e| anyhow::anyhow!("HKDF-Expand: {e}"))?;
    Ok(output)
}

pub struct KeySettings {
    pub user_id: String,
    pub seed: Vec<u8>,
    pub passphrase: Option<String>,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
    pub generate_encrypt_key: bool,
    pub generate_auth_key: bool,
    pub generate_age_key: bool,
    pub use_rfc9106_settings: bool,
    pub use_authorization_for_sign_key: bool,
}

impl Keys {
    fn build_keys(secret_key_bytes: &[u8], settings: KeySettings) -> Result<Keys> {
        Ok(Keys {
            user_id: UserId {
                user_id: settings.user_id,
            },
            sign_key: SignKey::new(
                &secret_key_bytes[..32],
                settings.creation_timestamp_secs,
                settings.expiration_timestamp_secs,
                settings.use_authorization_for_sign_key,
            )?,
            encrypt_key: if settings.generate_encrypt_key {
                Some(EncryptKey::new(
                    &secret_key_bytes[32..],
                    settings.creation_timestamp_secs,
                    settings.expiration_timestamp_secs,
                )?)
            } else {
                None
            },
            auth_key: None,
            age_key: None,
            passphrase: settings.passphrase,
        })
    }

    /// Derive keys using HKDF-Expand with domain separation.
    /// The Argon2id output is used as PRK, and separate info strings produce
    /// independent sign and encrypt key material.
    pub fn new_with_hkdf(settings: KeySettings) -> Result<Keys> {
        let generate_auth_key = settings.generate_auth_key;
        let generate_age_key = settings.generate_age_key;
        let creation_timestamp_secs = settings.creation_timestamp_secs;
        let expiration_timestamp_secs = settings.expiration_timestamp_secs;
        let prk = if let Some(pass) = &settings.passphrase {
            let mut bytes = settings.seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            run_argon(&bytes, &settings.user_id, settings.use_rfc9106_settings)?
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        let sign_key_bytes = hkdf_expand(&prk, b"bip39key-sign-v1", 32)?;
        let encrypt_key_bytes = hkdf_expand(&prk, b"bip39key-encrypt-v1", 32)?;
        let mut secret_key_bytes = sign_key_bytes;
        secret_key_bytes.extend_from_slice(&encrypt_key_bytes);
        let mut keys = Self::build_keys(&secret_key_bytes, settings)?;
        if generate_auth_key {
            let auth_key_bytes = hkdf_expand(&prk, b"bip39key-auth-v1", 32)?;
            keys.auth_key = Some(AuthKey::new(
                &auth_key_bytes,
                creation_timestamp_secs,
                expiration_timestamp_secs,
            )?);
        }
        if generate_age_key {
            let age_key_bytes = hkdf_expand(&prk, b"bip39key-age-v1", 32)?;
            keys.age_key = Some(EncryptKey::new(
                &age_key_bytes,
                creation_timestamp_secs,
                expiration_timestamp_secs,
            )?);
        }
        Ok(keys)
    }

    pub fn new_with_concat(settings: KeySettings) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt.
        let secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let mut bytes = settings.seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            run_argon(&bytes, &settings.user_id, settings.use_rfc9106_settings)?
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        Self::build_keys(&secret_key_bytes, settings)
    }

    pub fn new_with_xor(settings: KeySettings) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt
        let secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let bytes = run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?;
            // Generate another buffer with Argon for the passphrase and XOR it.
            let passphrase_bytes = run_argon(
                pass.as_bytes(),
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?;
            bytes
                .iter()
                .zip(passphrase_bytes.iter())
                .map(|(lhs, rhs)| lhs ^ rhs)
                .collect()
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        Self::build_keys(&secret_key_bytes, settings)
    }
}

/// Known-answer tests against the published vectors for each primitive bip39key
/// builds on. The golden vectors in tests/ catch *that* derived keys changed;
/// these say *which stage* changed, e.g. after a dependency upgrade.
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn unhex32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    // RFC 5869 Appendix A, the SHA-256 cases. bip39key only runs the Expand
    // step (Argon2id output is the PRK), so start from each case's PRK.
    #[test]
    fn hkdf_expand_rfc5869_vectors() {
        let cases = [
            (
                // A.1: basic case.
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "f0f1f2f3f4f5f6f7f8f9",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                // A.2: longer inputs and outputs.
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                 d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                // A.3: zero-length salt and info.
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (prk, info, okm) in cases {
            let okm = unhex(okm);
            assert_eq!(
                hkdf_expand(&unhex(prk), &unhex(info), okm.len()).unwrap(),
                okm
            );
        }
    }

    // RFC 9106 Section 5.3, the Argon2id vector. This checks the Argon2id
    // implementation itself; run_argon cannot take its secret and associated
    // data, so call the crate with the RFC's parameters directly.
    #[test]
    fn argon2id_rfc9106_vector() {
        let secret = [0x03; 8];
        let ad = [0x04; 12];
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 32,
            time_cost: 3,
            lanes: 4,
            secret: &secret,
            ad: &ad,
            hash_length: 32,
        };
        let tag = argon2::hash_raw(&[0x01; 32], &[0x02; 16], &config).unwrap();
        assert_eq!(
            tag,
            unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    // Pin the parameters behind -r/--use-rfc9106-settings. They come from the
    // argon2 crate's Config::rfc9106(), so a crate upgrade that changed them
    // would silently change every -r key.
    //
    // NOTE: the crate uses 1 lane, while RFC 9106's first recommendation is
    // p=4. Keys derived with -r have always used p=1, so this must stay 1.
    #[test]
    fn rfc9106_settings_are_pinned() {
        let config = argon2::Config::rfc9106();
        assert_eq!(config.variant, argon2::Variant::Argon2id);
        assert_eq!(config.version, argon2::Version::Version13);
        assert_eq!(config.mem_cost, 2 * 1024 * 1024, "2 GiB in KiB");
        assert_eq!(config.time_cost, 1);
        assert_eq!(config.lanes, 1, "not the RFC's p=4; see the note above");
        assert!(config.secret.is_empty());
        assert!(config.ad.is_empty());
    }

    // RFC 7748 Section 6.1. Alice's and Bob's private keys are unclamped
    // random bytes, so this also checks EncryptKey's clamping.
    #[test]
    fn x25519_rfc7748_vectors() {
        let alice = EncryptKey::new(
            &unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            DEFAULT_CREATION_TIMESTAMP,
            None,
        )
        .unwrap();
        let bob = EncryptKey::new(
            &unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
            DEFAULT_CREATION_TIMESTAMP,
            None,
        )
        .unwrap();
        assert_eq!(
            alice.public_key,
            unhex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob.public_key,
            unhex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        // The private bytes bip39key writes out must be a working scalar: both
        // sides of the exchange have to reach the RFC's shared secret.
        let shared = unhex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        let alice_secret = x25519_dalek::StaticSecret::from(alice.private_key);
        let bob_secret = x25519_dalek::StaticSecret::from(bob.private_key);
        let bob_public = x25519_dalek::PublicKey::from(bob.public_key);
        let alice_public = x25519_dalek::PublicKey::from(alice.public_key);
        assert_eq!(alice_secret.diffie_hellman(&bob_public).to_bytes(), shared);
        assert_eq!(bob_secret.diffie_hellman(&alice_public).to_bytes(), shared);

        // And the written-out scalar is clamped per RFC 7748 Section 5.
        for key in [&alice, &bob] {
            assert_eq!(key.private_key[0] & 7, 0);
            assert_eq!(key.private_key[31] & 0x80, 0);
            assert_eq!(key.private_key[31] & 0x40, 0x40);
        }
    }

    // RFC 8032 Section 7.1, TEST 1 (empty message) and TEST 2 (one byte).
    #[test]
    fn ed25519_rfc8032_vectors() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (secret, public, message, signature) in cases {
            let key =
                SignKey::new(&unhex(secret), DEFAULT_CREATION_TIMESTAMP, None, false).unwrap();
            assert_eq!(key.public_key, unhex32(public));
            assert_eq!(key.private_key, unhex32(secret));
            assert_eq!(
                key.signing_key.sign(&unhex(message)).to_bytes().to_vec(),
                unhex(signature)
            );
        }
    }
}
