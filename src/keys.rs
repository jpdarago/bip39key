use crate::types::*;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

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

impl Zeroize for SignKey {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        // Overwrite the SigningKey by replacing it with a key derived from zeroed bytes.
        self.signing_key = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl Drop for SignKey {
    fn drop(&mut self) {
        self.zeroize();
    }
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

impl Zeroize for EncryptKey {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}

impl Drop for EncryptKey {
    fn drop(&mut self) {
        self.zeroize();
    }
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

pub struct Keys {
    pub user_id: UserId,
    pub sign_key: SignKey,
    pub encrypt_key: Option<EncryptKey>,
    pub passphrase: Option<String>,
}

impl Drop for Keys {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.passphrase {
            p.zeroize();
        }
    }
}

/// Key derivation algorithm for combining seed and passphrase.
#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
pub enum KeyAlgorithm {
    /// DEPRECATED: XOR of separate Argon2id hashes of seed and passphrase.
    Xor,
    /// DEPRECATED: Argon2id of concatenated seed and passphrase, split into sign/encrypt keys.
    Concat,
    /// Argon2id of concatenated seed and passphrase, then HKDF-Expand with domain separation
    /// for sign and encrypt keys.
    Hkdf,
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
    pub use_rfc9106_settings: bool,
    pub use_authorization_for_sign_key: bool,
}

impl Drop for KeySettings {
    fn drop(&mut self) {
        self.seed.zeroize();
        if let Some(ref mut p) = self.passphrase {
            p.zeroize();
        }
    }
}

impl Keys {
    fn build_keys(secret_key_bytes: &[u8], mut settings: KeySettings) -> Result<Keys> {
        Ok(Keys {
            user_id: UserId {
                user_id: std::mem::take(&mut settings.user_id),
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
            passphrase: settings.passphrase.take(),
        })
    }

    /// Derive keys using HKDF-Expand with domain separation.
    /// The Argon2id output is used as PRK, and separate info strings produce
    /// independent sign and encrypt key material.
    pub fn new_with_hkdf(settings: KeySettings) -> Result<Keys> {
        let mut prk = if let Some(pass) = &settings.passphrase {
            let mut bytes = settings.seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            let result = run_argon(&bytes, &settings.user_id, settings.use_rfc9106_settings)?;
            bytes.zeroize();
            result
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        let sign_key_bytes = hkdf_expand(&prk, b"bip39key-sign-v1", 32)?;
        let mut encrypt_key_bytes = hkdf_expand(&prk, b"bip39key-encrypt-v1", 32)?;
        prk.zeroize();
        let mut secret_key_bytes = sign_key_bytes;
        secret_key_bytes.extend_from_slice(&encrypt_key_bytes);
        encrypt_key_bytes.zeroize();
        let result = Self::build_keys(&secret_key_bytes, settings);
        secret_key_bytes.zeroize();
        result
    }

    pub fn new_with_concat(settings: KeySettings) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt.
        let mut secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let mut bytes = settings.seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            let result = run_argon(&bytes, &settings.user_id, settings.use_rfc9106_settings)?;
            bytes.zeroize();
            result
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        let result = Self::build_keys(&secret_key_bytes, settings);
        secret_key_bytes.zeroize();
        result
    }

    pub fn new_with_xor(settings: KeySettings) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt
        let mut secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let mut bytes = run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?;
            // Generate another buffer with Argon for the passphrase and XOR it.
            let mut passphrase_bytes = run_argon(
                pass.as_bytes(),
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?;
            let result: Vec<u8> = bytes
                .iter()
                .zip(passphrase_bytes.iter())
                .map(|(lhs, rhs)| lhs ^ rhs)
                .collect();
            bytes.zeroize();
            passphrase_bytes.zeroize();
            result
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
            )?
        };
        let result = Self::build_keys(&secret_key_bytes, settings);
        secret_key_bytes.zeroize();
        result
    }
}
