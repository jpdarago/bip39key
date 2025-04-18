use crate::types::*;

pub struct UserId {
    pub user_id: String,
}

pub struct SignKey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub signing_key: ed25519_dalek::SigningKey,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
}

impl SignKey {
    pub fn new(
        secret_key_bytes: &[u8],
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
    ) -> Result<SignKey> {
        let mut input = [0u8; 32];
        input.copy_from_slice(secret_key_bytes);
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&input);
        Ok(SignKey {
            creation_timestamp_secs,
            expiration_timestamp_secs,
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

impl Keys {
    fn build_keys(
        secret_key_bytes: &[u8],
        user_id: &str,
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
        generate_encrypt_key: bool,
        pass: &Option<String>,
    ) -> Result<Keys> {
        Ok(Keys {
            user_id: UserId {
                user_id: user_id.to_string(),
            },
            sign_key: SignKey::new(
                &secret_key_bytes[..32],
                creation_timestamp_secs,
                expiration_timestamp_secs,
            )?,
            encrypt_key: if generate_encrypt_key {
                Some(EncryptKey::new(
                    &secret_key_bytes[32..],
                    creation_timestamp_secs,
                    expiration_timestamp_secs,
                )?)
            } else {
                None
            },
            passphrase: pass.clone(),
        })
    }

    pub fn new_with_concat(
        user_id: &str,
        seed: &[u8],
        passphrase: &Option<String>,
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
        generate_encrypt_key: bool,
        use_rfc9106_settings: bool,
    ) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt.
        let secret_key_bytes = if let Some(pass) = &passphrase {
            let mut bytes = seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            run_argon(&bytes, user_id, use_rfc9106_settings)?
        } else {
            run_argon(seed, user_id, use_rfc9106_settings)?
        };
        Self::build_keys(
            &secret_key_bytes,
            user_id,
            creation_timestamp_secs,
            expiration_timestamp_secs,
            generate_encrypt_key,
            passphrase,
        )
    }

    pub fn new_with_xor(
        user_id: &str,
        seed: &[u8],
        passphrase: &Option<String>,
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
        generate_encrypt_key: bool,
        use_rfc9106_settings: bool,
    ) -> Result<Keys> {
        // Derive 64 bytes by running Argon with the user id as salt.
        let secret_key_bytes = if let Some(pass) = &passphrase {
            let bytes = run_argon(seed, user_id, use_rfc9106_settings)?;
            // Generate another buffer with Argon for the passphrase and XOR it.
            let passphrase_bytes = run_argon(pass.as_bytes(), user_id, use_rfc9106_settings)?;
            bytes
                .iter()
                .zip(passphrase_bytes.iter())
                .map(|(lhs, rhs)| lhs ^ rhs)
                .collect()
        } else {
            run_argon(seed, user_id, use_rfc9106_settings)?
        };
        Self::build_keys(
            &secret_key_bytes,
            user_id,
            creation_timestamp_secs,
            expiration_timestamp_secs,
            generate_encrypt_key,
            passphrase,
        )
    }
}
