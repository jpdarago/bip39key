use crate::types::*;
use byteorder::{BigEndian, WriteBytesExt};

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

// Add a SignSubkey struct for signature subkeys
pub struct SignSubkey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub signing_key: ed25519_dalek::SigningKey,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
}

impl SignSubkey {
    pub fn new(
        secret_key_bytes: &[u8],
        creation_timestamp_secs: i64,
        expiration_timestamp_secs: Option<i64>,
    ) -> Result<SignSubkey> {
        let mut input = [0u8; 32];
        input.copy_from_slice(secret_key_bytes);
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&input);
        Ok(SignSubkey {
            creation_timestamp_secs,
            expiration_timestamp_secs,
            public_key: secret_key.verifying_key().to_bytes(),
            private_key: secret_key.to_bytes(),
            signing_key: secret_key,
        })
    }
}

// Add an AuthKey struct for authentication subkeys
pub struct AuthKey {
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    pub private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub signing_key: ed25519_dalek::SigningKey,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
}

// Add functions for SignSubkey public key payload
pub fn public_sign_subkey_payload(key: &SignSubkey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    cursor.write_all(&[22])?; // Algorithm, EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
    cursor.write_u16::<BigEndian>(263)?;
    // Prefix octet for EdDSA Point Format.
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key)?;
    Ok(cursor.into_inner())
}

// Add functions for AuthKey public key payload
pub fn public_auth_key_payload(key: &AuthKey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    cursor.write_all(&[22])?; // Algorithm, EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
    cursor.write_u16::<BigEndian>(263)?;
    // Prefix octet for EdDSA Point Format.
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key)?;
    Ok(cursor.into_inner())
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
            signing_key: secret_key,
        })
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
    pub sign_subkey: Option<SignSubkey>,
    pub auth_key: Option<AuthKey>,
    pub passphrase: Option<String>,
}

fn run_argon(bytes: &[u8], user_id: &str, use_rfc9106_settings: bool, hash_length: usize) -> Result<Vec<u8>> {
    let config = if use_rfc9106_settings {
        let mut result = argon2::Config::rfc9106();
        result.hash_length = hash_length;
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
            hash_length,
        }
    };
    Ok(argon2::hash_raw(bytes, user_id.as_bytes(), &config)?)
}

pub struct KeySettings {
    pub user_id: String,
    pub seed: Vec<u8>,
    pub passphrase: Option<String>,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
    pub generate_encrypt_key: bool,
    pub generate_sign_subkey: bool,
    pub generate_auth_key: bool,
    pub use_rfc9106_settings: bool,
    pub use_authorization_for_sign_key: bool,
}

impl Keys {
    fn build_keys(secret_key_bytes: &[u8], settings: KeySettings) -> Result<Keys> {
        // Calculate how many subkeys we're generating
        let mut offset = 32; // Start after the primary key
        
        // Create the primary signing key
        let sign_key = SignKey::new(
            &secret_key_bytes[..32],
            settings.creation_timestamp_secs,
            settings.expiration_timestamp_secs,
            settings.use_authorization_for_sign_key,
        )?;
        
        // Create encryption key if requested
        let encrypt_key = if settings.generate_encrypt_key {
            let key = EncryptKey::new(
                &secret_key_bytes[offset..offset+32],
                settings.creation_timestamp_secs,
                settings.expiration_timestamp_secs,
            )?;
            offset += 32;
            Some(key)
        } else {
            None
        };
        
        // Create signing subkey if requested
        let sign_subkey = if settings.generate_sign_subkey {
            let key = SignSubkey::new(
                &secret_key_bytes[offset..offset+32],
                settings.creation_timestamp_secs,
                settings.expiration_timestamp_secs,
            )?;
            offset += 32;
            Some(key)
        } else {
            None
        };
        
        // Create authentication key if requested
        let auth_key = if settings.generate_auth_key {
            let key = AuthKey::new(
                &secret_key_bytes[offset..offset+32],
                settings.creation_timestamp_secs,
                settings.expiration_timestamp_secs,
            )?;
            Some(key)
        } else {
            None
        };
        
        Ok(Keys {
            user_id: UserId {
                user_id: settings.user_id,
            },
            sign_key,
            encrypt_key,
            sign_subkey,
            auth_key,
            passphrase: settings.passphrase,
        })
    }

    pub fn new_with_concat(settings: KeySettings) -> Result<Keys> {
        // Calculate required hash length based on number of subkeys
        let mut hash_length = 32; // Primary key
        if settings.generate_encrypt_key { hash_length += 32; }
        if settings.generate_sign_subkey { hash_length += 32; }
        if settings.generate_auth_key { hash_length += 32; }
        
        // Derive bytes by running Argon with the user id as salt
        let secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let mut bytes = settings.seed.to_vec();
            bytes.extend_from_slice(pass.as_bytes());
            run_argon(&bytes, &settings.user_id, settings.use_rfc9106_settings, hash_length)?
        } else {
            run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
                hash_length,
            )?
        };
        Self::build_keys(&secret_key_bytes, settings)
    }

    pub fn new_with_xor(settings: KeySettings) -> Result<Keys> {
        // Calculate required hash length based on number of subkeys
        let mut hash_length = 32; // Primary key
        if settings.generate_encrypt_key { hash_length += 32; }
        if settings.generate_sign_subkey { hash_length += 32; }
        if settings.generate_auth_key { hash_length += 32; }
        
        // Derive bytes by running Argon with the user id as salt
        let secret_key_bytes = if let Some(pass) = &settings.passphrase {
            let bytes = run_argon(
                &settings.seed,
                &settings.user_id,
                settings.use_rfc9106_settings,
                hash_length,
            )?;
            // Generate another buffer with Argon for the passphrase and XOR it
            let passphrase_bytes = run_argon(
                pass.as_bytes(),
                &settings.user_id,
                settings.use_rfc9106_settings,
                hash_length,
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
                hash_length,
            )?
        };
        Self::build_keys(&secret_key_bytes, settings)
    }
}
