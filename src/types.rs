use anyhow::Result as AnyhowResult;

pub type Result<T> = AnyhowResult<T>;
pub type ByteCursor = std::io::Cursor<Vec<u8>>;

pub struct UserId {
    pub user_id: String,
}

pub struct SignKey {
    pub keypair: ed25519_dalek::Keypair,
    pub created_timestamp_secs: u32,
}

impl SignKey {
    pub fn new(secret_key_bytes: &[u8], timestamp_secs: u32) -> Result<SignKey> {
        let sign_secret_key = ed25519_dalek::SecretKey::from_bytes(secret_key_bytes)?;
        let sign_public_key: ed25519_dalek::PublicKey = (&sign_secret_key).into();
        Ok(SignKey {
            created_timestamp_secs: timestamp_secs,
            keypair: ed25519_dalek::Keypair {
                public: sign_public_key,
                secret: sign_secret_key,
            },
        })
    }
}

pub struct EncryptKey {
    pub secret_key: x25519_dalek::StaticSecret,
    pub public_key: x25519_dalek::PublicKey,
    pub created_timestamp_secs: u32,
}

impl EncryptKey {
    pub fn new(secret_key_bytes: &[u8], timestamp_secs: u32) -> Result<EncryptKey> {
        // x25519_dalek requires a fixed size buffer. Instead of wrangling slices let's just copy.
        let mut encrypt_secret_key_bytes = [0u8; 32];
        encrypt_secret_key_bytes.copy_from_slice(secret_key_bytes);
        let encrypt_secret_key: x25519_dalek::StaticSecret = encrypt_secret_key_bytes.into();
        let encrypt_public_key = x25519_dalek::PublicKey::from(&encrypt_secret_key);
        Ok(EncryptKey {
            created_timestamp_secs: timestamp_secs,
            public_key: encrypt_public_key,
            secret_key: encrypt_secret_key,
        })
    }
}

pub struct Context {
    pub user_id: UserId,
    pub sign_key: SignKey,
    pub encrypt_key: Option<EncryptKey>,
    pub passphrase: Option<String>,
}

impl Context {
    pub fn new(
        user_id: &str,
        seed: &[u8],
        passphrase: &Option<String>,
        timestamp_secs: u32,
        generate_encrypt_key: bool,
    ) -> Result<Context> {
        // Derive 64 bytes by running Argon with the user id as salt.
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 64 * 1024,
            time_cost: 32,
            lanes: 8,
            thread_mode: argon2::ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 64,
        };
        let mut secret_key_bytes = argon2::hash_raw(seed, user_id.as_bytes(), &config)?;
        if let Some(pass) = &passphrase {
            // Generate another buffer with Argon for the passphrase and XOR it.
            let passphrase_bytes = argon2::hash_raw(pass.as_bytes(), user_id.as_bytes(), &config)?;
            secret_key_bytes = secret_key_bytes
                .iter()
                .zip(passphrase_bytes.iter())
                .map(|(lhs, rhs)| lhs ^ rhs)
                .collect();
        }
        let encrypt_key = if generate_encrypt_key {
            Some(EncryptKey::new(&secret_key_bytes[32..], timestamp_secs)?)
        } else {
            None
        };
        Ok(Context {
            user_id: UserId {
                user_id: user_id.to_string(),
            },
            sign_key: SignKey::new(&secret_key_bytes[..32], timestamp_secs)?,
            encrypt_key,
            passphrase: passphrase.clone(),
        })
    }
}
