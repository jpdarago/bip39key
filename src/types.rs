pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type ByteCursor = std::io::Cursor<Vec<u8>>;

pub struct UserId {
    pub user_id: String,
}

pub struct Comment {
    pub data: String,
    pub timestamp_secs: u32,
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
        let mut encrypt_secret_key_bytes: [u8; 32] = [0; 32];
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
