use crate::types::*;

use anyhow::bail;
use bip39::{Language, Mnemonic};
use pbkdf2::password_hash::{PasswordHasher, SaltString};

#[derive(PartialEq, Eq, Clone, clap::ArgEnum, Debug)]
pub enum SeedFormat {
    Bip39,
    Electrum,
}

fn electrum_seed(phrase: &str) -> pbkdf2::password_hash::Result<Vec<u8>> {
    let params = pbkdf2::Params {
        rounds: 2048,
        output_length: 32,
    };
    let salt = SaltString::new("electrum")?;
    let entropy = pbkdf2::Pbkdf2.hash_password_customized(
        phrase.as_bytes(),
        Some(pbkdf2::Algorithm::Pbkdf2Sha512.ident()),
        None,
        params,
        &salt,
    )?;
    let hash = entropy.hash.unwrap();
    Ok(hash.as_bytes().to_vec())
}

fn is_valid_electrum_phrase(phrase: &str) -> bool {
    let encoded = hex::encode(hmac_sha512::HMAC::mac(phrase, b"Seed version"));
    encoded[..2].eq("01") || encoded[..3].eq("100")
}

pub fn decode_phrase(seed_format: &SeedFormat, phrase: &str) -> Result<Vec<u8>> {
    match seed_format {
        SeedFormat::Bip39 => {
            let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
            let entropy = mnemonic.entropy();
            if 8 * entropy.len() < 128 {
                bail!("Insufficient entropy");
            }
            Ok(entropy.to_vec())
        }
        SeedFormat::Electrum => {
            if !is_valid_electrum_phrase(phrase) {
                bail!("Invalid Electrum seed phrase {}", phrase);
            }
            let result = electrum_seed(phrase);
            if let Err(err) = result {
                bail!("Failed to build seed phrase {:?}", err);
            }
            Ok(result.unwrap())
        }
    }
}
