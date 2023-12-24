use crate::types::*;

use anyhow::bail;
use bip39::{Language, Mnemonic};
use hmac::Mac;
use inquire::Text;
use pbkdf2::password_hash::{PasswordHasher, SaltString};
use std::fmt;
use std::io::{self, Write};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

#[derive(PartialEq, Eq, Clone, clap::ArgEnum, Debug)]
pub enum SeedFormat {
    Bip39,
    Electrum,
}

impl fmt::Display for SeedFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SeedFormat::Bip39 => write!(f, "BIP39"),
            SeedFormat::Electrum => write!(f, "Electrum"),
        }
    }
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
    let mut hmac = HmacSha512::new_from_slice(b"Seed version").expect("Could not initialize HMAC");
    hmac.update(phrase.as_bytes());
    let encoded = hex::encode(hmac.finalize().into_bytes());
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

pub fn from_prompt(seed_format: &SeedFormat) -> Result<Vec<u8>> {
    loop {
        let input = Text::new(&format!("Please input a {} phrase: ", seed_format)).prompt()?;
        let words: String = input.split_whitespace().collect::<Vec<&str>>().join(" ");
        match decode_phrase(seed_format, &words) {
            Ok(phrase) => {
                return Ok(phrase);
            }
            Err(s) => {
                Text::new(&format!("Failed to parse {} phrase: {}", seed_format, s));
                io::stdout().flush().unwrap();
            }
        }
    }
}
