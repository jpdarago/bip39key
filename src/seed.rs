use crate::types::*;

use anyhow::bail;
use bip39::{Language, Mnemonic};
use hmac::Mac;
use inquire::validator::Validation;
use inquire::{CustomUserError, Text};
use lazy_static::lazy_static;
use pbkdf2::password_hash::{PasswordHasher, SaltString};
use std::fmt;
use std::io::{self, BufRead, Write};
use strsim::levenshtein;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
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
    let salt = SaltString::from_b64("electrum")?;
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

const DEFAULT_ENGLISH_WORDLIST: &str = include_str!("../resources/bip39.txt");

fn wordlist() -> Result<Vec<String>> {
    let mut words: Vec<String> = Vec::new();
    match std::env::var("WORDLIST_BIP39") {
        Ok(path) => {
            let wordfile = std::fs::File::open(path)?;
            for line in std::io::BufReader::new(wordfile).lines() {
                words.push(line?.trim().to_string());
            }
        }
        Err(_) => {
            for line in DEFAULT_ENGLISH_WORDLIST.lines() {
                words.push(line.trim().to_string());
            }
        }
    }
    words.sort();
    Ok(words)
}

lazy_static! {
    static ref WORDLIST: Vec<String> = wordlist().expect("Failed to read wordlist");
}

fn suggest(
    input: &str,
) -> std::result::Result<
    Vec<std::string::String>,
    Box<(dyn std::error::Error + Send + Sync + 'static)>,
> {
    Ok(WORDLIST
        .iter()
        .filter(|s| s.to_lowercase().starts_with(input))
        .map(String::from)
        .collect())
}

fn check_word_is_valid(input: &str) -> Option<String> {
    if WORDLIST
        .binary_search_by(|s| s.as_str().cmp(input))
        .is_err()
    {
        let closest = WORDLIST
            .iter()
            .min_by_key(|word| levenshtein(word, input))
            .unwrap();
        Some(closest.to_string())
    } else {
        None
    }
}

fn validate(input: &str) -> std::result::Result<Validation, CustomUserError> {
    if let Some(closest) = check_word_is_valid(input) {
        Ok(Validation::Invalid(
            format!(
                "Word {} is not in the dictionary, maybe you meant {}?",
                input, closest
            )
            .into(),
        ))
    } else {
        Ok(Validation::Valid)
    }
}

pub fn decode_phrase(seed_format: &SeedFormat, phrase: &str) -> Result<Vec<u8>> {
    for (i, word) in phrase.split(" ").enumerate() {
        if let Some(closest) = check_word_is_valid(word) {
            bail!(
                "Word {} ({}) in the phrase is invalid, maybe you meant `{}`?",
                i + 1,
                word,
                closest
            );
        }
    }

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
    println!("Please input a {} phrase: ", seed_format);
    io::stdout().flush().unwrap();
    loop {
        let mut result = vec![];
        let mut i = 0;
        loop {
            if i > 12 {
                println!("Too many words");
                io::stdout().flush().unwrap();
                result.clear();
                break;
            }
            if i == 12 {
                break;
            }
            let input = Text::new(&format!("Word (currently {}): ", i + 1))
                .with_validator(validate)
                .with_autocomplete(suggest)
                .prompt()?;
            for word in input.split_whitespace() {
                result.push(word.trim().to_string());
                i += 1;
            }
        }
        if result.is_empty() {
            continue;
        }
        match decode_phrase(seed_format, &result.join(" ")) {
            Ok(phrase) => {
                return Ok(phrase);
            }
            Err(s) => {
                println!("Failed to parse {} phrase: {}", seed_format, s);
                result.clear();
                io::stdout().flush().unwrap();
            }
        }
    }
}
