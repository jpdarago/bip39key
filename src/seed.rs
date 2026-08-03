use crate::types::*;

use crate::cli::SeedFormat;
use anyhow::bail;
use bip39::{Language, Mnemonic};
use hmac::Mac;
use inquire::validator::Validation;
use inquire::{CustomUserError, Text};
use pbkdf2::password_hash::{PasswordHasher, SaltString};
use std::io::{self, BufRead, Write};
use std::sync::OnceLock;
use strsim::levenshtein;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

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

fn get_wordlist() -> &'static Vec<String> {
    static WORDLIST: OnceLock<Vec<String>> = OnceLock::new();
    WORDLIST.get_or_init(|| wordlist().expect("Failed to read wordlist"))
}

fn suggest(
    input: &str,
) -> std::result::Result<Vec<std::string::String>, Box<dyn std::error::Error + Send + Sync + 'static>>
{
    Ok(get_wordlist()
        .iter()
        .filter(|s| s.to_lowercase().starts_with(input))
        .map(String::from)
        .collect())
}

fn check_word_is_valid(input: &str) -> Option<String> {
    if get_wordlist()
        .binary_search_by(|s| s.as_str().cmp(input))
        .is_err()
    {
        let closest = get_wordlist()
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
                // Do not echo the phrase: it is secret material and would
                // land in terminal scrollback and logs.
                bail!("Not a valid Electrum seed phrase (seed version check failed)");
            }
            let result = electrum_seed(phrase);
            if let Err(err) = result {
                bail!("Failed to build seed phrase {:?}", err);
            }
            Ok(result.unwrap())
        }
    }
}

/// Maximum number of words in a supported seed phrase (24-word BIP39).
const MAX_SEED_WORDS: usize = 24;

/// Collect seed words by repeatedly calling `read_input` with the next word
/// number. Each input may contain several whitespace-separated words (paste).
/// Collection stops on an empty input (after at least one word) or once
/// MAX_SEED_WORDS words have been entered. May return more than
/// MAX_SEED_WORDS if a paste overshoots; `decode_phrase` rejects that.
fn collect_words<F>(mut read_input: F) -> Result<Vec<String>>
where
    F: FnMut(usize) -> Result<String>,
{
    let mut words: Vec<String> = Vec::new();
    while words.len() < MAX_SEED_WORDS {
        let input = read_input(words.len() + 1)?;
        if input.trim().is_empty() {
            if words.is_empty() {
                continue;
            }
            break;
        }
        words.extend(input.split_whitespace().map(String::from));
    }
    Ok(words)
}

pub fn from_prompt(seed_format: &SeedFormat) -> Result<Vec<u8>> {
    console_logln!("Please input a seed phrase in {} format.", seed_format);
    console_logln!(
        "Enter one or more words per line ({} words maximum). \
         Press Enter on an empty line to finish.",
        MAX_SEED_WORDS
    );
    loop {
        let words = collect_words(|word_number| {
            let input = Text::new(&format!("Word (currently {}): ", word_number))
                .with_validator(validate)
                .with_autocomplete(suggest)
                .prompt()?;
            let entered = input.split_whitespace().count();
            if entered > 0 {
                // Overwrite the answered prompt line so previously entered words
                // are not readable in terminal scrollback or screen captures.
                // Move cursor up one line, clear it, and print a masked replacement.
                print!("\x1b[1A\x1b[2KWord {}: ****", word_number);
                if entered > 1 {
                    // Multiple words were pasted at once.
                    print!(" ({} words entered)", entered);
                }
                println!();
                io::stdout().flush()?;
            }
            Ok(input)
        })?;
        match decode_phrase(seed_format, &words.join(" ")) {
            Ok(phrase) => {
                return Ok(phrase);
            }
            Err(s) => {
                println!("Failed to parse {} phrase: {}", seed_format, s);
                io::stdout().flush()?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripted<'a>(inputs: &'a [&'a str]) -> impl FnMut(usize) -> Result<String> + 'a {
        let mut iter = inputs.iter();
        move |_| Ok(iter.next().expect("ran out of scripted inputs").to_string())
    }

    const GOLDEN_24: &str = "void come effort suffer camp survey warrior heavy shoot primary \
         clutch crush open amazing screen patrol group space point ten exist slush involve unfold";

    #[test]
    fn test_collect_24_words_one_at_a_time() {
        let inputs: Vec<&str> = GOLDEN_24.split_whitespace().collect();
        let words = collect_words(scripted(&inputs)).unwrap();
        assert_eq!(words.len(), 24);
        assert_eq!(words.join(" "), GOLDEN_24);
    }

    #[test]
    fn test_collect_stops_on_empty_input() {
        let words = collect_words(scripted(&["abandon", "ability", ""])).unwrap();
        assert_eq!(words, ["abandon", "ability"]);
    }

    #[test]
    fn test_collect_pasted_phrase() {
        let words = collect_words(scripted(&[GOLDEN_24])).unwrap();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_decode_24_word_phrase() {
        let entropy = decode_phrase(&SeedFormat::Bip39, GOLDEN_24).unwrap();
        assert_eq!(entropy.len() * 8, 256);
    }
}
