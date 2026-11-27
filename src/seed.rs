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

/// Validate one line of prompt input. A line may hold several words (a paste)
/// or none at all (an empty line ends collection; see `collect_words`), so
/// each word is checked on its own and an empty line is valid.
fn validate(input: &str) -> std::result::Result<Validation, CustomUserError> {
    for word in input.split_whitespace() {
        if let Some(closest) = check_word_is_valid(word) {
            return Ok(Validation::Invalid(
                format!(
                    "Word {} is not in the dictionary, maybe you meant {}?",
                    word, closest
                )
                .into(),
            ));
        }
    }
    Ok(Validation::Valid)
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

/// What replaces a submitted line of seed words on screen, so they are not
/// readable in terminal scrollback or screen captures.
fn mask_answer(answer: &str) -> String {
    match answer.split_whitespace().count() {
        0 => String::new(),
        1 => "****".to_string(),
        // Several words were typed or pasted on one line.
        entered => format!("**** ({} words entered)", entered),
    }
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
                // What stays on screen once the line is submitted. inquire
                // redraws the whole prompt with this in place of the answer,
                // however many terminal rows the answer took. Clearing the
                // line by hand afterwards only reached the last row, so a
                // pasted phrase that wrapped stayed readable above the mask.
                .with_formatter(&mask_answer)
                .prompt()?;
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

    // The prompt runs `validate` on every line before `collect_words` sees it,
    // so anything collect_words is meant to accept must also pass validation.
    // Previously an empty line (the only way to finish a seed shorter than 24
    // words) and a pasted multi-word line were both rejected here.

    #[test]
    fn test_mask_answer_never_shows_a_word() {
        assert_eq!(mask_answer(""), "");
        assert_eq!(mask_answer("  "), "");
        assert_eq!(mask_answer("abandon"), "****");
        assert_eq!(mask_answer(GOLDEN_24), "**** (24 words entered)");
        for word in GOLDEN_24.split_whitespace() {
            assert!(!mask_answer(GOLDEN_24).contains(word));
        }
    }

    #[test]
    fn test_validate_accepts_empty_line() {
        assert!(matches!(validate("").unwrap(), Validation::Valid));
        assert!(matches!(validate("   ").unwrap(), Validation::Valid));
    }

    #[test]
    fn test_validate_accepts_pasted_phrase() {
        assert!(matches!(validate(GOLDEN_24).unwrap(), Validation::Valid));
    }

    #[test]
    fn test_validate_names_the_bad_word_in_a_paste() {
        let result = validate("abandon fatigeu ability").unwrap();
        let Validation::Invalid(message) = result else {
            panic!("a misspelled word must be rejected");
        };
        let message = format!("{message:?}");
        assert!(message.contains("Word fatigeu "), "{message}");
        assert!(message.contains("fatigue"), "{message}");
    }

    #[test]
    fn test_every_line_collect_words_accepts_validates() {
        let lines = ["abandon", "ability able", ""];
        for line in lines {
            assert!(
                matches!(validate(line).unwrap(), Validation::Valid),
                "{line:?}"
            );
        }
        let words = collect_words(scripted(&lines)).unwrap();
        assert_eq!(words, ["abandon", "ability", "able"]);
    }

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

/// Known-answer tests against each seed format's upstream vectors.
#[cfg(test)]
mod vector_tests {
    use super::*;

    /// Every English vector from Trezor's reference implementation
    /// (python-mnemonic, vectors.json), as (entropy, mnemonic). bip39key keys
    /// off the BIP39 entropy, not the PBKDF2 seed, so the entropy column is the
    /// one to check.
    const TREZOR_ENGLISH: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
        ),
        (
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
        ),
        (
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        ),
        (
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    #[test]
    fn bip39_trezor_vectors() {
        assert_eq!(TREZOR_ENGLISH.len(), 24);
        for (entropy, mnemonic) in TREZOR_ENGLISH {
            assert_eq!(
                hex::encode(decode_phrase(&SeedFormat::Bip39, mnemonic).unwrap()),
                *entropy,
                "{mnemonic}"
            );
        }
    }

    // Electrum's own test vector (tests/test_mnemonic.py, SEED_TEST_CASES
    // "english"), the only English one without a passphrase.
    //
    // bip39key's Electrum seed is NOT Electrum's BIP32 seed. Electrum runs
    // PBKDF2-HMAC-SHA512(phrase, salt = b"electrum", 2048). electrum_seed()
    // passes "electrum" through SaltString::from_b64, so PBKDF2 gets the six
    // base64-*decoded* bytes 7a579cb6bba6 as its salt instead. The output is
    // still a deterministic function of the phrase, and it only feeds Argon2id,
    // but it can never be changed: every Electrum-derived key depends on it.
    //
    // This pins that behavior against an independent PBKDF2 call, and checks
    // the literal-salt computation does reproduce Electrum's published seed,
    // so the divergence is the salt and nothing else.
    #[test]
    fn electrum_upstream_vector() {
        let phrase =
            "wild father tree among universe such mobile favorite target dynamic credit identify";
        let electrum_bip32_seed = "aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e30\
                                   64342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756";

        // Electrum's seed version check accepts its own vector (a segwit seed).
        assert!(is_valid_electrum_phrase(phrase));

        let mut literal_salt = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            phrase.as_bytes(),
            b"electrum",
            2048,
            &mut literal_salt,
        );
        assert_eq!(hex::encode(literal_salt), electrum_bip32_seed);

        let mut decoded_salt = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            phrase.as_bytes(),
            &[0x7a, 0x57, 0x9c, 0xb6, 0xbb, 0xa6],
            2048,
            &mut decoded_salt,
        );
        let seed = decode_phrase(&SeedFormat::Electrum, phrase).unwrap();
        assert_eq!(seed, decoded_salt);
        assert_eq!(
            hex::encode(&seed),
            "7f8e333959cf6bdbc395cb1d99d1978e887103a3513e965b04dbf437afea25da"
        );
    }
}
