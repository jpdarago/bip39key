mod pgp;
mod ssh;
mod types;

use crate::types::*;

use anyhow::bail;
use bip39::{Language, Mnemonic};
use clap::Parser;
use pbkdf2::password_hash::{PasswordHasher, SaltString};
use std::io::BufWriter;
use std::io::Read;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

#[derive(PartialEq, Eq, Clone, clap::ArgEnum, Debug)]
enum OutputFormat {
    Pgp,
    Ssh,
}

#[derive(PartialEq, Eq, Clone, clap::ArgEnum, Debug)]
enum SeedFormat {
    Bip39,
    Electrum,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// RFC 2822 of the user, e.g. "User <user@email.com>".
    #[clap(short, long)]
    user_id: String,

    /// Filename where to output the keys, if not present then write to stdout.
    #[clap(short, long)]
    output_filename: Option<String>,

    /// Timestamp (in seconds) for the dates. If unset, use the default 1231006505.
    #[clap(short, long)]
    timestamp: Option<u32>,

    /// Only output the sign key for PGP.
    #[clap(short, long)]
    just_signkey: bool,

    /// Output format: SSH or PGP.
    #[clap(short, long, arg_enum, default_value = "pgp")]
    format: OutputFormat,

    /// Output as armored.
    #[clap(short, long)]
    armor: bool,

    /// Optional passphrase. See README.md for details.
    #[clap(short, long)]
    passphrase: Option<String>,

    /// Seed Format: BIP39, Electrum
    #[clap(short, long, arg_enum, default_value = "bip39")]
    seed_format: SeedFormat,
}

fn write_keys<W: std::io::Write>(
    args: &Args,
    context: &Context,
    mut writer: BufWriter<W>,
) -> Result<()> {
    match args.format {
        OutputFormat::Pgp => {
            if args.armor {
                pgp::output_armored(context, &mut writer)?;
            } else {
                pgp::output_as_packets(context, &mut writer)?;
            }
        }
        OutputFormat::Ssh => {
            ssh::output_secret_as_pem(context, &mut writer)?;
        }
    };
    Ok(())
}

fn electrum_seed(phrase: &str) -> pbkdf2::password_hash::Result<Vec<u8>> {
    let mut params = pbkdf2::Params::default();
    params.rounds = 2048;
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

fn decode_seed_phrase(args: &Args, phrase: &str) -> Result<Vec<u8>> {
    match args.seed_format {
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

fn main() -> Result<()> {
    let args = Args::parse();
    if args.just_signkey && args.format == OutputFormat::Ssh {
        eprintln!("Subkey option (--subkey/-s) only works with PGP output format.");
        std::process::exit(1);
    }
    if args.armor && args.format == OutputFormat::Ssh {
        eprintln!("Armor option (--armor/-a) only works with PGP output format.");
        std::process::exit(1);
    }
    let mut phrase = String::new();
    std::io::stdin().read_to_string(&mut phrase)?;
    let entropy = decode_seed_phrase(&args, phrase.trim())?;
    let context = Context::new(
        &args.user_id,
        &entropy,
        &args.passphrase,
        args.timestamp.unwrap_or(TIMESTAMP),
        !args.just_signkey,
    )
    .expect("Could not build OpenPGP keys");
    if let Some(filename) = &args.output_filename {
        let output = std::fs::File::open(&filename);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", filename, err);
            std::process::exit(1);
        }
        write_keys(&args, &context, BufWriter::new(&mut output.unwrap()))
    } else {
        write_keys(&args, &context, BufWriter::new(std::io::stdout()))
    }
}
