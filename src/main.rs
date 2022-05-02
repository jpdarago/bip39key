mod pgp;
mod types;

use crate::types::*;

use bip39::{Language, Mnemonic};
use clap::Parser;
use std::io::BufWriter;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// RFC 2822 of the user, e.g. "User <user@email.com>".
    #[clap(short, long)]
    user_id: String,

    /// Filename where to output the keys, if not present then write to stdout.
    #[clap(short, long)]
    filename: Option<String>,

    /// Timestamp (in seconds) for the dates. If unset, use the default 1231006505.
    #[clap(short, long)]
    timestamp: Option<u32>,

    /// Output encryption key as well as sign key.
    #[clap(short, long)]
    subkey: Option<bool>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let mnemonic = Mnemonic::from_phrase(phrase.trim(), Language::English);
    if let Err(err) = mnemonic {
        eprintln!("Invalid BIP39 mnemonic: {}", err);
        std::process::exit(1);
    }
    let unwrapped = mnemonic.unwrap();
    let entropy = unwrapped.entropy();
    if 8 * entropy.len() < 128 {
        eprintln!(
            "Invalid BIP39 mnemonic, insufficient entropy (need at least 128 bits, have {}).",
            8 * entropy.len()
        );
        std::process::exit(1);
    }
    let context = Context::new(&args.user_id, entropy, args.timestamp.unwrap_or(TIMESTAMP))
        .expect("Could not build OpenPGP keys");
    let output_keys = if args.subkey.unwrap_or(true) {
        OutputKeys::SignAndEncryptionKey
    } else {
        OutputKeys::SignKey
    };
    if let Some(filename) = args.filename {
        let output = std::fs::File::open(&filename);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", filename, err);
            std::process::exit(1);
        }
        pgp::output_as_packets(&context, output_keys, BufWriter::new(&mut output.unwrap()))
    } else {
        pgp::output_as_packets(&context, output_keys, BufWriter::new(std::io::stdout()))
    }
}
