mod pgp;
mod types;

use crate::types::*;

use bip39::{Language, Mnemonic};
use clap::Parser;
use std::io::{BufWriter, Write};

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

struct PGPContext {
    user_id: UserId,
    sign_key: SignKey,
    encrypt_key: EncryptKey,
    metadata: Comment,
}

enum OutputKeys {
    SignKey,
    SignAndEncryptionKey,
}

fn output_pgp_packets<W: Write>(
    context: &PGPContext,
    output_keys: OutputKeys,
    mut out: BufWriter<W>,
) -> Result<()> {
    let mut buffer = ByteCursor::new(Vec::new());
    pgp::output_secret_key(&context.sign_key, &mut buffer)?;
    pgp::output_user_id(&context.user_id, &mut buffer)?;
    pgp::output_self_signature(&context.sign_key, &context.user_id, &mut buffer)?;
    if let OutputKeys::SignAndEncryptionKey = output_keys {
        pgp::output_secret_subkey(&context.encrypt_key, &mut buffer)?;
        pgp::output_subkey_signature(&context.sign_key, &context.encrypt_key, &mut buffer)?;
    }
    pgp::output_comment(&context.metadata, &mut buffer)?;
    if let Err(err) = out.write_all(buffer.get_ref()) {
        Err(Box::new(err))
    } else {
        Ok(())
    }
}

fn build_keys(user_id: &str, seed: &[u8], timestamp_secs: u32) -> Result<PGPContext> {
    // Derive 64 bytes by running Argon with the user id as salt.
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 32 * 1024,
        time_cost: 8,
        lanes: 4,
        thread_mode: argon2::ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 64,
    };
    let secret_key_bytes = argon2::hash_raw(seed, user_id.as_bytes(), &config)?;
    Ok(PGPContext {
        user_id: UserId {
            user_id: user_id.to_string(),
        },
        sign_key: SignKey::new(&secret_key_bytes[..32], timestamp_secs)?,
        encrypt_key: EncryptKey::new(&secret_key_bytes[32..], timestamp_secs)?,
        metadata: Comment {
            timestamp_secs,
            data: format!(
                "Created by {} version {} with Argon settings {:?}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                &config
            ),
        },
    })
}

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
    let context = build_keys(&args.user_id, entropy, args.timestamp.unwrap_or(TIMESTAMP))
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
        output_pgp_packets(&context, output_keys, BufWriter::new(&mut output.unwrap()))
    } else {
        output_pgp_packets(&context, output_keys, BufWriter::new(std::io::stdout()))
    }
}
