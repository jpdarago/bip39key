mod pgp;
mod ssh;
mod types;

use crate::types::*;

use bip39::{Language, Mnemonic};
use clap::Parser;
use std::io::BufWriter;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

#[derive(PartialEq, Eq, Clone, clap::ArgEnum, Debug)]
enum OutputFormat {
    Pgp,
    Ssh,
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
    let context = Context::new(
        &args.user_id,
        entropy,
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
