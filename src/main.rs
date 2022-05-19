mod pgp;
mod pinentry;
mod seed;
mod ssh;
mod types;

use crate::types::*;

use clap::Parser;
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

    /// Output the public key.
    #[clap(short = 'k', long)]
    public_key: bool,

    /// Optional passphrase. If set, -e/--pinentry must not be set.
    /// See README.md for details.
    #[clap(short, long)]
    passphrase: Option<String>,

    /// Request passphrase with pinentry.
    /// See README.md for details.
    #[clap(short = 'e', long)]
    pinentry: bool,

    /// Seed Format: BIP39, Electrum
    #[clap(short, long, arg_enum, default_value = "bip39")]
    seed_format: seed::SeedFormat,
}

fn write_keys<W: std::io::Write>(
    args: &Args,
    context: &Context,
    mut writer: BufWriter<W>,
) -> Result<()> {
    match args.format {
        OutputFormat::Pgp => {
            if args.public_key {
                if args.armor {
                    pgp::output_public_armored(context, &mut writer)?;
                } else {
                    pgp::output_public_as_packets(context, &mut writer)?;
                }
            } else if args.armor {
                pgp::output_armored(context, &mut writer)?;
            } else {
                pgp::output_as_packets(context, &mut writer)?;
            }
        }
        OutputFormat::Ssh => {
            if args.public_key {
                ssh::output_public_as_pem(context, &mut writer)?;
            } else {
                ssh::output_secret_as_pem(context, &mut writer)?;
            }
        }
    };
    Ok(())
}

fn passphrase(args: &Args) -> Result<Option<String>> {
    if args.pinentry {
        let passphrase = pinentry::get_passphrase()?;
        Ok(Some(passphrase))
    } else if let Some(pass) = &args.passphrase {
        Ok(Some(pass.clone()))
    } else {
        Ok(None)
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
    if args.passphrase.is_some() && args.pinentry {
        eprintln!("One of --passphrase/--pinentry must be set at a time.");
        std::process::exit(1);
    }
    let mut phrase = String::new();
    std::io::stdin().read_to_string(&mut phrase)?;
    let entropy = seed::decode_phrase(&args.seed_format, phrase.trim())?;
    let pass = passphrase(&args)?;
    let context = Context::new(
        &args.user_id,
        &entropy,
        &pass,
        args.timestamp.unwrap_or(TIMESTAMP),
        !args.just_signkey,
    )
    .expect("Could not build keys");
    if let Some(filename) = &args.output_filename {
        let output = std::fs::File::create(&filename);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", filename, err);
            std::process::exit(1);
        }
        write_keys(&args, &context, BufWriter::new(&mut output.unwrap()))
    } else {
        write_keys(&args, &context, BufWriter::new(std::io::stdout()))
    }
}
