mod passphrase;
mod pgp;
mod seed;
mod ssh;
mod keys;
mod types;

use crate::keys::*;
use crate::types::*;

use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::Read;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
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

    /// Filename from which to read the mnemonic words.
    #[clap(short, long)]
    input_filename: Option<String>,

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
    #[clap(short, long, default_value = "pgp")]
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
    #[clap(short, long, default_value = "bip39")]
    seed_format: seed::SeedFormat,

    /// Use a hash of the concatenation of key and password instead of XOR of the hashes.
    #[clap(short = 'c', long)]
    use_concatenation: bool,

    /// Request seed phrase through an interactive CLI prompt.
    #[clap(short = 'q', long)]
    interactive: bool,
}

fn write_keys<W: std::io::Write>(
    args: &Args,
    keys: &Keys,
    mut writer: BufWriter<W>,
) -> Result<()> {
    match args.format {
        OutputFormat::Pgp => {
            if args.public_key {
                if args.armor {
                    pgp::output_public_armored(keys, &mut writer)?;
                } else {
                    pgp::output_public_as_packets(keys, &mut writer)?;
                }
            } else if args.armor {
                pgp::output_armored(keys, &mut writer)?;
            } else {
                pgp::output_as_packets(keys, &mut writer)?;
            }
        }
        OutputFormat::Ssh => {
            if args.public_key {
                ssh::output_public_as_pem(keys, &mut writer)?;
            } else {
                ssh::output_secret_as_pem(keys, &mut writer)?;
            }
        }
    };
    Ok(())
}

fn get_passphrase(args: &Args) -> Result<Option<String>> {
    if args.interactive {
        let passphrase = passphrase::from_interactive_prompt()?;
        Ok(Some(passphrase))
    } else if args.pinentry {
        Ok(Some(passphrase::from_pinentry()?))
    } else if let Some(pass) = &args.passphrase {
        Ok(Some(pass.clone()))
    } else {
        Ok(None)
    }
}

fn get_seed(args: &Args) -> Result<Vec<u8>> {
    if args.interactive {
        return seed::from_prompt(&args.seed_format);
    }
    let mut phrase = String::new();
    if let Some(input_filename) = &args.input_filename {
        phrase = std::fs::read_to_string(input_filename)?;
    } else {
        std::io::stdin().read_to_string(&mut phrase)?;
    }
    let mut stripped = String::new();
    for word in phrase.split_whitespace() {
        if word.is_empty() {
            continue;
        }
        stripped.push_str(word);
        stripped.push(' ');
    }
    seed::decode_phrase(&args.seed_format, stripped.trim())
}

fn output_keys(args: &Args, keys: &Keys) -> Result<()> {
    let filename = if args.interactive {
        Some(Text::new("Provide an output filename for the key: ").prompt()?)
    } else {
        args.output_filename.as_ref().map(|f| f.to_string())
    };
    if let Some(f) = filename {
        let output = std::fs::File::create(&f);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", f, err);
            std::process::exit(1);
        }
        write_keys(args, keys, BufWriter::new(&mut output.unwrap()))
    } else {
        write_keys(args, keys, BufWriter::new(std::io::stdout()))
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
    let seed = get_seed(&args)?;
    let pass = get_passphrase(&args)?;
    let keys = Keys::new(
        &args.user_id,
        &seed,
        &pass,
        args.timestamp.unwrap_or(TIMESTAMP),
        !args.just_signkey,
        args.use_concatenation,
    )
    .expect("Could not build keys");
    output_keys(&args, &keys)
}
