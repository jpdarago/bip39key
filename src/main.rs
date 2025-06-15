#[macro_use]
mod console;
mod keys;
mod passphrase;
mod pgp;
mod seed;
mod ssh;
mod types;

use crate::keys::*;
use crate::types::*;

use anyhow::bail;
use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Read;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const CREATION_TIMESTAMP: i64 = 1231006505;

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

    /// Timestamp (as unix timestamp in seconds) for the dates. If unset, use the default 1231006505.
    #[clap(short, long, hide = true)]
    timestamp: Option<i64>,

    /// Creation timestamp (as unix timestamp in seconds). If unset, uses the genesis block (1231006505).
    #[clap(short = 'd', long)]
    creation_timestamp: Option<i64>,

    /// Creation timestamp (as unix timestamp in seconds). If unset, the keys do not expire.
    #[clap(short = 'y', long)]
    expiration_timestamp: Option<i64>,

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

    /// DEPRECATED! Request seed phrase through an interactive CLI prompt.
    #[clap(short = 'q', long)]
    interactive: Option<bool>,

    /// Use RFC 9106 settings for Argon2id.
    #[clap(short = 'r', long)]
    use_rfc9106_settings: bool,

    /// Add authorization capability to the sign key.
    #[clap(short = 'b', long)]
    authorization_for_sign_key: bool,

    /// Do not add the passphrase as extra entropy. If set, the passphrase will only be used to
    /// encrypt the PGP or SSH key contents, and the key material itself will be generated from
    /// the seed and the user id.
    #[clap(short = 'n', long)]
    skip_passphrase_for_key_material: bool,
}

fn write_keys<W: std::io::Write>(
    args: &Args,
    keys: &Keys,
    mut writer: BufWriter<W>,
    output_as_text: bool,
) -> Result<()> {
    match args.format {
        OutputFormat::Pgp => {
            if args.public_key {
                if output_as_text {
                    pgp::output_public_armored(keys, &mut writer)?;
                } else {
                    pgp::output_public_as_packets(keys, &mut writer)?;
                }
            } else if output_as_text {
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
    if args.pinentry {
        Ok(Some(passphrase::from_pinentry()?))
    } else if let Some(pass) = &args.passphrase {
        Ok(Some(pass.clone()))
    } else if console::is_input_interactive() {
        console_log!("Please input your passphrase. Press enter for no passphrase: ");
        let passphrase = passphrase::from_interactive_prompt()?;
        if passphrase.is_empty() {
            Ok(None)
        } else {
            Ok(Some(passphrase))
        }
    } else {
        Ok(None)
    }
}

fn get_seed(args: &Args) -> Result<Vec<u8>> {
    if console::is_input_interactive() {
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

fn output_keys_to_stdout(args: &Args, keys: &Keys) -> Result<()> {
    let stdout = std::io::stdout();
    let is_terminal = stdout.is_terminal();
    write_keys(
        args,
        keys,
        BufWriter::new(stdout),
        /*output_as_text=*/ args.armor || is_terminal,
    )
}

fn output_keys(args: &Args, keys: &Keys) -> Result<()> {
    let filename = if args.output_filename.is_some() {
        args.output_filename.as_ref().map(|f| f.to_string())
    } else if console::is_input_interactive() {
        Some(Text::new("Provide an output filename for the key (empty for stdout): ").prompt()?)
    } else {
        None
    };
    if let Some(f) = filename {
        if f.is_empty() {
            return output_keys_to_stdout(args, keys);
        }
        let output = std::fs::File::create(&f);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", f, err);
            std::process::exit(1);
        }
        write_keys(
            args,
            keys,
            BufWriter::new(&mut output.unwrap()),
            /*output_as_text=*/ args.armor,
        )
    } else {
        output_keys_to_stdout(args, keys)
    }
}

fn get_creation_timestamp_secs(args: &Args) -> i64 {
    args.creation_timestamp
        .or(args.timestamp)
        .unwrap_or(CREATION_TIMESTAMP)
}

fn validate(args: &Args) -> Result<()> {
    if args.interactive.is_some() {
        console_logln!("WARNING: -q/--interactive flag is deprecated. You probably want an earlier BIP39 version.");
    }
    if args.creation_timestamp.is_some() && args.timestamp.is_some() {
        bail!("--timestamp (-t) flag is deprecated, use --creation-timestamp");
    }
    let creation_timestamp_secs = get_creation_timestamp_secs(args);
    if creation_timestamp_secs < 0 {
        bail!("--creation_timestamp_secs must be a positive number");
    }
    if let Some(expiration_secs) = args.expiration_timestamp {
        if expiration_secs < 0 {
            bail!("--creation_timestamp_secs must be a positive number");
        }
        if expiration_secs < creation_timestamp_secs {
            bail!(
                "--expiration-timestamp is before creation timestamp: {} vs {}",
                expiration_secs,
                creation_timestamp_secs
            );
        }
    }
    if args.just_signkey && args.format == OutputFormat::Ssh {
        bail!("Subkey option (--subkey/-s) only works with PGP output format.");
    }
    if args.armor && args.format == OutputFormat::Ssh {
        bail!("Armor option (--armor/-a) only works with PGP output format.");
    }
    if args.passphrase.is_some() && args.pinentry {
        bail!("One of --passphrase/--pinentry must be set at a time.");
    }
    Ok(())
}

fn main() -> Result<()> {
    console_logln!("Welcome to BIP39Key");

    let args = Args::parse();
    validate(&args)?;

    let creation_timestamp_secs = get_creation_timestamp_secs(&args);
    let expiration_timestamp_secs = args.expiration_timestamp;
    let seed = get_seed(&args)?;
    let pass = get_passphrase(&args)?;
    let settings = KeySettings {
        user_id: args.user_id.clone(),
        seed,
        passphrase: if args.skip_passphrase_for_key_material {
            None
        } else {
            pass
        },
        creation_timestamp_secs,
        expiration_timestamp_secs,
        generate_encrypt_key: !args.just_signkey,
        use_rfc9106_settings: args.use_rfc9106_settings,
        use_authorization_for_sign_key: args.authorization_for_sign_key,
    };
    let keys = if args.use_concatenation {
        Keys::new_with_concat(settings)
    } else {
        console_logln!("WARNING: Using deprecated xor method, if making a new key prefer to use concatenation method with -c"); 
        Keys::new_with_xor(settings)
    }
    .expect("Could not build keys");
    output_keys(&args, &keys)
}
