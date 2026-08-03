#[macro_use]
mod console;
mod keys;
mod passphrase;
mod pgp;
mod seed;
mod ssh;
mod types;

mod cli;
use crate::keys::*;
use crate::types::*;
use cli::{Args, KeyAlgorithm, OutputFormat};

use anyhow::{bail, Context};
use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Read;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const CREATION_TIMESTAMP: i64 = 1231006505;

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

/// Restrict the OpenOptions mode for files created for key output:
/// 0600 for secret keys, 0644 for public keys.
#[cfg(unix)]
fn set_creation_permissions(opts: &mut std::fs::OpenOptions, public_key: bool) {
    use std::os::unix::fs::OpenOptionsExt;
    // Secret key files must not be readable by other users.
    opts.mode(if public_key { 0o644 } else { 0o600 });
}

#[cfg(not(unix))]
fn set_creation_permissions(_opts: &mut std::fs::OpenOptions, _public_key: bool) {}

/// Tighten permissions on an already-open output file. The creation mode
/// only applies to newly created files; pre-existing files keep their old
/// mode across truncation, so secret key output must be chmod'ed too.
#[cfg(unix)]
fn set_permissions(output: &std::fs::File, public_key: bool) -> Result<()> {
    if !public_key {
        use std::os::unix::fs::PermissionsExt;
        output.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions(_output: &std::fs::File, _public_key: bool) -> Result<()> {
    Ok(())
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
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        set_creation_permissions(&mut opts, args.public_key);
        let output = match opts.open(&f) {
            Ok(output) => output,
            Err(err) => bail!("Cannot open output file {}: {}", f, err),
        };
        set_permissions(&output, args.public_key)?;
        write_keys(
            args,
            keys,
            BufWriter::new(output),
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
        bail!("--creation-timestamp must be a positive number");
    }
    if let Some(expiration_secs) = args.expiration_timestamp {
        if expiration_secs < 0 {
            bail!("--expiration-timestamp must be a positive number");
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
    if args.use_concatenation && args.algorithm != KeyAlgorithm::Xor {
        bail!("-c/--use-concatenation cannot be combined with --algorithm. Use --algorithm alone.");
    }
    if args.auth_subkey && args.algorithm != KeyAlgorithm::Hkdf {
        bail!("--auth-subkey requires --algorithm hkdf.");
    }
    Ok(())
}

/// Format the key fingerprint for display.
/// PGP: groups of 4 hex chars separated by spaces, with a double space in the middle
/// (e.g. "67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F").
/// SSH: SHA256 hash of the public key in base64 (e.g. "SHA256:...").
fn format_fingerprint(args: &Args, keys: &Keys) -> Result<String> {
    match args.format {
        OutputFormat::Pgp => {
            let fp = pgp::key_fingerprint(&keys.sign_key)?;
            let hex: Vec<String> = fp.iter().map(|b| format!("{:02X}", b)).collect();
            let formatted = hex
                .chunks(2)
                .map(|pair| pair.join(""))
                .collect::<Vec<_>>()
                .chunks(5)
                .map(|group| group.join(" "))
                .collect::<Vec<_>>()
                .join("  ");
            Ok(format!("PGP fingerprint: {}", formatted))
        }
        OutputFormat::Ssh => {
            let fp = ssh::key_fingerprint(keys)?;
            Ok(format!("SSH fingerprint: SHA256:{}", fp))
        }
    }
}

fn main() -> Result<()> {
    console_logln!("Welcome to BIP39Key");

    let args = Args::parse();
    validate(&args)?;

    let creation_timestamp_secs = get_creation_timestamp_secs(&args);
    let expiration_timestamp_secs = args.expiration_timestamp;
    let seed = get_seed(&args)?;
    let pass = get_passphrase(&args)?;
    if pass.is_none() {
        console_logln!("WARNING: Using no passphrase");
    }
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
        generate_auth_key: args.auth_subkey,
        use_rfc9106_settings: args.use_rfc9106_settings,
        use_authorization_for_sign_key: args.authorization_for_sign_key,
    };
    let algorithm = if args.use_concatenation {
        KeyAlgorithm::Concat
    } else {
        args.algorithm.clone()
    };
    match algorithm {
        KeyAlgorithm::Xor => {
            console_logln!(
                "WARNING: xor algorithm is deprecated. Use --algorithm hkdf for new keys."
            );
        }
        KeyAlgorithm::Concat => {
            console_logln!(
                "WARNING: concat algorithm is deprecated. Use --algorithm hkdf for new keys."
            );
        }
        KeyAlgorithm::Hkdf => {}
    }
    console_logln!("Generating key entropy");
    let keys = match algorithm {
        KeyAlgorithm::Hkdf => Keys::new_with_hkdf(settings),
        KeyAlgorithm::Concat => Keys::new_with_concat(settings),
        KeyAlgorithm::Xor => Keys::new_with_xor(settings),
    }
    .context("Could not build keys")?;
    console_logln!("Done generating key entropy");
    console_logln!("{}", format_fingerprint(&args, &keys)?);
    output_keys(&args, &keys)
}
