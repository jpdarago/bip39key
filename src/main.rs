use bip39key::cli::{Args, KeyAlgorithm, OutputFormat};
use bip39key::keys::*;
use bip39key::plan::{self, Env, OutputTarget, PassphraseSource, Plan, SeedSource};
use bip39key::types::*;
use bip39key::{age, console, console_logln, passphrase, pgp, seed, ssh};

use anyhow::{bail, Context};
use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Read;

// Everything in this file carries out a Plan. Decisions about flags and the
// terminal belong in plan.rs, where they are tested for every combination.

fn write_keys<W: std::io::Write>(
    plan: &Plan,
    keys: &Keys,
    mut writer: BufWriter<W>,
    output_as_text: bool,
) -> Result<()> {
    match plan.format {
        OutputFormat::Pgp => {
            if plan.public_key {
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
            if plan.public_key {
                ssh::output_public_as_pem(keys, &mut writer)?;
            } else {
                ssh::output_secret_as_pem(keys, &mut writer)?;
            }
        }
        OutputFormat::Age => {
            if plan.public_key {
                age::output_public(keys, &mut writer)?;
            } else {
                age::output_secret(keys, &mut writer)?;
            }
        }
    };
    Ok(())
}

fn get_passphrase(plan: &Plan) -> Result<Option<String>> {
    match &plan.passphrase_source {
        PassphraseSource::Pinentry => Ok(Some(passphrase::from_pinentry()?)),
        PassphraseSource::Flag(pass) => Ok(Some(pass.clone())),
        PassphraseSource::Prompt => {
            let passphrase = passphrase::from_interactive_prompt()?;
            Ok(Some(passphrase).filter(|p| !p.is_empty()))
        }
        PassphraseSource::None => Ok(None),
    }
}

fn get_seed(plan: &Plan) -> Result<Vec<u8>> {
    let mut phrase = String::new();
    match &plan.seed_source {
        SeedSource::File(input_filename) => {
            phrase = std::fs::read_to_string(input_filename)
                .with_context(|| format!("Could not read seed phrase from {input_filename}"))?;
        }
        SeedSource::Prompt => return seed::from_prompt(&plan.seed_format),
        SeedSource::Stdin => {
            std::io::stdin().read_to_string(&mut phrase)?;
        }
    }
    let mut stripped = String::new();
    for word in phrase.split_whitespace() {
        if word.is_empty() {
            continue;
        }
        stripped.push_str(word);
        stripped.push(' ');
    }
    seed::decode_phrase(&plan.seed_format, stripped.trim())
}

fn output_keys_to_stdout(plan: &Plan, keys: &Keys) -> Result<()> {
    write_keys(
        plan,
        keys,
        BufWriter::new(std::io::stdout()),
        /*output_as_text=*/ plan.text_to_stdout,
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

/// Refuse to write the key over the seed file. plan.rs rejects the same path
/// spelled the same way; this catches other spellings (./seed.txt, symlinks)
/// and a filename typed at the prompt. A file that does not exist yet cannot
/// be the seed file, so failing to resolve it is not an error.
fn ensure_not_seed_file(plan: &Plan, output_filename: &str) -> Result<()> {
    let SeedSource::File(seed_filename) = &plan.seed_source else {
        return Ok(());
    };
    let (Ok(seed), Ok(output)) = (
        std::fs::canonicalize(seed_filename),
        std::fs::canonicalize(output_filename),
    ) else {
        return Ok(());
    };
    if seed == output {
        bail!(
            "Output file {} is the seed file: the key would overwrite the seed phrase.",
            output_filename
        );
    }
    Ok(())
}

fn output_keys(plan: &Plan, keys: &Keys) -> Result<()> {
    let target = match &plan.output {
        OutputTarget::Ask => OutputTarget::from_answer(
            &Text::new("Provide an output filename for the key (empty for stdout): ").prompt()?,
        ),
        target => target.clone(),
    };
    let filename = match target {
        OutputTarget::File(filename) => filename,
        OutputTarget::Stdout | OutputTarget::Ask => return output_keys_to_stdout(plan, keys),
    };
    ensure_not_seed_file(plan, &filename)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    set_creation_permissions(&mut opts, plan.public_key);
    let output = match opts.open(&filename) {
        Ok(output) => output,
        Err(err) => bail!("Cannot open output file {}: {}", filename, err),
    };
    set_permissions(&output, plan.public_key)?;
    write_keys(
        plan,
        keys,
        BufWriter::new(output),
        /*output_as_text=*/ plan.text_to_file,
    )
}

/// Format the key fingerprint for display.
/// PGP: groups of 4 hex chars separated by spaces, with a double space in the middle
/// (e.g. "67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F").
/// SSH: SHA256 hash of the public key in base64 (e.g. "SHA256:...").
fn format_fingerprint(plan: &Plan, keys: &Keys) -> Result<String> {
    match plan.format {
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
        OutputFormat::Age => Ok(format!("age recipient: {}", age::recipient(keys)?)),
    }
}

fn main() -> Result<()> {
    console_logln!("Welcome to BIP39Key");

    let args = Args::parse();
    let env = Env {
        stdin_is_terminal: console::is_input_interactive(),
        stdout_is_terminal: std::io::stdout().is_terminal(),
    };
    let plan = plan::plan(&args, env)?;
    for warning in &plan.warnings {
        console_logln!("{}", warning.message());
    }
    // Before the slow derivation, when -o already names the file.
    if let OutputTarget::File(filename) = &plan.output {
        ensure_not_seed_file(&plan, filename)?;
    }

    let seed = get_seed(&plan)?;
    let pass = get_passphrase(&plan)?;
    if pass.is_none() {
        console_logln!("WARNING: Using no passphrase");
    }
    let settings = plan.key_settings(seed, pass.as_deref());
    console_logln!("Generating key entropy");
    let mut keys = match plan.algorithm {
        KeyAlgorithm::Hkdf => Keys::new_with_hkdf(settings),
        KeyAlgorithm::Concat => Keys::new_with_concat(settings),
        KeyAlgorithm::Xor => Keys::new_with_xor(settings),
    }
    .context("Could not build keys")?;
    // Keys.passphrase is what pgp.rs and ssh.rs encrypt the key file with.
    // The plan decides that separately from derivation, so -n cannot leave a
    // key file unprotected.
    keys.passphrase = plan.output_passphrase(pass.as_deref());
    console_logln!("Done generating key entropy");
    console_logln!("{}", format_fingerprint(&plan, &keys)?);
    output_keys(&plan, &keys)
}
