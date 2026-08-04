use bip39key::cli::{Args, KeyAlgorithm, OutputFormat};
use bip39key::keys::*;
use bip39key::types::*;
use bip39key::{console, console_logln, html_receipt, passphrase, pgp, receipt, seed, ssh};

use anyhow::{bail, Context};
use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Read;

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
        .unwrap_or(DEFAULT_CREATION_TIMESTAMP)
}

fn user_id(args: &Args) -> Result<&str> {
    args.user_id
        .as_deref()
        .context("--user-id is required (or use --from-receipt)")
}

/// Load a receipt file: either a full HTML receipt or a raw receipt string.
/// Returns the parsed receipt plus the fingerprints stored in the HTML, when
/// present, for post-generation verification.
#[allow(clippy::type_complexity)]
fn load_receipt(
    path: &str,
) -> Result<(
    receipt::Receipt,
    Option<String>,
    Option<Vec<(String, String)>>,
)> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read receipt {}", path))?;
    if content.contains("data-bip39key-receipt") {
        let parsed = html_receipt::parse_html_receipt(&content)?;
        let rec = receipt::Receipt::parse(&parsed.receipt_string)?;
        Ok((rec, parsed.fingerprint, parsed.subkey_fingerprints))
    } else {
        let rec = receipt::Receipt::parse(&content)?;
        Ok((rec, None, None))
    }
}

/// Apply the parameters recorded in a receipt. The receipt is authoritative:
/// it supplies the user ID and every derivation flag, so combining it with
/// explicit overrides would silently derive a different key.
fn apply_receipt(args: &mut Args, rec: &receipt::Receipt) -> Result<()> {
    if args.user_id.is_some() {
        bail!("--user-id cannot be combined with --from-receipt; the receipt supplies the user ID");
    }
    args.user_id = Some(rec.user_id.clone());
    args.seed_format = rec.seed_format.clone();
    args.algorithm = rec.algorithm.clone();
    args.use_concatenation = false;
    args.use_rfc9106_settings = rec.rfc9106;
    args.auth_subkey = rec.auth_subkey;
    args.authorization_for_sign_key = rec.sign_auth;
    args.just_signkey = rec.just_signkey;
    args.format = if rec.ssh_format {
        OutputFormat::Ssh
    } else {
        OutputFormat::Pgp
    };
    args.creation_timestamp = Some(rec.created);
    args.timestamp = None;
    args.expiration_timestamp = if rec.expires != 0 {
        Some(rec.expires)
    } else {
        None
    };
    args.skip_passphrase_for_key_material = rec.pass_role == receipt::PassRole::NoPass;
    Ok(())
}

/// Compare the regenerated key against the fingerprints stored in the
/// receipt. A mismatch means the wrong mnemonic or passphrase was entered, or
/// the receipt was altered.
fn verify_against_receipt(
    args: &Args,
    keys: &Keys,
    fingerprint: &Option<String>,
    subkey_fingerprints: &Option<Vec<(String, String)>>,
) -> Result<()> {
    if let Some(expected) = fingerprint {
        let actual = match args.format {
            OutputFormat::Pgp => hex::encode_upper(pgp::key_fingerprint(&keys.sign_key)?),
            OutputFormat::Ssh => format!("SHA256:{}", ssh::key_fingerprint(keys)?),
        };
        if &actual != expected {
            bail!(
                "Fingerprint mismatch: receipt has {}, derived {}.\n\
                 The seed phrase or passphrase is wrong, or the receipt was altered.",
                expected,
                actual
            );
        }
        console_logln!("Fingerprint matches the receipt.");
    }
    if args.format == OutputFormat::Pgp {
        if let Some(expected) = subkey_fingerprints {
            let actual = pgp::subkey_fingerprints(keys)?;
            if &actual != expected {
                bail!(
                    "Subkey fingerprint mismatch: receipt has {:?}, derived {:?}.\n\
                     The seed phrase or passphrase is wrong, or the receipt was altered.",
                    expected,
                    actual
                );
            }
            console_logln!("Subkey fingerprints match the receipt.");
        }
    }
    Ok(())
}

fn validate(args: &Args) -> Result<()> {
    user_id(args)?;
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
    // Enforce the OpenPGP v4 u32 limits, which would otherwise panic in
    // pgp.rs after the expensive Argon2id derivation has already run.
    if args.format == OutputFormat::Pgp {
        pgp::validate_timestamps(creation_timestamp_secs, args.expiration_timestamp)?;
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
            Ok(format!("PGP fingerprint: {}", pgp_fingerprint_display(&fp)))
        }
        OutputFormat::Ssh => {
            let fp = ssh::key_fingerprint(keys)?;
            Ok(format!("SSH fingerprint: SHA256:{}", fp))
        }
    }
}

/// Group a raw PGP fingerprint as GPG displays it: blocks of 4 hex chars
/// separated by spaces, with a double space in the middle.
fn pgp_fingerprint_display(fp: &[u8]) -> String {
    let hex: Vec<String> = fp.iter().map(|b| format!("{:02X}", b)).collect();
    hex.chunks(2)
        .map(|pair| pair.join(""))
        .collect::<Vec<_>>()
        .chunks(5)
        .map(|group| group.join(" "))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Write an HTML recovery receipt when --output-receipt is set. The receipt
/// carries only public parameters and fingerprints — never the mnemonic,
/// passphrase, or key material.
fn write_receipt(
    args: &Args,
    keys: &Keys,
    algorithm: &KeyAlgorithm,
    pass_role: receipt::PassRole,
) -> Result<()> {
    let Some(path) = &args.output_receipt else {
        return Ok(());
    };
    let ssh_format = args.format == OutputFormat::Ssh;
    let rec = receipt::Receipt::new(
        args.seed_format.clone(),
        pass_role,
        algorithm.clone(),
        args.use_rfc9106_settings,
        args.auth_subkey,
        args.authorization_for_sign_key,
        args.just_signkey,
        ssh_format,
        user_id(args)?.to_string(),
        get_creation_timestamp_secs(args),
        args.expiration_timestamp,
    );
    let receipt_string = rec.encode();
    let (fingerprint_raw, fingerprint_display, subkey_fingerprints) = match args.format {
        OutputFormat::Pgp => {
            let fp = pgp::key_fingerprint(&keys.sign_key)?;
            (
                hex::encode_upper(&fp),
                pgp_fingerprint_display(&fp),
                pgp::subkey_fingerprints(keys)?,
            )
        }
        OutputFormat::Ssh => {
            let fp = format!("SHA256:{}", ssh::key_fingerprint(keys)?);
            (fp.clone(), fp, vec![])
        }
    };
    let html = html_receipt::generate_html(&html_receipt::HtmlReceiptData {
        receipt: rec,
        receipt_string: receipt_string.clone(),
        fingerprint_raw,
        fingerprint_display,
        subkey_fingerprints,
    })?;
    std::fs::write(path, html).with_context(|| format!("Cannot write receipt to {}", path))?;
    console_logln!("Receipt: {}", receipt_string);
    console_logln!("Receipt written to {}", path);
    Ok(())
}

fn main() -> Result<()> {
    console_logln!("Welcome to BIP39Key");

    let mut args = Args::parse();
    let receipt_fingerprints = if let Some(path) = args.from_receipt.clone() {
        let (rec, fingerprint, subkey_fingerprints) = load_receipt(&path)?;
        apply_receipt(&mut args, &rec)?;
        console_logln!("Regenerating key from receipt:");
        console_logln!("{}", rec.display());
        Some((fingerprint, subkey_fingerprints))
    } else {
        None
    };
    validate(&args)?;

    let creation_timestamp_secs = get_creation_timestamp_secs(&args);
    let expiration_timestamp_secs = args.expiration_timestamp;
    let seed = get_seed(&args)?;
    let pass = get_passphrase(&args)?;
    if pass.is_none() {
        console_logln!("WARNING: Using no passphrase");
    }
    if args.from_receipt.is_some() && !args.skip_passphrase_for_key_material && pass.is_none() {
        bail!(
            "The receipt records that a passphrase was used in key derivation. \
             Provide it with -p/--passphrase or -e/--pinentry."
        );
    }
    let pass_role = if args.skip_passphrase_for_key_material || pass.is_none() {
        receipt::PassRole::NoPass
    } else {
        receipt::PassRole::WithPass
    };
    let settings = KeySettings {
        user_id: user_id(&args)?.to_string(),
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
    if let Some((fingerprint, subkey_fingerprints)) = &receipt_fingerprints {
        verify_against_receipt(&args, &keys, fingerprint, subkey_fingerprints)?;
    }
    console_logln!("{}", format_fingerprint(&args, &keys)?);
    output_keys(&args, &keys)?;
    write_receipt(&args, &keys, &algorithm, pass_role)
}
