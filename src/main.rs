use bip39key::cli::{Args, KeyAlgorithm, OutputFormat};
use bip39key::keys::*;
use bip39key::plan::{self, Env, OutputTarget, PassphraseSource, Plan, Recovery, SeedSource};
use bip39key::types::*;
use bip39key::{age, console, console_logln, html_receipt, passphrase, pgp, receipt, seed, ssh};

use anyhow::{bail, Context};
use clap::Parser;
use inquire::Text;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Read;
use std::path::{Path, PathBuf};

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
    let pass = match &plan.passphrase_source {
        PassphraseSource::Pinentry => Some(passphrase::from_pinentry()?),
        PassphraseSource::Flag(pass) => Some(pass.clone()),
        PassphraseSource::Prompt => {
            let passphrase = passphrase::from_interactive_prompt(plan.confirm_passphrase)?;
            // An empty answer normally means "no passphrase". When the receipt
            // says one was used, it can only mean the empty passphrase: the
            // key was made with -p "" or an empty pinentry entry.
            Some(passphrase).filter(|p| !p.is_empty() || plan.passphrase_required)
        }
        PassphraseSource::None => None,
    };
    if plan.passphrase_required && pass.is_none() {
        bail!(
            "The receipt records that a passphrase was used in key derivation. \
             Provide it with -p/--passphrase or -e/--pinentry."
        );
    }
    Ok(pass)
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

/// The file a path names, for comparing two paths. A file that does not exist
/// yet is resolved through its directory, so two new outputs still compare
/// equal when they are spelled differently. Falls back to the path as written.
fn resolve(path: &str) -> PathBuf {
    let path = Path::new(path);
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return resolved;
    }
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    match (std::fs::canonicalize(parent), path.file_name()) {
        (Ok(parent), Some(name)) => parent.join(name),
        _ => path.to_path_buf(),
    }
}

/// Refuse to write `output` over a file this run reads, or over its other
/// output. plan.rs rejects the same path spelled the same way; this catches
/// other spellings (./seed.txt, symlinks) and a filename typed at the prompt.
fn ensure_distinct_output(plan: &Plan, output: &str, other_output: Option<&str>) -> Result<()> {
    let resolved = resolve(output);
    for input in &plan.input_files {
        if resolve(input) == resolved {
            bail!(
                "Output file {} is also read by this run ({}): writing it would overwrite the seed phrase or the receipt.",
                output,
                input
            );
        }
    }
    if let Some(other) = other_output {
        if resolve(other) == resolved {
            bail!(
                "The key and the receipt would be written to the same file ({}).",
                output
            );
        }
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
    ensure_distinct_output(plan, &filename, plan.receipt_output.as_deref())?;
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

/// Group a raw PGP fingerprint as GPG displays it: blocks of 4 hex chars
/// separated by spaces, with a double space in the middle
/// (e.g. "67EA E069 0476 6020 FB5B  41B3 14B8 857D 6EFD 7E9F").
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

/// Format the key fingerprint for display.
/// SSH: SHA256 hash of the public key in base64 (e.g. "SHA256:...").
fn format_fingerprint(plan: &Plan, keys: &Keys) -> Result<String> {
    match plan.format {
        OutputFormat::Pgp => {
            let fp = pgp::key_fingerprint(&keys.sign_key)?;
            Ok(format!("PGP fingerprint: {}", pgp_fingerprint_display(&fp)))
        }
        OutputFormat::Ssh => {
            let fp = ssh::key_fingerprint(keys)?;
            Ok(format!("SSH fingerprint: SHA256:{}", fp))
        }
        OutputFormat::Age => Ok(format!("age recipient: {}", age::recipient(keys)?)),
    }
}

/// The public key as the text a receipt carries: the armored OpenPGP block,
/// the OpenSSH public key line, or the age recipient.
fn public_key_text(plan: &Plan, keys: &Keys) -> Result<String> {
    let mut writer = BufWriter::new(Vec::new());
    match plan.format {
        OutputFormat::Pgp => pgp::output_public_armored(keys, &mut writer)?,
        OutputFormat::Ssh => ssh::output_public_as_pem(keys, &mut writer)?,
        OutputFormat::Age => age::output_public(keys, &mut writer)?,
    }
    let bytes = writer
        .into_inner()
        .map_err(|err| anyhow::anyhow!("Could not render the public key: {}", err))?;
    Ok(String::from_utf8(bytes)?.trim_end().to_string())
}

/// A receipt loaded from disk, plus the fingerprints stored alongside it in
/// an HTML receipt (absent for a raw receipt string) for post-generation
/// verification.
struct LoadedReceipt {
    receipt: receipt::Receipt,
    fingerprint: Option<String>,
    subkey_fingerprints: Option<Vec<(String, String)>>,
    public_key: Option<String>,
}

/// Load a receipt file: either a full HTML receipt or a raw receipt string.
fn load_receipt(path: &str) -> Result<LoadedReceipt> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read receipt {}", path))?;
    // A file that parses as a receipt string is one, whatever its user ID
    // happens to contain. Anything else is treated as an HTML receipt.
    if let Ok(receipt) = receipt::Receipt::parse(&content) {
        return Ok(LoadedReceipt {
            receipt,
            fingerprint: None,
            subkey_fingerprints: None,
            public_key: None,
        });
    }
    if !html_receipt::looks_like_html_receipt(&content) {
        // Not HTML either: report why it is not a valid receipt string.
        receipt::Receipt::parse(&content)?;
    }
    let parsed = html_receipt::parse_html_receipt(&content)?;
    Ok(LoadedReceipt {
        receipt: receipt::Receipt::parse(&parsed.receipt_string)?,
        fingerprint: parsed.fingerprint,
        subkey_fingerprints: parsed.subkey_fingerprints,
        public_key: parsed.public_key,
    })
}

/// Compare the regenerated key against the fingerprints stored in the
/// receipt. A mismatch means the wrong mnemonic or passphrase was entered, or
/// the receipt was altered.
fn verify_against_receipt(plan: &Plan, keys: &Keys, loaded: &LoadedReceipt) -> Result<()> {
    let Some(expected) = &loaded.fingerprint else {
        return Ok(());
    };
    let actual = match plan.format {
        OutputFormat::Pgp => hex::encode_upper(pgp::key_fingerprint(&keys.sign_key)?),
        OutputFormat::Ssh => format!("SHA256:{}", ssh::key_fingerprint(keys)?),
        // An age key has no fingerprint of its own; the recipient is its
        // public identity.
        OutputFormat::Age => age::recipient(keys)?,
    };
    if &actual != expected {
        bail!(
            "Fingerprint mismatch: receipt has {}, derived {}.\n\
             The seed phrase or passphrase is wrong, or the receipt was altered.",
            expected,
            actual
        );
    }
    if plan.format == OutputFormat::Pgp {
        // A receipt with a primary fingerprint always lists the subkeys too.
        // If the list is gone the receipt is damaged, and saying "matches"
        // without comparing the subkeys would be a lie.
        let actual = pgp::subkey_fingerprints(keys)?;
        // A key with no subkeys has no list in its receipt. Any other receipt
        // without one is damaged.
        let expected = match &loaded.subkey_fingerprints {
            Some(expected) => expected.clone(),
            None if actual.is_empty() => vec![],
            None => bail!(
                "The receipt has a key fingerprint but no subkey fingerprints, so the \
                 subkeys cannot be verified. The receipt is damaged or was altered."
            ),
        };
        if actual != expected {
            bail!(
                "Subkey fingerprint mismatch: receipt has {:?}, derived {:?}.\n\
                 The seed phrase or passphrase is wrong, or the receipt was altered.",
                expected,
                actual
            );
        }
    }
    // The fingerprints cover the key material. The public key in the receipt
    // also carries the user ID and self-signatures, and it is what the owner
    // has been handing out, so a copy that differs from the regenerated key
    // means the receipt was damaged or altered.
    if let Some(expected) = &loaded.public_key {
        if expected.trim_end() != public_key_text(plan, keys)? {
            bail!(
                "The public key in the receipt is not the public key of the regenerated \
                 key, although the fingerprints match. The receipt is damaged or was altered."
            );
        }
    }
    console_logln!("Fingerprint matches the receipt.");
    Ok(())
}

/// Write the HTML recovery receipt. It carries only public parameters and
/// fingerprints — never the mnemonic, passphrase, or key material.
fn write_receipt(plan: &Plan, keys: &Keys, path: &str, has_passphrase: bool) -> Result<()> {
    let rec = receipt::Receipt {
        seed_format: plan.seed_format.clone(),
        pass_role: plan.receipt_pass_role(has_passphrase),
        algorithm: plan.algorithm.clone(),
        rfc9106: plan.use_rfc9106_settings,
        auth_subkey: plan.generate_auth_key,
        sign_auth: plan.use_authorization_for_sign_key,
        just_signkey: !plan.generate_encrypt_key,
        format: plan.format.clone(),
        created: plan.creation_timestamp_secs,
        expires: plan.expiration_timestamp_secs,
        user_id: plan.user_id.clone(),
    };
    let receipt_string = rec.encode();
    let (fingerprint_raw, fingerprint_display, subkey_fingerprints) = match plan.format {
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
        OutputFormat::Age => {
            let recipient = age::recipient(keys)?;
            (recipient.clone(), recipient, vec![])
        }
    };
    let html = html_receipt::generate_html(&html_receipt::HtmlReceiptData {
        receipt: rec,
        receipt_string: receipt_string.clone(),
        fingerprint_raw,
        fingerprint_display,
        subkey_fingerprints,
        public_key: public_key_text(plan, keys)?,
    })?;
    std::fs::write(path, html).with_context(|| format!("Cannot write receipt to {}", path))?;
    console_logln!("Receipt: {}", receipt_string);
    console_logln!("Receipt written to {}", path);
    Ok(())
}

fn main() -> Result<()> {
    console_logln!("Welcome to BIP39Key");

    let mut args = Args::parse();
    let loaded_receipt = match args.from_receipt.clone() {
        Some(path) => {
            let loaded = load_receipt(&path)?;
            plan::apply_receipt(&mut args, &loaded.receipt);
            Some(loaded)
        }
        None => None,
    };
    let env = Env {
        stdin_is_terminal: console::is_input_interactive(),
        stdout_is_terminal: std::io::stdout().is_terminal(),
    };
    let recovery = loaded_receipt.as_ref().map(|loaded| Recovery {
        has_fingerprint: loaded.fingerprint.is_some(),
        with_pass: loaded.receipt.pass_role == receipt::PassRole::WithPass,
    });
    let plan = plan::plan(&args, env, recovery)?;
    if let Some(loaded) = &loaded_receipt {
        console_logln!("Regenerating key from receipt:");
        console_logln!("{}", loaded.receipt.display());
    }
    for warning in &plan.warnings {
        if warning.always_shown() {
            eprintln!("{}", warning.message());
        } else {
            console_logln!("{}", warning.message());
        }
    }
    // Before the slow derivation, for every output already named.
    if let OutputTarget::File(filename) = &plan.output {
        ensure_distinct_output(&plan, filename, plan.receipt_output.as_deref())?;
    }
    if let Some(receipt_path) = &plan.receipt_output {
        ensure_distinct_output(&plan, receipt_path, None)?;
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
    if let Some(loaded) = &loaded_receipt {
        verify_against_receipt(&plan, &keys, loaded)?;
    }
    console_logln!("{}", format_fingerprint(&plan, &keys)?);
    // The receipt goes first: it holds no secrets, so a failure here leaves
    // nothing behind, where a failure after the key was written would exit
    // non-zero with a secret key already on disk.
    if let Some(receipt_path) = &plan.receipt_output {
        write_receipt(&plan, &keys, receipt_path, pass.is_some())?;
    }
    output_keys(&plan, &keys)
}
