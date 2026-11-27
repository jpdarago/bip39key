use crate::cli::OutputFormat;
use crate::keys::DEFAULT_CREATION_TIMESTAMP;
use crate::receipt::{PassRole, Receipt};
use crate::types::*;
use qrcode::QrCode;
use std::fmt::Write as FmtWrite;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The receipt string as a QR code, or `None` when it is too long for one (a
/// QR code holds at most about 2.3 KB at this error-correction level, and user
/// IDs can be longer). The receipt is written after the key, so this must not
/// fail the run: the receipt string itself is always in the page.
fn qr_svg(data: &str) -> Result<Option<String>> {
    let code = match QrCode::new(data.as_bytes()) {
        Ok(code) => code,
        Err(qrcode::types::QrError::DataTooLong) => return Ok(None),
        Err(e) => anyhow::bail!("QR code generation failed: {e}"),
    };
    let module_count = code.width();
    let quiet = 2;
    let scale = 4;
    let total = (module_count + 2 * quiet) * scale;

    let mut svg = String::with_capacity(4096);
    write!(
        svg,
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" width="{total}" height="{total}">"#,
    )?;
    write!(
        svg,
        r#"<rect width="{total}" height="{total}" fill="white"/>"#,
    )?;

    for y in 0..module_count {
        for x in 0..module_count {
            use qrcode::Color;
            if code[(x, y)] == Color::Dark {
                let px = (x + quiet) * scale;
                let py = (y + quiet) * scale;
                write!(
                    svg,
                    r#"<rect x="{px}" y="{py}" width="{scale}" height="{scale}" fill="black"/>"#,
                )?;
            }
        }
    }
    svg.push_str("</svg>");
    Ok(Some(svg))
}

// --- Provenance helpers ---

fn binary_sha256() -> String {
    let exe_path = std::env::current_exe().ok();
    match exe_path {
        Some(path) => {
            use sha2::Digest;
            match std::fs::read(&path) {
                Ok(bytes) => format!("{:x}", sha2::Sha256::digest(&bytes)),
                Err(_) => "unavailable".to_string(),
            }
        }
        None => "unavailable".to_string(),
    }
}

fn format_timestamp_iso(unix: u64) -> String {
    let secs = unix % 60;
    let mins = (unix / 60) % 60;
    let hours = (unix / 3600) % 24;
    let mut days = unix / 86400;

    // Convert days since epoch to year-month-day.
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i + 1;
            break;
        }
        days -= md;
    }
    let day = days + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// True when `commit` is a full, clean git hash: the only case where the
/// reproducible-build instructions can actually reproduce this binary.
fn is_clean_commit(commit: &str) -> bool {
    commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build-instruction section of the receipt. When the binary was built from
/// an unknown or modified source tree, say so instead of printing a `nix
/// build` command that points nowhere.
fn build_instructions(commit: &str) -> String {
    if is_clean_commit(commit) {
        format!(
            r#"<h3>Reproducible build (Nix)</h3>
<pre>nix build github:jpdarago/bip39key/{commit}
sha256sum result/bin/bip39key</pre>

<h3>Fallback build (without Nix)</h3>
<pre>git clone https://github.com/jpdarago/bip39key
cd bip39key &amp;&amp; git checkout {commit}
# Install Rust toolchain from rust-toolchain.toml
cargo build --release --locked
sha256sum target/release/bip39key</pre>
<p>Note: only Nix builds are guaranteed bit-for-bit reproducible. Cargo builds may differ due to system libraries and linker.</p>"#
        )
    } else {
        format!(
            r#"<h3>Reproducible build</h3>
<p class="warn">This binary was built from an unknown or modified source tree (commit <code>{}</code>), so no published commit reproduces it and the binary hash above cannot be independently verified. Any release of <code>bip39key</code> that supports receipt version 1 can still regenerate the key.</p>
<pre>nix build github:jpdarago/bip39key
sha256sum result/bin/bip39key</pre>"#,
            html_escape(commit)
        )
    }
}

// --- HTML generation ---

pub struct HtmlReceiptData {
    pub receipt: Receipt,
    pub receipt_string: String,
    pub fingerprint_raw: String,
    pub fingerprint_display: String,
    /// Labeled subkey fingerprints (hex, emission order), e.g.
    /// ("encrypt", "AABB...") and ("auth", "CCDD..."). Empty for SSH output
    /// or --just-signkey keys.
    pub subkey_fingerprints: Vec<(String, String)>,
    /// The public key as text: the armored OpenPGP public key block, or the
    /// OpenSSH `ssh-ed25519 ...` line. With it the receipt is all that is
    /// needed to use the key (encrypt to it, authorize it) until the day the
    /// secret half has to be regenerated.
    pub public_key: String,
}

pub fn generate_html(data: &HtmlReceiptData) -> Result<String> {
    let receipt = &data.receipt;
    let receipt_str_escaped = html_escape(&data.receipt_string);
    let fp_raw = html_escape(&data.fingerprint_raw);
    let fp_display = html_escape(&data.fingerprint_display);
    let user_id_escaped = html_escape(&receipt.user_id);
    let qr = match qr_svg(&data.receipt_string)? {
        Some(svg) => format!(r#"<div class="qr">{svg}</div>"#),
        None => "<p>This receipt string is too long for a QR code. Keep this file, or a copy of the string above.</p>".to_string(),
    };

    let subkey_fps_attr = html_escape(
        &data
            .subkey_fingerprints
            .iter()
            .map(|(name, fp)| format!("{}={}", name, fp))
            .collect::<Vec<_>>()
            .join(","),
    );
    let subkey_fps_display = data
        .subkey_fingerprints
        .iter()
        .map(|(name, fp)| format!("{}: <code>{}</code>", html_escape(name), html_escape(fp)))
        .collect::<Vec<_>>()
        .join("<br>");
    let subkey_section = if data.subkey_fingerprints.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h3>Subkey fingerprints</h3>
<p class="fp" data-bip39key-subkey-fingerprints="{subkey_fps_attr}">{subkey_fps_display}</p>
<p>Compare them with <code>gpg --list-keys --with-subkey-fingerprint</code> after import.</p>"#
        )
    };

    let public_key_escaped = html_escape(data.public_key.trim_end());
    let public_key_hint = match receipt.format {
        OutputFormat::Pgp => "Save this block to a file and run <code>gpg --import</code> on it to encrypt to this key or verify its signatures.",
        OutputFormat::Ssh => "Add this line to <code>authorized_keys</code> on the machines this key should open.",
        OutputFormat::Age => "Encrypt to this key with <code>age -r</code> followed by this recipient.",
    };

    let version = env!("CARGO_PKG_VERSION");
    let commit = env!("BIP39KEY_COMMIT");
    let target = env!("BIP39KEY_TARGET");
    let bin_hash = binary_sha256();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_iso = format_timestamp_iso(now);

    let seed_format_display = match receipt.seed_format {
        crate::cli::SeedFormat::Bip39 => "BIP39",
        crate::cli::SeedFormat::Electrum => "Electrum",
    };
    let pass_display = match receipt.pass_role {
        PassRole::WithPass => "Yes — passphrase used in key derivation",
        PassRole::NoPass => "No — key derived from seed and user ID only",
    };
    let argon_display = receipt.argon_display();
    let algorithm_display = receipt.algorithm_display();
    let created_display = if receipt.created == DEFAULT_CREATION_TIMESTAMP {
        "2009-01-03T18:15:05Z (Bitcoin genesis block)".to_string()
    } else {
        receipt.created.to_string()
    };
    let expires_display = match receipt.expires {
        None => "Never".to_string(),
        Some(expires) => expires.to_string(),
    };

    let key_structure = if receipt.format == OutputFormat::Ssh {
        "Ed25519 SSH key".to_string()
    } else if receipt.format == OutputFormat::Age {
        "X25519 age identity".to_string()
    } else {
        let mut parts = vec![if receipt.sign_auth {
            "Sign + Certify + Auth primary key"
        } else {
            "Sign + Certify primary key"
        }];
        if !receipt.just_signkey {
            parts.push("Encrypt subkey");
        }
        if receipt.auth_subkey {
            parts.push("Auth subkey");
        }
        parts.join(" + ")
    };

    let fingerprint_label = match receipt.format {
        OutputFormat::Pgp => "PGP Key Fingerprint",
        OutputFormat::Ssh => "SSH Key Fingerprint",
        OutputFormat::Age => "age Recipient",
    };

    let needs_passphrase = matches!(receipt.pass_role, PassRole::WithPass);
    let passphrase_checklist = if needs_passphrase {
        "<li>Your passphrase</li>"
    } else {
        ""
    };
    let passphrase_step = if needs_passphrase {
        "<li>Enter your passphrase when prompted.</li>"
    } else if receipt.format == OutputFormat::Age {
        // --from-receipt does not ask: an age identity cannot be encrypted,
        // so a passphrase could only change the key.
        "<li>You will not be asked for a passphrase: this key was made without one.</li>"
    } else {
        "<li>If asked for a password, it only encrypts the new key file and does not change the key. Leave it empty for an unencrypted file.</li>"
    };
    let from_receipt_command = match receipt.format {
        OutputFormat::Pgp => "bip39key --from-receipt receipt.html -o key.gpg",
        OutputFormat::Ssh => "bip39key --from-receipt receipt.html -o key.ssh",
        OutputFormat::Age => "bip39key --from-receipt receipt.html -o identity.txt",
    };

    let recovery_command = html_escape(&receipt.recovery_command());
    // The manual command cannot pass -n for an age key, so the prompt has to
    // be left empty by hand.
    let manual_note = if receipt.format == OutputFormat::Age && !needs_passphrase {
        " If it asks for a password, leave it empty: any passphrase would produce a different key."
    } else {
        ""
    };
    let import_step = match receipt.format {
        OutputFormat::Pgp => "<li>Import the key: <code>gpg --import key.gpg</code></li>",
        OutputFormat::Ssh => "<li>Install the key: <code>cp key.ssh ~/.ssh/id_ed25519</code> and set permissions to 0600.</li>",
        OutputFormat::Age => "<li>Decrypt with the identity: <code>age -d -i identity.txt FILE.age</code>. The identity file is not encrypted.</li>",
    };

    let build_section = build_instructions(commit);
    // Both come from the build environment (BIP39KEY_COMMIT can be set by a
    // packager), so they are escaped like any other value in the page.
    let commit = html_escape(commit);
    let target = html_escape(target);

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>bip39key Receipt — {user_id_escaped}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 800px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; line-height: 1.6; }}
  h1 {{ font-size: 1.6em; margin-bottom: 0.5em; }}
  h2 {{ font-size: 1.2em; margin: 1.5em 0 0.5em; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }}
  h3 {{ font-size: 1em; margin: 1em 0 0.3em; }}
  .receipt-box {{ background: #f5f5f5; border: 1px solid #ddd; padding: 1em;
                  border-radius: 4px; margin: 0.5em 0; overflow-x: auto; }}
  .receipt-box code {{ font-size: 0.95em; word-break: break-all; }}
  .qr {{ text-align: center; margin: 1em 0; }}
  .qr svg {{ max-width: 200px; height: auto; }}
  .fp {{ font-family: "SF Mono", "Consolas", "Liberation Mono", monospace; font-size: 1.1em;
         letter-spacing: 0.05em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; }}
  td {{ padding: 0.4em 0.8em; border: 1px solid #ddd; }}
  td:first-child {{ font-weight: 600; width: 40%; background: #fafafa; }}
  pre {{ background: #f5f5f5; padding: 0.8em 1em; border-radius: 4px; overflow-x: auto;
         font-size: 0.85em; margin: 0.5em 0; }}
  ol, ul {{ margin-left: 1.5em; margin-top: 0.3em; }}
  li {{ margin-bottom: 0.3em; }}
  footer {{ margin-top: 2em; padding-top: 1em; border-top: 1px solid #ddd;
            color: #666; font-size: 0.85em; }}
  .safe {{ background: #d4edda; border: 1px solid #28a745; padding: 0.5em 1em;
           border-radius: 4px; margin-top: 0.5em; }}
  .warn {{ background: #fff3cd; border: 1px solid #ffc107; padding: 0.5em 1em;
           border-radius: 4px; margin: 0.5em 0; }}
  @media print {{ body {{ font-size: 11pt; }} .qr svg {{ max-width: 150px; }} }}
</style>
</head>
<body>

<div class="safe">This file contains no secret material (no mnemonic, no passphrase, no private key). It is safe to store in Google Drive, Dropbox, email, or print. It does record the user ID, derivation settings, and fingerprints, so anyone who also obtains the mnemonic (and passphrase, if used) can regenerate the key; keep the mnemonic secret.</div>

<h1>bip39key Receipt</h1>

<h2>Receipt String</h2>
<div class="receipt-box">
  <code data-bip39key-receipt="{receipt_str_escaped}">{receipt_str_escaped}</code>
</div>
{qr}

<h2>{fingerprint_label}</h2>
<p class="fp">
  <code data-bip39key-fingerprint="{fp_raw}">{fp_display}</code>
</p>
{subkey_section}

<h2>Public Key</h2>
<p>{public_key_hint} It is the public half only: it cannot sign or decrypt.</p>
<pre data-bip39key-public-key="{public_key_escaped}">{public_key_escaped}</pre>

<h2>Derivation Parameters</h2>
<table>
  <tr><td>Version</td><td>1</td></tr>
  <tr><td>Seed format</td><td>{seed_format_display}</td></tr>
  <tr><td>Passphrase</td><td>{pass_display}</td></tr>
  <tr><td>Argon2id</td><td>{argon_display}</td></tr>
  <tr><td>Algorithm</td><td>{algorithm_display}</td></tr>
  <tr><td>Key structure</td><td>{key_structure}</td></tr>
  <tr><td>Created</td><td>{created_display}</td></tr>
  <tr><td>Expires</td><td>{expires_display}</td></tr>
  <tr><td>User ID</td><td><code>{user_id_escaped}</code></td></tr>
</table>

<h2>Recovery</h2>

<h3>What you'll need</h3>
<ul>
  <li>This file</li>
  <li>Your mnemonic seed phrase ({seed_format_display} format, typically 12 or 24 words)</li>
  {passphrase_checklist}
  <li>The <code>bip39key</code> tool (version {version} or compatible)</li>
</ul>

<h3>Recovery command</h3>
<pre>{from_receipt_command}</pre>
<p>Replace <code>receipt.html</code> with the path to this file. The command reads every setting from it and checks the regenerated key against the fingerprint above, so a mistyped seed phrase or passphrase is reported instead of producing a different key.</p>

<h3>Without this file</h3>
<p>The same key, from the settings alone. Nothing is verified, so compare the printed fingerprint yourself.{manual_note}</p>
<pre>{recovery_command}</pre>

<h3>Step-by-step recovery</h3>
<ol>
  <li>Install <code>bip39key</code> (see Provenance section below for build instructions).</li>
  <li>Run the recovery command above.</li>
  <li>Enter your mnemonic seed phrase when prompted.</li>
  {passphrase_step}
  <li>Check that it reports "Fingerprint matches the receipt".</li>
  {import_step}
  <li>Transfer to a hardware token if desired, then securely delete the key file.</li>
</ol>

<h2>Provenance</h2>
<table>
  <tr><td>bip39key version</td><td>{version}</td></tr>
  <tr><td>Git commit</td><td><code>{commit}</code></td></tr>
  <tr><td>Target</td><td><code>{target}</code></td></tr>
  <tr><td>Binary SHA-256</td><td><code>{bin_hash}</code></td></tr>
  <tr><td>Generated</td><td>{now_iso}</td></tr>
  <tr><td>Source</td><td>https://github.com/jpdarago/bip39key</td></tr>
</table>

{build_section}

<footer>
  <p>Generated by bip39key. This file is safe to store anywhere — it contains no secrets.</p>
</footer>

</body>
</html>
"##
    );

    Ok(html)
}

/// Data recovered from an HTML receipt file.
pub struct ParsedHtmlReceipt {
    pub receipt_string: String,
    pub fingerprint: Option<String>,
    /// Labeled subkey fingerprints (name, hex) when the receipt carries them.
    pub subkey_fingerprints: Option<Vec<(String, String)>>,
    /// The public key text, when the receipt carries it (1.11.0 and later).
    pub public_key: Option<String>,
}

/// Whether `content` carries the attribute an HTML receipt stores its receipt
/// string in. Matches the attribute syntax, not the bare name, which can
/// appear in a user ID.
pub fn looks_like_html_receipt(content: &str) -> bool {
    content.contains("data-bip39key-receipt=\"")
}

/// Parse an HTML receipt file to extract the receipt string and fingerprints.
pub fn parse_html_receipt(html: &str) -> Result<ParsedHtmlReceipt> {
    let receipt_string = extract_data_attr(html, "data-bip39key-receipt")
        .ok_or_else(|| anyhow::anyhow!("No data-bip39key-receipt attribute found in HTML"))?;
    let fingerprint = extract_data_attr(html, "data-bip39key-fingerprint");
    // Every entry must parse. Dropping a malformed one would shorten the list
    // the regenerated subkeys are compared against.
    let subkey_fingerprints = extract_data_attr(html, "data-bip39key-subkey-fingerprints")
        .map(|v| {
            v.split(',')
                .map(|entry| match entry.split_once('=') {
                    Some((name, fp)) if !name.is_empty() && !fp.is_empty() => {
                        Ok((name.to_string(), fp.to_string()))
                    }
                    _ => Err(anyhow::anyhow!(
                        "Malformed subkey fingerprint in receipt: '{}'",
                        entry
                    )),
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let public_key = extract_data_attr(html, "data-bip39key-public-key");
    Ok(ParsedHtmlReceipt {
        receipt_string,
        fingerprint,
        subkey_fingerprints,
        public_key,
    })
}

fn extract_data_attr(html: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    let start = html.find(&pattern)?;
    let value_start = start + pattern.len();
    let rest = &html[value_start..];
    let end = rest.find('"')?;
    let raw = &rest[..end];
    // Unescape HTML entities. `&amp;` must be handled last: it is the
    // escaped form of a literal `&`, so unescaping it earlier would turn a
    // user ID containing a literal "&quot;" into a stray quote.
    Some(
        raw.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{KeyAlgorithm, SeedFormat};
    use crate::receipt::Receipt;

    /// Shaped like an armored key: several lines, and characters that must
    /// survive HTML escaping.
    const TEST_PUBLIC_KEY: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmDME<a&b>\"+/=\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----";

    #[test]
    fn test_public_key_round_trips_through_the_page() {
        let html = generate_html(&HtmlReceiptData {
            receipt: test_receipt(false),
            receipt_string: test_receipt(false).encode(),
            fingerprint_raw: "AB".repeat(20),
            fingerprint_display: "AB".repeat(20),
            subkey_fingerprints: vec![],
            public_key: format!("{TEST_PUBLIC_KEY}\n"),
        })
        .unwrap();
        assert!(html.contains("<h2>Public Key</h2>"));
        let parsed = parse_html_receipt(&html).unwrap();
        assert_eq!(parsed.public_key.as_deref(), Some(TEST_PUBLIC_KEY));
    }

    #[test]
    fn test_receipt_without_public_key_still_parses() {
        // Receipts written by 1.10.x have no public key section.
        let html = r#"<code data-bip39key-receipt="x">x</code>"#;
        assert!(parse_html_receipt(html).unwrap().public_key.is_none());
    }

    fn test_receipt(ssh: bool) -> Receipt {
        let format = if ssh {
            OutputFormat::Ssh
        } else {
            OutputFormat::Pgp
        };
        Receipt {
            seed_format: SeedFormat::Bip39,
            pass_role: PassRole::WithPass,
            algorithm: KeyAlgorithm::Hkdf,
            rfc9106: false,
            auth_subkey: false,
            sign_auth: false,
            just_signkey: false,
            format,
            created: DEFAULT_CREATION_TIMESTAMP,
            expires: None,
            user_id: "Test User <test@example.com>".to_string(),
        }
    }

    #[test]
    fn test_unescape_entities_in_user_id() {
        // A user ID containing literal entity text must survive the
        // escape/unescape round trip; `&amp;` has to be unescaped last.
        let receipt = Receipt {
            user_id: "Q &quot; &amp;lt; \"R\" <q@example.com>".to_string(),
            ..test_receipt(false)
        };
        let receipt_str = receipt.encode();
        let data = HtmlReceiptData {
            receipt,
            receipt_string: receipt_str.clone(),
            fingerprint_raw: "AABBCCDD".to_string(),
            fingerprint_display: "AABB CCDD".to_string(),
            subkey_fingerprints: vec![],
            public_key: TEST_PUBLIC_KEY.to_string(),
        };
        let html = generate_html(&data).unwrap();
        let parsed = parse_html_receipt(&html).unwrap();
        assert_eq!(parsed.receipt_string, receipt_str);
        assert!(Receipt::parse(&parsed.receipt_string).is_ok());
    }

    #[test]
    fn test_build_instructions() {
        let clean = "0123456789abcdef0123456789abcdef01234567";
        let html = build_instructions(clean);
        assert!(html.contains(&format!("nix build github:jpdarago/bip39key/{clean}")));
        assert!(html.contains(&format!("git checkout {clean}")));

        for bad in [
            "unknown",
            "0123456789abcdef0123456789abcdef01234567-dirty",
            "abc1234",
        ] {
            let html = build_instructions(bad);
            assert!(!html.contains(&format!("bip39key/{bad}")), "{bad}: {html}");
            assert!(html.contains("unknown or modified source tree"), "{bad}");
        }
    }

    #[test]
    fn test_html_roundtrip() {
        let receipt = test_receipt(false);
        let receipt_str = receipt.encode();
        let data = HtmlReceiptData {
            receipt,
            receipt_string: receipt_str.clone(),
            fingerprint_raw: "AABBCCDD".to_string(),
            fingerprint_display: "AABB CCDD".to_string(),
            subkey_fingerprints: vec![
                ("encrypt".to_string(), "1111".to_string()),
                ("auth".to_string(), "2222".to_string()),
            ],
            public_key: TEST_PUBLIC_KEY.to_string(),
        };
        let html = generate_html(&data).unwrap();

        let parsed = parse_html_receipt(&html).unwrap();
        assert_eq!(parsed.receipt_string, receipt_str);
        assert_eq!(parsed.fingerprint.unwrap(), "AABBCCDD");
        assert_eq!(
            parsed.subkey_fingerprints.unwrap(),
            vec![
                ("encrypt".to_string(), "1111".to_string()),
                ("auth".to_string(), "2222".to_string())
            ]
        );

        // Provenance fields present.
        assert!(html.contains("Git commit"));
        assert!(html.contains("Binary SHA-256"));
        assert!(html.contains("Target"));
        // The exact build instructions depend on whether this test binary was
        // built from a clean commit; `test_build_instructions` covers both.
        assert!(html.contains("nix build"));
        // Recovery command reconstructs the invocation.
        assert!(html.contains("bip39key -g hkdf -u"));
    }

    #[test]
    fn test_parse_rejects_malformed_subkey_fingerprints() {
        for value in ["encrypt=AB,auth", "encrypt=AB,", "=AB", "encrypt="] {
            let html = format!(
                r#"<p data-bip39key-receipt="x" data-bip39key-subkey-fingerprints="{value}">"#
            );
            assert!(parse_html_receipt(&html).is_err(), "{value}");
        }
    }

    #[test]
    fn test_parse_receipt_without_subkey_fingerprints() {
        let html = r#"<code data-bip39key-receipt="bip39key:1:bip39:nopass:hkdf:X:ABCD">x</code>"#;
        let parsed = parse_html_receipt(html).unwrap();
        assert_eq!(parsed.receipt_string, "bip39key:1:bip39:nopass:hkdf:X:ABCD");
        assert!(parsed.fingerprint.is_none());
        assert!(parsed.subkey_fingerprints.is_none());
    }

    #[test]
    fn test_html_escaping() {
        let receipt = test_receipt(false);
        let receipt_str = receipt.encode();
        let data = HtmlReceiptData {
            receipt,
            receipt_string: receipt_str.clone(),
            fingerprint_raw: "AABBCCDD".to_string(),
            fingerprint_display: "AABB CCDD".to_string(),
            subkey_fingerprints: vec![],
            public_key: TEST_PUBLIC_KEY.to_string(),
        };
        let html = generate_html(&data).unwrap();

        assert!(html.contains("&lt;test@example.com&gt;"));
        let parsed = parse_html_receipt(&html).unwrap();
        assert_eq!(parsed.receipt_string, receipt_str);
    }

    #[test]
    fn test_ssh_receipt_html() {
        let receipt = test_receipt(true);
        let receipt_str = receipt.encode();
        let data = HtmlReceiptData {
            receipt,
            receipt_string: receipt_str,
            fingerprint_raw: "SHA256:abcdef".to_string(),
            fingerprint_display: "SHA256:abcdef".to_string(),
            subkey_fingerprints: vec![],
            public_key: TEST_PUBLIC_KEY.to_string(),
        };
        let html = generate_html(&data).unwrap();
        assert!(html.contains("SSH Key Fingerprint"));
        assert!(html.contains("-f ssh"));
        assert!(!html.contains("data-bip39key-subkey-fingerprints"));
    }

    #[test]
    fn test_iso_timestamp() {
        assert_eq!(format_timestamp_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp_iso(1231006505), "2009-01-03T18:15:05Z");
    }
    fn html_for(receipt: Receipt) -> String {
        let receipt_string = receipt.encode();
        generate_html(&HtmlReceiptData {
            receipt,
            receipt_string,
            fingerprint_raw: "AABBCCDD".to_string(),
            fingerprint_display: "AABB CCDD".to_string(),
            subkey_fingerprints: vec![],
            public_key: TEST_PUBLIC_KEY.to_string(),
        })
        .unwrap()
    }

    #[test]
    fn test_recovery_leads_with_from_receipt() {
        let html = html_for(test_receipt(false));
        let from_receipt = html
            .find("bip39key --from-receipt receipt.html -o key.gpg")
            .expect("no --from-receipt command");
        let manual = html.find("bip39key -g hkdf -u").expect("no manual command");
        assert!(from_receipt < manual);
        assert!(html_for(test_receipt(true))
            .contains("bip39key --from-receipt receipt.html -o key.ssh"));
    }

    #[test]
    fn test_nopass_receipt_explains_the_password_prompt() {
        let html = html_for(Receipt {
            pass_role: PassRole::NoPass,
            ..test_receipt(false)
        });
        assert!(html.contains("only encrypts the new key file"));
        assert!(!html.contains("<li>Your passphrase</li>"));
        // The manual command must keep the passphrase out of derivation.
        assert!(html.contains(" -n "));
    }

    #[test]
    fn test_long_user_id_omits_the_qr_code() {
        // Past a QR code's capacity the receipt must still be written, and
        // must still parse back, just without the QR code.
        let receipt = Receipt {
            user_id: format!("{} <long@test.com>", "A".repeat(8400)),
            ..test_receipt(false)
        };
        let receipt_string = receipt.encode();
        let html = html_for(receipt);
        assert!(!html.contains("<svg"));
        assert!(html.contains("too long for a QR code"));
        assert_eq!(
            parse_html_receipt(&html).unwrap().receipt_string,
            receipt_string
        );
        assert!(html_for(test_receipt(false)).contains("<svg"));
    }
}
