use crate::cli::{KeyAlgorithm, OutputFormat, SeedFormat};
use crate::keys::DEFAULT_CREATION_TIMESTAMP;
use crate::types::*;
use sha2::Digest;
use std::fmt;

const RECEIPT_TOOL: &str = "bip39key";
const RECEIPT_VERSION: &str = "1";

/// What `-r/--use-rfc9106-settings` really runs: argon2::Config::rfc9106(),
/// which has 1 lane where RFC 9106 itself recommends 4. Lanes change the
/// Argon2id output, so the receipt must state the parameters actually used.
const RFC9106_DISPLAY: &str =
    "RFC 9106 memory and passes (2 GiB memory, 1 iteration), but 1 lane, not the RFC's 4";

/// Quote `s` for a POSIX shell: single quotes, with embedded single quotes
/// written as `'\''`. Nothing inside single quotes is expanded, so a user ID
/// with `"`, `$` or backticks pastes back as exactly the same bytes.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The receipt string is colon-separated, so a user ID containing a colon
/// would produce a receipt that cannot be parsed back. Reject it before the
/// expensive key derivation instead of writing an unrecoverable receipt.
pub fn validate_user_id(user_id: &str) -> Result<()> {
    if user_id.is_empty() {
        anyhow::bail!("User ID must not be empty when writing a receipt");
    }
    if user_id.contains(':') {
        anyhow::bail!(
            "User ID must not contain ':' when writing a receipt (receipts are colon-separated): '{}'",
            user_id
        );
    }
    if user_id.contains(['\n', '\r']) {
        anyhow::bail!("User ID must not contain line breaks when writing a receipt");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassRole {
    WithPass,
    NoPass,
}

impl fmt::Display for PassRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PassRole::WithPass => write!(f, "withpass"),
            PassRole::NoPass => write!(f, "nopass"),
        }
    }
}

fn algorithm_str(algorithm: &KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Xor => "xor",
        KeyAlgorithm::Concat => "concat",
        KeyAlgorithm::Hkdf => "hkdf",
    }
}

/// Parse a boolean flag value. Only "1" is accepted: receipts are written by
/// this tool, so anything else is a transcription error, not a preference.
fn parse_flag(key: &str, value: &str) -> Result<bool> {
    match value {
        "1" => Ok(true),
        other => anyhow::bail!(
            "Invalid value for receipt option '{}': expected '1', got '{}'",
            key,
            other
        ),
    }
}

/// All parameters needed to deterministically regenerate a key, minus the
/// secrets (mnemonic and passphrase). Unlike memo2key, bip39key does not fix
/// the derivation algorithm or Argon2id parameters, so both are recorded.
///
/// Receipt version 1 implies the legacy Argon2id parameter set (64 MiB,
/// 32 iterations, 8 lanes) unless `argon=rfc9106` is present. Changing those
/// defaults requires a new receipt version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub seed_format: SeedFormat,
    pub pass_role: PassRole,
    pub algorithm: KeyAlgorithm,
    /// Argon2id with RFC 9106 parameters (`-r`); default is the legacy
    /// parameter set (64 MiB, 32 iterations, 8 lanes).
    pub rfc9106: bool,
    /// A separate authentication subkey was generated (`--auth-subkey`).
    pub auth_subkey: bool,
    /// The sign key carries the authentication capability flag (`-b`).
    pub sign_auth: bool,
    /// No encrypt subkey was generated (`-j/--just-signkey`).
    pub just_signkey: bool,
    /// What was emitted: OpenPGP (the default, not written to the receipt
    /// string), OpenSSH (`format=ssh`) or age (`format=age`).
    pub format: OutputFormat,
    pub created: i64,
    /// Absolute expiration timestamp; `None` means the key never expires.
    pub expires: Option<i64>,
    pub user_id: String,
}

impl Receipt {
    fn compute_checksum(fields_before_checksum: &str) -> String {
        let hash = sha2::Sha256::digest(fields_before_checksum.as_bytes());
        format!("{:02X}{:02X}", hash[0], hash[1])
    }

    pub fn encode(&self) -> String {
        let seed_fmt = match self.seed_format {
            SeedFormat::Bip39 => "bip39",
            SeedFormat::Electrum => "electrum",
        };

        let mut parts: Vec<String> = vec![
            RECEIPT_TOOL.to_string(),
            RECEIPT_VERSION.to_string(),
            seed_fmt.to_string(),
            self.pass_role.to_string(),
            algorithm_str(&self.algorithm).to_string(),
        ];

        // Optional key=value fields (only when non-default).
        if self.rfc9106 {
            parts.push("argon=rfc9106".to_string());
        }
        if self.auth_subkey {
            parts.push("auth=1".to_string());
        }
        if self.sign_auth {
            parts.push("signauth=1".to_string());
        }
        if self.just_signkey {
            parts.push("nosubkey=1".to_string());
        }
        match self.format {
            OutputFormat::Pgp => {}
            OutputFormat::Ssh => parts.push("format=ssh".to_string()),
            OutputFormat::Age => parts.push("format=age".to_string()),
        }
        if self.created != DEFAULT_CREATION_TIMESTAMP {
            parts.push(format!("created={}", self.created));
        }
        if let Some(expires) = self.expires {
            parts.push(format!("expires={}", expires));
        }

        // User ID (second-to-last field).
        parts.push(self.user_id.clone());

        let before_checksum = parts.join(":");
        let checksum = Self::compute_checksum(&before_checksum);
        format!("{}:{}", before_checksum, checksum)
    }

    pub fn parse(input: &str) -> Result<Receipt> {
        let input = input.trim();
        let parts: Vec<&str> = input.split(':').collect();
        if parts.len() < 7 {
            anyhow::bail!("Receipt too short: expected at least 7 colon-separated fields");
        }

        // Field 0: tool identifier.
        if parts[0] != RECEIPT_TOOL {
            anyhow::bail!(
                "Invalid receipt: expected tool '{}', got '{}'",
                RECEIPT_TOOL,
                parts[0]
            );
        }

        // Field 1: version.
        if parts[1] != RECEIPT_VERSION {
            anyhow::bail!(
                "Unsupported receipt version '{}', expected '{}'",
                parts[1],
                RECEIPT_VERSION
            );
        }

        // Field 2: seed format.
        let seed_format = match parts[2] {
            "bip39" => SeedFormat::Bip39,
            "electrum" => SeedFormat::Electrum,
            other => anyhow::bail!("Unknown seed format in receipt: '{}'", other),
        };

        // Field 3: passphrase role.
        let pass_role = match parts[3] {
            "withpass" => PassRole::WithPass,
            "nopass" => PassRole::NoPass,
            other => anyhow::bail!("Unknown pass role in receipt: '{}'", other),
        };

        // Field 4: derivation algorithm.
        let algorithm = match parts[4] {
            "xor" => KeyAlgorithm::Xor,
            "concat" => KeyAlgorithm::Concat,
            "hkdf" => KeyAlgorithm::Hkdf,
            other => anyhow::bail!("Unknown algorithm in receipt: '{}'", other),
        };

        // Last field: checksum (4 hex characters).
        let checksum = parts[parts.len() - 1];
        if checksum.len() != 4 || !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "Invalid checksum: expected 4 hex characters, got '{}'",
                checksum
            );
        }

        // Validate checksum against all preceding fields.
        let before_checksum = parts[..parts.len() - 1].join(":");
        let expected = Self::compute_checksum(&before_checksum);
        if expected != checksum.to_uppercase() {
            anyhow::bail!(
                "Checksum mismatch: computed {}, receipt has {}",
                expected,
                checksum.to_uppercase()
            );
        }

        // Second-to-last field: user ID.
        let user_id = parts[parts.len() - 2].to_string();
        if user_id.is_empty() {
            anyhow::bail!("Invalid receipt: the user ID is empty");
        }

        // Fields 5..n-2: optional key=value pairs.
        let mut rfc9106 = false;
        let mut auth_subkey = false;
        let mut sign_auth = false;
        let mut just_signkey = false;
        let mut format = OutputFormat::Pgp;
        let mut created = DEFAULT_CREATION_TIMESTAMP;
        let mut expires = None;

        for &field in &parts[5..parts.len() - 2] {
            let Some((key, value)) = field.split_once('=') else {
                anyhow::bail!("Invalid receipt field (expected key=value): '{}'", field);
            };
            match key {
                "argon" => match value {
                    "rfc9106" => rfc9106 = true,
                    other => anyhow::bail!("Unknown argon value in receipt: '{}'", other),
                },
                "auth" => auth_subkey = parse_flag(key, value)?,
                "signauth" => sign_auth = parse_flag(key, value)?,
                "nosubkey" => just_signkey = parse_flag(key, value)?,
                "format" => match value {
                    "ssh" => format = OutputFormat::Ssh,
                    "age" => format = OutputFormat::Age,
                    other => anyhow::bail!("Unknown format value in receipt: '{}'", other),
                },
                "created" => {
                    created = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Invalid created value: '{}'", value))?
                }
                "expires" => {
                    expires = Some(
                        value
                            .parse()
                            .map_err(|_| anyhow::anyhow!("Invalid expires value: '{}'", value))?,
                    )
                }
                other => anyhow::bail!("Unknown receipt option: '{}'", other),
            }
        }

        if format == OutputFormat::Pgp {
            crate::pgp::validate_timestamps(created, expires)?;
        }
        if format == OutputFormat::Age {
            // The age key exists only under hkdf, and an age identity has no
            // subkeys, capabilities or timestamps for a receipt to record.
            if algorithm != KeyAlgorithm::Hkdf {
                anyhow::bail!("Invalid receipt: format=age requires the hkdf algorithm");
            }
            if auth_subkey
                || sign_auth
                || just_signkey
                || created != DEFAULT_CREATION_TIMESTAMP
                || expires.is_some()
            {
                anyhow::bail!(
                    "Invalid receipt: format=age cannot be combined with subkey or timestamp options"
                );
            }
        }

        if auth_subkey && algorithm != KeyAlgorithm::Hkdf {
            anyhow::bail!("Invalid receipt: auth=1 requires the hkdf algorithm");
        }

        let receipt = Receipt {
            seed_format,
            pass_role,
            algorithm,
            rfc9106,
            auth_subkey,
            sign_auth,
            just_signkey,
            format,
            created,
            expires,
            user_id,
        };

        // A receipt is only ever written by `encode`, so the input must be
        // exactly what `encode` would write for these values (the checksum
        // may be in either case). This rejects duplicated, reordered or
        // redundant fields, where the reader could not tell which value was
        // meant, instead of silently picking one.
        let canonical = format!("{}:{}", before_checksum, checksum.to_uppercase());
        if receipt.encode() != canonical {
            anyhow::bail!(
                "Invalid receipt: fields are duplicated, out of order, or restate a default"
            );
        }
        Ok(receipt)
    }

    /// Human-readable description of the Argon2id parameter set in use.
    pub fn argon_display(&self) -> &'static str {
        if self.rfc9106 {
            RFC9106_DISPLAY
        } else {
            "Legacy parameters (64 MiB memory, 32 iterations, 8 lanes)"
        }
    }

    /// Human-readable description of the derivation algorithm.
    pub fn algorithm_display(&self) -> &'static str {
        match self.algorithm {
            KeyAlgorithm::Xor => "XOR of separate Argon2id hashes (deprecated)",
            KeyAlgorithm::Concat => "Argon2id of seed+passphrase, split output (deprecated)",
            KeyAlgorithm::Hkdf => "Argon2id + HKDF-Expand-SHA256 with domain separation",
        }
    }

    /// Reconstruct the exact command line that regenerates this key without
    /// the receipt file. The mnemonic is read from stdin or the interactive
    /// prompt; only public parameters appear here. `--from-receipt` is the
    /// preferred path, since it also verifies the fingerprint.
    pub fn recovery_command(&self) -> String {
        let mut cmd = format!("bip39key -g {}", algorithm_str(&self.algorithm));
        cmd.push_str(&format!(" -u {}", shell_quote(&self.user_id)));
        if self.seed_format == SeedFormat::Electrum {
            cmd.push_str(" -s electrum");
        }
        if self.rfc9106 {
            cmd.push_str(" -r");
        }
        if self.pass_role == PassRole::NoPass && self.format != OutputFormat::Age {
            // Without -n, a passphrase typed at the prompt would be mixed
            // into the derivation and produce a different key. age output
            // rejects -n (an age identity cannot be encrypted, so the
            // passphrase would do nothing); there the prompt must be left
            // empty, which the receipt page says.
            cmd.push_str(" -n");
        }
        if self.auth_subkey {
            cmd.push_str(" --auth-subkey");
        }
        if self.sign_auth {
            cmd.push_str(" -b");
        }
        if self.just_signkey {
            cmd.push_str(" -j");
        }
        if self.created != DEFAULT_CREATION_TIMESTAMP {
            cmd.push_str(&format!(" -d {}", self.created));
        }
        if let Some(expires) = self.expires {
            cmd.push_str(&format!(" -y {}", expires));
        }
        match self.format {
            OutputFormat::Pgp => cmd.push_str(" -o key.gpg"),
            OutputFormat::Ssh => cmd.push_str(" -f ssh -o key.ssh"),
            OutputFormat::Age => cmd.push_str(" -f age -o identity.txt"),
        }
        cmd
    }

    pub fn display(&self) -> String {
        let mut lines = vec![];

        lines.push(format!("Version:      {}", RECEIPT_VERSION));
        lines.push(format!("Seed format:  {}", self.seed_format));
        lines.push(format!(
            "Passphrase:   {}",
            match self.pass_role {
                PassRole::WithPass => "used in key derivation",
                PassRole::NoPass => "not used",
            }
        ));
        lines.push(format!("Argon2id:     {}", self.argon_display()));
        lines.push(format!("Algorithm:    {}", self.algorithm_display()));
        lines.push(format!(
            "Format:       {}",
            match self.format {
                OutputFormat::Pgp => "PGP",
                OutputFormat::Ssh => "SSH",
                OutputFormat::Age => "age",
            }
        ));
        if self.auth_subkey {
            lines.push("Auth subkey:  yes".to_string());
        }
        if self.sign_auth {
            lines.push("Sign key:     has authentication capability".to_string());
        }
        if self.just_signkey {
            lines.push("Encrypt key:  not generated (--just-signkey)".to_string());
        }

        let created_str = if self.created == DEFAULT_CREATION_TIMESTAMP {
            "2009-01-03T18:15:05Z (Bitcoin genesis)".to_string()
        } else {
            format!("{}", self.created)
        };
        lines.push(format!("Created:      {}", created_str));

        let expires_str = match self.expires {
            None => "never".to_string(),
            Some(expires) => format!("{}", expires),
        };
        lines.push(format!("Expires:      {}", expires_str));
        lines.push(format!("User ID:      {}", self.user_id));

        let receipt_str = self.encode();
        let checksum = receipt_str.split(':').next_back().unwrap_or("????");
        lines.push(format!("Checksum:     {} (valid)", checksum));

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_receipt() -> Receipt {
        Receipt {
            seed_format: SeedFormat::Bip39,
            pass_role: PassRole::WithPass,
            algorithm: KeyAlgorithm::Hkdf,
            rfc9106: false,
            auth_subkey: false,
            sign_auth: false,
            just_signkey: false,
            format: OutputFormat::Pgp,
            created: DEFAULT_CREATION_TIMESTAMP,
            expires: None,
            user_id: "Satoshi Nakamoto <satoshin@gmx.com>".to_string(),
        }
    }

    #[test]
    fn test_encode_golden() {
        // Golden value: the exact receipt string (including checksum) for a
        // default receipt. Any change to the format, field order, or checksum
        // input breaks recovery of receipts already in the wild, so this
        // must only ever change together with RECEIPT_VERSION.
        assert_eq!(
            basic_receipt().encode(),
            "bip39key:1:bip39:withpass:hkdf:Satoshi Nakamoto <satoshin@gmx.com>:C957"
        );
    }

    #[test]
    fn test_encode_defaults_omitted() {
        let encoded = basic_receipt().encode();
        assert!(!encoded.contains("argon="));
        assert!(!encoded.contains("auth="));
        assert!(!encoded.contains("signauth="));
        assert!(!encoded.contains("nosubkey="));
        assert!(!encoded.contains("format="));
        assert!(!encoded.contains("created="));
        assert!(!encoded.contains("expires="));
    }

    #[test]
    fn test_roundtrip() {
        let original = basic_receipt();
        let parsed = Receipt::parse(&original.encode()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_roundtrip_with_options() {
        let original = Receipt {
            seed_format: SeedFormat::Electrum,
            pass_role: PassRole::NoPass,
            algorithm: KeyAlgorithm::Hkdf,
            rfc9106: true,
            auth_subkey: true,
            sign_auth: true,
            just_signkey: false,
            format: OutputFormat::Pgp,
            created: 1744948062,
            expires: Some(1745554397),
            user_id: "Alice Smith <alice@company.com>".to_string(),
        };
        let encoded = original.encode();
        assert!(encoded.contains("argon=rfc9106"));
        assert!(encoded.contains("auth=1"));
        assert!(encoded.contains("signauth=1"));
        assert!(encoded.contains("created=1744948062"));
        assert!(encoded.contains("expires=1745554397"));
        assert_eq!(Receipt::parse(&encoded).unwrap(), original);
    }

    #[test]
    fn test_roundtrip_age() {
        let original = Receipt {
            format: OutputFormat::Age,
            rfc9106: true,
            ..basic_receipt()
        };
        let encoded = original.encode();
        assert!(encoded.contains(":argon=rfc9106:format=age:"), "{encoded}");
        assert_eq!(Receipt::parse(&encoded).unwrap(), original);
        assert!(original
            .recovery_command()
            .contains("-f age -o identity.txt"));
        // -n is rejected with age output, so the manual command never has it.
        let nopass = Receipt {
            pass_role: PassRole::NoPass,
            ..original
        };
        assert!(!nopass.recovery_command().contains(" -n"));
    }

    #[test]
    fn test_age_receipt_rejects_what_age_keys_cannot_have() {
        for bad in [
            Receipt {
                algorithm: KeyAlgorithm::Xor,
                ..basic_receipt()
            },
            Receipt {
                auth_subkey: true,
                ..basic_receipt()
            },
            Receipt {
                just_signkey: true,
                ..basic_receipt()
            },
            Receipt {
                created: 1_600_000_000,
                ..basic_receipt()
            },
            Receipt {
                expires: Some(1_900_000_000),
                ..basic_receipt()
            },
        ] {
            let encoded = Receipt {
                format: OutputFormat::Age,
                ..bad
            }
            .encode();
            assert!(Receipt::parse(&encoded).is_err(), "{encoded}");
        }
    }

    #[test]
    fn test_roundtrip_ssh() {
        let original = Receipt {
            algorithm: KeyAlgorithm::Concat,
            format: OutputFormat::Ssh,
            user_id: "Test <t@t.com>".to_string(),
            ..basic_receipt()
        };
        let encoded = original.encode();
        assert!(encoded.contains("format=ssh"));
        assert_eq!(Receipt::parse(&encoded).unwrap(), original);
    }

    #[test]
    fn test_parse_bad_checksum() {
        let result = Receipt::parse("bip39key:1:bip39:withpass:hkdf:Test <t@t.com>:0000");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Checksum mismatch"));
    }

    #[test]
    fn test_parse_bad_tool() {
        let result = Receipt::parse("wrongtool:1:bip39:withpass:hkdf:Test <t@t.com>:ABCD");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_short() {
        let result = Receipt::parse("bip39key:1:bip39");
        assert!(result.is_err());
    }

    fn with_checksum(before: &str) -> String {
        format!("{before}:{}", Receipt::compute_checksum(before))
    }

    #[test]
    fn test_parse_rejects_auth_without_hkdf() {
        let err = Receipt::parse(&with_checksum(
            "bip39key:1:bip39:nopass:xor:auth=1:Alice <a@b.com>",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("hkdf"), "got: {err}");
    }

    #[test]
    fn test_parse_rejects_bad_flag_values() {
        // Flags are only ever written as `=1`; anything else is a
        // transcription error and must not be silently read as "off".
        for field in ["auth=0", "auth=yes", "signauth=true", "nosubkey="] {
            let err = Receipt::parse(&with_checksum(&format!(
                "bip39key:1:bip39:nopass:hkdf:{field}:Alice <a@b.com>"
            )))
            .unwrap_err()
            .to_string();
            assert!(err.contains("expected '1'"), "{field}: {err}");
        }
    }

    #[test]
    fn test_parse_rejects_out_of_range_created() {
        // A checksum-valid receipt with an out-of-range timestamp must be
        // rejected at parse time, not panic later in pgp.rs.
        let err = Receipt::parse(&with_checksum(
            "bip39key:1:bip39:nopass:hkdf:created=99999999999:Alice <a@b.com>",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("out of range"), "got: {err}");
    }

    #[test]
    fn test_validate_user_id() {
        assert!(validate_user_id("Alice <a@b.com>").is_ok());
        assert!(validate_user_id("").is_err());
        assert!(validate_user_id("Alice (dept: sales) <a@b.com>").is_err());
        assert!(validate_user_id("Alice\n<a@b.com>").is_err());
    }

    #[test]
    fn test_recovery_command() {
        let r = Receipt {
            seed_format: SeedFormat::Electrum,
            rfc9106: true,
            auth_subkey: true,
            expires: Some(2000000000),
            user_id: "Alice <a@b.com>".to_string(),
            ..basic_receipt()
        };
        assert_eq!(
            r.recovery_command(),
            "bip39key -g hkdf -u 'Alice <a@b.com>' -s electrum -r --auth-subkey -y 2000000000 -o key.gpg"
        );
    }
    #[test]
    fn test_recovery_command_quotes_for_the_shell() {
        // Double quotes would let the shell expand $(...) and backticks, and
        // an embedded " would change the user ID (the Argon2id salt).
        let r = Receipt {
            user_id: r#"Bob "Bobby" $(id) `id` O'Neil <bob@x.com>"#.to_string(),
            ..basic_receipt()
        };
        assert_eq!(
            r.recovery_command(),
            r#"bip39key -g hkdf -u 'Bob "Bobby" $(id) `id` O'\''Neil <bob@x.com>' -o key.gpg"#
        );
    }

    #[test]
    fn test_recovery_command_nopass_skips_passphrase() {
        // A nopass key ignores the passphrase in derivation. Without -n the
        // printed command would mix in whatever is typed at the prompt.
        let r = Receipt {
            pass_role: PassRole::NoPass,
            ..basic_receipt()
        };
        assert!(r.recovery_command().contains(" -n "));
        assert!(!basic_receipt().recovery_command().contains(" -n "));
    }

    #[test]
    fn test_argon_display_matches_the_parameters_used() {
        // keys.rs derives -r keys with argon2::Config::rfc9106(). The receipt
        // text must describe that config, not RFC 9106's own recommendation.
        let config = argon2::Config::rfc9106();
        let r = Receipt {
            rfc9106: true,
            ..basic_receipt()
        };
        let text = r.argon_display();
        assert_eq!(config.lanes, 1);
        assert!(text.contains("1 lane,"), "got: {text}");
        assert_eq!(config.mem_cost, 2 * 1024 * 1024);
        assert!(text.contains("2 GiB memory"), "got: {text}");
        assert_eq!(config.time_cost, 1);
        assert!(text.contains("1 iteration"), "got: {text}");
        assert!(basic_receipt().argon_display().contains("8 lanes"));
    }

    #[test]
    fn test_parse_rejects_non_canonical_receipts() {
        for (before, why) in [
            (
                "bip39key:1:bip39:nopass:hkdf:created=1:created=2:Alice <a@b.com>",
                "duplicate field",
            ),
            (
                "bip39key:1:bip39:nopass:hkdf:format=ssh:argon=rfc9106:Alice <a@b.com>",
                "fields out of order",
            ),
            (
                "bip39key:1:bip39:nopass:hkdf:created=+5:Alice <a@b.com>",
                "non-canonical number",
            ),
            (
                "bip39key:1:bip39:nopass:hkdf:created=1231006505:Alice <a@b.com>",
                "restated default",
            ),
        ] {
            let err = Receipt::parse(&with_checksum(before))
                .unwrap_err()
                .to_string();
            assert!(err.contains("duplicated, out of order"), "{why}: {err}");
        }
    }

    #[test]
    fn test_parse_rejects_empty_user_id() {
        let err = Receipt::parse(&with_checksum("bip39key:1:bip39:nopass:hkdf:"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("user ID is empty"), "got: {err}");
    }

    #[test]
    fn test_parse_accepts_lowercase_checksum() {
        let encoded = basic_receipt().encode();
        let (before, checksum) = encoded.rsplit_once(':').unwrap();
        let lower = format!("{before}:{}", checksum.to_lowercase());
        assert_eq!(Receipt::parse(&lower).unwrap(), basic_receipt());
    }
}
