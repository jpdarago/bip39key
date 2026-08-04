use clap::Parser;
use std::fmt;

#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
pub enum OutputFormat {
    Pgp,
    Ssh,
}

#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
pub enum SeedFormat {
    Bip39,
    Electrum,
}

impl fmt::Display for SeedFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SeedFormat::Bip39 => write!(f, "BIP39"),
            SeedFormat::Electrum => write!(f, "Electrum"),
        }
    }
}

/// Key derivation algorithm for combining seed and passphrase.
#[derive(PartialEq, Eq, Clone, clap::ValueEnum, Debug)]
pub enum KeyAlgorithm {
    /// DEPRECATED: XOR of separate Argon2id hashes of seed and passphrase.
    Xor,
    /// DEPRECATED: Argon2id of concatenated seed and passphrase, split into sign/encrypt keys.
    Concat,
    /// Argon2id of concatenated seed and passphrase, then HKDF-Expand with domain separation
    /// for sign and encrypt keys.
    Hkdf,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// RFC 2822 of the user, e.g. "User <user@email.com>".
    /// Required unless --from-receipt is set.
    #[clap(short, long)]
    pub user_id: Option<String>,

    /// Filename from which to read the mnemonic words.
    #[clap(short, long)]
    pub input_filename: Option<String>,

    /// Filename where to output the keys, if not present then write to stdout.
    #[clap(short, long)]
    pub output_filename: Option<String>,

    /// Timestamp (as unix timestamp in seconds) for the dates. If unset, use the default 1231006505.
    #[clap(short, long, hide = true)]
    pub timestamp: Option<i64>,

    /// Creation timestamp (as unix timestamp in seconds). If unset, uses the genesis block (1231006505).
    #[clap(short = 'd', long)]
    pub creation_timestamp: Option<i64>,

    /// Expiration timestamp (as unix timestamp in seconds). If unset, the keys do not expire.
    #[clap(short = 'y', long)]
    pub expiration_timestamp: Option<i64>,

    /// Only output the sign key for PGP.
    #[clap(short, long)]
    pub just_signkey: bool,

    /// Output format: SSH or PGP.
    #[clap(short, long, default_value = "pgp")]
    pub format: OutputFormat,

    /// Output as armored.
    #[clap(short, long)]
    pub armor: bool,

    /// Output the public key.
    #[clap(short = 'k', long)]
    pub public_key: bool,

    /// Optional passphrase. If set, -e/--pinentry must not be set.
    /// See README.md for details.
    #[clap(short, long)]
    pub passphrase: Option<String>,

    /// Request passphrase with pinentry.
    /// See README.md for details.
    #[clap(short = 'e', long)]
    pub pinentry: bool,

    /// Seed Format: BIP39, Electrum
    #[clap(short, long, default_value = "bip39")]
    pub seed_format: SeedFormat,

    /// DEPRECATED: Use concatenation method. Equivalent to --algorithm concat.
    #[clap(short = 'c', long, hide = true)]
    pub use_concatenation: bool,

    /// Key derivation algorithm: xor (legacy default), concat, hkdf (recommended for new keys).
    /// Use --algorithm hkdf for new keys. Defaults to xor for backward compatibility.
    #[clap(short = 'g', long, default_value = "xor")]
    pub algorithm: KeyAlgorithm,

    /// DEPRECATED! Request seed phrase through an interactive CLI prompt.
    #[clap(short = 'q', long)]
    pub interactive: Option<bool>,

    /// Use RFC 9106 settings for Argon2id.
    #[clap(short = 'r', long)]
    pub use_rfc9106_settings: bool,

    /// Add authorization capability to the sign key.
    #[clap(short = 'b', long)]
    pub authorization_for_sign_key: bool,

    /// Generate a separate authentication subkey (requires --algorithm hkdf).
    #[clap(long)]
    pub auth_subkey: bool,

    /// Do not add the passphrase as extra entropy. If set, the passphrase will only be used to
    /// encrypt the PGP or SSH key contents, and the key material itself will be generated from
    /// the seed and the user id.
    #[clap(short = 'n', long)]
    pub skip_passphrase_for_key_material: bool,

    /// Write an HTML recovery receipt to this file. The receipt records the
    /// derivation parameters, key fingerprints, and build provenance — but no
    /// secrets — so the key can be regenerated from the mnemonic later.
    #[clap(long, value_name = "FILE")]
    pub output_receipt: Option<String>,

    /// Regenerate a key from a receipt file (HTML receipt or raw receipt
    /// string). The receipt supplies the user ID and all derivation
    /// parameters; only the mnemonic (and passphrase, if used) is prompted.
    /// The regenerated key's fingerprint is checked against the receipt.
    #[clap(long, value_name = "FILE")]
    pub from_receipt: Option<String>,
}
