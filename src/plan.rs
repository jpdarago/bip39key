//! Decides what an invocation will do, before it does any of it.
//!
//! [`plan`] turns the parsed flags and the two facts about the terminal into a
//! [`Plan`]: where the seed and the passphrase come from, what the passphrase
//! is used for, what gets derived, and where the key is written. It performs
//! no I/O and no key derivation, so the tests below can check every flag
//! combination in milliseconds. `main.rs` only carries the plan out.
//!
//! Decisions about flags belong here, not in `main.rs`. A check made halfway
//! through execution cannot be tested without a terminal and a real Argon2id
//! run, which is how `-n` came to write unencrypted key files and `-i` came to
//! be ignored on a terminal.

use crate::cli::{Args, KeyAlgorithm, OutputFormat, SeedFormat};
use crate::keys::{KeySettings, DEFAULT_CREATION_TIMESTAMP};
use crate::pgp;

use std::fmt;

/// What the process can see of its surroundings. Passed in, never detected
/// here, so tests can set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Env {
    pub stdin_is_terminal: bool,
    pub stdout_is_terminal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedSource {
    /// `-i FILE`.
    File(String),
    /// The interactive word-by-word prompt.
    Prompt,
    /// Standard input, read to the end.
    Stdin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PassphraseSource {
    /// `-e`.
    Pinentry,
    /// `-p VALUE`.
    Flag(String),
    /// Asked on the terminal. An empty answer means no passphrase.
    Prompt,
    /// Not a terminal and nothing was given: there is no passphrase.
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputTarget {
    /// `-o FILE`.
    File(String),
    /// Ask on the terminal; see [`OutputTarget::from_answer`].
    Ask,
    Stdout,
}

impl OutputTarget {
    /// Where an `-o` value or an answer to the filename prompt points. Empty
    /// means standard output.
    pub fn from_answer(answer: &str) -> OutputTarget {
        if answer.is_empty() {
            OutputTarget::Stdout
        } else {
            OutputTarget::File(answer.to_string())
        }
    }
}

/// Things worth telling the user that do not stop the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    DeprecatedInteractiveFlag,
    DeprecatedXor,
    DeprecatedConcat,
    /// age identities cannot be passphrase protected.
    AgeSecretIsPlaintext,
    /// A passphrase was given with `-p` or `-e`, but it neither feeds
    /// derivation (`-n`) nor encrypts anything (public key output).
    PassphraseUnused,
}

impl Warning {
    pub fn message(&self) -> &'static str {
        match self {
            Warning::DeprecatedInteractiveFlag => {
                "WARNING: -q/--interactive flag is deprecated. You probably want an earlier BIP39 version."
            }
            Warning::DeprecatedXor => {
                "WARNING: xor algorithm is deprecated. Use --algorithm hkdf for new keys."
            }
            Warning::DeprecatedConcat => {
                "WARNING: concat algorithm is deprecated. Use --algorithm hkdf for new keys."
            }
            Warning::AgeSecretIsPlaintext => {
                "WARNING: age identities cannot be passphrase protected. The secret key is written in plaintext."
            }
            Warning::PassphraseUnused => {
                "WARNING: the passphrase is not used: -n keeps it out of key derivation, and a public key is not encrypted."
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub seed_source: SeedSource,
    pub seed_format: SeedFormat,

    pub passphrase_source: PassphraseSource,
    /// Whether a passphrase, if there is one, is mixed into the key material.
    pub passphrase_in_derivation: bool,
    /// Whether a passphrase, if there is one, encrypts the written key.
    pub passphrase_encrypts_output: bool,

    /// The algorithm after resolving the deprecated `-c`.
    pub algorithm: KeyAlgorithm,
    pub user_id: String,
    pub creation_timestamp_secs: i64,
    pub expiration_timestamp_secs: Option<i64>,
    pub generate_encrypt_key: bool,
    pub generate_auth_key: bool,
    pub generate_age_key: bool,
    pub use_rfc9106_settings: bool,
    pub use_authorization_for_sign_key: bool,

    pub format: OutputFormat,
    pub public_key: bool,
    pub output: OutputTarget,
    /// Armor PGP output when it goes to a file.
    pub text_to_file: bool,
    /// Armor PGP output when it goes to standard output.
    pub text_to_stdout: bool,

    pub warnings: Vec<Warning>,
}

impl Plan {
    /// Derivation settings for this plan. `passphrase` is whatever the
    /// passphrase source produced; it is dropped here when `-n` keeps it out
    /// of the key material.
    pub fn key_settings(&self, seed: Vec<u8>, passphrase: Option<&str>) -> KeySettings {
        KeySettings {
            user_id: self.user_id.clone(),
            seed,
            passphrase: passphrase
                .filter(|_| self.passphrase_in_derivation)
                .map(str::to_string),
            creation_timestamp_secs: self.creation_timestamp_secs,
            expiration_timestamp_secs: self.expiration_timestamp_secs,
            generate_encrypt_key: self.generate_encrypt_key,
            generate_auth_key: self.generate_auth_key,
            generate_age_key: self.generate_age_key,
            use_rfc9106_settings: self.use_rfc9106_settings,
            use_authorization_for_sign_key: self.use_authorization_for_sign_key,
        }
    }

    /// The passphrase the encoders encrypt the key file with, if any.
    pub fn output_passphrase(&self, passphrase: Option<&str>) -> Option<String> {
        passphrase
            .filter(|_| self.passphrase_encrypts_output)
            .map(str::to_string)
    }
}

fn creation_timestamp_secs(args: &Args) -> i64 {
    args.creation_timestamp
        .or(args.timestamp)
        .unwrap_or(DEFAULT_CREATION_TIMESTAMP)
}

/// Why an invocation was rejected. A plain message, not an `anyhow::Error`:
/// anyhow captures a backtrace per error when `RUST_BACKTRACE` is set, and the
/// tests below reject hundreds of thousands of invocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanError(pub String);

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlanError {}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(PlanError(format!($($arg)*)))
    };
}

/// Reject flag combinations that cannot work. Depends on the flags alone,
/// never on the terminal: a command line must not be valid in a shell and
/// invalid in a script.
fn validate(args: &Args) -> std::result::Result<(), PlanError> {
    if args.creation_timestamp.is_some() && args.timestamp.is_some() {
        bail!("--timestamp (-t) flag is deprecated, use --creation-timestamp");
    }
    let creation_timestamp_secs = creation_timestamp_secs(args);
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
        pgp::validate_timestamps(creation_timestamp_secs, args.expiration_timestamp)
            .map_err(|err| PlanError(err.to_string()))?;
    }
    if args.just_signkey && args.format == OutputFormat::Ssh {
        bail!("Subkey option (--just-signkey/-j) only works with PGP output format.");
    }
    if args.armor && args.format != OutputFormat::Pgp {
        bail!("Armor option (--armor/-a) only works with PGP output format.");
    }
    if args.format == OutputFormat::Age {
        // The age key has its own HKDF info string, so it is independent of
        // the PGP encryption subkey. xor and concat only produce the 64 bytes
        // the sign and encrypt keys already use, so they cannot derive it.
        if args.algorithm != KeyAlgorithm::Hkdf || args.use_concatenation {
            bail!("age output requires --algorithm hkdf (-g hkdf).");
        }
        // age keys are a single X25519 key: there is no signing key to
        // restrict to, and no subkeys or capabilities to add.
        if args.just_signkey {
            bail!("Subkey option (--just-signkey/-j) only works with PGP output format.");
        }
        if args.auth_subkey {
            bail!("--auth-subkey only works with PGP output format.");
        }
        if args.authorization_for_sign_key {
            bail!("--authorization-for-sign-key (-b) only works with PGP output format.");
        }
        // age identity files cannot be passphrase protected, so with -n the
        // passphrase would do nothing at all.
        if args.skip_passphrase_for_key_material {
            bail!(
                "--skip-passphrase-for-key-material (-n) does not work with age output: \
                 age keys cannot be passphrase protected, so the passphrase would be unused."
            );
        }
        if args.expiration_timestamp.is_some() {
            bail!("--expiration-timestamp (-y) does not work with age output: age keys do not expire.");
        }
        if args.creation_timestamp.is_some() || args.timestamp.is_some() {
            bail!(
                "--creation-timestamp (-d) does not work with age output: age keys carry no timestamp."
            );
        }
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
    // The seed file is read before the key is written, so the run would
    // succeed and leave the seed phrase replaced by the key. Different
    // spellings of one path are caught when the file is opened.
    if let (Some(input), Some(output)) = (&args.input_filename, &args.output_filename) {
        if input == output {
            bail!(
                "--output-filename is the seed file ({}): the key would overwrite the seed phrase.",
                input
            );
        }
    }
    Ok(())
}

/// Work out what this invocation does, or why it cannot run.
pub fn plan(args: &Args, env: Env) -> std::result::Result<Plan, PlanError> {
    validate(args)?;

    let seed_source = match &args.input_filename {
        // An explicit -i wins over the prompt: the terminal only decides what
        // to do when no file was named.
        Some(filename) => SeedSource::File(filename.clone()),
        None if env.stdin_is_terminal => SeedSource::Prompt,
        None => SeedSource::Stdin,
    };

    let passphrase_source = if args.pinentry {
        PassphraseSource::Pinentry
    } else if let Some(passphrase) = &args.passphrase {
        PassphraseSource::Flag(passphrase.clone())
    } else if env.stdin_is_terminal {
        PassphraseSource::Prompt
    } else {
        PassphraseSource::None
    };
    // -n keeps the passphrase out of derivation only. It still protects the
    // key file, which is the one thing left for it to do.
    let passphrase_in_derivation = !args.skip_passphrase_for_key_material;
    // Public keys are not encrypted, and age identities cannot be.
    let passphrase_encrypts_output = !args.public_key && args.format != OutputFormat::Age;

    let algorithm = if args.use_concatenation {
        KeyAlgorithm::Concat
    } else {
        args.algorithm.clone()
    };

    let output = match &args.output_filename {
        Some(filename) => OutputTarget::from_answer(filename),
        None if env.stdin_is_terminal => OutputTarget::Ask,
        None => OutputTarget::Stdout,
    };

    let mut warnings = Vec::new();
    if args.interactive.is_some() {
        warnings.push(Warning::DeprecatedInteractiveFlag);
    }
    match algorithm {
        KeyAlgorithm::Xor => warnings.push(Warning::DeprecatedXor),
        KeyAlgorithm::Concat => warnings.push(Warning::DeprecatedConcat),
        KeyAlgorithm::Hkdf => {}
    }
    if args.format == OutputFormat::Age && !args.public_key {
        warnings.push(Warning::AgeSecretIsPlaintext);
    }
    let passphrase_was_given = matches!(
        passphrase_source,
        PassphraseSource::Pinentry | PassphraseSource::Flag(_)
    );
    if passphrase_was_given && !passphrase_in_derivation && !passphrase_encrypts_output {
        warnings.push(Warning::PassphraseUnused);
    }

    Ok(Plan {
        seed_source,
        seed_format: args.seed_format.clone(),
        passphrase_source,
        passphrase_in_derivation,
        passphrase_encrypts_output,
        algorithm,
        user_id: args.user_id.clone(),
        creation_timestamp_secs: creation_timestamp_secs(args),
        expiration_timestamp_secs: args.expiration_timestamp,
        generate_encrypt_key: !args.just_signkey,
        generate_auth_key: args.auth_subkey,
        generate_age_key: args.format == OutputFormat::Age,
        use_rfc9106_settings: args.use_rfc9106_settings,
        use_authorization_for_sign_key: args.authorization_for_sign_key,
        format: args.format.clone(),
        public_key: args.public_key,
        output,
        text_to_file: args.armor,
        text_to_stdout: args.armor || env.stdout_is_terminal,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const FORMATS: [OutputFormat; 3] = [OutputFormat::Pgp, OutputFormat::Ssh, OutputFormat::Age];
    const ALGORITHMS: [KeyAlgorithm; 3] =
        [KeyAlgorithm::Xor, KeyAlgorithm::Concat, KeyAlgorithm::Hkdf];

    fn base_args() -> Args {
        Args {
            user_id: "Alice <alice@example.com>".to_string(),
            input_filename: None,
            output_filename: None,
            timestamp: None,
            creation_timestamp: None,
            expiration_timestamp: None,
            just_signkey: false,
            format: OutputFormat::Pgp,
            armor: false,
            public_key: false,
            passphrase: None,
            pinentry: false,
            seed_format: SeedFormat::Bip39,
            use_concatenation: false,
            algorithm: KeyAlgorithm::Xor,
            interactive: None,
            use_rfc9106_settings: false,
            authorization_for_sign_key: false,
            auth_subkey: false,
            skip_passphrase_for_key_material: false,
        }
    }

    /// Bits of `n` in order, one per call.
    struct Bits(u32);

    impl Bits {
        fn next(&mut self) -> bool {
            let bit = self.0 & 1 == 1;
            self.0 >>= 1;
            bit
        }
    }

    const FLAG_BITS: u32 = 16;

    /// Every combination of the flags that decide anything, with fixed
    /// stand-ins for the values that are only carried through. Calls `check`
    /// 3 * 3 * 2^16 times.
    fn for_each_invocation(mut check: impl FnMut(&Args, Env)) {
        for format in &FORMATS {
            for algorithm in &ALGORITHMS {
                for n in 0..(1u32 << FLAG_BITS) {
                    let mut bits = Bits(n);
                    let mut args = base_args();
                    args.format = format.clone();
                    args.algorithm = algorithm.clone();
                    args.use_concatenation = bits.next();
                    args.just_signkey = bits.next();
                    args.auth_subkey = bits.next();
                    args.authorization_for_sign_key = bits.next();
                    args.armor = bits.next();
                    args.public_key = bits.next();
                    args.skip_passphrase_for_key_material = bits.next();
                    args.pinentry = bits.next();
                    args.passphrase = bits.next().then(|| "hunter2".to_string());
                    args.input_filename = bits.next().then(|| "seed.txt".to_string());
                    args.output_filename = bits.next().then(|| "key.out".to_string());
                    args.creation_timestamp = bits.next().then_some(1_600_000_000);
                    args.expiration_timestamp = bits.next().then_some(1_700_000_000);
                    args.interactive = bits.next().then_some(true);
                    let env = Env {
                        stdin_is_terminal: bits.next(),
                        stdout_is_terminal: bits.next(),
                    };
                    check(&args, env);
                }
            }
        }
    }

    /// Like [`for_each_invocation`], but only the ones that are accepted.
    fn for_each_plan(mut check: impl FnMut(&Args, Env, &Plan)) {
        let mut accepted = 0u32;
        for_each_invocation(|args, env| {
            if let Ok(plan) = plan(args, env) {
                accepted += 1;
                check(args, env, &plan);
            }
        });
        // Guards against a validation change that rejects everything and
        // makes every property below pass on nothing.
        assert!(accepted > 10_000, "only {accepted} invocations accepted");
    }

    #[test]
    fn input_file_is_always_the_seed_source() {
        for_each_plan(|args, env, plan| {
            let expected = match (&args.input_filename, env.stdin_is_terminal) {
                (Some(file), _) => SeedSource::File(file.clone()),
                (None, true) => SeedSource::Prompt,
                (None, false) => SeedSource::Stdin,
            };
            assert_eq!(plan.seed_source, expected, "{args:?} {env:?}");
        });
    }

    #[test]
    fn nothing_prompts_without_a_terminal() {
        for_each_plan(|args, env, plan| {
            if env.stdin_is_terminal {
                return;
            }
            assert_ne!(plan.seed_source, SeedSource::Prompt, "{args:?}");
            assert_ne!(plan.passphrase_source, PassphraseSource::Prompt, "{args:?}");
            assert_ne!(plan.output, OutputTarget::Ask, "{args:?}");
        });
    }

    #[test]
    fn a_given_passphrase_or_output_file_is_never_asked_for() {
        for_each_plan(|args, _env, plan| {
            if args.pinentry {
                assert_eq!(plan.passphrase_source, PassphraseSource::Pinentry);
            }
            if let Some(passphrase) = &args.passphrase {
                assert_eq!(
                    plan.passphrase_source,
                    PassphraseSource::Flag(passphrase.clone())
                );
            }
            if let Some(file) = &args.output_filename {
                assert_eq!(plan.output, OutputTarget::File(file.clone()));
            }
        });
    }

    #[test]
    fn skip_flag_only_affects_derivation() {
        // The 1.9.0 bug: -n also switched off encryption of the key file.
        for_each_plan(|args, _env, plan| {
            assert_eq!(
                plan.passphrase_in_derivation, !args.skip_passphrase_for_key_material,
                "{args:?}"
            );
            let secret_pgp_or_ssh = !args.public_key && args.format != OutputFormat::Age;
            assert_eq!(
                plan.passphrase_encrypts_output, secret_pgp_or_ssh,
                "{args:?}"
            );
        });
    }

    #[test]
    fn a_given_passphrase_is_used_or_reported_unused() {
        for_each_plan(|args, _env, plan| {
            if args.passphrase.is_none() && !args.pinentry {
                return;
            }
            let used = plan.passphrase_in_derivation || plan.passphrase_encrypts_output;
            let warned = plan.warnings.contains(&Warning::PassphraseUnused);
            assert_ne!(used, warned, "{args:?}");
        });
    }

    #[test]
    fn key_settings_and_output_passphrase_follow_the_plan() {
        for_each_plan(|args, _env, plan| {
            let settings = plan.key_settings(vec![7; 16], Some("hunter2"));
            assert_eq!(
                settings.passphrase.is_some(),
                plan.passphrase_in_derivation,
                "{args:?}"
            );
            assert_eq!(
                plan.output_passphrase(Some("hunter2")).is_some(),
                plan.passphrase_encrypts_output,
                "{args:?}"
            );
            assert!(plan.key_settings(vec![7; 16], None).passphrase.is_none());
            assert!(plan.output_passphrase(None).is_none());
        });
    }

    #[test]
    fn age_plans_are_hkdf_only_and_warn_about_plaintext() {
        for_each_plan(|args, _env, plan| {
            assert_eq!(plan.generate_age_key, plan.format == OutputFormat::Age);
            if plan.format != OutputFormat::Age {
                assert!(!plan.warnings.contains(&Warning::AgeSecretIsPlaintext));
                return;
            }
            assert_eq!(plan.algorithm, KeyAlgorithm::Hkdf, "{args:?}");
            assert!(!plan.generate_auth_key && !plan.use_authorization_for_sign_key);
            assert_eq!(
                plan.warnings.contains(&Warning::AgeSecretIsPlaintext),
                !plan.public_key,
                "{args:?}"
            );
        });
    }

    #[test]
    fn algorithm_is_resolved_and_deprecations_are_reported() {
        for_each_plan(|args, _env, plan| {
            if args.use_concatenation {
                assert_eq!(plan.algorithm, KeyAlgorithm::Concat, "{args:?}");
            } else {
                assert_eq!(plan.algorithm, args.algorithm, "{args:?}");
            }
            if plan.generate_auth_key {
                assert_eq!(plan.algorithm, KeyAlgorithm::Hkdf, "{args:?}");
            }
            assert_eq!(
                plan.warnings.contains(&Warning::DeprecatedXor),
                plan.algorithm == KeyAlgorithm::Xor
            );
            assert_eq!(
                plan.warnings.contains(&Warning::DeprecatedConcat),
                plan.algorithm == KeyAlgorithm::Concat
            );
        });
    }

    #[test]
    fn armor_is_pgp_only_and_follows_the_terminal_on_stdout() {
        for_each_plan(|args, env, plan| {
            assert_eq!(plan.text_to_file, args.armor, "{args:?}");
            assert_eq!(
                plan.text_to_stdout,
                args.armor || env.stdout_is_terminal,
                "{args:?} {env:?}"
            );
            if args.armor {
                assert_eq!(plan.format, OutputFormat::Pgp, "{args:?}");
            }
        });
    }

    #[test]
    fn whether_flags_are_accepted_does_not_depend_on_the_terminal() {
        for_each_invocation(|args, env| {
            let piped = Env {
                stdin_is_terminal: false,
                stdout_is_terminal: false,
            };
            assert_eq!(
                plan(args, env).is_ok(),
                plan(args, piped).is_ok(),
                "{args:?} {env:?}"
            );
        });
    }

    #[test]
    fn every_rejection_explains_itself() {
        for_each_invocation(|args, env| {
            if let Err(err) = plan(args, env) {
                assert!(!err.to_string().trim().is_empty(), "{args:?}");
            }
        });
    }

    #[test]
    fn output_onto_the_seed_file_is_rejected() {
        let mut args = base_args();
        args.input_filename = Some("seed.txt".to_string());
        args.output_filename = Some("seed.txt".to_string());
        let env = Env {
            stdin_is_terminal: false,
            stdout_is_terminal: false,
        };
        let err = plan(&args, env).unwrap_err().to_string();
        assert!(err.contains("overwrite the seed phrase"), "{err}");
    }

    #[test]
    fn empty_output_filename_means_stdout() {
        assert_eq!(OutputTarget::from_answer(""), OutputTarget::Stdout);
        assert_eq!(
            OutputTarget::from_answer("k"),
            OutputTarget::File("k".to_string())
        );
    }

    fn any_format() -> impl Strategy<Value = OutputFormat> {
        prop::sample::select(FORMATS.to_vec())
    }

    fn any_algorithm() -> impl Strategy<Value = KeyAlgorithm> {
        prop::sample::select(ALGORITHMS.to_vec())
    }

    prop_compose! {
        /// Arbitrary values in every field, including the ones the exhaustive
        /// tests hold fixed: free text, paths and the full i64 range.
        fn any_args()(
            user_id in ".*",
            input_filename in prop::option::of(".*"),
            output_filename in prop::option::of(".*"),
            timestamp in prop::option::of(any::<i64>()),
            creation_timestamp in prop::option::of(any::<i64>()),
            expiration_timestamp in prop::option::of(any::<i64>()),
            format in any_format(),
            algorithm in any_algorithm(),
            passphrase in prop::option::of(".*"),
            flags in any::<u16>(),
        ) -> Args {
            let mut bits = Bits(flags as u32);
            Args {
                user_id,
                input_filename,
                output_filename,
                timestamp,
                creation_timestamp,
                expiration_timestamp,
                just_signkey: bits.next(),
                format,
                armor: bits.next(),
                public_key: bits.next(),
                passphrase,
                pinentry: bits.next(),
                seed_format: if bits.next() { SeedFormat::Electrum } else { SeedFormat::Bip39 },
                use_concatenation: bits.next(),
                algorithm,
                interactive: bits.next().then_some(true),
                use_rfc9106_settings: bits.next(),
                authorization_for_sign_key: bits.next(),
                auth_subkey: bits.next(),
                skip_passphrase_for_key_material: bits.next(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn accepted_plans_carry_values_through_unchanged(
            args in any_args(),
            stdin_is_terminal in any::<bool>(),
            stdout_is_terminal in any::<bool>(),
        ) {
            let env = Env { stdin_is_terminal, stdout_is_terminal };
            // Must not panic, whatever the values.
            let Ok(plan) = plan(&args, env) else { return Ok(()) };

            prop_assert_eq!(&plan.user_id, &args.user_id);
            prop_assert_eq!(&plan.seed_format, &args.seed_format);
            prop_assert_eq!(plan.use_rfc9106_settings, args.use_rfc9106_settings);
            prop_assert_eq!(plan.generate_encrypt_key, !args.just_signkey);
            prop_assert_eq!(plan.public_key, args.public_key);

            // Timestamps that reach the encoders are in range and in order.
            prop_assert!(plan.creation_timestamp_secs >= 0);
            if let Some(expiration) = plan.expiration_timestamp_secs {
                prop_assert!(expiration >= plan.creation_timestamp_secs);
            }
            if plan.format == OutputFormat::Pgp {
                prop_assert!(plan.creation_timestamp_secs <= u32::MAX as i64);
                prop_assert!(
                    pgp::validate_timestamps(
                        plan.creation_timestamp_secs,
                        plan.expiration_timestamp_secs
                    )
                    .is_ok()
                );
            }

            // The key never lands on the seed file.
            if let (SeedSource::File(seed), OutputTarget::File(key)) =
                (&plan.seed_source, &plan.output)
            {
                prop_assert_ne!(seed, key);
            }
            // -o "" is standard output, never a file with an empty name.
            prop_assert_ne!(&plan.output, &OutputTarget::File(String::new()));
        }
    }
}
