//! Differential tests: serialize random key material with bip39key's encoders,
//! then check that independent implementations accept it and can use it.
//!
//! - OpenPGP: rPGP (the `pgp` crate)
//! - OpenSSH: RustCrypto's `ssh-key`
//! - age: the reference Rust `age` crate
//!
//! Each case builds `Keys` directly from random bytes, skipping Argon2id, so a
//! case costs milliseconds rather than seconds (see the testing layers in
//! CLAUDE.md). Derivation itself is pinned by the golden vectors and the
//! known-answer tests; this layer checks serialization.
//!
//! The checks go past "it parses": every self-signature and binding signature
//! must verify, the oracle must sign with the secret key and verify with the
//! public one, and must decrypt a message encrypted to the public key. Those
//! are the paths where an encoder bug that still parses would show up, like
//! the class that once made libgcrypt reject valid keys.

use std::io::BufWriter;
use std::str::FromStr;

use bip39key::keys::*;
use bip39key::{age as bage, pgp as bpgp, ssh as bssh};

use pgp::composed::{
    Deserializable, DetachedSignature, Message, MessageBuilder, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::types::{EcdhPublicParams, EddsaLegacyPublicParams, KeyDetails, Password, PublicParams};
use proptest::prelude::*;

// --- Strategies ---

/// Printable ASCII of the given length.
fn ascii(len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(0x20u8..0x7f, len).prop_map(|bytes| String::from_utf8(bytes).unwrap())
}

/// User IDs whose lengths straddle the OpenPGP packet length encodings: one
/// octet below 192, two octets up to 8383, five octets from 8384 (RFC 4880
/// section 4.2.2). The user ID packet body is the user ID itself, and the
/// signature packets that follow grow with it.
fn user_id() -> impl Strategy<Value = String> {
    prop_oneof![
        (1usize..64).prop_flat_map(ascii),
        (185usize..200).prop_flat_map(ascii),
        (8375usize..8392).prop_flat_map(ascii),
    ]
}

/// Creation and optional expiration timestamps within the OpenPGP v4 limits.
fn timestamps() -> impl Strategy<Value = (i64, Option<i64>)> {
    (1i64..=u32::MAX as i64).prop_flat_map(|created| {
        let max_delta = (u32::MAX as i64).min(i64::MAX - created);
        (
            Just(created),
            prop::option::of((1i64..=max_delta).prop_map(move |delta| created + delta)),
        )
    })
}

#[derive(Debug, Clone)]
struct KeyInput {
    sign: [u8; 32],
    encrypt: Option<[u8; 32]>,
    auth: Option<[u8; 32]>,
    authorization_for_sign_key: bool,
    user_id: String,
    created: i64,
    expires: Option<i64>,
}

fn key_input() -> impl Strategy<Value = KeyInput> {
    (
        any::<[u8; 32]>(),
        prop::option::of(any::<[u8; 32]>()),
        prop::option::of(any::<[u8; 32]>()),
        any::<bool>(),
        user_id(),
        timestamps(),
    )
        .prop_map(
            |(sign, encrypt, auth, authorization_for_sign_key, user_id, (created, expires))| {
                KeyInput {
                    sign,
                    encrypt,
                    auth,
                    authorization_for_sign_key,
                    user_id,
                    created,
                    expires,
                }
            },
        )
}

fn build_keys(input: &KeyInput, passphrase: Option<&str>) -> Keys {
    Keys {
        user_id: UserId {
            user_id: input.user_id.clone(),
        },
        sign_key: SignKey::new(
            &input.sign,
            input.created,
            input.expires,
            input.authorization_for_sign_key,
        )
        .unwrap(),
        encrypt_key: input
            .encrypt
            .map(|bytes| EncryptKey::new(&bytes, input.created, input.expires).unwrap()),
        auth_key: input
            .auth
            .map(|bytes| AuthKey::new(&bytes, input.created, input.expires).unwrap()),
        age_key: None,
        passphrase: passphrase.map(String::from),
    }
}

/// Run one of bip39key's writers into a byte vector.
fn render(write: impl FnOnce(&mut BufWriter<Vec<u8>>) -> bip39key::types::Result<()>) -> Vec<u8> {
    let mut writer = BufWriter::new(Vec::new());
    write(&mut writer).unwrap();
    writer.into_inner().unwrap()
}

// --- OpenPGP (rPGP) ---

fn check_pgp(input: &KeyInput, passphrase: Option<&str>) {
    let keys = build_keys(input, passphrase);
    let password = Password::from(passphrase.unwrap_or(""));
    let mut rng = rand::thread_rng();

    let binary = render(|w| bpgp::output_as_packets(&keys, w));
    let secret = SignedSecretKey::from_bytes(&binary[..]).expect("rPGP rejected the secret key");
    secret
        .verify_bindings()
        .expect("a self-signature or binding signature does not verify");

    // The armored writer must produce the same key as the binary one.
    let armored = render(|w| bpgp::output_armored(&keys, w));
    let (from_armor, _) =
        SignedSecretKey::from_armor_single(&armored[..]).expect("rPGP rejected the armor");
    if passphrase.is_none() {
        assert_eq!(from_armor, secret, "armored and binary output differ");
    } else {
        // S2K draws a fresh salt and IV on every write, so two protected
        // renderings differ in their secret material; the rest must not.
        assert_eq!(
            from_armor.to_public_key(),
            secret.to_public_key(),
            "armored and binary output differ"
        );
    }

    // Primary key: Ed25519 (legacy EdDSA), with bip39key's fingerprint.
    assert_eq!(
        secret.primary_key.fingerprint().as_bytes(),
        &bpgp::key_fingerprint(&keys.sign_key).unwrap()[..]
    );
    match secret.primary_key.public_params() {
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
            assert_eq!(key.to_bytes(), keys.sign_key.public_key)
        }
        other => panic!("primary key is not legacy Ed25519: {other:?}"),
    }
    assert_eq!(secret.details.users.len(), 1);
    assert_eq!(
        secret.details.users[0].id.id(),
        input.user_id.as_bytes(),
        "user ID did not round-trip"
    );

    let expected_subkeys = usize::from(input.encrypt.is_some()) + usize::from(input.auth.is_some());
    assert_eq!(secret.secret_subkeys.len(), expected_subkeys);

    // rPGP signs with the (unlocked) primary secret key, and the signature
    // must verify against the public key: the secret and public halves agree.
    let data = b"bip39key differential signature";
    let signature = DetachedSignature::sign_binary_data(
        &mut rng,
        &secret.primary_key,
        &password,
        HashAlgorithm::Sha256,
        &data[..],
    )
    .expect("rPGP could not sign with the primary key");
    signature
        .verify(secret.primary_key.public_key(), data)
        .expect("signature by the primary key does not verify");

    // The public key output must parse, verify, and match the secret key.
    let public_bytes = render(|w| bpgp::output_public_as_packets(&keys, w));
    let public =
        SignedPublicKey::from_bytes(&public_bytes[..]).expect("rPGP rejected the public key");
    public
        .verify_bindings()
        .expect("public key signatures do not verify");
    assert_eq!(
        public.primary_key.fingerprint(),
        secret.primary_key.fingerprint()
    );
    assert_eq!(public.public_subkeys.len(), expected_subkeys);

    if let Some(encrypt_key) = &keys.encrypt_key {
        let subkey = public
            .public_subkeys
            .iter()
            .find(|subkey| matches!(subkey.key.public_params(), PublicParams::ECDH(_)))
            .expect("no ECDH subkey in the public key");
        match subkey.key.public_params() {
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p, .. }) => {
                assert_eq!(p.to_bytes(), encrypt_key.public_key)
            }
            other => panic!("encryption subkey is not legacy Curve25519 ECDH: {other:?}"),
        }

        // Encrypt to the public subkey and decrypt with the secret key. This
        // exercises the ECDH secret scalar, which parsing alone never does.
        let plaintext = b"bip39key differential message";
        let mut builder = MessageBuilder::from_bytes("", &plaintext[..])
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, subkey)
            .expect("rPGP could not encrypt to the subkey");
        let ciphertext = builder.to_vec(&mut rng).unwrap();
        let message = Message::from_bytes(&ciphertext[..]).unwrap();
        let mut decrypted = message
            .decrypt(&password, &secret)
            .expect("rPGP could not decrypt with the secret subkey");
        assert_eq!(decrypted.as_data_vec().unwrap(), plaintext);
    }
}

proptest! {
    #[test]
    fn pgp_unprotected_keys_work_in_rpgp(input in key_input()) {
        check_pgp(&input, None);
    }
}

proptest! {
    // Each passphrase case runs the maximum S2K count several times (bip39key
    // to encrypt, rPGP to unlock), so keep the case count low.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn pgp_passphrase_keys_work_in_rpgp(input in key_input(), passphrase in "[ -~]{1,32}") {
        check_pgp(&input, Some(&passphrase));
    }
}

// --- OpenSSH (ssh-key) ---

/// OpenSSH comments are a single line, so keep to printable ASCII, and skip
/// the very long user IDs: no OpenSSH length boundary sits near them. A public
/// key line cannot carry leading or trailing whitespace in its comment (it is
/// indistinguishable from the separator and line end), and real user IDs never
/// have any, so trim it off.
fn ssh_input() -> impl Strategy<Value = KeyInput> {
    let comment = (1usize..200)
        .prop_flat_map(ascii)
        .prop_map(|s| s.trim().to_string())
        .prop_filter("empty after trimming", |s| !s.is_empty());
    (any::<[u8; 32]>(), comment).prop_map(|(sign, user_id)| KeyInput {
        sign,
        encrypt: None,
        auth: None,
        authorization_for_sign_key: false,
        user_id,
        created: DEFAULT_CREATION_TIMESTAMP,
        expires: None,
    })
}

fn check_ssh(input: &KeyInput, passphrase: Option<&str>) {
    let keys = build_keys(input, passphrase);

    let pem = render(|w| bssh::output_secret_as_pem(&keys, w));
    let parsed = ssh_key::PrivateKey::from_openssh(&pem).expect("ssh-key rejected the secret key");
    assert_eq!(parsed.is_encrypted(), passphrase.is_some());
    let private = match passphrase {
        Some(passphrase) => parsed
            .decrypt(passphrase)
            .expect("ssh-key could not decrypt the secret key"),
        None => parsed,
    };

    let keypair = private.key_data().ed25519().expect("not an Ed25519 key");
    assert_eq!(keypair.public.0, keys.sign_key.public_key);
    assert_eq!(keypair.private.to_bytes(), keys.sign_key.private_key);
    assert_eq!(private.comment(), input.user_id);

    // bip39key's displayed fingerprint must match ssh-key's.
    assert_eq!(
        private.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        format!("SHA256:{}", bssh::key_fingerprint(&keys).unwrap())
    );

    // The public key line must parse to the same key and comment.
    let line = String::from_utf8(render(|w| bssh::output_public_as_pem(&keys, w))).unwrap();
    let public =
        ssh_key::PublicKey::from_openssh(line.trim()).expect("ssh-key rejected the public key");
    assert_eq!(public.key_data(), private.public_key().key_data());
    assert_eq!(public.comment(), input.user_id);

    // Sign with the secret key, verify with the public key line.
    let data = b"bip39key differential signature";
    let signature = private
        .sign("file", ssh_key::HashAlg::Sha512, data)
        .expect("ssh-key could not sign");
    public
        .verify("file", data, &signature)
        .expect("signature does not verify against the public key line");
}

proptest! {
    #[test]
    fn ssh_unprotected_keys_work_in_ssh_key(input in ssh_input()) {
        check_ssh(&input, None);
    }
}

proptest! {
    // bip39key uses 512 bcrypt-pbkdf rounds, so one case costs about 30s
    // between bip39key encrypting and ssh-key decrypting.
    #![proptest_config(ProptestConfig::with_cases(1))]

    #[test]
    fn ssh_passphrase_keys_work_in_ssh_key(input in ssh_input(), passphrase in "[ -~]{1,32}") {
        check_ssh(&input, Some(&passphrase));
    }
}

// --- age ---

proptest! {
    #[test]
    fn age_keys_work_in_the_age_crate(secret in any::<[u8; 32]>()) {
        let keys = Keys {
            user_id: UserId { user_id: String::new() },
            sign_key: SignKey::new(&[1; 32], DEFAULT_CREATION_TIMESTAMP, None, false).unwrap(),
            encrypt_key: None,
            auth_key: None,
            age_key: Some(EncryptKey::new(&secret, DEFAULT_CREATION_TIMESTAMP, None).unwrap()),
            passphrase: None,
        };

        let file = String::from_utf8(render(|w| bage::output_secret(&keys, w))).unwrap();
        let recipient_line =
            String::from_utf8(render(|w| bage::output_public(&keys, w))).unwrap();

        // The identity line parses, and its public half is both the recipient
        // bip39key prints and the one in the file's "# public key:" comment.
        let identity_line = file.lines().last().unwrap();
        let identity = age::x25519::Identity::from_str(identity_line)
            .expect("age rejected the identity");
        let recipient = age::x25519::Recipient::from_str(recipient_line.trim())
            .expect("age rejected the recipient");
        prop_assert_eq!(identity.to_public().to_string(), recipient.to_string());
        let header = format!("# public key: {}\n", recipient);
        prop_assert!(file.starts_with(&header));

        // The whole file is a valid age identity file.
        let entries = age::IdentityFile::from_buffer(file.as_bytes())
            .expect("age rejected the identity file")
            .into_identities()
            .unwrap();
        prop_assert_eq!(entries.len(), 1);

        // Encrypt to the printed recipient, decrypt with the identity.
        let plaintext = b"bip39key differential message";
        let ciphertext = age::encrypt(&recipient, plaintext).unwrap();
        prop_assert_eq!(age::decrypt(&identity, &ciphertext).unwrap(), plaintext);
    }
}
