use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Output;

use duct::cmd;
use tempfile::{NamedTempFile, TempDir};

// --- Constants ---

const BIP39: &[&str] = &[
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "about",
];

const ELECTRUM: &[&str] = &[
    "work", "size", "tomato", "royal", "recipe", "old", "portion", "nut", "mask", "laptop",
    "diamond", "junior",
];

const REALNAME: &str = "Satoshi Nakamoto";
const EMAIL: &str = "satoshin@gmx.com";
const PASS: &str = "m4gicp455w0rd";

fn userid() -> String {
    format!("{REALNAME} <{EMAIL}>")
}

fn golden_path(filename: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test")
        .join(filename)
}

#[cfg(unix)]
fn set_permissions_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_permissions_private(_path: &Path) {}

// --- GPG wrapper ---

struct Gpg {
    tmpdir: TempDir,
}

impl Gpg {
    fn new() -> Self {
        let tmpdir = TempDir::new().expect("Failed to create GPG temp dir");
        set_permissions_private(tmpdir.path());
        fs::write(
            tmpdir.path().join("gpg-agent.conf"),
            "allow-loopback-pinentry\n",
        )
        .unwrap();
        Gpg { tmpdir }
    }

    fn homedir(&self) -> &str {
        self.tmpdir.path().to_str().unwrap()
    }

    fn run(&self, flags: &[&str], stdin: Option<&[u8]>) -> io::Result<Output> {
        let homedir = self.homedir();
        let mut args = vec![
            "--display-charset",
            "utf-8",
            "-utf8-strings",
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--homedir",
            homedir,
        ];
        args.extend_from_slice(flags);
        let expr = cmd("gpg", &args)
            .env("GNUPGHOME", homedir)
            .stdout_capture()
            .stderr_capture()
            .unchecked();
        let output = match stdin {
            Some(data) => expr.stdin_bytes(data.to_vec()).run(),
            None => expr.run(),
        }?;
        if output.status.success() {
            Ok(output)
        } else {
            // duct's own error drops stderr, which is the only place gpg says
            // why it failed.
            Err(io::Error::other(format!(
                "gpg {:?} exited with {}:\n{}",
                flags,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn import(&self, key: &[u8], filename: Option<&str>, password: Option<&str>) {
        let mut flags: Vec<String> = vec!["--import".into()];
        if let Some(f) = filename {
            flags.push(f.to_string());
        }
        if let Some(pw) = password {
            let passfile = PathBuf::from(self.homedir()).join("passwords.txt");
            fs::write(&passfile, pw).unwrap();
            flags.push("--passphrase-file".into());
            flags.push(passfile.to_str().unwrap().to_string());
            flags.push("--pinentry-mode".into());
            flags.push("loopback".into());
        }

        let flag_refs: Vec<&str> = flags.iter().map(|s| s.as_str()).collect();
        self.run(&flag_refs, Some(key)).unwrap();

        if password.is_some() {
            let _ = fs::remove_file(PathBuf::from(self.homedir()).join("passwords.txt"));
        }
    }
}

impl Drop for Gpg {
    fn drop(&mut self) {
        let _ = cmd("gpgconf", &["--kill", "gpg-agent"])
            .env("GNUPGHOME", self.homedir())
            .stdout_null()
            .stderr_null()
            .unchecked()
            .run();
    }
}

// --- GPG colon output parser ---

fn parse_gpg_keys(raw: &[u8]) -> HashMap<String, Vec<String>> {
    let stdout = String::from_utf8_lossy(raw);
    let mut result = HashMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        let head = parts[0];
        if head == "tru" {
            continue;
        }
        let cols: Vec<String> = parts[1..]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        result.insert(head.to_string(), cols);
    }
    result
}

// --- SSH keygen ---

fn run_ssh_keygen(key_data: &[u8], passphrase: &str) -> io::Result<Output> {
    let mut f = NamedTempFile::new()?;
    f.write_all(key_data)?;
    f.flush()?;
    let path = f.into_temp_path();
    set_permissions_private(&path);
    let path_str = path.to_str().unwrap();
    cmd(
        "ssh-keygen",
        &["-v", "-y", "-P", passphrase, "-f", path_str],
    )
    .stdout_capture()
    .stderr_capture()
    .run()
}

// --- age ---

fn run_age_keygen_y(identity: &[u8]) -> io::Result<Output> {
    let mut f = NamedTempFile::new()?;
    f.write_all(identity)?;
    f.flush()?;
    let path = f.into_temp_path();
    cmd("age-keygen", &["-y", path.to_str().unwrap()])
        .stdout_capture()
        .stderr_capture()
        .run()
}

/// Encrypt `plaintext` to `recipient` with the real age binary, then decrypt
/// it with `identity`, returning the decrypted bytes.
fn age_round_trip(recipient: &str, identity: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let dir = TempDir::new().unwrap();
    let identity_path = dir.path().join("identity.txt");
    fs::write(&identity_path, identity).unwrap();
    let ciphertext = cmd("age", &["-r", recipient])
        .stdin_bytes(plaintext.to_vec())
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    cmd("age", &["-d", "-i", identity_path.to_str().unwrap()])
        .stdin_bytes(ciphertext)
        .stdout_capture()
        .run()
        .unwrap()
        .stdout
}

// --- bip39key runner ---

fn run_bip39key(bip39: &[&str], userid: &str, flags: &[&str]) -> io::Result<Output> {
    let mut args = vec!["-u", userid];
    args.extend_from_slice(flags);
    cmd(env!("CARGO_BIN_EXE_bip39key"), &args)
        .stdin_bytes(bip39.join(" ").into_bytes())
        .stdout_capture()
        .stderr_capture()
        .run()
}

// --- Key assertion helper ---

fn check_key(keys: &HashMap<String, Vec<String>>, fp: &str, subfp: &str) {
    let userid = userid();
    assert_eq!(keys["pub"][7], "ed25519");
    assert_eq!(keys["fpr"], vec![fp]);
    assert_eq!(keys["uid"][1], "1231006505");
    assert_eq!(keys["uid"][3], userid);
    assert_eq!(keys["sub"][3], subfp);
    assert_eq!(keys["sub"][4], "1231006505");
    assert_eq!(keys["sub"][5], "e");
    assert_eq!(keys["sub"][6], "cv25519");
}

// --- Tests ---

#[test]
fn test_gpg_raw_xor() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["--algorithm", "xor"]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "A10531F7669DDD0FA50B0A00656C58480711970B",
        "656C58480711970B",
    );
}

#[test]
fn test_gpg_raw_hkdf() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["--algorithm", "hkdf"]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "67EAE06904766020FB5B41B314B8857D6EFD7E9F",
        "14B8857D6EFD7E9F",
    );
}

#[test]
fn test_gpg_public() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["--public-key", "--algorithm", "xor"]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    assert_eq!(keys["pub"][7], "ed25519");
    assert_eq!(
        keys["fpr"],
        vec!["A10531F7669DDD0FA50B0A00656C58480711970B"]
    );
    assert_eq!(keys["uid"][3], userid());
}

#[test]
fn test_gpg_raw_with_file() {
    let gpg = Gpg::new();
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_string();
    let temp_path = f.into_temp_path();
    let output = run_bip39key(BIP39, &userid(), &["-o", &path, "--algorithm", "xor"]).unwrap();
    gpg.import(&output.stdout, Some(&path), None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "A10531F7669DDD0FA50B0A00656C58480711970B",
        "656C58480711970B",
    );
    drop(temp_path);
}

#[test]
fn test_gpg_armor() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["-a", "--algorithm", "xor"]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "A10531F7669DDD0FA50B0A00656C58480711970B",
        "656C58480711970B",
    );
}

#[test]
fn test_electrum() {
    let gpg = Gpg::new();
    let output = run_bip39key(
        ELECTRUM,
        &userid(),
        &["-s", "electrum", "--algorithm", "xor"],
    )
    .unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "384CC65ACAD3BECE74FFF34391BA6BD773B77C9E",
        "91BA6BD773B77C9E",
    );
}

#[test]
fn test_gpg_import_with_passphrase() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["-p", PASS, "--algorithm", "xor"]).unwrap();
    gpg.import(&output.stdout, None, Some(PASS));
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "973FB9F6845B59C12544D62695C556EA825BA259",
        "95C556EA825BA259",
    );
}

#[test]
fn test_ssh_xor() {
    let secretkey = run_bip39key(BIP39, &userid(), &["-f", "ssh", "--algorithm", "xor"]).unwrap();
    let keygenpub = run_ssh_keygen(&secretkey.stdout, "").unwrap();
    let bip39pub = run_bip39key(
        BIP39,
        &userid(),
        &["-f", "ssh", "--public-key", "--algorithm", "xor"],
    )
    .unwrap();
    let lhs = String::from_utf8_lossy(&keygenpub.stdout);
    let rhs = String::from_utf8_lossy(&bip39pub.stdout);
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    assert!(lhs.starts_with(rhs), "{} vs {}", lhs, rhs);
}

#[test]
fn test_ssh_hkdf() {
    let secretkey = run_bip39key(BIP39, &userid(), &["-f", "ssh"]).unwrap();
    let keygenpub = run_ssh_keygen(&secretkey.stdout, "").unwrap();
    let bip39pub = run_bip39key(BIP39, &userid(), &["-f", "ssh", "--public-key"]).unwrap();
    let lhs = String::from_utf8_lossy(&keygenpub.stdout);
    let rhs = String::from_utf8_lossy(&bip39pub.stdout);
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    assert!(lhs.starts_with(rhs), "{} vs {}", lhs, rhs);
}

#[test]
fn test_bad_bip39() {
    let result = run_bip39key(&["foobarbaz"], &userid(), &["-f", "ssh"]);
    assert!(result.is_err(), "Expected failure for invalid BIP39 word");
}

#[test]
fn test_bad_bip39_checksum() {
    let mut mnemonic: Vec<&str> = BIP39.to_vec();
    *mnemonic.last_mut().unwrap() = "abandon";
    let result = run_bip39key(&mnemonic, &userid(), &["-f", "ssh"]);
    assert!(result.is_err(), "Expected failure for bad BIP39 checksum");
}

#[test]
fn test_gpg_import_with_passphrase_fails() {
    let output = run_bip39key(BIP39, &userid(), &["-p", PASS, "--algorithm", "xor"]).unwrap();
    let gpg = Gpg::new();
    let keyfile = PathBuf::from(gpg.homedir()).join("key.gpg");
    fs::write(&keyfile, &output.stdout).unwrap();
    let keyfile_str = keyfile.to_str().unwrap().to_string();
    let result = gpg.run(
        &[
            "--import",
            &keyfile_str,
            "--passphrase",
            "badpassword",
            "--pinentry-mode",
            "loopback",
        ],
        None,
    );
    assert!(result.is_err(), "Import with wrong passphrase should fail");
    let _ = fs::remove_file(&keyfile);
}

#[test]
fn test_ssh_with_passphrase() {
    let output = run_bip39key(
        BIP39,
        &userid(),
        &["-f", "ssh", "-p", PASS, "--algorithm", "xor"],
    )
    .unwrap();
    run_ssh_keygen(&output.stdout, PASS).unwrap();
    let result = run_ssh_keygen(&output.stdout, "badpassword");
    assert!(
        result.is_err(),
        "ssh-keygen with wrong passphrase should fail"
    );
}

#[test]
fn test_golden_with_passphrase() {
    let bip39: Vec<&str> =
        "fatigue mosquito exclude vessel reward slight protect purity language hat anger pen"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["-p", password, "--algorithm", "xor"]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-with-passphrase.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message\n");
}

#[test]
fn test_golden_without_passphrase() {
    let bip39: Vec<&str> =
        "fatigue mosquito exclude vessel reward slight protect purity language hat anger pen"
            .split(' ')
            .collect();
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["--algorithm", "xor"]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, None);
    let gpg_file = golden_path("message-without-passphrase.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg.run(&["--decrypt", &gpg_file_str], None).unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

#[test]
fn test_golden_concatenated() {
    let bip39: Vec<&str> =
        "fatigue mosquito exclude vessel reward slight protect purity language hat anger pen"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["--algorithm", "concat", "-p", password]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-concatenated.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

#[test]
fn test_golden_electrum() {
    let electrum: Vec<&str> =
        "cause shine enable penalty moral toy undo tree bike satisfy narrow upon"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(
        &electrum,
        uid,
        &["-p", password, "-s", "electrum", "--algorithm", "xor"],
    )
    .unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-electrum.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

#[test]
fn test_golden_electrum_concatenated() {
    let electrum: Vec<&str> =
        "cause shine enable penalty moral toy undo tree bike satisfy narrow upon"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(
        &electrum,
        uid,
        &["--algorithm", "concat", "-p", password, "-s", "electrum"],
    )
    .unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-electrum-concatenated.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

#[test]
fn test_from_prompt() {
    let bip39: Vec<&str> =
        "switch limit barely shoot ritual reveal bomb obey luxury around language build"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["-p", password, "--algorithm", "xor"]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-prompt.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

#[test]
fn test_custom_timestamps() {
    let bip39: Vec<&str> =
        "switch limit barely shoot ritual reveal bomb obey luxury around language build"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(
        &bip39,
        uid,
        &[
            "-p",
            password,
            "--algorithm",
            "concat",
            "-d",
            "1744948062",
            "-y",
            "1745554397",
        ],
    )
    .unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    assert_eq!(keys["pub"][4], "1744948062");
    assert_eq!(keys["pub"][5], "1745554397");
}

#[test]
fn test_authentication() {
    let bip39: Vec<&str> =
        "switch limit barely shoot ritual reveal bomb obey luxury around language build"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(
        &bip39,
        uid,
        &["-p", password, "--algorithm", "concat", "-b"],
    )
    .unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    assert!(
        keys["pub"][6].contains('a'),
        "Expected authentication capability in pub key capabilities: {}",
        keys["pub"][6]
    );
}

#[test]
fn test_auth_subkey() {
    let bip39: Vec<&str> =
        "switch limit barely shoot ritual reveal bomb obey luxury around language build"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(
        &bip39,
        uid,
        &["-p", password, "--algorithm", "hkdf", "--auth-subkey"],
    )
    .unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let stdout = String::from_utf8_lossy(&keysout.stdout);
    // Verify there are two subkeys: one encrypt (e) and one auth (a).
    let sub_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("sub:")).collect();
    assert_eq!(
        sub_lines.len(),
        2,
        "Expected 2 subkeys, got: {:?}",
        sub_lines
    );
    let caps: Vec<String> = sub_lines
        .iter()
        .map(|l| l.split(':').nth(11).unwrap_or("").to_string())
        .collect();
    assert!(
        caps.iter().any(|c| c.contains('e')),
        "Expected encrypt capability in subkeys: {:?}",
        caps
    );
    assert!(
        caps.iter().any(|c| c.contains('a')),
        "Expected authentication capability in subkeys: {:?}",
        caps
    );
}

#[test]
fn test_auth_subkey_without_passphrase() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &["--algorithm", "hkdf", "--auth-subkey"]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let stdout = String::from_utf8_lossy(&keysout.stdout);
    let sub_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("sub:")).collect();
    assert_eq!(
        sub_lines.len(),
        2,
        "Expected 2 subkeys, got: {:?}",
        sub_lines
    );
    let caps: Vec<String> = sub_lines
        .iter()
        .map(|l| l.split(':').nth(11).unwrap_or("").to_string())
        .collect();
    assert!(
        caps.iter().any(|c| c.contains('a')),
        "Expected authentication capability in subkeys: {:?}",
        caps
    );
}

#[test]
fn test_auth_subkey_public_key() {
    let gpg = Gpg::new();
    let output = run_bip39key(
        BIP39,
        &userid(),
        &["--algorithm", "hkdf", "--auth-subkey", "--public-key"],
    )
    .unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let stdout = String::from_utf8_lossy(&keysout.stdout);
    let sub_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("sub:")).collect();
    assert_eq!(
        sub_lines.len(),
        2,
        "Expected 2 subkeys, got: {:?}",
        sub_lines
    );
}

#[test]
fn test_no_passphrase() {
    let bip39: Vec<&str> =
        "switch limit barely shoot ritual reveal bomb obey luxury around language build"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["-p", password, "-n", "--algorithm", "xor"]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-no-passphrase.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!\n");
}

#[test]
fn test_default_algorithm_is_xor() {
    let gpg = Gpg::new();
    let output = run_bip39key(BIP39, &userid(), &[]).unwrap();
    gpg.import(&output.stdout, None, None);
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let keys = parse_gpg_keys(&keysout.stdout);
    check_key(
        &keys,
        "A10531F7669DDD0FA50B0A00656C58480711970B",
        "656C58480711970B",
    );
}

#[test]
fn test_concat_flag_backwards_compat() {
    let bip39: Vec<&str> =
        "fatigue mosquito exclude vessel reward slight protect purity language hat anger pen"
            .split(' ')
            .collect();
    let password = "magic-password";
    let uid = "Integration Test <integration@test.com>";
    let output = run_bip39key(&bip39, uid, &["-c", "-p", password]).unwrap();
    let gpg = Gpg::new();
    gpg.import(&output.stdout, None, Some(password));
    let gpg_file = golden_path("message-concatenated.gpg");
    let gpg_file_str = gpg_file.to_str().unwrap().to_string();
    let message = gpg
        .run(
            &[
                "--passphrase",
                password,
                "--pinentry-mode",
                "loopback",
                "--decrypt",
                &gpg_file_str,
            ],
            None,
        )
        .unwrap();
    assert_eq!(message.stdout, b"Secret message!!\n");
}

// --- Golden vectors ---
//
// A golden vector pins the exact bytes bip39key produces for one combination
// of flags. Everything the vectors below cover is deterministic: Ed25519
// signatures are deterministic per RFC 8032, and none of these paths draw a
// random S2K or bcrypt salt.
//
// IMPORTANT: a diff in test/golden/ is a breaking change, not a test failure
// to paper over. These bytes are the keys that existing users regenerate from
// their seed phrase; if they move, everyone who regenerates gets a different
// key and loses access to anything encrypted to the old one. Regenerating the
// files with BIP39KEY_UPDATE_GOLDEN=1 is only correct when the change in key
// material is itself the intended, released change.
//
// Passphrase-protected *secret* output is not pinned, because S2K and bcrypt
// draw a fresh random salt each run. Those combinations are covered by pinning
// the *public* key instead, which is deterministic and still a direct function
// of the derived key material, so it detects any change in how the passphrase
// feeds derivation.

const LONG_USER_ID_FILLER: usize = 250;

#[derive(Clone, Copy)]
enum Verify {
    PgpSecret,
    PgpPublic,
    SshSecret,
    SshPublic,
    AgeSecret,
    AgePublic,
}

fn golden_vector_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test")
        .join("golden")
        .join(format!("{name}.golden"))
}

/// A user ID long enough that the PGP user ID packet needs a two-octet length
/// header (RFC 4880 section 4.2.2 switches at 192 octets). Short user IDs stay
/// on the one-octet path, so without this no golden exercises the wider header.
fn long_user_id() -> String {
    let user_id = format!("{} <long@test.com>", "A".repeat(LONG_USER_ID_FILLER));
    assert!(
        user_id.len() > 192,
        "the long user ID vector must exceed the 192-octet header boundary, got {}",
        user_id.len()
    );
    user_id
}

/// Confirm the bytes are not merely stable but actually a key that the real
/// tools accept. Without this a golden could pin output that GPG rejects.
fn verify_golden_output(verify: Verify, output: &[u8], user_id: &str) {
    match verify {
        Verify::PgpSecret | Verify::PgpPublic => {
            let gpg = Gpg::new();
            gpg.import(output, None, None);
            let listed = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
            let keys = parse_gpg_keys(&listed.stdout);
            // parse_gpg_keys drops empty colon fields, so column positions
            // shift with which fields GPG populated (setting an expiry moves
            // every later column along). Search instead of indexing.
            assert!(
                keys["pub"].iter().any(|field| field == "ed25519"),
                "GPG did not import an ed25519 primary key: {:?}",
                keys["pub"]
            );
            assert!(
                keys["uid"].iter().any(|field| field == user_id),
                "GPG imported a different user ID: {:?}",
                keys["uid"]
            );
        }
        Verify::SshSecret => {
            let keygen = run_ssh_keygen(output, "").unwrap();
            assert!(
                keygen.status.success(),
                "ssh-keygen rejected the key: {}",
                String::from_utf8_lossy(&keygen.stderr)
            );
        }
        Verify::SshPublic => {
            let line = String::from_utf8_lossy(output);
            let line = line.trim();
            assert!(
                line.starts_with("ssh-ed25519 "),
                "not an ed25519 public key line: {line}"
            );
            assert!(
                line.ends_with(user_id),
                "public key line does not carry the user ID as its comment: {line}"
            );
        }
        Verify::AgeSecret => {
            // age-keygen must accept the identity and derive the same
            // recipient that the "# public key:" comment advertises.
            let keygen = run_age_keygen_y(output).unwrap();
            let derived = String::from_utf8_lossy(&keygen.stdout);
            let text = String::from_utf8_lossy(output);
            let advertised = text
                .lines()
                .find_map(|line| line.strip_prefix("# public key: "))
                .expect("identity file has no '# public key:' comment");
            assert_eq!(derived.trim(), advertised);
            let identity = text.lines().last().unwrap();
            assert!(
                identity.starts_with("AGE-SECRET-KEY-1"),
                "not an age identity line: {identity}"
            );
        }
        Verify::AgePublic => {
            let line = String::from_utf8_lossy(output);
            let line = line.trim();
            assert!(line.starts_with("age1"), "not an age recipient: {line}");
            assert!(!line.contains('\n'), "recipient output has extra lines");
        }
    }
}

fn check_golden_vector(name: &str, seed: &[&str], user_id: &str, flags: &[&str], verify: Verify) {
    let output = run_bip39key(seed, user_id, flags).unwrap();
    assert!(
        output.status.success(),
        "bip39key {flags:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = output.stdout;

    // The same flags must produce the same bytes within a single run, or the
    // golden comparison below would be testing nothing but luck.
    let repeat = run_bip39key(seed, user_id, flags).unwrap();
    assert_eq!(
        actual, repeat.stdout,
        "{name}: output is not deterministic across runs"
    );

    verify_golden_output(verify, &actual, user_id);

    let path = golden_vector_path(name);
    if std::env::var("BIP39KEY_UPDATE_GOLDEN").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &actual).unwrap();
        return;
    }

    let expected = fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "{name}: cannot read golden file {}: {err}\n\
             If this vector is new, generate it with BIP39KEY_UPDATE_GOLDEN=1.",
            path.display()
        )
    });
    if expected == actual {
        return;
    }
    // Armored and OpenSSH output is text, so show it; binary packets are not
    // worth dumping, so report where they diverge instead.
    let message = match (std::str::from_utf8(&expected), std::str::from_utf8(&actual)) {
        (Ok(expected), Ok(actual)) => {
            format!("expected:\n{expected}\nactual:\n{actual}")
        }
        _ => {
            let first_difference = expected
                .iter()
                .zip(actual.iter())
                .position(|(a, b)| a != b)
                .map(|index| index.to_string())
                .unwrap_or_else(|| "(one is a prefix of the other)".to_string());
            format!(
                "binary output differs at byte {first_difference}; \
                 {} expected bytes vs {} actual",
                expected.len(),
                actual.len()
            )
        }
    };
    panic!(
        "{name}: output no longer matches {}.\n\
         This means the key derived from a given seed phrase has CHANGED, \
         which breaks every existing user. Only regenerate with \
         BIP39KEY_UPDATE_GOLDEN=1 if that is the intended release.\n{message}",
        path.display()
    );
}

macro_rules! golden_vectors {
    ($($name:ident($seed:expr, $user_id:expr, $flags:expr, $verify:expr);)*) => {
        $(
            #[test]
            fn $name() {
                check_golden_vector(stringify!($name), $seed, &$user_id, &$flags, $verify);
            }
        )*
    };
}

golden_vectors! {
    // PGP secret keys, one per derivation algorithm. The two deprecated
    // algorithms matter most here: users hold keys made with them, so their
    // output must never move.
    golden_pgp_xor_binary(BIP39, userid(), ["--algorithm", "xor"], Verify::PgpSecret);
    golden_pgp_xor_armored(BIP39, userid(), ["--algorithm", "xor", "-a"], Verify::PgpSecret);
    golden_pgp_concat_armored(BIP39, userid(), ["-c", "-a"], Verify::PgpSecret);
    golden_pgp_hkdf_armored(BIP39, userid(), ["--algorithm", "hkdf", "-a"], Verify::PgpSecret);

    // Subkey layout variations.
    golden_pgp_hkdf_just_signkey(
        BIP39, userid(), ["--algorithm", "hkdf", "-j", "-a"], Verify::PgpSecret);
    golden_pgp_hkdf_auth_subkey(
        BIP39, userid(), ["--algorithm", "hkdf", "--auth-subkey", "-a"], Verify::PgpSecret);
    golden_pgp_hkdf_sign_key_authorization(
        BIP39, userid(), ["--algorithm", "hkdf", "-b", "-a"], Verify::PgpSecret);

    // Timestamps are part of the fingerprint, so both the default genesis
    // block value and an explicit pair need pinning.
    golden_pgp_hkdf_custom_timestamps(
        BIP39,
        userid(),
        ["--algorithm", "hkdf", "-d", "1700000000", "-y", "1800000000", "-a"],
        Verify::PgpSecret
    );

    // Argon2id parameter set.
    golden_pgp_hkdf_rfc9106(
        BIP39, userid(), ["--algorithm", "hkdf", "-r", "-a"], Verify::PgpSecret);

    // Electrum seeds take a different path to the same 512 bits.
    golden_pgp_electrum_xor(
        ELECTRUM, userid(), ["-s", "electrum", "--algorithm", "xor", "-a"], Verify::PgpSecret);
    golden_pgp_electrum_hkdf(
        ELECTRUM, userid(), ["-s", "electrum", "--algorithm", "hkdf", "-a"], Verify::PgpSecret);

    // A user ID past the 192-octet packet length boundary, which no other
    // vector reaches.
    golden_pgp_hkdf_long_user_id(
        BIP39, long_user_id(), ["--algorithm", "hkdf", "-a"], Verify::PgpSecret);

    // Public output is deterministic even with a passphrase, so these pin how
    // the passphrase feeds key derivation for each algorithm.
    golden_pgp_public_xor_passphrase(
        BIP39, userid(), ["-p", PASS, "--algorithm", "xor", "-k", "-a"], Verify::PgpPublic);
    golden_pgp_public_concat_passphrase(
        BIP39, userid(), ["-p", PASS, "-c", "-k", "-a"], Verify::PgpPublic);
    golden_pgp_public_hkdf_passphrase(
        BIP39, userid(), ["-p", PASS, "--algorithm", "hkdf", "-k", "-a"], Verify::PgpPublic);
    // -n keeps the passphrase out of the key material, so this must match the
    // no-passphrase public key rather than the vector above it.
    golden_pgp_public_hkdf_passphrase_skipped(
        BIP39, userid(), ["-p", PASS, "-n", "--algorithm", "hkdf", "-k", "-a"], Verify::PgpPublic);
    golden_pgp_public_hkdf_no_passphrase(
        BIP39, userid(), ["--algorithm", "hkdf", "-k", "-a"], Verify::PgpPublic);

    // OpenSSH output, which uses only the Ed25519 signing half.
    golden_ssh_xor_secret(BIP39, userid(), ["-f", "ssh", "--algorithm", "xor"], Verify::SshSecret);
    golden_ssh_concat_secret(BIP39, userid(), ["-f", "ssh", "-c"], Verify::SshSecret);
    golden_ssh_hkdf_secret(
        BIP39, userid(), ["-f", "ssh", "--algorithm", "hkdf"], Verify::SshSecret);
    golden_ssh_electrum_hkdf_secret(
        ELECTRUM, userid(), ["-s", "electrum", "-f", "ssh", "--algorithm", "hkdf"],
        Verify::SshSecret);
    golden_ssh_hkdf_public(
        BIP39, userid(), ["-f", "ssh", "--algorithm", "hkdf", "-k"], Verify::SshPublic);
    golden_ssh_public_hkdf_passphrase(
        BIP39, userid(), ["-f", "ssh", "-p", PASS, "--algorithm", "hkdf", "-k"],
        Verify::SshPublic);

    // age output, from its own HKDF info string (hkdf only). age identities
    // have no passphrase protection, so even passphrase secrets are pinned.
    golden_age_hkdf_secret(
        BIP39, userid(), ["-f", "age", "--algorithm", "hkdf"], Verify::AgeSecret);
    golden_age_hkdf_passphrase_secret(
        BIP39, userid(), ["-f", "age", "-p", PASS, "--algorithm", "hkdf"], Verify::AgeSecret);
    golden_age_hkdf_public(
        BIP39, userid(), ["-f", "age", "--algorithm", "hkdf", "-k"], Verify::AgePublic);
}

// --- Relationships between golden vectors ---
//
// These read the committed files rather than deriving anything, so they cost
// no Argon2id time. They assert the *intent* behind the vectors: byte equality
// alone would still pass if, say, a flag silently stopped having any effect.

fn read_golden(name: &str) -> Vec<u8> {
    let path = golden_vector_path(name);
    fs::read(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

#[test]
fn test_golden_skip_passphrase_matches_no_passphrase() {
    // -n/--skip-passphrase-for-key-material must keep the passphrase out of
    // the derived key entirely, so the public key has to match the one derived
    // with no passphrase at all.
    assert_eq!(
        read_golden("golden_pgp_public_hkdf_passphrase_skipped"),
        read_golden("golden_pgp_public_hkdf_no_passphrase"),
        "-n changed the derived key, so the passphrase is still reaching key material"
    );
}

#[test]
fn test_golden_passphrase_changes_derived_key() {
    assert_ne!(
        read_golden("golden_pgp_public_hkdf_passphrase"),
        read_golden("golden_pgp_public_hkdf_no_passphrase"),
        "the passphrase made no difference to the derived key"
    );
}

#[test]
fn test_golden_algorithms_derive_distinct_keys() {
    // The three algorithms combine seed and passphrase differently, so no two
    // may land on the same key from the same inputs.
    let xor = read_golden("golden_pgp_public_xor_passphrase");
    let concat = read_golden("golden_pgp_public_concat_passphrase");
    let hkdf = read_golden("golden_pgp_public_hkdf_passphrase");
    assert_ne!(xor, concat, "xor and concat derived the same key");
    assert_ne!(concat, hkdf, "concat and hkdf derived the same key");
    assert_ne!(xor, hkdf, "xor and hkdf derived the same key");
}

#[test]
fn test_golden_seed_format_changes_derived_key() {
    assert_ne!(
        read_golden("golden_pgp_electrum_hkdf"),
        read_golden("golden_pgp_hkdf_armored"),
        "the Electrum and BIP39 seeds derived the same key"
    );
}

#[test]
fn test_golden_armor_matches_binary_packets() {
    // The armored and binary writers must serialize the same packets; only the
    // base64 envelope differs. Decoding the armor back has to reproduce the
    // binary golden exactly.
    let binary = read_golden("golden_pgp_xor_binary");
    let armored = read_golden("golden_pgp_xor_armored");
    let armored = String::from_utf8(armored).unwrap();

    let body: String = armored
        .lines()
        .skip_while(|line| !line.is_empty())
        .skip(1)
        .take_while(|line| !line.starts_with('=') && !line.starts_with("-----END"))
        .collect();
    let decoded = base64_decode(&body);
    assert_eq!(
        decoded, binary,
        "armored output does not decode to the same packets as the binary output"
    );
}

/// Minimal base64 decoder, so the test does not depend on the same crate the
/// implementation encodes with.
fn base64_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for byte in input.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .unwrap_or_else(|| panic!("not a base64 character: {}", byte as char));
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}

#[test]
fn test_rejects_timestamps_outside_openpgp_range() {
    // Out-of-range timestamps used to panic in pgp.rs after the Argon2id
    // run; they must now be rejected up front with a clean error.
    for (flags, expected) in [
        (vec!["-d", "5000000000"], "out of range"),
        (vec!["-y", "6000000000"], "exceeds the OpenPGP u32 limit"),
    ] {
        let mut args = vec!["-u", "Satoshi Nakamoto <satoshin@gmx.com>", "-g", "hkdf"];
        args.extend(flags.iter());
        let output = cmd(env!("CARGO_BIN_EXE_bip39key"), &args)
            .stdin_bytes(BIP39.join(" ").into_bytes())
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{:?}: stderr: {}", flags, stderr);
        assert!(
            !stderr.contains("panicked"),
            "{:?}: stderr: {}",
            flags,
            stderr
        );
    }
}

/// Minimal Bech32 decoder (data part only, checksum not verified: age-keygen
/// already validated these strings), so the test does not reuse the encoder.
fn bech32_data(input: &str) -> Vec<u8> {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let input = input.to_lowercase();
    let data = &input[input.rfind('1').unwrap() + 1..input.len() - 6];
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for byte in data.bytes() {
        let value = CHARSET.iter().position(|c| *c == byte).unwrap();
        accumulator = (accumulator << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}

#[test]
fn test_golden_age_differs_from_pgp_encrypt_subkey() {
    // The age key has its own HKDF info string, so it must not be the PGP
    // encryption subkey derived from the same inputs. The subkey's public MPI
    // is 0x40 followed by the native X25519 public key, so if the keys were
    // shared that point would appear verbatim in the PGP packets.
    let recipient = String::from_utf8(read_golden("golden_age_hkdf_public")).unwrap();
    let mut point = vec![0x40];
    point.extend(bech32_data(recipient.trim()));
    assert_eq!(point.len(), 33);

    let armored = String::from_utf8(read_golden("golden_pgp_hkdf_armored")).unwrap();
    let body: String = armored
        .lines()
        .skip_while(|line| !line.is_empty())
        .skip(1)
        .take_while(|line| !line.starts_with('=') && !line.starts_with("-----END"))
        .collect();
    let packets = base64_decode(&body);
    // Guard against the search below passing vacuously: the PGP packets must
    // contain some 0x40-prefixed point at all.
    assert!(packets.contains(&0x40));
    assert!(
        !packets.windows(point.len()).any(|w| w == point.as_slice()),
        "the age key is the PGP encryption subkey; it must be derived separately"
    );
}

#[test]
fn test_golden_age_secret_matches_public() {
    let secret = String::from_utf8(read_golden("golden_age_hkdf_secret")).unwrap();
    let public = String::from_utf8(read_golden("golden_age_hkdf_public")).unwrap();
    assert!(
        secret.contains(&format!("# public key: {}", public.trim())),
        "-k printed a different recipient from the identity file"
    );
}

#[test]
fn test_golden_age_passphrase_changes_derived_key() {
    assert_ne!(
        read_golden("golden_age_hkdf_passphrase_secret"),
        read_golden("golden_age_hkdf_secret"),
        "the passphrase made no difference to the age key"
    );
}

#[test]
fn test_age_encrypt_decrypt_round_trip() {
    let identity = run_bip39key(BIP39, &userid(), &["-f", "age", "-g", "hkdf", "-r"]).unwrap();
    let recipient =
        run_bip39key(BIP39, &userid(), &["-f", "age", "-g", "hkdf", "-r", "-k"]).unwrap();
    let recipient = String::from_utf8(recipient.stdout).unwrap();
    let plaintext = b"bip39key age round trip";
    assert_eq!(
        age_round_trip(recipient.trim(), &identity.stdout, plaintext),
        plaintext
    );
}

#[test]
fn test_age_rejects_pgp_only_flags() {
    // These are rejected in validate(), before the seed is read or Argon2id
    // runs, so this test is cheap.
    for (flags, expected) in [
        (vec!["-a"], "--armor"),
        (vec!["-j"], "--just-signkey"),
        (vec!["--auth-subkey"], "--auth-subkey"),
        (vec!["-b"], "--authorization-for-sign-key"),
        (vec!["-n", "-p", PASS], "--skip-passphrase-for-key-material"),
        (vec!["-y", "1800000000"], "--expiration-timestamp"),
        (vec!["-d", "1700000000"], "--creation-timestamp"),
        (vec!["-t", "1700000000"], "--creation-timestamp"),
    ] {
        let mut args = vec![
            "-u",
            "Satoshi Nakamoto <satoshin@gmx.com>",
            "-f",
            "age",
            "-g",
            "hkdf",
        ];
        args.extend(flags.iter());
        let output = cmd(env!("CARGO_BIN_EXE_bip39key"), &args)
            .stdin_bytes(BIP39.join(" ").into_bytes())
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap();
        assert!(!output.status.success(), "{flags:?} was accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{flags:?}: stderr: {stderr}");
    }
}

#[test]
fn test_age_requires_hkdf() {
    // Only hkdf can derive a separate age key, so leaving out -g (which
    // defaults to xor) or choosing another algorithm must fail up front.
    for flags in [vec![], vec!["-g", "xor"], vec!["-g", "concat"], vec!["-c"]] {
        let mut args = vec!["-u", "Satoshi Nakamoto <satoshin@gmx.com>", "-f", "age"];
        args.extend(flags.iter());
        let output = cmd(env!("CARGO_BIN_EXE_bip39key"), &args)
            .stdin_bytes(BIP39.join(" ").into_bytes())
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap();
        assert!(!output.status.success(), "{flags:?} was accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("requires --algorithm hkdf"),
            "{flags:?}: stderr: {stderr}"
        );
    }
}

/// Decrypt the age file at `ciphertext` with the identity bytes, without
/// failing on a non-zero exit so callers can assert either outcome.
fn age_decrypt_file(identity: &[u8], ciphertext: &Path) -> Output {
    let dir = TempDir::new().unwrap();
    let identity_path = dir.path().join("identity.txt");
    fs::write(&identity_path, identity).unwrap();
    cmd(
        "age",
        &[
            "-d",
            "-i",
            identity_path.to_str().unwrap(),
            ciphertext.to_str().unwrap(),
        ],
    )
    .stdout_capture()
    .stderr_capture()
    .unchecked()
    .run()
    .unwrap()
}

#[test]
fn test_golden_age_message_with_passphrase() {
    // message-age-with-passphrase.age was encrypted with the real age binary
    // to the recipient derived from BIP39, userid(), PASS and -g hkdf on the
    // default Argon2id settings. A freshly derived identity must still open
    // it: this is what a user regenerating their key from the seed relies on.
    let identity =
        run_bip39key(BIP39, &userid(), &["-f", "age", "-g", "hkdf", "-p", PASS]).unwrap();
    let output = age_decrypt_file(
        &identity.stdout,
        &golden_path("message-age-with-passphrase.age"),
    );
    assert!(
        output.status.success(),
        "age could not decrypt the golden message: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Secret message\n");
}

#[test]
fn test_golden_age_message_wrong_key_fails() {
    // The identity derived without the passphrase is a different key, so it
    // must not open a message encrypted to the passphrase-derived one. Uses
    // the committed golden identity, so no Argon2id run is needed.
    let output = age_decrypt_file(
        &read_golden("golden_age_hkdf_secret"),
        &golden_path("message-age-with-passphrase.age"),
    );
    assert!(
        !output.status.success(),
        "the wrong age identity decrypted the message"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn test_age_round_trip_via_output_file_with_passphrase() {
    // Writes the identity with -o, as users do, rather than via stdout, and
    // derives with a passphrase. -r keeps the Argon2id cost down.
    let dir = TempDir::new().unwrap();
    let identity_path = dir.path().join("identity.txt");
    let flags = ["-f", "age", "-g", "hkdf", "-r", "-p", PASS];
    let mut with_output = flags.to_vec();
    with_output.extend(["-o", identity_path.to_str().unwrap()]);
    let written = run_bip39key(BIP39, &userid(), &with_output).unwrap();
    assert!(written.stdout.is_empty(), "-o still wrote to stdout");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&identity_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file is not private");
    }

    let mut public = flags.to_vec();
    public.push("-k");
    let recipient = run_bip39key(BIP39, &userid(), &public).unwrap();
    let recipient = String::from_utf8(recipient.stdout).unwrap();

    let identity = fs::read(&identity_path).unwrap();
    let plaintext = b"bip39key age round trip via -o";
    assert_eq!(
        age_round_trip(recipient.trim(), &identity, plaintext),
        plaintext
    );
}

#[test]
fn test_golden_base64_lines_are_fixed_width() {
    // Armor wraps at 64 columns and OpenSSH private keys at 70, every line
    // full except the last, as GnuPG and OpenSSH write them. Strict RFC 7468
    // parsers reject anything else; bip39key once broke lines at '/'.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test")
        .join("golden");
    let mut checked = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Ok(text) = fs::read_to_string(&path) else {
            continue; // binary PGP packets
        };
        let (width, body): (usize, Vec<&str>) = if text.starts_with("-----BEGIN PGP") {
            // Skip the armor headers up to the blank line; stop at the
            // checksum line.
            let body = text
                .lines()
                .skip_while(|line| !line.is_empty())
                .skip(1)
                .take_while(|line| !line.starts_with('='))
                .collect();
            (64, body)
        } else if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            let body = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            (70, body)
        } else {
            continue;
        };
        let (last, full) = body.split_last().unwrap();
        assert!(
            full.iter().all(|line| line.len() == width) && last.len() <= width,
            "{} is not wrapped at exactly {width} columns",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 20, "only found {checked} base64 golden files");
}

#[test]
fn test_skip_passphrase_still_encrypts_the_key_file() {
    // -n keeps the passphrase out of derivation but, as its help says, the
    // passphrase still encrypts the output. It used to be dropped entirely,
    // leaving a plaintext secret key the user believed was protected.
    let with_n = run_bip39key(
        BIP39,
        &userid(),
        &["-f", "ssh", "-g", "hkdf", "-n", "-p", PASS],
    )
    .unwrap();
    assert!(
        run_ssh_keygen(&with_n.stdout, "").is_err(),
        "the -n key file is not encrypted"
    );
    let unlocked = run_ssh_keygen(&with_n.stdout, PASS).unwrap();

    // ...and the key inside is the no-passphrase key.
    let plain = run_bip39key(BIP39, &userid(), &["-f", "ssh", "-g", "hkdf"]).unwrap();
    let plain_public = run_ssh_keygen(&plain.stdout, "").unwrap();
    assert_eq!(unlocked.stdout, plain_public.stdout);
}

#[test]
#[cfg(target_os = "linux")]
fn test_input_file_is_read_when_stdin_is_a_terminal() {
    // -i used to be ignored on a terminal: the seed prompt came first. script(1)
    // gives the child a pty on stdin, which a plain Command cannot.
    if cmd("script", &["--version"]).stdout_null().run().is_err() {
        eprintln!("skipping: script(1) not found");
        return;
    }
    let dir = TempDir::new().unwrap();
    let seed_path = dir.path().join("seed.txt");
    let key_path = dir.path().join("identity.txt");
    fs::write(&seed_path, BIP39.join(" ")).unwrap();

    let command = format!(
        "'{}' -u '{}' -f age -g hkdf -r -p '{}' -i '{}' -o '{}'",
        env!("CARGO_BIN_EXE_bip39key"),
        userid(),
        PASS,
        seed_path.display(),
        key_path.display(),
    );
    let output = cmd("script", &["-qec", &command, "/dev/null"])
        .stdin_null()
        .stdout_capture()
        .unchecked()
        .run()
        .unwrap();
    assert!(
        output.status.success(),
        "bip39key failed on a terminal: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let flags = ["-f", "age", "-g", "hkdf", "-r", "-p", PASS];
    let piped = run_bip39key(BIP39, &userid(), &flags).unwrap();
    assert_eq!(fs::read(&key_path).unwrap(), piped.stdout);
}

#[test]
fn test_output_onto_seed_file_is_rejected() {
    // The seed is read before the key is written, so this used to succeed and
    // leave the seed phrase replaced by the key. Both spellings fail before
    // derivation: the literal one in plan.rs, the other when paths resolve.
    let dir = TempDir::new().unwrap();
    let seed_path = dir.path().join("seed.txt");
    let phrase = BIP39.join(" ");
    fs::write(&seed_path, &phrase).unwrap();
    let seed = seed_path.to_str().unwrap().to_string();
    let respelled = dir.path().join(".").join("seed.txt");

    for output in [seed.as_str(), respelled.to_str().unwrap()] {
        let args = ["-u", "A <a@b>", "-i", seed.as_str(), "-o", output];
        let result = cmd(env!("CARGO_BIN_EXE_bip39key"), args)
            .stdin_null()
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap();
        assert!(!result.status.success(), "-o {output} was accepted");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("overwrite the seed phrase"), "{stderr}");
        assert_eq!(fs::read_to_string(&seed_path).unwrap(), phrase);
    }
}

// --- Receipt tests ---

fn run_bip39key_raw(seed: &[&str], flags: &[&str]) -> io::Result<Output> {
    cmd(env!("CARGO_BIN_EXE_bip39key"), flags)
        .stdin_bytes(seed.join(" ").into_bytes())
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
}

#[test]
fn test_receipt_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();
    let key1 = tmp.path().join("key1.gpg");
    let key2 = tmp.path().join("key2.gpg");

    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "--auth-subkey",
            "-y",
            "2000000000",
            "--output-receipt",
            receipt_str,
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());

    let html = fs::read_to_string(&receipt_path).unwrap();
    assert!(html.contains("data-bip39key-receipt=\"bip39key:1:bip39:nopass:hkdf:"));
    assert!(html.contains("auth=1"));
    assert!(html.contains("expires=2000000000"));
    assert!(html.contains("data-bip39key-fingerprint="));
    assert!(html.contains("data-bip39key-subkey-fingerprints=\"encrypt="));
    assert!(html.contains(",auth="));
    // The receipt must not contain the mnemonic.
    assert!(!html.contains(&BIP39.join(" ")));

    // Regenerate from the receipt alone: no -u or derivation flags. The
    // key has no passphrase, so the output bytes are deterministic.
    let regen = run_bip39key_raw(
        BIP39,
        &["--from-receipt", receipt_str, "-o", key2.to_str().unwrap()],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(fs::read(&key1).unwrap(), fs::read(&key2).unwrap());
}

#[test]
fn test_receipt_detects_wrong_seed() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();
    let key1 = tmp.path().join("key1.gpg");
    let key2 = tmp.path().join("key2.gpg");

    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "--output-receipt",
            receipt_str,
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());

    let wrong: Vec<&str> =
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
            .split(' ')
            .collect();
    let regen = run_bip39key_raw(
        &wrong,
        &["--from-receipt", receipt_str, "-o", key2.to_str().unwrap()],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(
        stderr.contains("Fingerprint mismatch"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_receipt_rejects_user_id_override() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();

    let output = run_bip39key(
        BIP39,
        &userid(),
        &["-g", "hkdf", "--output-receipt", receipt_str],
    )
    .unwrap();
    assert!(output.status.success());

    // Every flag the receipt supplies is rejected, not silently overridden.
    for flags in [
        ["-u", "Other <other@test.com>"],
        ["-f", "ssh"],
        ["-g", "xor"],
        ["-y", "2100000000"],
        ["-s", "electrum"],
    ] {
        let regen =
            run_bip39key_raw(BIP39, &[flags[0], flags[1], "--from-receipt", receipt_str]).unwrap();
        assert!(!regen.status.success(), "{:?} was accepted", flags);
        let stderr = String::from_utf8_lossy(&regen.stderr);
        assert!(
            stderr.contains("cannot be used with"),
            "{:?}: stderr: {}",
            flags,
            stderr
        );
    }
    for flag in ["-j", "-r", "-b", "-n", "--auth-subkey"] {
        let regen = run_bip39key_raw(BIP39, &[flag, "--from-receipt", receipt_str]).unwrap();
        assert!(!regen.status.success(), "{} was accepted", flag);
        let stderr = String::from_utf8_lossy(&regen.stderr);
        assert!(
            stderr.contains("cannot be used with"),
            "{}: stderr: {}",
            flag,
            stderr
        );
    }

    let regen = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "Other <other@test.com>",
            "--from-receipt",
            receipt_str,
        ],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(stderr.contains("cannot be used with"), "stderr: {}", stderr);
}

#[test]
fn test_ssh_receipt_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();
    let key1 = tmp.path().join("key1.ssh");
    let key2 = tmp.path().join("key2.ssh");

    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "-f",
            "ssh",
            "--output-receipt",
            receipt_str,
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());

    let html = fs::read_to_string(&receipt_path).unwrap();
    assert!(html.contains("format=ssh"));
    assert!(html.contains("SSH Key Fingerprint"));

    let regen = run_bip39key_raw(
        BIP39,
        &["--from-receipt", receipt_str, "-o", key2.to_str().unwrap()],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(fs::read(&key1).unwrap(), fs::read(&key2).unwrap());

    // The regenerated key is a valid SSH key.
    let keygen = run_ssh_keygen(&fs::read(&key2).unwrap(), "").unwrap();
    assert!(keygen.status.success());
}

/// Extract the receipt string from an HTML receipt, as a user copying it
/// from the page (or scanning the QR code) would.
fn receipt_string_from_html(html: &str) -> String {
    let start = html.find("data-bip39key-receipt=\"").unwrap() + "data-bip39key-receipt=\"".len();
    let end = html[start..].find('"').unwrap();
    html[start..start + end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

#[test]
fn test_receipt_withpass_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();
    let key1 = tmp.path().join("key1.gpg");
    let key2 = tmp.path().join("key2.gpg");

    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "-p",
            "correct horse",
            "--output-receipt",
            receipt_str,
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());
    let html = fs::read_to_string(&receipt_path).unwrap();
    assert!(html.contains(":withpass:"));
    assert!(!html.contains("correct horse"));

    // No passphrase at all: refused before deriving anything.
    let regen = run_bip39key_raw(
        BIP39,
        &["--from-receipt", receipt_str, "-o", key2.to_str().unwrap()],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(
        stderr.contains("records that a passphrase was used"),
        "stderr: {}",
        stderr
    );

    // Wrong passphrase: derives a different key, caught by the fingerprint.
    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt_str,
            "-p",
            "wrong horse",
            "-o",
            key2.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(
        stderr.contains("Fingerprint mismatch"),
        "stderr: {}",
        stderr
    );

    // Right passphrase: succeeds and the key imports into GPG.
    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt_str,
            "-p",
            "correct horse",
            "-o",
            key2.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    let gpg = Gpg::new();
    gpg.import(&fs::read(&key2).unwrap(), None, Some("correct horse"));
    // GPG must agree with the receipt on both the primary and the encrypt
    // subkey fingerprints.
    let keysout = gpg.run(&["--with-colons", "--list-keys"], None).unwrap();
    let gpg_fprs: Vec<String> = String::from_utf8_lossy(&keysout.stdout)
        .lines()
        .filter(|l| l.starts_with("fpr:"))
        .map(|l| l.split(':').nth(9).unwrap().to_string())
        .collect();
    let attr = |name: &str| {
        let marker = format!("{name}=\"");
        let start = html.find(&marker).unwrap() + marker.len();
        let end = html[start..].find('"').unwrap();
        html[start..start + end].to_string()
    };
    let receipt_fp = attr("data-bip39key-fingerprint");
    let encrypt_fp = attr("data-bip39key-subkey-fingerprints")
        .strip_prefix("encrypt=")
        .unwrap()
        .to_string();
    assert_eq!(gpg_fprs, vec![receipt_fp, encrypt_fp]);
}

#[test]
fn test_receipt_raw_string_default_algorithm() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let raw_path = tmp.path().join("receipt.txt");
    let key1 = tmp.path().join("key1.gpg");
    let key2 = tmp.path().join("key2.gpg");

    // Default algorithm (xor), no passphrase.
    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "--output-receipt",
            receipt_path.to_str().unwrap(),
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());
    let html = fs::read_to_string(&receipt_path).unwrap();
    let receipt_string = receipt_string_from_html(&html);
    assert!(receipt_string.starts_with("bip39key:1:bip39:nopass:xor:"));
    fs::write(&raw_path, format!("{receipt_string}\n")).unwrap();

    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            raw_path.to_str().unwrap(),
            "-o",
            key2.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(fs::read(&key1).unwrap(), fs::read(&key2).unwrap());
}

#[test]
fn test_receipt_concat_flag() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");
    let receipt_str = receipt_path.to_str().unwrap();
    let key1 = tmp.path().join("key1.gpg");
    let key2 = tmp.path().join("key2.gpg");

    // The deprecated -c flag is recorded as the concat algorithm.
    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-c",
            "--output-receipt",
            receipt_str,
            "-o",
            key1.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(output.status.success());
    let html = fs::read_to_string(&receipt_path).unwrap();
    assert!(receipt_string_from_html(&html).starts_with("bip39key:1:bip39:nopass:concat:"));

    let regen = run_bip39key_raw(
        BIP39,
        &["--from-receipt", receipt_str, "-o", key2.to_str().unwrap()],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(fs::read(&key1).unwrap(), fs::read(&key2).unwrap());
}

#[test]
fn test_receipt_rejects_colon_in_user_id() {
    let tmp = TempDir::new().unwrap();
    let receipt_path = tmp.path().join("receipt.html");

    let output = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "Alice (dept: sales) <alice@example.com>",
            "-g",
            "hkdf",
            "--output-receipt",
            receipt_path.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not contain ':'"),
        "stderr: {}",
        stderr
    );
    // Rejected before anything was written.
    assert!(!receipt_path.exists());

    // Without a receipt the same user ID is still fine.
    let output = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "Alice (dept: sales) <alice@example.com>",
            "-g",
            "hkdf",
        ],
    )
    .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_nopass_receipt_encrypts_with_the_given_passphrase() {
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.html");
    let receipt = receipt.to_str().unwrap();
    let key = tmp.path().join("key.ssh");
    let key = key.to_str().unwrap();

    let made = run_bip39key(
        BIP39,
        &userid(),
        &["-f", "ssh", "-g", "hkdf", "-r", "--output-receipt", receipt],
    )
    .unwrap();
    assert!(made.status.success());
    assert!(fs::read_to_string(receipt).unwrap().contains(":nopass:"));

    // The passphrase does not feed derivation (the fingerprint still
    // matches), but it must protect the regenerated file.
    let regen =
        run_bip39key_raw(BIP39, &["--from-receipt", receipt, "-p", PASS, "-o", key]).unwrap();
    assert!(
        regen.status.success(),
        "{}",
        String::from_utf8_lossy(&regen.stderr)
    );
    let bytes = fs::read(key).unwrap();
    assert!(
        run_ssh_keygen(&bytes, "").is_err(),
        "key file is not encrypted"
    );
    run_ssh_keygen(&bytes, PASS).unwrap();
}

#[test]
fn test_receipt_paths_must_not_collide() {
    // Rejected in validate(), before the seed is read.
    let output = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "-o",
            "same.out",
            "--output-receipt",
            "same.out",
        ],
    );
    assert!(
        output.is_err(),
        "-o and --output-receipt on one path was accepted"
    );
    assert!(!Path::new("same.out").exists());

    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.txt");
    let receipt = receipt.to_str().unwrap();
    fs::write(
        receipt,
        "bip39key:1:bip39:nopass:hkdf:Satoshi Nakamoto <satoshin@gmx.com>:C816",
    )
    .unwrap();
    let regen = run_bip39key_raw(BIP39, &["--from-receipt", receipt, "-o", receipt]).unwrap();
    assert!(!regen.status.success());
    assert!(String::from_utf8_lossy(&regen.stderr).contains("overwrite the receipt"));
    assert!(fs::read_to_string(receipt)
        .unwrap()
        .starts_with("bip39key:1:"));
}

#[test]
fn test_raw_receipt_string_warns_on_stderr_without_a_tty() {
    // A raw receipt string has no fingerprint, so nothing checks the result.
    // Tests run without a TTY, like scripts: the warning must still appear.
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.txt");
    let receipt = receipt.to_str().unwrap();
    let made = run_bip39key(
        BIP39,
        &userid(),
        &[
            "-g",
            "hkdf",
            "-r",
            "--output-receipt",
            tmp.path().join("r.html").to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(made.status.success());
    let html = fs::read_to_string(tmp.path().join("r.html")).unwrap();
    let start = html.find("data-bip39key-receipt=\"").unwrap() + "data-bip39key-receipt=\"".len();
    let raw = html[start..start + html[start..].find('"').unwrap()]
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    fs::write(receipt, raw).unwrap();

    let regen = run_bip39key_raw(BIP39, &["--from-receipt", receipt]).unwrap();
    assert!(regen.status.success());
    assert!(
        String::from_utf8_lossy(&regen.stderr).contains("carries no fingerprint"),
        "no warning on stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(regen.stdout, made.stdout);
}

#[test]
fn test_missing_user_id_is_a_usage_error() {
    let output = run_bip39key_raw(BIP39, &["-g", "hkdf"]).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--user-id"));
}

#[test]
fn test_receipt_and_key_spelled_differently_are_the_same_file() {
    // "-o ./k --output-receipt k" used to write the key and then replace it
    // with the receipt. Rejected before derivation, so this is fast.
    let tmp = TempDir::new().unwrap();
    let plain = tmp.path().join("k");
    let respelled = tmp.path().join(".").join("k");
    let output = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "A <a@b>",
            "-g",
            "hkdf",
            "-o",
            respelled.to_str().unwrap(),
            "--output-receipt",
            plain.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("same file"), "{stderr}");
    assert!(!plain.exists(), "something was written");
}

#[test]
fn test_unwritable_receipt_leaves_no_key_behind() {
    // The receipt is written before the key, so a receipt that cannot be
    // written must not leave a secret key on disk next to a failed exit.
    let tmp = TempDir::new().unwrap();
    let key = tmp.path().join("key.gpg");
    let receipt = tmp.path().join("no-such-dir").join("receipt.html");
    let output = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "Alice <alice@example.com>",
            "-g",
            "hkdf",
            "-r",
            "-o",
            key.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Cannot write receipt"), "{stderr}");
    assert!(
        !key.exists(),
        "the key was written before the receipt failed"
    );
}

#[test]
fn test_receipt_without_subkey_fingerprints_is_rejected() {
    // A receipt whose subkey list was stripped must not report a match on the
    // primary fingerprint alone. The raw receipt string, which has no
    // fingerprints at all, recovers the same key even when its user ID
    // contains the HTML attribute name.
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.html");
    let key = tmp.path().join("key.gpg");
    let user_id = "data-bip39key-receipt <a@b>";
    let made = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            user_id,
            "-g",
            "hkdf",
            "-r",
            "-o",
            key.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(made.status.success());
    let html = fs::read_to_string(&receipt).unwrap();

    let attr = "data-bip39key-subkey-fingerprints=\"";
    let start = html.find(attr).unwrap();
    let end = start + attr.len() + html[start + attr.len()..].find('"').unwrap() + 1;
    let stripped = tmp.path().join("stripped.html");
    fs::write(&stripped, format!("{}{}", &html[..start], &html[end..])).unwrap();
    let out = tmp.path().join("out.gpg");
    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            stripped.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(stderr.contains("no subkey fingerprints"), "{stderr}");
    assert!(!out.exists());

    let raw = tmp.path().join("receipt.txt");
    fs::write(&raw, receipt_string_from_html(&html)).unwrap();
    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            raw.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ],
    )
    .unwrap();
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(regen.status.success(), "{stderr}");
    assert!(stderr.contains("carries no fingerprint"), "{stderr}");
    assert_eq!(fs::read(&key).unwrap(), fs::read(&out).unwrap());
}

/// The public key text an HTML receipt carries.
fn public_key_from_html(html: &str) -> String {
    let attr = "data-bip39key-public-key=\"";
    let start = html.find(attr).unwrap() + attr.len();
    let end = html[start..].find('"').unwrap();
    html[start..start + end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

#[test]
fn test_receipt_carries_the_public_key() {
    // The receipt's public key is exactly what -k prints, for every format, so
    // the receipt alone is enough to use the key until it must be regenerated.
    for format_flags in [vec!["-a"], vec!["-f", "ssh"], vec!["-f", "age"]] {
        let tmp = TempDir::new().unwrap();
        let receipt = tmp.path().join("receipt.html");
        let key = tmp.path().join("key");
        let mut flags = vec!["-g", "hkdf", "-r", "-p", PASS];
        flags.extend(&format_flags);
        let mut generate = flags.clone();
        generate.extend([
            "-o",
            key.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ]);
        run_bip39key(BIP39, &userid(), &generate).unwrap();
        let mut public = flags.clone();
        public.push("-k");
        let expected = run_bip39key(BIP39, &userid(), &public).unwrap().stdout;

        let html = fs::read_to_string(&receipt).unwrap();
        assert_eq!(
            public_key_from_html(&html),
            String::from_utf8(expected).unwrap().trim_end(),
            "{format_flags:?}"
        );
        // Public half only.
        assert!(!html.contains("PRIVATE KEY"), "{format_flags:?}");
    }
}

#[test]
fn test_receipt_with_altered_public_key_is_rejected() {
    // Same fingerprints, different public key text: the receipt was damaged
    // or altered, and recovery must say so rather than report a match.
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.html");
    let key = tmp.path().join("key.gpg");
    let made = run_bip39key_raw(
        BIP39,
        &[
            "-u",
            "Alice <alice@example.com>",
            "-g",
            "hkdf",
            "-r",
            "-o",
            key.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(made.status.success());
    let html = fs::read_to_string(&receipt).unwrap();
    let altered = html.replacen(
        "data-bip39key-public-key=\"-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "data-bip39key-public-key=\"-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: altered",
        1,
    );
    assert_ne!(html, altered);
    fs::write(&receipt, altered).unwrap();

    let out = tmp.path().join("out.gpg");
    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!regen.status.success());
    let stderr = String::from_utf8_lossy(&regen.stderr);
    assert!(stderr.contains("public key in the receipt"), "{stderr}");
    assert!(!out.exists());
}

#[test]
fn test_age_receipt_roundtrip() {
    // An age key has no fingerprint; its recipient plays that part. The
    // regenerated identity must be the same file, and must open a message
    // encrypted to the recipient taken from the receipt.
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.html");
    let identity = tmp.path().join("identity.txt");
    let recovered = tmp.path().join("recovered.txt");
    run_bip39key(
        BIP39,
        &userid(),
        &[
            "-f",
            "age",
            "-g",
            "hkdf",
            "-r",
            "-p",
            PASS,
            "-o",
            identity.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ],
    )
    .unwrap();
    let html = fs::read_to_string(&receipt).unwrap();
    assert!(html.contains(
        "data-bip39key-receipt=\"bip39key:1:bip39:withpass:hkdf:argon=rfc9106:format=age:"
    ));
    let recipient = public_key_from_html(&html);
    assert!(recipient.starts_with("age1"), "{recipient}");
    assert!(html.contains(&format!("data-bip39key-fingerprint=\"{recipient}\"")));
    assert!(!html.contains("AGE-SECRET-KEY"));

    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt.to_str().unwrap(),
            "-p",
            PASS,
            "-o",
            recovered.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "{}",
        String::from_utf8_lossy(&regen.stderr)
    );
    let recovered_identity = fs::read(&recovered).unwrap();
    assert_eq!(fs::read(&identity).unwrap(), recovered_identity);
    assert_eq!(
        age_round_trip(&recipient, &recovered_identity, b"break glass"),
        b"break glass"
    );

    // The wrong passphrase gives a different key, which the receipt catches.
    let wrong = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt.to_str().unwrap(),
            "-p",
            "not the passphrase",
            "-o",
            tmp.path().join("wrong.txt").to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("Fingerprint mismatch"));
    assert!(!tmp.path().join("wrong.txt").exists());
}

#[test]
fn test_age_receipt_without_passphrase_takes_none() {
    // -n does not exist for age keys, so a receipt for an age key made
    // without a passphrase must refuse one outright: it could only change
    // the key.
    let tmp = TempDir::new().unwrap();
    let receipt = tmp.path().join("receipt.html");
    let identity = tmp.path().join("identity.txt");
    let recovered = tmp.path().join("recovered.txt");
    run_bip39key(
        BIP39,
        &userid(),
        &[
            "-f",
            "age",
            "-g",
            "hkdf",
            "-r",
            "-o",
            identity.to_str().unwrap(),
            "--output-receipt",
            receipt.to_str().unwrap(),
        ],
    )
    .unwrap();
    let html = fs::read_to_string(&receipt).unwrap();
    assert!(html.contains(":nopass:hkdf:argon=rfc9106:format=age:"));

    let with_passphrase = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt.to_str().unwrap(),
            "-p",
            PASS,
            "-o",
            recovered.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(!with_passphrase.status.success());
    let stderr = String::from_utf8_lossy(&with_passphrase.stderr);
    assert!(stderr.contains("made without a passphrase"), "{stderr}");
    assert!(!recovered.exists());

    let regen = run_bip39key_raw(
        BIP39,
        &[
            "--from-receipt",
            receipt.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
        ],
    )
    .unwrap();
    assert!(
        regen.status.success(),
        "{}",
        String::from_utf8_lossy(&regen.stderr)
    );
    assert_eq!(fs::read(&identity).unwrap(), fs::read(&recovered).unwrap());
}
