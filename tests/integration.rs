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
            .stderr_capture();
        match stdin {
            Some(data) => expr.stdin_bytes(data.to_vec()).run(),
            None => expr.run(),
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
