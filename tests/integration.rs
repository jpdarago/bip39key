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
