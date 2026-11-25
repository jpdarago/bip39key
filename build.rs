use clap::CommandFactory;
use clap_complete::{generate, Shell};
use clap_mangen::Man;
use std::fs;
use std::path::Path;

include!("src/cli.rs");

fn git(args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// `HEAD` as a full hash, with `-dirty` appended when the sources differ from
/// it. A receipt must not claim a clean commit reproduces a binary that was
/// built from modified sources.
///
/// Returns `None` unless this package is the root of the git repository. git
/// walks up to any enclosing repository, so a source tree unpacked inside
/// someone else's repo (a vendored copy, ~/.cargo under a dotfiles repo)
/// would otherwise report that repo's unrelated HEAD as bip39key's commit.
fn git_commit() -> Option<String> {
    let toplevel = git(&["rev-parse", "--show-toplevel"])?;
    let same_dir = match (
        fs::canonicalize(&toplevel),
        fs::canonicalize(env!("CARGO_MANIFEST_DIR")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same_dir {
        return None;
    }
    let head = git(&["rev-parse", "HEAD"])?;
    // Tracked changes anywhere, plus untracked files where they can change
    // the binary: a new src/*.rs file is compiled without ever being added.
    let dirty = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ".",
        ":(exclude)target",
    ])
    .is_some_and(|status| {
        status.lines().any(|line| {
            !line.starts_with("??") || {
                let path = line[2..].trim_start();
                path.starts_with("src/")
                    || path.starts_with("resources/")
                    || path == "build.rs"
                    || path == "Cargo.toml"
            }
        })
    });
    Some(if dirty { format!("{head}-dirty") } else { head })
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // Embed the git commit hash at compile time for receipt provenance. An
    // explicit BIP39KEY_COMMIT environment variable wins over git: builds from
    // a source tree without .git (Nix sandbox, source tarballs) can inject the
    // commit and still produce an identical binary.
    let commit = std::env::var("BIP39KEY_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(git_commit)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BIP39KEY_COMMIT={}", commit);
    println!("cargo:rerun-if-env-changed=BIP39KEY_COMMIT");
    println!(
        "cargo:rustc-env=BIP39KEY_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
    // Re-run when anything compiled into the binary changes, so the dirty
    // marker tracks the working tree rather than the last build. resources/
    // is here because seed.rs embeds the wordlist with include_str!.
    for path in ["src", "resources", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    // Re-run when HEAD moves. git is asked where these live, because .git is
    // a file in a worktree and absent in a source tarball. Paths that do not
    // exist are skipped: cargo treats a missing path as always changed, which
    // would rerun this script, and recompile the crate, on every build.
    for name in ["HEAD", "index", "packed-refs", "refs"] {
        if let Some(path) = git(&["rev-parse", "--git-path", name]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }

    let mut cmd = Args::command();
    cmd = cmd.name("bip39key");

    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let completions_dir = out_dir.join("completions");
    fs::create_dir_all(&completions_dir)?;

    for shell in [Shell::Bash, Shell::Zsh] {
        let mut buf = Vec::new();
        generate(shell, &mut cmd, "bip39key", &mut buf);
        let ext = match shell {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            _ => unreachable!(),
        };
        fs::write(completions_dir.join(format!("bip39key.{ext}")), buf)?;
    }

    let man_dir = out_dir.join("man");
    fs::create_dir_all(&man_dir)?;

    let man = Man::new(cmd);
    let mut buf = Vec::new();
    man.render(&mut buf)?;

    buf.extend_from_slice(
        r#".SH "KEY DERIVATION"
The seed phrase (BIP39 or Electrum) is expanded from 128\-256 bits to 512 bits
using Argon2id, with the user ID as the salt. If a passphrase is provided, it
is combined with the seed before derivation (except with the \fBxor\fR
algorithm, which hashes them separately).
.PP
The resulting 512 bits are then split into an Ed25519 signing key and a
Curve25519 encryption key. For OpenPGP output, both keys are emitted (unless
\fB\-\-just\-signkey\fR is set). For OpenSSH output, only the Ed25519 signing
key is used.
.PP
The \fB\-\-algorithm\fR flag controls how the seed and passphrase are combined:
.SS "hkdf (recommended)"
Concatenates the seed and passphrase, applies Argon2id, then uses HKDF\-Expand
(RFC 5869) with distinct info strings (\fIbip39key\-sign\-v1\fR and
\fIbip39key\-encrypt\-v1\fR) to derive independent signing and encryption keys.
This provides proper domain separation between key types.
.PP
\fBAll new keys should use \-\-algorithm hkdf.\fR
.SS "concat (deprecated)"
Concatenates the seed and passphrase, applies Argon2id, and splits the output
at a fixed byte offset. Lacks domain separation between key types.
.SS "xor (deprecated, current default)"
Applies Argon2id separately to the seed and the passphrase, then XORs the two
results. This has a known weakness: if an attacker obtains the passphrase and
the output key, they can recover the hashed seed and attempt to brute\-force
the input seed phrase.
.PP
The \fBxor\fR algorithm remains the default only for backward compatibility with
existing keys. It will be replaced by \fBhkdf\fR as the default in a future
major version.
.SH "DEPRECATED OPTIONS"
The following options are deprecated and should not be used for new keys:
.TP
\fB\-c\fR, \fB\-\-use\-concatenation\fR
Equivalent to \fB\-\-algorithm concat\fR. Use \fB\-\-algorithm\fR directly instead.
.TP
\fB\-t\fR, \fB\-\-timestamp\fR
Renamed to \fB\-\-creation\-timestamp\fR (\fB\-d\fR).
.TP
\fB\-q\fR, \fB\-\-interactive\fR
No longer needed. Interactive mode is now automatically enabled when stdin is a
terminal.
.SH "ENVIRONMENT"
.TP
\fBWORDLIST_BIP39\fR
Path to a custom BIP39 wordlist file. Must contain one word per line in the same
format as the bundled English wordlist. If unset, the bundled wordlist is used.
.TP
\fBBIP39_PINENTRY\fR
Path to the pinentry executable used by \fB\-\-pinentry\fR. Defaults to
\fBpinentry\fR.
.TP
\fBNO_INTERACTIVE_OUTPUT\fR
Set to \fB1\fR to suppress all informational output (welcome message, warnings,
fingerprint) even when stdout is a terminal. Useful for scripting.
.SH "EXAMPLES"
Generate a PGP key pair using the recommended algorithm, reading the seed from
a file:
.PP
.nf
bip39key \-\-algorithm hkdf \-u "Alice <alice@example.com>" \-i seed.txt
.fi
.PP
Generate an armored PGP public key:
.PP
.nf
bip39key \-\-algorithm hkdf \-u "Alice <alice@example.com>" \-i seed.txt \-ak
.fi
.PP
Generate an SSH key with a passphrase provided via pinentry:
.PP
.nf
bip39key \-\-algorithm hkdf \-u "Alice <alice@example.com>" \-f ssh \-e \-i seed.txt
.fi
.PP
Pipe a seed phrase from another program:
.PP
.nf
echo "abandon abandon ... about" | bip39key \-\-algorithm hkdf \-u "Alice <alice@example.com>"
.fi
.PP
Generate a PGP key with an expiration date (Unix timestamp):
.PP
.nf
bip39key \-\-algorithm hkdf \-u "Alice <alice@example.com>" \-y 1893456000 \-i seed.txt
.fi
.SH "EXIT STATUS"
.TP
\fB0\fR
Successful key generation.
.TP
\fB1\fR
Error (invalid arguments, unreadable input, passphrase mismatch, etc.).
.SH "SEE ALSO"
\fBgpg\fR(1), \fBssh\-keygen\fR(1)
"#
        .as_bytes(),
    );

    fs::write(man_dir.join("bip39key.1"), buf)?;

    update_readme_usage(&out_dir.join("README.md"))?;

    Ok(())
}

const USAGE_BEGIN: &str =
    "<!-- BEGIN USAGE: generated by build.rs from src/cli.rs on every build; do not edit -->";
const USAGE_END: &str = "<!-- END USAGE -->";

/// Rewrite the usage block in README.md with the current `--help` text, so it
/// cannot drift from src/cli.rs. CI fails if the committed README differs
/// from what this writes. A README without the markers (a packaged source
/// tree may not ship one) is left alone, and nothing is written when the
/// block is already current.
fn update_readme_usage(readme: &Path) -> std::io::Result<()> {
    let Ok(current) = fs::read_to_string(readme) else {
        return Ok(());
    };
    let (Some(begin), Some(end)) = (current.find(USAGE_BEGIN), current.find(USAGE_END)) else {
        return Ok(());
    };
    if end < begin {
        return Ok(());
    }
    let help = Args::command()
        .name("bip39key")
        .render_long_help()
        .to_string();
    let updated = format!(
        "{}{USAGE_BEGIN}\n```\n{}\n```\n{}",
        &current[..begin],
        help.trim_end(),
        &current[end..]
    );
    if updated != current {
        fs::write(readme, updated)?;
    }
    Ok(())
}
