use anyhow::Context;

use crate::types::*;
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::process::{Command, Stdio};

pub fn get_passphrase() -> Result<String> {
    let pinentry_executable =
        std::env::var("BIP39_PINENTRY").unwrap_or_else(|_| "pinentry".to_string());
    let pinentry = Command::new(&pinentry_executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not find executable {}, try using -p/--passphrase or use BIP39_PINENTRY env var to set the path.", pinentry_executable))?;
    let stdout = pinentry
        .stdout
        .ok_or_else(|| Error::new(ErrorKind::Other, "Could not capture standard output"))?;
    let mut stdin = pinentry
        .stdin
        .ok_or_else(|| Error::new(ErrorKind::Other, "Could not pipe to pinentry"))?;
    let mut reader = BufReader::new(stdout);
    let input = &[
        "SETREPEAT",
        "SETTITLE bip39key",
        "SETPROMPT BIP39 Key",
        "SETDESC Please input your passphrase",
        "GETPIN",
        "",
    ]
    .join("\n");
    stdin.write_all(input.as_bytes())?;
    let mut result = String::new();
    'top: loop {
        let mut line = String::new();
        loop {
            reader.read_line(&mut line)?;
            if line.starts_with("OK closing connection") {
                break 'top;
            }
            if !line.starts_with("OK ") {
                break;
            }
            line.clear();
        }
        if let Some(pass) = line.strip_prefix("D ") {
            stdin.write_all(b"BYE\n")?;
            result = pass.trim().to_string();
        } else if line.strip_prefix("ERR 83886179").is_some() {
            eprintln!("Passphrases do not match. Try again");
            stdin.write_all(input.as_bytes())?;
        }
    }
    Ok(result.trim().to_string())
}
