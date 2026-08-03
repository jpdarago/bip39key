use anyhow::Context;

use crate::types::*;
use inquire::{Confirm, Password};
use std::io::{BufRead, BufReader, Error, Write};
use std::process::{Command, Stdio};

/// One complete Assuan response: any `D` data lines followed by `OK`/`ERR`.
enum Response {
    Ok(Option<String>),
    Err(String),
}

/// Read one Assuan response, collecting `D` data (raw, undecoded) until the
/// terminating `OK` or `ERR` line. Status (`S`) and comment (`#`) lines are
/// ignored.
fn read_response<R: BufRead>(reader: &mut R) -> Result<Response> {
    let mut data: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            anyhow::bail!("pinentry closed the connection unexpectedly");
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(d) = line.strip_prefix("D ") {
            // Do not trim: everything after "D " is passphrase data.
            data = Some(d.to_string());
        } else if line == "OK" || line.starts_with("OK ") {
            return Ok(Response::Ok(data));
        } else if line.starts_with("ERR ") {
            return Ok(Response::Err(line.to_string()));
        }
    }
}

/// Decode Assuan percent-escapes (`%25`, `%0A`, `%0D`, ...). pinentry escapes
/// `%`, CR, and LF in `D` lines; decoding any `%XX` sequence covers all of
/// them. Without this, a passphrase containing such bytes derives a
/// different key via pinentry than via the interactive prompt.
fn assuan_decode(data: &str) -> String {
    let bytes = data.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&data[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Get a passphrase from a pinentry program. Returns the empty string when
/// the user submits an empty passphrase; errors when the user cancels the
/// dialog or pinentry fails.
pub fn from_pinentry() -> Result<String> {
    let pinentry_executable =
        std::env::var("BIP39_PINENTRY").unwrap_or_else(|_| "pinentry".to_string());
    let mut child = Command::new(&pinentry_executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not find executable {}, try using -p/--passphrase or use BIP39_PINENTRY env var to set the path.", pinentry_executable))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("Could not capture standard output"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::other("Could not pipe to pinentry"))?;
    let mut reader = BufReader::new(stdout);

    // Greeting.
    if let Response::Err(err) = read_response(&mut reader)? {
        anyhow::bail!("pinentry greeting failed: {}", err);
    }

    // UI setup is best-effort: an ERR here (e.g. SETREPEAT unsupported by an
    // old pinentry) must not abort passphrase entry.
    for command in [
        "SETREPEAT",
        "SETTITLE bip39key",
        "SETPROMPT BIP39 Key",
        "SETDESC Please input your passphrase",
    ] {
        writeln!(stdin, "{}", command)?;
        stdin.flush()?;
        let _ = read_response(&mut reader)?;
    }

    writeln!(stdin, "GETPIN")?;
    stdin.flush()?;
    let response = read_response(&mut reader)?;
    let _ = writeln!(stdin, "BYE");
    match response {
        Response::Ok(data) => Ok(data.map(|d| assuan_decode(&d)).unwrap_or_default()),
        Response::Err(err) => {
            // 83886179 is GPG_ERR_CANCELED from the pinentry error source.
            if err.contains("83886179") || err.to_lowercase().contains("cancel") {
                anyhow::bail!("Passphrase entry was cancelled");
            }
            anyhow::bail!("pinentry failed: {}", err);
        }
    }
}

pub fn from_interactive_prompt() -> Result<String> {
    loop {
        let password = Password::new("Enter your password:").prompt()?;
        if !password.is_empty() {
            return Ok(password);
        }
        if Confirm::new("The password is empty, are you sure about this?").prompt()? {
            return Ok(password);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assuan_decode() {
        assert_eq!(assuan_decode("plain"), "plain");
        assert_eq!(assuan_decode("pass%25word"), "pass%word");
        assert_eq!(assuan_decode("line%0Abreak"), "line\nbreak");
        assert_eq!(assuan_decode("cr%0Dhere"), "cr\rhere");
        // Trailing or malformed escapes pass through unchanged.
        assert_eq!(assuan_decode("dangling%2"), "dangling%2");
        assert_eq!(assuan_decode("not%zzhex"), "not%zzhex");
        // Trailing spaces are preserved (no trimming).
        assert_eq!(assuan_decode("spaces  "), "spaces  ");
    }

    #[test]
    fn test_read_response() {
        let mut input = "S KEYINFO fake\nD secret%25pass\nOK\n".as_bytes();
        match read_response(&mut input).unwrap() {
            Response::Ok(Some(d)) => assert_eq!(d, "secret%25pass"),
            _ => panic!("expected data response"),
        }
        let mut cancel = "ERR 83886179 Operation cancelled <Pinentry>\n".as_bytes();
        assert!(matches!(
            read_response(&mut cancel).unwrap(),
            Response::Err(_)
        ));
    }
}
