use crate::types::*;

use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;

fn put_u32(v: u32, out: &mut ByteCursor) -> Result<()> {
    out.write_u32::<BigEndian>(v)?;
    Ok(())
}

fn put_bytes(s: &[u8], out: &mut ByteCursor) -> Result<()> {
    put_u32(s.len().try_into()?, out)?;
    out.write_all(&s)?;
    Ok(())
}

fn put_string(s: &str, out: &mut ByteCursor) -> Result<()> {
    put_bytes(s.as_bytes(), out)
}

pub fn output_secret_as_pem<W: Write>(
    context: &Context,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    // See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    // for a detail of the contents of an OpenSSH private key.
    let mut cursor = ByteCursor::new(Vec::with_capacity(1024));
    cursor.write_all(b"openssh-key-v1\x00")?;
    // ciphername - none, no encryption.
    put_string("none", &mut cursor)?;
    // kdfname - none, no encryption.
    put_string("none", &mut cursor)?;
    // kdfoptions - none, no encryption.
    put_u32(0, &mut cursor)?;
    // 1 secret key.
    put_u32(1, &mut cursor)?;
    // Public key.
    let mut public_key = ByteCursor::new(Vec::with_capacity(512));
    put_string("ssh-ed25519", &mut public_key)?;
    put_bytes(context.sign_key.keypair.public.as_bytes(), &mut public_key)?;
    put_bytes(public_key.get_ref(), &mut cursor)?;
    // Private key.
    let mut private_key = ByteCursor::new(Vec::with_capacity(512));
    // checkint times 2.
    put_u32(0, &mut private_key)?;
    put_u32(0, &mut private_key)?;
    put_string("ssh-ed25519", &mut private_key)?;
    put_bytes(context.sign_key.keypair.public.as_bytes(), &mut private_key)?;
    let mut private_payload = ByteCursor::new(Vec::with_capacity(64));
    private_payload.write_all(&context.sign_key.keypair.secret.as_bytes()[..32])?;
    private_payload.write_all(context.sign_key.keypair.public.as_bytes())?;
    put_bytes(private_payload.get_mut(), &mut private_key)?;
    put_string(&context.user_id.user_id, &mut private_key)?;
    // Pad to 8 bytes.
    let content = private_key.get_mut();
    for i in 1..8 {
        if content.len() % 8 == 0 {
            break;
        }
        content.push(i as u8);
    }
    put_bytes(content, &mut cursor)?;
    // Output all.
    out.write_all(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")?;
    // Output as base64 encoded.
    out.write_all(textwrap::fill(&base64::encode(cursor.get_mut()), 70).as_bytes())?;
    out.write_all(b"\n-----END OPENSSH PRIVATE KEY-----\n")?;
    Ok(())
}
