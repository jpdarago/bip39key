use crate::types::*;

use aes::cipher::{KeyIvInit, StreamCipher};
use bcrypt_pbkdf::bcrypt_pbkdf;
use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use rand::RngCore;
use std::io::Write;

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

fn put_u32(v: u32, out: &mut ByteCursor) -> Result<()> {
    out.write_u32::<BigEndian>(v)?;
    Ok(())
}

fn put_bytes(s: &[u8], out: &mut ByteCursor) -> Result<()> {
    put_u32(s.len().try_into()?, out)?;
    out.write_all(s)?;
    Ok(())
}

fn put_string(s: &str, out: &mut ByteCursor) -> Result<()> {
    put_bytes(s.as_bytes(), out)
}

fn put_public_key(context: &Context, cursor: &mut ByteCursor) -> Result<()> {
    let mut public_key = ByteCursor::new(Vec::with_capacity(512));
    put_string("ssh-ed25519", &mut public_key)?;
    put_bytes(context.sign_key.keypair.public.as_bytes(), &mut public_key)?;
    put_bytes(public_key.get_ref(), cursor)?;
    Ok(())
}

fn pad(padding: usize, content: &mut Vec<u8>) {
    for i in 1..padding {
        if content.len() % padding == 0 {
            break;
        }
        content.push(i as u8);
    }
}

fn put_kdfoptions(salt: &[u8], rounds: u32, cursor: &mut ByteCursor) -> Result<()> {
    let mut tmp = ByteCursor::new(vec![]);
    put_bytes(salt, &mut tmp)?;
    put_u32(rounds, &mut tmp)?;
    put_bytes(tmp.get_mut(), cursor)?;
    Ok(())
}

fn put_private_key_payload(context: &Context, check: u32, cursor: &mut ByteCursor) -> Result<()> {
    // checkint times 2.
    put_u32(check, cursor)?;
    put_u32(check, cursor)?;
    put_string("ssh-ed25519", cursor)?;
    put_bytes(context.sign_key.keypair.public.as_bytes(), cursor)?;
    let mut private_payload = ByteCursor::new(Vec::with_capacity(64));
    private_payload.write_all(context.sign_key.keypair.secret.as_bytes())?;
    private_payload.write_all(context.sign_key.keypair.public.as_bytes())?;
    put_bytes(private_payload.get_mut(), cursor)?;
    let mut comment = context.user_id.user_id.clone();
    comment.push_str(" - ");
    comment.push_str(&context.metadata.data);
    put_string(&comment, cursor)?;
    Ok(())
}

fn put_ssh_key_with_passphrase(
    context: &Context,
    passphrase: &str,
    cursor: &mut ByteCursor,
) -> Result<()> {
    // ciphername - AES256 CTR mode.
    put_string("aes256-ctr", cursor)?;
    // kdfname - bcrypt.
    put_string("bcrypt", cursor)?;
    // Get a seed.
    let mut randbuf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut randbuf);
    let salt = &randbuf[..16];
    let check = LittleEndian::read_u32(&randbuf[16..20]);
    let rounds = 64;
    // kdfoptions - salt and rounds.
    put_kdfoptions(salt, rounds, cursor)?;
    // 1 secret key.
    put_u32(1, cursor)?;
    put_public_key(context, cursor)?;
    let mut private_key = ByteCursor::new(Vec::with_capacity(512));
    put_private_key_payload(context, check, &mut private_key)?;
    let content = private_key.get_mut();
    pad(16, content);
    // Run BCrypt to build the key and IV for AES 256 cipher, and encrypt the private key
    // buffer with it.
    let mut buf = [0u8; 48];
    bcrypt_pbkdf(passphrase, salt, rounds, &mut buf)?;
    let mut stream = Aes256Ctr::new(buf[..32].into(), buf[32..].into());
    stream.apply_keystream(content);
    put_bytes(content, cursor)?;
    Ok(())
}

fn put_ssh_key_without_passphrase(context: &Context, cursor: &mut ByteCursor) -> Result<()> {
    // ciphername - none, no encryption.
    put_string("none", cursor)?;
    // kdfname - none, no encryption.
    put_string("none", cursor)?;
    // kdfoptions - none, no encryption.
    put_u32(0, cursor)?;
    // 1 secret key.
    put_u32(1, cursor)?;
    put_public_key(context, cursor)?;
    let mut private_key = ByteCursor::new(Vec::with_capacity(512));
    put_private_key_payload(context, /*check=*/ 0, &mut private_key)?;
    let content = private_key.get_mut();
    pad(8, content);
    put_bytes(content, cursor)?;
    Ok(())
}

pub fn output_secret_as_pem<W: Write>(
    context: &Context,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    // See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    // for a detail of the contents of an OpenSSH private key.
    out.write_all(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")?;
    let mut cursor = ByteCursor::new(Vec::with_capacity(1024));
    cursor.write_all(b"openssh-key-v1\x00")?;
    if let Some(passphrase) = &context.passphrase {
        put_ssh_key_with_passphrase(context, passphrase, &mut cursor)?;
    } else {
        put_ssh_key_without_passphrase(context, &mut cursor)?;
    }
    // Output as base64 encoded.
    out.write_all(textwrap::fill(&base64::encode(cursor.get_mut()), 70).as_bytes())?;
    out.write_all(b"\n-----END OPENSSH PRIVATE KEY-----\n")?;
    Ok(())
}
