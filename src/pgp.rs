use crate::types::*;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use ed25519_dalek::Signer;
use rand::RngCore;
use sha2::Digest;
use std::io::Write;

type Aes256Cfb = cfb_mode::Encryptor<aes::Aes256>;

pub enum PacketType {
    PrivateEncryptSubkey,
    PrivateSignKey,
    PublicSignKey,
    PublicSubKey,
    Signature,
    UserId,
}

fn s2k_byte_count(count: u8) -> usize {
    (16 + ((count & 15) as usize)) << (((count >> 4) as usize) + 6)
}

fn hash_u16(n: u16, hasher: &mut sha2::Sha256) {
    let mut buf = [0; 2];
    BigEndian::write_u16(&mut buf, n);
    hasher.update(buf);
}

fn hash_u32(n: u32, hasher: &mut sha2::Sha256) {
    let mut buf = [0; 4];
    BigEndian::write_u32(&mut buf, n);
    hasher.update(buf);
}

// Encode the contents of the byte buffer as a PGP packet of the given type.
fn output_as_packet(
    packet_type: PacketType,
    packet_bytes: &[u8],
    out: &mut ByteCursor,
) -> Result<()> {
    let type_byte: u8 = 0xc0
        | match packet_type {
            PacketType::PrivateEncryptSubkey => 7,
            PacketType::PrivateSignKey => 5,
            PacketType::PublicSignKey => 6,
            PacketType::PublicSubKey => 14,
            PacketType::Signature => 2,
            PacketType::UserId => 13,
        };
    out.write_all(&[type_byte])?;
    let length = packet_bytes.len();
    match length {
        0..=191 => {
            out.write_all(&[(length & 0xFF) as u8])?;
        }
        192..=8383 => {
            let first_byte: u8 = (((length & !0xFF) >> 8) + 192).try_into()?;
            let second_byte: u8 = ((length & 0xFF) - 192).try_into()?;
            out.write_all(&[first_byte, second_byte])?;
        }
        _ => {
            out.write_all(&[255])?;
            out.write_u32::<BigEndian>(length.try_into()?)?;
        }
    };
    out.write_all(packet_bytes)?;
    Ok(())
}

// Encode buffer as MPI (Multi Precision Intenger), defined in OpenPGP RFC 4880.
fn mpi_encode(data: &[u8]) -> Vec<u8> {
    let mut slice = data;
    // Remove all leading zeroes.
    while !slice.is_empty() && slice[0] == 0 {
        slice = &slice[1..];
    }
    if slice.is_empty() {
        return vec![0, 0];
    }
    let mut vec = Vec::with_capacity(slice.len() + 2);
    let c = slice.len() * 8 - (slice[0].leading_zeros() as usize);
    vec.push(((c >> 8) & 0xFF) as u8);
    vec.push((c & 0xFF) as u8);
    vec.extend_from_slice(slice);
    vec
}

fn s2k_key(passphrase: &str, salt: &[u8], count: usize) -> Vec<u8> {
    let mut hash = sha2::Sha256::new();
    // The implementation follows what GPG does, not the OpenPGP spec in the RFC.
    // See report by skeeto@ (https://dev.gnupg.org/T4676).
    let mut buf = vec![0u8; passphrase.len() + salt.len()];
    buf[..salt.len()].copy_from_slice(salt);
    buf[salt.len()..].copy_from_slice(passphrase.as_bytes());
    let iterations = count / buf.len();
    for _ in 0..iterations {
        hash.update(&buf);
    }
    let tail = count - iterations * buf.len();
    hash.update(&buf[..tail]);
    hash.finalize().to_vec()
}

fn s2k_encrypt(key: &[u8], passphrase: &str, out: &mut ByteCursor) -> Result<()> {
    let mut salt_and_iv = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt_and_iv);
    let max_s2k_count = s2k_byte_count(0xFF);
    let salt = &salt_and_iv[..8];
    let iv = &salt_and_iv[8..];
    let encrypt_key = s2k_key(passphrase, salt, max_s2k_count);
    let mut data = mpi_encode(key);
    // Compute SHA1 and append it as HMAC to the data.
    let mut mac = sha1::Sha1::new();
    mac.update(&data);
    data.extend(mac.finalize());
    // Encrypt data using AES.
    Aes256Cfb::new(encrypt_key.as_slice().into(), iv.into()).encrypt(&mut data);
    // S2K Encrypted. AES256, Iterated and Salted S2k, SHA-256
    out.write_all(&[254, 9, 3, 8])?;
    out.write_all(salt)?;
    // Max S2K byte.
    out.write_all(&[0xFF])?;
    out.write_all(iv)?;
    out.write_all(&data)?;
    Ok(())
}

// Returns the PGP checksum for a data buffer, defined in OpenPGP RFC 4880.
fn checksum(buffer: &[u8]) -> u16 {
    let mut result: u32 = 0;
    for &byte in buffer {
        result = (result + (byte as u32)) % 65536;
    }
    result as u16
}

// Outputs the user id as a PGP user id packet.
fn output_user_id(user_id: &UserId, out: &mut ByteCursor) -> Result<()> {
    output_as_packet(PacketType::UserId, user_id.user_id.as_bytes(), out)
}

fn public_subkey_payload(key: &EncryptKey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.created_timestamp_secs)?;
    cursor.write_all(&[18])?; // Elliptic Curve Diffie-Hellmann.
    let oid: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    cursor.write_u16::<BigEndian>(263)?;
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key.to_bytes())?;
    // KDF parameters. Length, Reserved, SHA-256, AES-256.
    cursor.write_all(&[3, 1, 8, 9])?;
    Ok(cursor.get_mut().to_vec())
}

fn output_public_subkey(key: &EncryptKey, cursor: &mut ByteCursor) -> Result<()> {
    let payload = public_subkey_payload(key)?;
    output_as_packet(PacketType::PublicSubKey, &payload, cursor)
}

fn output_unencrypted_secret_subkey(key: &EncryptKey, out: &mut ByteCursor) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_subkey_payload(key)?;
    cursor.write_all(&payload)?;
    // S2K unencrypted i.e. without passphrase protection.
    cursor.write_all(&[0])?;
    // TODO: Why do we need this? I took it from passphrase2pgp but I do not understand why we
    // would need to reverse the secret key.
    let mut reverse_secret_key = [0u8; 32];
    reverse_secret_key.copy_from_slice(&key.secret_key.to_bytes());
    reverse_secret_key.reverse();
    let mpi_key = mpi_encode(&reverse_secret_key);
    cursor.write_all(&mpi_key)?;
    cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
    output_as_packet(PacketType::PrivateEncryptSubkey, cursor.get_ref(), out)
}

fn output_encrypted_secret_subkey(
    key: &EncryptKey,
    passphrase: &str,
    out: &mut ByteCursor,
) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_subkey_payload(key)?;
    cursor.write_all(&payload)?;
    // TODO: Why do we need this? I took it from passphrase2pgp but I do not understand why we
    // would need to reverse the secret key.
    let mut reverse_secret_key = [0u8; 32];
    reverse_secret_key.copy_from_slice(&key.secret_key.to_bytes());
    reverse_secret_key.reverse();
    s2k_encrypt(&reverse_secret_key, passphrase, &mut cursor)?;
    output_as_packet(PacketType::PrivateEncryptSubkey, cursor.get_ref(), out)
}

fn public_key_payload(key: &SignKey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.created_timestamp_secs)?;
    cursor.write_all(&[22])?; // Algorithm, EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
    cursor.write_u16::<BigEndian>(263)?;
    // Prefix octet for EdDSA Point Format.
    cursor.write_all(&[0x40])?;
    cursor.write_all(key.keypair.public.as_bytes())?;
    Ok(cursor.into_inner())
}

fn output_public_key(key: &SignKey, out: &mut ByteCursor) -> Result<()> {
    let payload = public_key_payload(key)?;
    output_as_packet(PacketType::PublicSignKey, &payload, out)
}

fn output_unencrypted_secret_key(key: &SignKey, out: &mut ByteCursor) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_key_payload(key)?;
    cursor.write_all(&payload)?;
    // S2K unencrypted i.e. without passphrase protection.
    cursor.write_all(&[0])?;
    let mpi_key = mpi_encode(key.keypair.secret.as_bytes());
    cursor.write_all(&mpi_key)?;
    cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
    output_as_packet(PacketType::PrivateSignKey, cursor.get_ref(), out)
}

fn output_encrypted_secret_key(
    key: &SignKey,
    passphrase: &str,
    out: &mut ByteCursor,
) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_key_payload(key)?;
    cursor.write_all(&payload)?;
    s2k_encrypt(key.keypair.secret.as_bytes(), passphrase, &mut cursor)?;
    output_as_packet(PacketType::PrivateSignKey, cursor.get_ref(), out)
}

fn key_fingerprint(key: &SignKey) -> Result<Vec<u8>> {
    let mut hasher = sha1::Sha1::new();
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    output_public_key(key, &mut cursor)?;
    let packet = cursor.get_ref();
    let without_header = &packet[2..];
    hasher.update([0x99, 0, without_header.len() as u8]);
    hasher.update(without_header);
    Ok(hasher.finalize().to_vec())
}

fn output_self_signature(key: &SignKey, user_id: &UserId, out: &mut ByteCursor) -> Result<()> {
    let mut packet_cursor = ByteCursor::new(Vec::with_capacity(256));
    // Version 4 signature.
    // Positive certification signature (0x13).
    // EdDSA signature (22), SHA-256 hash (8).
    packet_cursor.write_all(&[0x04, 0x13, 22, 8])?;
    // Write subpackets to a buffer.
    // Signature creation time subpacket (2), 5 bytes.
    let mut subpacket_cursor = ByteCursor::new(Vec::with_capacity(256));
    subpacket_cursor.write_all(&[5, 2])?;
    subpacket_cursor.write_u32::<BigEndian>(key.created_timestamp_secs)?;
    // Issuer subpacket (16), signature key id.
    let key_fp = key_fingerprint(key)?;
    subpacket_cursor.write_all(&[9, 16])?;
    subpacket_cursor.write_all(&key_fp[12..20])?;
    // Issuer fingerprint (33), version 4.
    subpacket_cursor.write_all(&[22, 33, 4])?;
    subpacket_cursor.write_all(&key_fp)?;
    // Key Flags (27) subpacket (sign and certify).
    subpacket_cursor.write_all(&[2, 27, 0x03])?;
    // Features Subpacket (30): MDC
    subpacket_cursor.write_all(&[2, 30, 0x01])?;
    // Trust signature: 120 for complete trust.
    subpacket_cursor.write_all(&[3, 5, 0, 120])?;
    // Write subpackets into the hashed subpacket area.
    let subpackets = subpacket_cursor.get_ref();
    packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
    packet_cursor.write_all(subpackets)?;
    // Compute total hash of the public key + subpackets + trailer
    // now that we have the packet up to the point we need to hash.
    let mut hasher = sha2::Sha256::new();
    let public_key_packet = public_key_payload(key)?;
    hasher.update([0x99]);
    hash_u16(public_key_packet.len().try_into()?, &mut hasher);
    hasher.update(&public_key_packet);
    let user_id = &user_id.user_id;
    hasher.update([0xb4]);
    hash_u32(user_id.len().try_into()?, &mut hasher);
    hasher.update(user_id.as_bytes());
    let packet = packet_cursor.get_ref();
    hasher.update(packet);
    hasher.update([0x04, 0xFF]);
    hash_u32(packet.len().try_into()?, &mut hasher);
    let hash = hasher.finalize();
    // Sign the hash.
    let signature = key.keypair.sign(&hash).to_bytes();
    // No unhashed subpackets.
    packet_cursor.write_u16::<BigEndian>(0)?;
    // Push the signature of the hash.
    packet_cursor.write_all(&hash[..2])?;
    packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
    packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
    output_as_packet(PacketType::Signature, packet_cursor.get_ref(), out)
}

fn output_subkey_signature(key: &SignKey, subkey: &EncryptKey, out: &mut ByteCursor) -> Result<()> {
    let mut packet_cursor = ByteCursor::new(Vec::with_capacity(256));
    // Version 4 signature.
    // Subkey binding signature (0x18).
    // EdDSA signature (22), SHA-256 hash (8).
    packet_cursor.write_all(&[0x04, 0x18, 22, 8])?;
    // Write subpackets to a buffer.
    // Signature creation time subpacket (2), 5 bytes.
    let mut subpacket_cursor = ByteCursor::new(Vec::with_capacity(256));
    subpacket_cursor.write_all(&[5, 2])?;
    subpacket_cursor.write_u32::<BigEndian>(key.created_timestamp_secs)?;
    // Issuer subpacket (16), signature key id.
    let key_fp = key_fingerprint(key)?;
    subpacket_cursor.write_all(&[9, 16])?;
    subpacket_cursor.write_all(&key_fp[12..20])?;
    // Issuer fingerprint (33), version 4.
    subpacket_cursor.write_all(&[22, 33, 4])?;
    subpacket_cursor.write_all(&key_fp)?;
    // Key Flags (27) subpacket (encrypt).
    subpacket_cursor.write_all(&[2, 27, 0x0c])?;
    // Trust signature: 120 for complete trust.
    subpacket_cursor.write_all(&[3, 5, 0, 120])?;
    // Write subpackets into the hashed subpacket area.
    let subpackets = subpacket_cursor.get_ref();
    packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
    packet_cursor.write_all(subpackets)?;
    // Compute total hash of the public key + encrypted public key +
    // subpackets + trailer now that we have the packet up to the point
    // we need to hash.
    let mut hasher = sha2::Sha256::new();
    // Sign public key packet.
    let sign_public_key = public_key_payload(key)?;
    hasher.update([0x99]);
    hash_u16(sign_public_key.len().try_into()?, &mut hasher);
    hasher.update(&sign_public_key);
    // Subkey public key packet.
    let subkey_public_key = public_subkey_payload(subkey)?;
    hasher.update([0x99]);
    hash_u16(subkey_public_key.len().try_into()?, &mut hasher);
    hasher.update(&subkey_public_key);
    let packet = packet_cursor.get_ref();
    hasher.update(packet);
    hasher.update([0x04, 0xFF]);
    hash_u32(packet.len().try_into()?, &mut hasher);
    let hash = hasher.finalize();
    // Sign the hash.
    let signature = key.keypair.sign(&hash).to_bytes();
    // No unhashed subpackets.
    packet_cursor.write_u16::<BigEndian>(0)?;
    // Push the signature of the hash.
    packet_cursor.write_all(&hash[..2])?;
    packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
    packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
    output_as_packet(PacketType::Signature, packet_cursor.get_ref(), out)
}

pub fn output_as_packets<W: Write>(
    context: &Context,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    let mut buffer = ByteCursor::new(Vec::new());
    if let Some(passphrase) = &context.passphrase {
        output_encrypted_secret_key(&context.sign_key, passphrase, &mut buffer)?;
    } else {
        output_unencrypted_secret_key(&context.sign_key, &mut buffer)?;
    }
    output_user_id(&context.user_id, &mut buffer)?;
    output_self_signature(&context.sign_key, &context.user_id, &mut buffer)?;
    if let Some(encrypt_key) = &context.encrypt_key {
        if let Some(passphrase) = &context.passphrase {
            output_encrypted_secret_subkey(encrypt_key, passphrase, &mut buffer)?;
        } else {
            output_unencrypted_secret_subkey(encrypt_key, &mut buffer)?;
        }
        output_subkey_signature(&context.sign_key, encrypt_key, &mut buffer)?;
    }
    out.write_all(buffer.get_ref())?;
    Ok(())
}

fn armor_checksum(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xB704CE;
    for v in bytes {
        crc ^= (*v as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if (crc & 0x1000000) != 0 {
                crc ^= 0x1864CFB;
            }
        }
    }
    crc & 0xFFFFFF
}

pub fn output_armored<W: Write>(context: &Context, out: &mut std::io::BufWriter<W>) -> Result<()> {
    out.write_all(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n")?;
    out.write_all(b"Version: GnuPG v2\n\n")?;
    let mut packets_cursor = ByteCursor::new(vec![]);
    let mut buffer = std::io::BufWriter::new(&mut packets_cursor);
    output_as_packets(context, &mut buffer)?;
    buffer.flush()?;
    let packets = buffer.get_mut().get_mut();
    out.write_all(textwrap::fill(&base64::encode(&packets), 64).as_bytes())?;
    let mut checksum_cursor = ByteCursor::new(vec![]);
    let checksum = armor_checksum(packets);
    checksum_cursor.write_all(&[
        ((checksum >> 16) & 0xFF) as u8,
        ((checksum >> 8) & 0xFF) as u8,
        (checksum & 0xFF) as u8,
    ])?;
    out.write_all(b"\n=")?;
    out.write_all(base64::encode(checksum_cursor.get_ref()).as_bytes())?;
    out.write_all(b"\n-----END PGP PRIVATE KEY BLOCK-----\n")?;
    Ok(())
}

pub fn output_public_armored<W: Write>(
    context: &Context,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    out.write_all(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")?;
    out.write_all(b"Version: GnuPG v2\n\n")?;
    let mut packets_cursor = ByteCursor::new(vec![]);
    let mut buffer = std::io::BufWriter::new(&mut packets_cursor);
    output_public_as_packets(context, &mut buffer)?;
    buffer.flush()?;
    let packets = buffer.get_mut().get_mut();
    out.write_all(textwrap::fill(&base64::encode(&packets), 64).as_bytes())?;
    let mut checksum_cursor = ByteCursor::new(vec![]);
    let checksum = armor_checksum(packets);
    checksum_cursor.write_all(&[
        ((checksum >> 16) & 0xFF) as u8,
        ((checksum >> 8) & 0xFF) as u8,
        (checksum & 0xFF) as u8,
    ])?;
    out.write_all(b"\n=")?;
    out.write_all(base64::encode(checksum_cursor.get_ref()).as_bytes())?;
    out.write_all(b"\n-----END PGP PUBLIC KEY BLOCK-----\n")?;
    Ok(())
}

pub fn output_public_as_packets<W: Write>(
    context: &Context,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    let mut buffer = ByteCursor::new(Vec::new());
    output_public_key(&context.sign_key, &mut buffer)?;
    output_user_id(&context.user_id, &mut buffer)?;
    output_self_signature(&context.sign_key, &context.user_id, &mut buffer)?;
    if let Some(encrypt_key) = &context.encrypt_key {
        output_public_subkey(encrypt_key, &mut buffer)?;
        output_subkey_signature(&context.sign_key, encrypt_key, &mut buffer)?;
    }
    out.write_all(buffer.get_ref())?;
    Ok(())
}
