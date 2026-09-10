use crate::keys::*;
use crate::types::*;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use ed25519_dalek::Signer;
use rand::RngCore;
use sha2::Digest;
use std::io::Write;

type Aes256Cfb = cfb_mode::Encryptor<aes::Aes256>;

pub enum PacketType {
    PrivateSubkey,
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
            PacketType::PrivateSubkey => 7,
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
            // RFC 4880 4.2.2.2: bodyLen = ((1st - 192) << 8) + 2nd + 192,
            // so subtract 192 from the whole length before splitting bytes.
            let adjusted = length - 192;
            out.write_all(&[((adjusted >> 8) + 192) as u8, (adjusted & 0xFF) as u8])?;
        }
        _ => {
            out.write_all(&[255])?;
            out.write_u32::<BigEndian>(length.try_into()?)?;
        }
    };
    out.write_all(packet_bytes)?;
    Ok(())
}

// Encode buffer as MPI (Multi Precision Integer), defined in OpenPGP RFC 4880.
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
    cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    cursor.write_all(&[18])?; // Elliptic Curve Diffie-Hellman.
    let oid: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    cursor.write_u16::<BigEndian>(263)?;
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key)?;
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
    // Keys from curve25519-dalek use little endian byte ordering, but OpenPGP (and therefore GPG)
    // uses big-endian representation of numbers.
    let mut reverse_secret_key = key.private_key;
    reverse_secret_key.reverse();
    let mpi_key = mpi_encode(&reverse_secret_key);
    cursor.write_all(&mpi_key)?;
    cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
    output_as_packet(PacketType::PrivateSubkey, cursor.get_ref(), out)
}

fn output_encrypted_secret_subkey(
    key: &EncryptKey,
    passphrase: &str,
    out: &mut ByteCursor,
) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_subkey_payload(key)?;
    cursor.write_all(&payload)?;
    // Keys from curve25519-dalek use little endian byte ordering, but OpenPGP (and therefore GPG)
    // uses big-endian representation of numbers.
    let mut reverse_secret_key = key.private_key;
    reverse_secret_key.reverse();
    s2k_encrypt(&reverse_secret_key, passphrase, &mut cursor)?;
    output_as_packet(PacketType::PrivateSubkey, cursor.get_ref(), out)
}

fn public_auth_subkey_payload(key: &AuthKey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    cursor.write_all(&[22])?; // Algorithm, EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    cursor.write_u16::<BigEndian>(263)?;
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key)?;
    Ok(cursor.into_inner())
}

fn output_public_auth_subkey(key: &AuthKey, cursor: &mut ByteCursor) -> Result<()> {
    let payload = public_auth_subkey_payload(key)?;
    output_as_packet(PacketType::PublicSubKey, &payload, cursor)
}

fn output_unencrypted_secret_auth_subkey(key: &AuthKey, out: &mut ByteCursor) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_auth_subkey_payload(key)?;
    cursor.write_all(&payload)?;
    // S2K unencrypted i.e. without passphrase protection.
    cursor.write_all(&[0])?;
    let mpi_key = mpi_encode(&key.private_key);
    cursor.write_all(&mpi_key)?;
    cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
    output_as_packet(PacketType::PrivateSubkey, cursor.get_ref(), out)
}

fn output_encrypted_secret_auth_subkey(
    key: &AuthKey,
    passphrase: &str,
    out: &mut ByteCursor,
) -> Result<()> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    let payload = public_auth_subkey_payload(key)?;
    cursor.write_all(&payload)?;
    s2k_encrypt(&key.private_key, passphrase, &mut cursor)?;
    output_as_packet(PacketType::PrivateSubkey, cursor.get_ref(), out)
}

fn output_auth_subkey_signature(
    key: &SignKey,
    auth_key: &AuthKey,
    out: &mut ByteCursor,
) -> Result<()> {
    let mut packet_cursor = ByteCursor::new(Vec::with_capacity(256));
    // Version 4 signature.
    // Subkey binding signature (0x18).
    // EdDSA signature (22), SHA-256 hash (8).
    packet_cursor.write_all(&[0x04, 0x18, 22, 8])?;
    // Write subpackets to a buffer.
    // Signature creation time subpacket (2), 5 bytes.
    let mut subpacket_cursor = ByteCursor::new(Vec::with_capacity(256));
    subpacket_cursor.write_all(&[5, 2])?;
    subpacket_cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    // Key expiration time subpacket (9) — the delta after which the subkey
    // expires.
    if let Some(expiration_time_secs) = auth_key.expiration_timestamp_secs {
        subpacket_cursor.write_all(&[5, 9])?;
        let expiration_delta_secs = expiration_time_secs - auth_key.creation_timestamp_secs;
        subpacket_cursor.write_u32::<BigEndian>(expiration_delta_secs.try_into().unwrap())?;
    }
    // Issuer subpacket (16), signature key id.
    let key_fp = key_fingerprint(key)?;
    subpacket_cursor.write_all(&[9, 16])?;
    subpacket_cursor.write_all(&key_fp[12..20])?;
    // Issuer fingerprint (33), version 4.
    subpacket_cursor.write_all(&[22, 33, 4])?;
    subpacket_cursor.write_all(&key_fp)?;
    // Key Flags (27) subpacket (authentication).
    subpacket_cursor.write_all(&[2, 27, 0x20])?;
    // Trust signature: 120 for complete trust.
    subpacket_cursor.write_all(&[3, 5, 0, 120])?;
    // Write subpackets into the hashed subpacket area.
    let subpackets = subpacket_cursor.get_ref();
    packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
    packet_cursor.write_all(subpackets)?;
    // Compute total hash of the public key + auth public key + subpackets + trailer.
    let mut hasher = sha2::Sha256::new();
    let sign_public_key = public_key_payload(key)?;
    hasher.update([0x99]);
    hash_u16(sign_public_key.len().try_into()?, &mut hasher);
    hasher.update(&sign_public_key);
    let auth_public_key = public_auth_subkey_payload(auth_key)?;
    hasher.update([0x99]);
    hash_u16(auth_public_key.len().try_into()?, &mut hasher);
    hasher.update(&auth_public_key);
    let packet = packet_cursor.get_ref();
    hasher.update(packet);
    hasher.update([0x04, 0xFF]);
    hash_u32(packet.len().try_into()?, &mut hasher);
    let hash = hasher.finalize();
    // Sign the hash.
    let signature = key.signing_key.sign(&hash).to_bytes();
    // No unhashed subpackets.
    packet_cursor.write_u16::<BigEndian>(0)?;
    // Push the signature of the hash.
    packet_cursor.write_all(&hash[..2])?;
    packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
    packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
    output_as_packet(PacketType::Signature, packet_cursor.get_ref(), out)
}

fn public_key_payload(key: &SignKey) -> Result<Vec<u8>> {
    let mut cursor = ByteCursor::new(Vec::with_capacity(256));
    cursor.write_all(&[0x04])?; // Version 4.
    cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    cursor.write_all(&[22])?; // Algorithm, EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
    cursor.write_all(&[oid.len().try_into()?])?;
    cursor.write_all(&oid)?;
    // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
    cursor.write_u16::<BigEndian>(263)?;
    // Prefix octet for EdDSA Point Format.
    cursor.write_all(&[0x40])?;
    cursor.write_all(&key.public_key)?;
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
    let mpi_key = mpi_encode(&key.private_key);
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
    s2k_encrypt(&key.private_key, passphrase, &mut cursor)?;
    output_as_packet(PacketType::PrivateSignKey, cursor.get_ref(), out)
}

// OpenPGP v4 fingerprint: SHA-1 over 0x99, the two-octet packet length, and
// the public key packet body (RFC 4880 section 12.2).
fn v4_fingerprint(public_key_payload: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = sha1::Sha1::new();
    let length: u16 = public_key_payload.len().try_into()?;
    hasher.update([0x99, (length >> 8) as u8, (length & 0xFF) as u8]);
    hasher.update(public_key_payload);
    Ok(hasher.finalize().to_vec())
}

pub fn key_fingerprint(key: &SignKey) -> Result<Vec<u8>> {
    v4_fingerprint(&public_key_payload(key)?)
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
    subpacket_cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    if let Some(expiration_time_secs) = key.expiration_timestamp_secs {
        subpacket_cursor.write_all(&[5, 9])?;
        // Expirations are in seconds from the creation time.
        let expiration_delta_secs = expiration_time_secs - key.creation_timestamp_secs;
        subpacket_cursor.write_u32::<BigEndian>(expiration_delta_secs.try_into().unwrap())?;
    }
    // Issuer subpacket (16), signature key id.
    let key_fp = key_fingerprint(key)?;
    subpacket_cursor.write_all(&[9, 16])?;
    subpacket_cursor.write_all(&key_fp[12..20])?;
    // Issuer fingerprint (33), version 4.
    subpacket_cursor.write_all(&[22, 33, 4])?;
    subpacket_cursor.write_all(&key_fp)?;
    // Key Flags (27) subpacket (sign and certify). If specified, we also include the authorization
    // capability with 0x20.
    let flags = if key.use_authorization_for_sign_key {
        0x3 | 0x20
    } else {
        0x3
    };
    subpacket_cursor.write_all(&[2, 27, flags])?;
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
    let signature = key.signing_key.sign(&hash).to_bytes();
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
    subpacket_cursor.write_u32::<BigEndian>(key.creation_timestamp_secs.try_into().unwrap())?;
    // Key expiration time subpacket (9) — the delta after which the subkey
    // expires.
    if let Some(expiration_time_secs) = subkey.expiration_timestamp_secs {
        subpacket_cursor.write_all(&[5, 9])?;
        // Expirations are in seconds from the creation time.
        let expiration_delta_secs = expiration_time_secs - subkey.creation_timestamp_secs;
        subpacket_cursor.write_u32::<BigEndian>(expiration_delta_secs.try_into().unwrap())?;
    }
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
    let signature = key.signing_key.sign(&hash).to_bytes();
    // No unhashed subpackets.
    packet_cursor.write_u16::<BigEndian>(0)?;
    // Push the signature of the hash.
    packet_cursor.write_all(&hash[..2])?;
    packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
    packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
    output_as_packet(PacketType::Signature, packet_cursor.get_ref(), out)
}

pub fn output_as_packets<W: Write>(keys: &Keys, out: &mut std::io::BufWriter<W>) -> Result<()> {
    let mut buffer = ByteCursor::new(Vec::new());
    if let Some(passphrase) = &keys.passphrase {
        output_encrypted_secret_key(&keys.sign_key, passphrase, &mut buffer)?;
    } else {
        output_unencrypted_secret_key(&keys.sign_key, &mut buffer)?;
    }
    output_user_id(&keys.user_id, &mut buffer)?;
    output_self_signature(&keys.sign_key, &keys.user_id, &mut buffer)?;
    if let Some(encrypt_key) = &keys.encrypt_key {
        if let Some(passphrase) = &keys.passphrase {
            output_encrypted_secret_subkey(encrypt_key, passphrase, &mut buffer)?;
        } else {
            output_unencrypted_secret_subkey(encrypt_key, &mut buffer)?;
        }
        output_subkey_signature(&keys.sign_key, encrypt_key, &mut buffer)?;
    }
    if let Some(auth_key) = &keys.auth_key {
        if let Some(passphrase) = &keys.passphrase {
            output_encrypted_secret_auth_subkey(auth_key, passphrase, &mut buffer)?;
        } else {
            output_unencrypted_secret_auth_subkey(auth_key, &mut buffer)?;
        }
        output_auth_subkey_signature(&keys.sign_key, auth_key, &mut buffer)?;
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

pub fn output_armored<W: Write>(keys: &Keys, out: &mut std::io::BufWriter<W>) -> Result<()> {
    out.write_all(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n")?;
    out.write_all(b"Version: GnuPG v2\n\n")?;
    let mut packets_cursor = ByteCursor::new(vec![]);
    let mut buffer = std::io::BufWriter::new(&mut packets_cursor);
    output_as_packets(keys, &mut buffer)?;
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

pub fn output_public_armored<W: Write>(keys: &Keys, out: &mut std::io::BufWriter<W>) -> Result<()> {
    out.write_all(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")?;
    out.write_all(b"Version: GnuPG v2\n\n")?;
    let mut packets_cursor = ByteCursor::new(vec![]);
    let mut buffer = std::io::BufWriter::new(&mut packets_cursor);
    output_public_as_packets(keys, &mut buffer)?;
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
    keys: &Keys,
    out: &mut std::io::BufWriter<W>,
) -> Result<()> {
    let mut buffer = ByteCursor::new(Vec::new());
    output_public_key(&keys.sign_key, &mut buffer)?;
    output_user_id(&keys.user_id, &mut buffer)?;
    output_self_signature(&keys.sign_key, &keys.user_id, &mut buffer)?;
    if let Some(encrypt_key) = &keys.encrypt_key {
        output_public_subkey(encrypt_key, &mut buffer)?;
        output_subkey_signature(&keys.sign_key, encrypt_key, &mut buffer)?;
    }
    if let Some(auth_key) = &keys.auth_key {
        output_public_auth_subkey(auth_key, &mut buffer)?;
        output_auth_subkey_signature(&keys.sign_key, auth_key, &mut buffer)?;
    }
    out.write_all(buffer.get_ref())?;
    Ok(())
}

/// Validate creation/expiration timestamps against the limits imposed by the
/// OpenPGP v4 packet format, which stores the creation time as a u32 and the
/// expiration as a u32 delta from creation.
///
/// Without this, an out-of-range value flows into the packet writers above and
/// panics on `try_into().unwrap()` after the expensive Argon2id derivation has
/// already run.
pub fn validate_timestamps(created: i64, expires: Option<i64>) -> Result<()> {
    if created < 0 || created > u32::MAX as i64 {
        anyhow::bail!(
            "Creation timestamp out of range (0..={}): {}",
            u32::MAX,
            created
        );
    }
    if let Some(expires) = expires {
        if expires < created {
            anyhow::bail!(
                "Expiration timestamp {} is before creation timestamp {}",
                expires,
                created
            );
        }
        if expires - created > u32::MAX as i64 {
            anyhow::bail!(
                "Expiration delta exceeds the OpenPGP u32 limit ({} seconds)",
                u32::MAX
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Strip leading zero bytes, the way an MPI body is defined.
    fn strip_leading_zeroes(data: &[u8]) -> &[u8] {
        let mut slice = data;
        while !slice.is_empty() && slice[0] == 0 {
            slice = &slice[1..];
        }
        slice
    }

    /// Bit length of a big-endian integer, computed by locating the highest set
    /// bit rather than by counting leading zeroes, so it is an independent check
    /// on what mpi_encode declares.
    fn bit_length(data: &[u8]) -> usize {
        for (index, byte) in data.iter().enumerate() {
            if *byte != 0 {
                let trailing_bytes = data.len() - index - 1;
                let highest_bit = 8 - byte.leading_zeros() as usize;
                return trailing_bytes * 8 + highest_bit;
            }
        }
        0
    }

    /// Decode a new-format packet header, returning the body length it declares
    /// and the number of header octets it occupies (RFC 4880 section 4.2.2).
    fn parse_packet_header(bytes: &[u8]) -> (usize, usize) {
        assert_eq!(bytes[0] & 0xc0, 0xc0, "not a new-format packet header");
        match bytes[1] {
            0..=191 => (bytes[1] as usize, 2),
            192..=223 => (
                (((bytes[1] - 192) as usize) << 8) + bytes[2] as usize + 192,
                3,
            ),
            255 => (
                u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize,
                6,
            ),
            // 224..=254 signal partial body lengths, which this encoder never
            // emits and GPG would interpret as a much shorter packet.
            other => panic!("unexpected length octet {other}"),
        }
    }

    /// Encode a packet with a `length`-byte body and assert that the header
    /// declares the right length *and* is sized so the body starts where the
    /// declared length says it does.
    fn assert_packet_roundtrips(length: usize) {
        let body: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut cursor = ByteCursor::new(vec![]);
        output_as_packet(PacketType::UserId, &body, &mut cursor).unwrap();
        let bytes = cursor.into_inner();

        let (declared, header_length) = parse_packet_header(&bytes);
        assert_eq!(declared, length, "body of {length} declared as {declared}");
        assert_eq!(
            bytes.len(),
            header_length + length,
            "header of {header_length} octets misplaces a {length} byte body"
        );
        assert_eq!(&bytes[header_length..], &body[..]);
    }

    #[test]
    fn test_packet_length_encoding_boundaries() {
        // The one/two/five octet header thresholds and the values either side.
        for length in [
            0, 1, 191, 192, 193, 255, 256, 300, 447, 448, 1000, 8383, 8384, 70000,
        ] {
            assert_packet_roundtrips(length);
        }
    }

    // Packet bodies as large as a user ID or a signature subpacket can get.
    proptest! {
        #[test]
        fn prop_packet_length_roundtrips(length in 0usize..100_000) {
            assert_packet_roundtrips(length);
        }
    }

    // CRC-24/OPENPGP, from the CRC catalogue: polynomial 0x864CFB, initial
    // value 0xB704CE, no reflection, no final xor. The check value over the
    // ASCII digits "123456789" is external ground truth for the armor trailer.
    #[test]
    fn test_armor_checksum_known_vectors() {
        assert_eq!(armor_checksum(b""), 0xB704CE);
        assert_eq!(armor_checksum(b"123456789"), 0x21CF02);
    }

    proptest! {
        // The armor trailer is written as exactly three octets, so a checksum
        // wider than 24 bits would be silently truncated.
        #[test]
        fn prop_armor_checksum_fits_in_24_bits(
            data in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            prop_assert!(armor_checksum(&data) <= 0xFFFFFF);
        }

        #[test]
        fn prop_checksum_is_sum_mod_65536(
            data in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let expected = data.iter().map(|b| *b as u64).sum::<u64>() % 65536;
            prop_assert_eq!(checksum(&data) as u64, expected);
        }

        #[test]
        fn prop_mpi_declares_correct_bit_length(
            data in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let encoded = mpi_encode(&data);
            let declared = ((encoded[0] as usize) << 8) | encoded[1] as usize;
            prop_assert_eq!(declared, bit_length(&data));
            prop_assert_eq!(encoded.len() - 2, declared.div_ceil(8));
        }

        #[test]
        fn prop_mpi_body_is_input_without_leading_zeroes(
            data in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let encoded = mpi_encode(&data);
            prop_assert_eq!(&encoded[2..], strip_leading_zeroes(&data));
        }

        // Leading zero bytes carry no value, so they must not change the
        // encoding. This is the input class fixed vectors never cover: every
        // real caller passes a 32 byte key, and roughly one key in 256 starts
        // with a zero byte.
        #[test]
        fn prop_mpi_ignores_leading_zeroes(
            zeroes in 0usize..8,
            data in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut padded = vec![0u8; zeroes];
            padded.extend_from_slice(&data);
            prop_assert_eq!(mpi_encode(&padded), mpi_encode(&data));
        }
    }

    #[test]
    fn test_validate_timestamps() {
        assert!(validate_timestamps(1231006505, None).is_ok());
        assert!(validate_timestamps(0, None).is_ok());
        assert!(validate_timestamps(u32::MAX as i64, None).is_ok());
        assert!(validate_timestamps(100, Some(200)).is_ok());
        assert!(validate_timestamps(-1, None).is_err());
        assert!(validate_timestamps(u32::MAX as i64 + 1, None).is_err());
        assert!(validate_timestamps(200, Some(100)).is_err());
        assert!(validate_timestamps(0, Some(u32::MAX as i64 + 1)).is_err());
    }
}
