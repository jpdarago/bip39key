use bip39::{Language, Mnemonic};
use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::Signer;
use sha1::Sha1;
use sha2::Digest;
use sha2::{Sha256, Sha512};
use std::error::Error;
use std::io::{BufWriter, Cursor, Write};

type ByteCursor = Cursor<Vec<u8>>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Set the creation time as the timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

// Encode buffer as MPI (Multi Precision Intenger), defined in OpenPGP RFC 4880.
fn mpi_encode(data: &[u8]) -> Vec<u8> {
    let mut slice = data;
    // Remove all leading zeroes.
    while slice.len() > 0 && slice[0] == 0 {
        slice = &slice[1..];
    }
    if slice.len() == 0 {
        return vec![0, 0];
    }
    let mut vec = Vec::with_capacity(slice.len() + 2);
    let c = slice.len() * 8 - (slice[0].leading_zeros() as usize);
    vec.push(((c >> 8) & 0xFF) as u8);
    vec.push((c & 0xFF) as u8);
    vec.extend_from_slice(slice);
    vec
}

// Returns the PGP checksum for a data buffer, defined in OpenPGP RFC 4880.
fn checksum(buffer: &[u8]) -> u16 {
    let mut result: u32 = 0;
    for &byte in buffer {
        result = (result + (byte as u32)) % 65536;
    }
    result as u16
}

struct PGPUserId {
    user_id: String,
}

impl PGPUserId {
    fn as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        out.write(&[0xc0 | 13])?;
        out.write(&[self.user_id.len().try_into()?])?;
        out.write(self.user_id.as_bytes())?;
        Ok(())
    }

    fn as_packet_vec(self: &Self) -> Result<Vec<u8>> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.as_packet(&mut cursor)?;
        Ok(cursor.get_mut().to_vec())
    }
}

struct PGPSignKey {
    keypair: ed25519_dalek::Keypair,
    created_timestamp_secs: u32,
}

impl PGPSignKey {
    fn new(secret_key_bytes: &[u8]) -> Result<PGPSignKey> {
        let sign_secret_key = ed25519_dalek::SecretKey::from_bytes(&secret_key_bytes)?;
        let sign_public_key: ed25519_dalek::PublicKey = (&sign_secret_key).into();
        Ok(PGPSignKey {
            created_timestamp_secs: TIMESTAMP,
            keypair: ed25519_dalek::Keypair {
                public: sign_public_key,
                secret: sign_secret_key,
            },
        })
    }

    fn public_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = ByteCursor::new(Vec::with_capacity(256));
        cursor.write(&[0xc0 | 6])?;
        // We write the length byte as 0 for now, we will replace it with the proper length below
        // once we have written all the information for the packet. It is assumed we only output
        // less than 255 bytes of information since that fits in one byte.
        cursor.write(&[0])?;
        cursor.write(&[0x04])?; // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs.try_into()?)?;
        cursor.write(&[22])?; // Algorithm, EdDSA
        let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
        cursor.write(&[oid.len().try_into()?])?;
        cursor.write(&oid);
        // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
        cursor.write_u16::<BigEndian>(263)?;
        // Prefix octet for EdDSA Point Format.
        cursor.write(&[0x40])?;
        cursor.write(self.keypair.public.as_bytes())?;
        let data = cursor.get_mut();
        // Now that we have the full length, set it in the packet.
        // The packet header does not count for the total length.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn public_as_packet_vec(self: &Self) -> Result<Vec<u8>> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        Ok(cursor.get_mut().to_vec())
    }

    fn secret_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        // S2K unencrypted i.e. without passphrase protection.
        cursor.write(&[0])?;
        let mpi_key = mpi_encode(self.keypair.secret.as_bytes());
        cursor.write(&mpi_key)?;
        cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
        // The packet header does not count for the total length.
        let data = cursor.get_mut();
        // Rewrite the packet type, from public to secret key.
        data[0] = 0xc0 | 5;
        // Now that we have the full length, set it in the packet and write.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn key_fingerprint(self: &Self) -> Result<Vec<u8>> {
        let mut hasher = Sha1::new();
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        let packet = cursor.get_ref();
        let without_header = &packet[2..];
        hasher.update(&[0x99, 0, without_header.len() as u8]);
        hasher.update(&without_header);
        Ok(hasher.finalize().to_vec())
    }

    fn self_sign_as_packet(self: &Self, user_id: &PGPUserId, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Signature Packet Header (2).
        // Length byte - Will be filled properly once the whole packet is computed.
        // Version 4 signature.
        // Positive certification signature (0x13).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write(&[0xc0 | 2, 0, 0x04, 0x13, 22, 8])?;
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write(&[5, 2])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs)?;
        // Issuer subpacket (16), signature key id.
        let key_fp = self.key_fingerprint()?;
        subpacket_cursor.write(&[9, 16])?;
        subpacket_cursor.write(&key_fp[12..20])?;
        // Issuer fingerprint (33), version 4.
        subpacket_cursor.write(&[22, 33, 4]);
        subpacket_cursor.write(&key_fp)?;
        // Key Flags (27) subpacket (sign and certify).
        subpacket_cursor.write(&[2, 27, 0x03])?;
        // Features Subpacket (30): MDC
        subpacket_cursor.write(&[2, 30, 0x01])?;
        // Write subpackets into the hashed subpacket area.
        let subpackets = subpacket_cursor.get_ref();
        packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
        packet_cursor.write(&subpackets)?;
        // Compute total hash of the public key + subpackets + trailer
        // now that we have the packet up to the point we need to hash.
        let mut hasher = Sha256::new();
        let public_key_packet = self.public_as_packet_vec()?;
        hasher.update(&[0x99, 0, (public_key_packet.len() - 2) as u8]);
        hasher.update(&public_key_packet[2..]);
        let user_id_packet = user_id.as_packet_vec()?;
        // TODO: handle user ids larger than one byte.
        hasher.update(&[0xb4, 0, 0, 0, (user_id_packet.len() - 2) as u8]);
        hasher.update(&user_id_packet[2..]);
        let packet = packet_cursor.get_ref();
        hasher.update(&packet[2..]);
        hasher.update(&[0x04, 0xFF, 0, 0, 0, (packet.len() - 2) as u8]);
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // No unhashed subpackets.
        packet_cursor.write_u16::<BigEndian>(0);
        // Push the signature of the hash.
        packet_cursor.write(&hash[..2])?;
        packet_cursor.write(&mpi_encode(&signature[..32]))?;
        packet_cursor.write(&mpi_encode(&signature[32..]))?;
        // Now that we have the full length, set it in the packet and write.
        // TODO: handle packets larger than 1 byte.
        let data = packet_cursor.get_mut();
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn bind_key_as_packet(self: &Self, subkey: &PGPEncryptKey, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Signature Packet Header (2).
        // Length byte - Will be filled properly once the whole packet is computed.
        // Version 4 signature.
        // Subkey binding signature (0x18).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write(&[0xc0 | 2, 0, 0x04, 0x18, 22, 8]);
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write(&[5, 2])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs);
        // Issuer subpacket (16), signature key id.
        let key_fp = self.key_fingerprint()?;
        subpacket_cursor.write(&[9, 16]);
        subpacket_cursor.write(&key_fp[12..20])?;
        // Issuer fingerprint (33), version 4.
        subpacket_cursor.write(&[22, 33, 4]);
        subpacket_cursor.write(&key_fp)?;
        // Key Flags (27) subpacket (encrypt).
        subpacket_cursor.write(&[2, 27, 0x0c])?;
        // Write subpackets into the hashed subpacket area.
        let subpackets = subpacket_cursor.get_ref();
        packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
        packet_cursor.write(&subpackets)?;
        // Compute total hash of the public key + encrypted public key +
        // subpackets + trailer now that we have the packet up to the point
        // we need to hash.
        let mut hasher = Sha256::new();
        // Sign public key packet.
        let mut sign_public_key = self.public_as_packet_vec()?;
        hasher.update(&[0x99, 0, (sign_public_key.len() - 2) as u8]);
        hasher.update(&sign_public_key[2..]);
        // Subkey public key packet.
        let mut subkey_public_key = subkey.public_as_packet_vec()?;
        hasher.update(&[0x99, 0, (subkey_public_key.len() - 2) as u8]);
        hasher.update(&subkey_public_key[2..]);
        let packet = packet_cursor.get_ref();
        hasher.update(&packet[2..]);
        hasher.update(&[0x04, 0xFF, 0, 0, 0, (packet.len() - 2) as u8]);
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // No unhashed subpackets.
        packet_cursor.write_u16::<BigEndian>(0)?;
        // Push the signature of the hash.
        packet_cursor.write(&hash[..2])?;
        packet_cursor.write(&mpi_encode(&signature[..32]))?;
        packet_cursor.write(&mpi_encode(&signature[32..]))?;
        // Now that we have the full length, set it in the packet and write.
        let data = packet_cursor.get_mut();
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }
}

struct PGPEncryptKey {
    secret_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
    created_timestamp_secs: u32,
}

impl PGPEncryptKey {
    fn new(secret_key_bytes: &[u8]) -> Result<PGPEncryptKey> {
        // x25519_dalek requires a fixed size buffer. Instead of wrangling slices let's just copy.
        let mut encrypt_secret_key_bytes: [u8; 32] = [0; 32];
        encrypt_secret_key_bytes.copy_from_slice(&secret_key_bytes);
        let encrypt_secret_key: x25519_dalek::StaticSecret = encrypt_secret_key_bytes.into();
        let encrypt_public_key = x25519_dalek::PublicKey::from(&encrypt_secret_key);
        Ok(PGPEncryptKey {
            created_timestamp_secs: TIMESTAMP,
            public_key: encrypt_public_key,
            secret_key: encrypt_secret_key,
        })
    }

    fn public_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        // PAcket header, Public-Subkey (14).
        cursor.write(&[0xc0 | 14])?;
        // We write the length byte as 0 for now, we will replace it with the proper length below
        // once we have written all the information for the packet. It is assumed we only output
        // less than 255 bytes of information since that fits in one byte.
        cursor.write(&[0])?;
        cursor.write(&[0x04])?; // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs.try_into()?)?;
        cursor.write(&[18])?; // Elliptic Curve Diffie-Hellmann.
        let oid: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
        cursor.write(&[oid.len().try_into()?])?;
        cursor.write(&oid)?;
        cursor.write_u16::<BigEndian>(263)?;
        cursor.write(&[0x40])?;
        cursor.write(&self.public_key.to_bytes())?;
        // KDF parameters. Length, Reserved, SHA-256, AES-256.
        cursor.write(&[3, 1, 8, 9])?;
        let data = cursor.get_mut();
        // Now that we have the full length, set it in the packet.
        // The packet header does not count for the total length.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn public_as_packet_vec(self: &Self) -> Result<Vec<u8>> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        Ok(cursor.get_mut().to_vec())
    }

    fn secret_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        // S2K unencrypted i.e. without passphrase protection.
        cursor.write(&[0])?;
        let mpi_key = mpi_encode(&self.secret_key.to_bytes());
        cursor.write(&mpi_key)?;
        cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
        // The packet header does not count for the total length.
        let data = cursor.get_mut();
        // Rewrite the packet type, from public to secret-subkey (7).
        data[0] = 0xc0 | 7;
        // Now that we have the full length, set it in the packet and write.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }
}

struct PGPContext {
    user_id: PGPUserId,
    sign_key: PGPSignKey,
    encrypt_key: PGPEncryptKey,
}

fn output_pgp_packets<W: Write>(context: &PGPContext, mut out: BufWriter<W>) -> Result<()> {
    let mut buffer = Cursor::new(Vec::new());
    // Write user id.
    context.sign_key.secret_as_packet(&mut buffer)?;
    context.user_id.as_packet(&mut buffer)?;
    context
        .sign_key
        .self_sign_as_packet(&context.user_id, &mut buffer)?;
    context.encrypt_key.secret_as_packet(&mut buffer)?;
    context
        .sign_key
        .bind_key_as_packet(&context.encrypt_key, &mut buffer)?;
    if let Err(err) = out.write(&buffer.get_ref()) {
        Err(Box::new(err))
    } else {
        Ok(())
    }
}

fn build_keys(user_id: &str, seed: &str) -> Result<PGPContext> {
    // Derive 64 bytes (32 for sign key, 32 for encryption key) from the bytes.
    let mut hasher = Sha512::new();
    hasher.update(&seed);
    // Build PGP context from the 64 bytes.
    let secret_key_bytes = hasher.finalize();
    Ok(PGPContext {
        user_id: PGPUserId {
            user_id: user_id.to_string(),
        },
        sign_key: PGPSignKey::new(&secret_key_bytes[..32])?,
        encrypt_key: PGPEncryptKey::new(&secret_key_bytes[32..])?,
    })
}

fn main() -> Result<()> {
    let user_id = "Juan Pablo Darago <jpdarago@gmail.com>";
    let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Language::English)?;
    let context = build_keys(&user_id, mnemonic.phrase())?;
    output_pgp_packets(&context, BufWriter::new(std::io::stdout()))
}

fn main2() -> Result<()> {
    print!("Please input the RFC 2822 User ID: ");
    std::io::stdout().flush()?;
    let mut user_id = String::new();
    std::io::stdin().read_line(&mut user_id)?;
    println!("Please input the BIP 39 words separated by spaces: ");
    // Convert BIP39 passphrase to seed.
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let mnemonic = Mnemonic::from_phrase(phrase.trim(), Language::English)?;
    let context = build_keys(&user_id, mnemonic.phrase())?;
    output_pgp_packets(&context, BufWriter::new(std::io::stdout()))
}
