use bip39::{Language, Mnemonic, Seed};
use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
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
}

struct PGPSignKey {
    keypair: Keypair,
    created_timestamp_secs: u32,
}

struct PGPEncryptKey {
    keypair: Keypair,
    created_timestamp_secs: u32,
}

// Encode buffer as MPI (Multi Precision Intenger), defined in OpenPGP RFC 4880.
fn mpi_encode(data: &[u8]) -> Vec<u8> {
    let mut slice = data;
    while slice[0] == 0 {
        slice = &slice[1..];
    }
    if slice.len() == 0 {
        return vec![0, 0];
    }
    let mut vec = Vec::with_capacity(slice.len() + 2);
    let c = data.len() * 8 - (slice[0].leading_zeros() as usize);
    vec.push(((c >> 8) & 0xFF) as u8);
    vec.push((c & 0xFF) as u8);
    vec.extend_from_slice(slice);
    vec
}

// Returns the PGP checksum for a data buffer, defined in OpenPGP RFC 4880.
fn checksum(buffer: &[u8]) -> u16 {
    let mut result = 0;
    for &byte in buffer {
        result += byte as u16;
    }
    result
}

impl PGPSignKey {
    fn public_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = ByteCursor::new(Vec::with_capacity(256));
        cursor.write(&[0xc0 | 6])?;
        // We write the length byte as 0 for now, we will replace it with the proper length below
        // once we have written all the information for the packet. It is assumed we only output
        // less than 255 bytes of information since that fits in one byte.
        cursor.write(&[0])?;
        cursor.write(&[0x04])?; // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs.try_into()?)?;
        cursor.write(&[0x22])?; // Algorithm, EdDSA
        let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
        cursor.write(&[oid.len().try_into()?])?;
        cursor.write_u16::<BigEndian>(263)?;
        cursor.write(&[0x40])?;
        cursor.write(self.keypair.public.as_bytes())?;
        let data = cursor.get_mut();
        // Now that we have the full length, set it in the packet.
        // The packet header does not count for the total length.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn private_as_packet(self: Self, out: &mut ByteCursor) -> Result<()> {
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

    fn keyid(self: Self) -> Result<Vec<u8>> {
        let mut hasher = Sha1::new();
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        let packet = cursor.get_ref();
        let without_header = &packet[2..];
        hasher.update(&[0x99, 0, without_header.len() as u8]);
        hasher.update(&without_header[2..]);
        let hash = hasher.finalize();
        Ok(hash[12..20].to_vec())
    }

    fn self_sign_as_packet(self: Self, user_id: &PGPUserId, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Signature Packet Header (2), Version 4.
        // Positive certification signature (0x13).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write(&[0xc0 | 2, 0x04, 0x18, 22, 8]);
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write(&[2, 5])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs);
        // Issuer subpacket (16), signature key id.
        let keyid = self.keyid()?;
        subpacket_cursor.write(&[9, 16]);
        subpacket_cursor.write(&keyid)?;
        // Key Flags (27) subpacket (sign and certify).
        subpacket_cursor.write(&[27, 0x03])?;
        // Features Subpacket (30): MDC
        subpacket_cursor.write(&[30, 0x01])?;
        // Write subpackets into the hashed subpacket area.
        let subpackets = subpacket_cursor.get_ref();
        packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
        packet_cursor.write(&subpackets)?;
        // No unhashed subpackets.
        packet_cursor.write(&[0]);
        // Compute total hash of the public key + subpackets.
        let mut hasher = Sha256::new();
        let mut public_key_cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut public_key_cursor)?;
        let public_key_packet = public_key_cursor.get_mut();
        hasher.update(&[0x99, 0, (public_key_packet.len() - 2) as u8]);
        hasher.update(&public_key_packet[2..]);
        let mut user_id_cursor = Cursor::new(Vec::with_capacity(256));
        user_id.as_packet(&mut user_id_cursor)?;
        let user_id_packet = user_id_cursor.get_mut();
        hasher.update(&[0xb4, 0, 0, 0, (user_id_packet.len() - 2) as u8]);
        hasher.update(&user_id_packet[2..]);
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // Push.
        packet_cursor.write(&hash[..2])?;
        packet_cursor.write(&mpi_encode(&signature[..32]))?;
        packet_cursor.write(&mpi_encode(&signature[32..]))?;
        // Now that we have the full length, set it in the packet and write.
        let data = packet_cursor.get_mut();
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn bind_key_as_packet(self: Self, subkey: &PGPEncryptKey, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Signature Packet Header (2), Version 4.
        // Subkey binding signature (0x18).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write(&[0xc0 | 2, 0x04, 0x18, 22, 8]);
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write(&[2, 5])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs);
        // Issuer subpacket (16), signature key id.
        let keyid = self.keyid()?;
        subpacket_cursor.write(&[9, 16]);
        subpacket_cursor.write(&keyid)?;
        // Key Flags (27) subpacket (encrypt).
        subpacket_cursor.write(&[27, 0x0c])?;
        // Write subpackets into the hashed subpacket area.
        let subpackets = subpacket_cursor.get_ref();
        packet_cursor.write_u16::<BigEndian>(subpackets.len() as u16)?;
        packet_cursor.write(&subpackets)?;
        // No unhashed subpackets.
        packet_cursor.write(&[0]);
        // Compute total hash of the public key + encrypted public key + subpackets.
        let mut hasher = Sha256::new();
        let mut public_key_cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut public_key_cursor)?;
        let public_key_packet = public_key_cursor.get_mut();
        hasher.update(&[0x99, 0, (public_key_packet.len() - 2) as u8]);
        hasher.update(&public_key_packet[2..]);
        let mut public_key_cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut public_key_cursor)?;
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // Push.
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

impl PGPEncryptKey {
    fn public_as_packet(self: &Self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
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
        cursor.write(self.keypair.public.as_bytes())?;
        // KDF parameters. Length, Reserved, SHA-256, AES-256.
        cursor.write(&[3, 1, 8, 9])?;
        let data = cursor.get_mut();
        // Now that we have the full length, set it in the packet.
        // The packet header does not count for the total length.
        data[1] = (data.len() - 2).try_into()?;
        out.write_all(data)?;
        Ok(())
    }

    fn private_as_packet(self: Self, out: &mut ByteCursor) -> Result<()> {
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

struct PGPBuffer {
    context: PGPContext,
    buffer: ByteCursor,
}

impl PGPBuffer {
    fn output<W: Write>(self: &mut Self, mut out: BufWriter<W>) -> Result<()> {
        // Write user id.
        self.context.user_id.as_packet(&mut self.buffer)?;
        self.context.sign_key.public_as_packet(&mut self.buffer)?;
        self.context
            .encrypt_key
            .public_as_packet(&mut self.buffer)?;
        self.context
            .sign_key
            .self_sign_as_packet(&self.context.user_id, &mut self.buffer);
        self.context
            .sign_key
            .bind_key_as_packet(&self.context.encrypt_key, &mut self.buffer);
        if let Err(err) = out.write(&self.buffer.get_ref()) {
            Err(Box::new(err))
        } else {
            Ok(())
        }
    }

    fn output_byte(self: &mut Self, val: u8) -> Result<()> {
        let buf: [u8; 1] = [val];
        if let Err(err) = self.buffer.write_all(&buf) {
            Err(Box::new(err))
        } else {
            Ok(())
        }
    }
}

fn main() -> Result<()> {
    print!("Please input the RFC 2822 User ID");
    let mut user_id = String::new();
    std::io::stdin().read_line(&mut user_id)?;
    println!("Please input the BIP 39 words separated by spaces:");
    // Convert BIP39 passphrase to seed.
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English)?;
    // We assume the mnemonic is not password protected.
    let seed = Seed::new(&mnemonic, "");
    // Derive 64 bytes (32 for sign key, 32 for encryption key) from the bytes.
    let mut hasher = Sha512::new();
    hasher.update(seed.as_bytes());
    // Build PGP context from the 64 bytes.
    let private_key_bytes = hasher.finalize();
    let sign_private_key = SecretKey::from_bytes(&private_key_bytes[..32])?;
    let sign_public_key: PublicKey = (&sign_private_key).into();
    let encrypt_private_key = SecretKey::from_bytes(&private_key_bytes[32..])?;
    let encrypt_public_key: PublicKey = (&sign_private_key).into();
    let context = PGPContext {
        user_id: PGPUserId { user_id },
        sign_key: PGPSignKey {
            created_timestamp_secs: TIMESTAMP,
            keypair: Keypair {
                public: sign_public_key,
                secret: sign_private_key,
            },
        },
        encrypt_key: PGPEncryptKey {
            created_timestamp_secs: TIMESTAMP,
            keypair: Keypair {
                public: encrypt_public_key,
                secret: encrypt_private_key,
            },
        },
    };
    // Build the PGP output.
    let mut buffer = PGPBuffer {
        context,
        buffer: Cursor::new(Vec::new()),
    };
    buffer.output(BufWriter::new(std::io::stdout()))
}
