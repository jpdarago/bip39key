use bip39::{Language, Mnemonic};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use clap::Parser;
use ed25519_dalek::Signer;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;
use std::error::Error;
use std::io::{BufWriter, Cursor, Write};

type ByteCursor = Cursor<Vec<u8>>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Default creation time: timestamp of the Bitcoin genesis block. Any timestamp would
// work but this one is fairly recent, well established, and stored in a decentralized
// database.
const TIMESTAMP: u32 = 1231006505;

enum PGPPacketType {
    PrivateEncryptSubkey,
    PrivateSignKey,
    PublicSignKey,
    Signature,
    UserId,
    LiteralData,
}

fn hash_u16(n: u16, hasher: &mut sha2::Sha256) {
    let mut buf = [0; 2];
    BigEndian::write_u16(&mut buf, n);
    hasher.update(&buf);
}

fn hash_u32(n: u32, hasher: &mut sha2::Sha256) {
    let mut buf = [0; 4];
    BigEndian::write_u32(&mut buf, n);
    hasher.update(&buf);
}

// Encode the contents of the byte buffer as a PGP packet of the given type.
fn output_as_packet(
    packet_type: PGPPacketType,
    packet_bytes: &[u8],
    out: &mut ByteCursor,
) -> Result<()> {
    let type_byte: u8 = 0xc0
        | match packet_type {
            PGPPacketType::PrivateEncryptSubkey => 7,
            PGPPacketType::PrivateSignKey => 5,
            PGPPacketType::PublicSignKey => 6,
            PGPPacketType::Signature => 2,
            PGPPacketType::UserId => 13,
            PGPPacketType::LiteralData => 11,
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
    fn as_packet(&self, out: &mut ByteCursor) -> Result<()> {
        output_as_packet(PGPPacketType::UserId, self.user_id.as_bytes(), out)
    }
}

struct PGPLiteralPacket {
    data: String,
    timestamp_secs: u32,
}

impl PGPLiteralPacket {
    fn as_packet(&self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = ByteCursor::new(Vec::with_capacity(256));
        // Text data as UTF-8.
        cursor.write_all(&[0x75])?;
        // Made up filename, its not important.
        let filename = "bip39pgp.info.txt";
        cursor.write_all(&[filename.len() as u8])?;
        cursor.write_all(filename.as_bytes())?;
        // Timestamp for the file, its not important.
        cursor.write_u32::<BigEndian>(self.timestamp_secs)?;
        cursor.write_all(self.data.as_bytes())?;
        output_as_packet(PGPPacketType::LiteralData, cursor.get_ref(), out)
    }
}

struct PGPSignKey {
    keypair: ed25519_dalek::Keypair,
    created_timestamp_secs: u32,
}

impl PGPSignKey {
    fn new(secret_key_bytes: &[u8], timestamp_secs: u32) -> Result<PGPSignKey> {
        let sign_secret_key = ed25519_dalek::SecretKey::from_bytes(secret_key_bytes)?;
        let sign_public_key: ed25519_dalek::PublicKey = (&sign_secret_key).into();
        Ok(PGPSignKey {
            created_timestamp_secs: timestamp_secs,
            keypair: ed25519_dalek::Keypair {
                public: sign_public_key,
                secret: sign_secret_key,
            },
        })
    }

    fn public_packet_payload(&self) -> Result<Vec<u8>> {
        let mut cursor = ByteCursor::new(Vec::with_capacity(256));
        cursor.write_all(&[0x04])?; // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs)?;
        cursor.write_all(&[22])?; // Algorithm, EdDSA
        let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
        cursor.write_all(&[oid.len().try_into()?])?;
        cursor.write_all(&oid)?;
        // 263 bits: 7 bits for 0x40 prefix byte and 32 bytes for public key.
        cursor.write_u16::<BigEndian>(263)?;
        // Prefix octet for EdDSA Point Format.
        cursor.write_all(&[0x40])?;
        cursor.write_all(self.keypair.public.as_bytes())?;
        Ok(cursor.into_inner())
    }

    fn public_as_packet(&self, out: &mut ByteCursor) -> Result<()> {
        let payload = self.public_packet_payload()?;
        output_as_packet(PGPPacketType::PublicSignKey, &payload, out)
    }

    fn secret_as_packet(&self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        let payload = self.public_packet_payload()?;
        cursor.write_all(&payload)?;
        // S2K unencrypted i.e. without passphrase protection.
        cursor.write_all(&[0])?;
        let mpi_key = mpi_encode(self.keypair.secret.as_bytes());
        cursor.write_all(&mpi_key)?;
        cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
        // The packet header does not count for the total length.
        output_as_packet(PGPPacketType::PrivateSignKey, cursor.get_ref(), out)
    }

    fn key_fingerprint(&self) -> Result<Vec<u8>> {
        let mut hasher = Sha1::new();
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        self.public_as_packet(&mut cursor)?;
        let packet = cursor.get_ref();
        let without_header = &packet[2..];
        hasher.update(&[0x99, 0, without_header.len() as u8]);
        hasher.update(&without_header);
        Ok(hasher.finalize().to_vec())
    }

    fn self_sign_as_packet(&self, user_id: &PGPUserId, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Version 4 signature.
        // Positive certification signature (0x13).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write_all(&[0x04, 0x13, 22, 8])?;
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write_all(&[5, 2])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs)?;
        // Issuer subpacket (16), signature key id.
        let key_fp = self.key_fingerprint()?;
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
        let mut hasher = Sha256::new();
        let public_key_packet = self.public_packet_payload()?;
        hasher.update(&[0x99]);
        hash_u16(public_key_packet.len().try_into()?, &mut hasher);
        hasher.update(&public_key_packet);
        let user_id = &user_id.user_id;
        hasher.update(&[0xb4]);
        hash_u32(user_id.len().try_into()?, &mut hasher);
        hasher.update(&user_id.as_bytes());
        let packet = packet_cursor.get_ref();
        hasher.update(&packet);
        hasher.update(&[0x04, 0xFF]);
        hash_u32(packet.len().try_into()?, &mut hasher);
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // No unhashed subpackets.
        packet_cursor.write_u16::<BigEndian>(0)?;
        // Push the signature of the hash.
        packet_cursor.write_all(&hash[..2])?;
        packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
        packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
        output_as_packet(PGPPacketType::Signature, packet_cursor.get_ref(), out)
    }

    fn bind_key_as_packet(&self, subkey: &PGPEncryptKey, out: &mut ByteCursor) -> Result<()> {
        let mut packet_cursor = Cursor::new(Vec::with_capacity(256));
        // Version 4 signature.
        // Subkey binding signature (0x18).
        // EdDSA signature (22), SHA-256 hash (8).
        packet_cursor.write_all(&[0x04, 0x18, 22, 8])?;
        // Write subpackets to a buffer.
        // Signature creation time subpacket (2), 5 bytes.
        let mut subpacket_cursor = Cursor::new(Vec::with_capacity(256));
        subpacket_cursor.write_all(&[5, 2])?;
        subpacket_cursor.write_u32::<BigEndian>(self.created_timestamp_secs)?;
        // Issuer subpacket (16), signature key id.
        let key_fp = self.key_fingerprint()?;
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
        let mut hasher = Sha256::new();
        // Sign public key packet.
        let sign_public_key = self.public_packet_payload()?;
        hasher.update(&[0x99]);
        hash_u16(sign_public_key.len().try_into()?, &mut hasher);
        hasher.update(&sign_public_key);
        // Subkey public key packet.
        let subkey_public_key = subkey.public_packet_payload()?;
        hasher.update(&[0x99]);
        hash_u16(subkey_public_key.len().try_into()?, &mut hasher);
        hasher.update(&subkey_public_key);
        let packet = packet_cursor.get_ref();
        hasher.update(&packet);
        hasher.update(&[0x04, 0xFF]);
        hash_u32(packet.len().try_into()?, &mut hasher);
        let hash = hasher.finalize();
        // Sign the hash.
        let signature = self.keypair.sign(&hash).to_bytes();
        // No unhashed subpackets.
        packet_cursor.write_u16::<BigEndian>(0)?;
        // Push the signature of the hash.
        packet_cursor.write_all(&hash[..2])?;
        packet_cursor.write_all(&mpi_encode(&signature[..32]))?;
        packet_cursor.write_all(&mpi_encode(&signature[32..]))?;
        output_as_packet(PGPPacketType::Signature, packet_cursor.get_ref(), out)
    }
}

struct PGPEncryptKey {
    secret_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
    created_timestamp_secs: u32,
}

impl PGPEncryptKey {
    fn new(secret_key_bytes: &[u8], timestamp_secs: u32) -> Result<PGPEncryptKey> {
        // x25519_dalek requires a fixed size buffer. Instead of wrangling slices let's just copy.
        let mut encrypt_secret_key_bytes: [u8; 32] = [0; 32];
        encrypt_secret_key_bytes.copy_from_slice(secret_key_bytes);
        let encrypt_secret_key: x25519_dalek::StaticSecret = encrypt_secret_key_bytes.into();
        let encrypt_public_key = x25519_dalek::PublicKey::from(&encrypt_secret_key);
        Ok(PGPEncryptKey {
            created_timestamp_secs: timestamp_secs,
            public_key: encrypt_public_key,
            secret_key: encrypt_secret_key,
        })
    }

    fn public_packet_payload(&self) -> Result<Vec<u8>> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        cursor.write_all(&[0x04])?; // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs)?;
        cursor.write_all(&[18])?; // Elliptic Curve Diffie-Hellmann.
        let oid: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
        cursor.write_all(&[oid.len().try_into()?])?;
        cursor.write_all(&oid)?;
        cursor.write_u16::<BigEndian>(263)?;
        cursor.write_all(&[0x40])?;
        cursor.write_all(&self.public_key.to_bytes())?;
        // KDF parameters. Length, Reserved, SHA-256, AES-256.
        cursor.write_all(&[3, 1, 8, 9])?;
        Ok(cursor.into_inner())
    }

    fn secret_as_packet(&self, out: &mut ByteCursor) -> Result<()> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        let payload = self.public_packet_payload()?;
        cursor.write_all(&payload)?;
        // S2K unencrypted i.e. without passphrase protection.
        cursor.write_all(&[0])?;
        // TODO: Why do we need this? I took it from passphrase2pgp but I do not understand why we
        // would need to reverse the secret key.
        let mut reverse_secret_key: [u8; 32] = [0; 32];
        reverse_secret_key.copy_from_slice(&self.secret_key.to_bytes());
        reverse_secret_key.reverse();
        let mpi_key = mpi_encode(&reverse_secret_key);
        cursor.write_all(&mpi_key)?;
        cursor.write_u16::<BigEndian>(checksum(&mpi_key))?;
        output_as_packet(PGPPacketType::PrivateEncryptSubkey, cursor.get_ref(), out)
    }
}

struct PGPContext {
    user_id: PGPUserId,
    sign_key: PGPSignKey,
    encrypt_key: PGPEncryptKey,
    metadata: PGPLiteralPacket,
}

enum OutputKeys {
    SignKey,
    SignAndEncryptionKey,
}

fn output_pgp_packets<W: Write>(
    context: &PGPContext,
    output_keys: OutputKeys,
    mut out: BufWriter<W>,
) -> Result<()> {
    let mut buffer = Cursor::new(Vec::new());
    context.sign_key.secret_as_packet(&mut buffer)?;
    context.user_id.as_packet(&mut buffer)?;
    context
        .sign_key
        .self_sign_as_packet(&context.user_id, &mut buffer)?;
    if let OutputKeys::SignAndEncryptionKey = output_keys {
        context.encrypt_key.secret_as_packet(&mut buffer)?;
        context
            .sign_key
            .bind_key_as_packet(&context.encrypt_key, &mut buffer)?;
    }
    context.metadata.as_packet(&mut buffer)?;
    if let Err(err) = out.write_all(buffer.get_ref()) {
        Err(Box::new(err))
    } else {
        Ok(())
    }
}

fn build_keys(user_id: &str, seed: &[u8], timestamp_secs: u32) -> Result<PGPContext> {
    // Derive 64 bytes by running Argon with the user id as salt.
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 32 * 1024,
        time_cost: 8,
        lanes: 4,
        thread_mode: argon2::ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 64,
    };
    let secret_key_bytes = argon2::hash_raw(seed, user_id.as_bytes(), &config)?;
    Ok(PGPContext {
        user_id: PGPUserId {
            user_id: user_id.to_string(),
        },
        sign_key: PGPSignKey::new(&secret_key_bytes[..32], timestamp_secs)?,
        encrypt_key: PGPEncryptKey::new(&secret_key_bytes[32..], timestamp_secs)?,
        metadata: PGPLiteralPacket {
            timestamp_secs,
            data: format!(
                "Created by {} version {} with Argon settings {:?}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                &config
            ),
        },
    })
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// RFC 2822 of the user, e.g. "User <user@email.com>".
    #[clap(short, long)]
    user_id: String,

    /// Filename where to output the keys, if not present then write to stdout.
    #[clap(short, long)]
    filename: Option<String>,

    /// Timestamp (in seconds) for the dates. If unset, use the default 1231006505.
    #[clap(short, long)]
    timestamp: Option<u32>,

    /// Output encryption key as well as sign key.
    #[clap(short, long)]
    subkey: Option<bool>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let mnemonic = Mnemonic::from_phrase(phrase.trim(), Language::English);
    if let Err(err) = mnemonic {
        eprintln!("Invalid BIP39 mnemonic: {}", err);
        std::process::exit(1);
    }
    let context = build_keys(
        &args.user_id,
        mnemonic.unwrap().entropy(),
        args.timestamp.unwrap_or(TIMESTAMP),
    )
    .expect("Could not build OpenPGP keys");
    let output_keys = if args.subkey.unwrap_or(true) {
        OutputKeys::SignAndEncryptionKey
    } else {
        OutputKeys::SignKey
    };
    if let Some(filename) = args.filename {
        let output = std::fs::File::open(&filename);
        if let Err(err) = output {
            eprintln!("Cannot open output file {}: {}", filename, err);
            std::process::exit(1);
        }
        output_pgp_packets(&context, output_keys, BufWriter::new(&mut output.unwrap()))
    } else {
        output_pgp_packets(&context, output_keys, BufWriter::new(std::io::stdout()))
    }
}
