use anyhow::Result;
use bip39::{Language, Mnemonic, Seed};
use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{PublicKey, SecretKey};
use sha2::Digest;
use sha2::Sha512;
use std::error::Error;
use std::io::{BufWriter, Cursor, Read, Write};

struct PGPContext {
    userid: String,
    sign_public_key: Vec<u8>,
    sign_private_key: Vec<u8>,
    encrypt_public_key: Vec<u8>,
    encrypt_private_key: Vec<u8>,
    created_timestamp_secs: u64,
}

enum KeyType {
    SIGN,
    ENCRYPT,
}

struct PGPKey {
    key_type: KeyType,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    created_timestamp_secs: u64,
}

impl PGPKey {
    fn public_as_packet<W: Write>(self: Self, mut out: BufWriter<W>) -> Result<(), Box<dyn Error>> {
        let mut cursor = Cursor::new(Vec::with_capacity(256));
        cursor.write(&[0xc0
            | match self.key_type {
                KeyType::SIGN => 6,
                KeyType::ENCRYPT => 14,
            }])?;
        // We write the length byte as 0 for now, we will replace it with the proper length below
        // once we have written all the information for the packet.
        cursor.write(&[0]);
        cursor.write(&[0x04]); // Version 4.
        cursor.write_u32::<BigEndian>(self.created_timestamp_secs.try_into()?)?;
        match self.key_type {
            KeyType::SIGN => {
                cursor.write(&[0x22])?; // Algorith, EdDSA
                let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // EdDSA OID
                cursor.write(&[oid.len().try_into()?])?;
                cursor.write_u16::<BigEndian>(263)?;
                cursor.write(&[0x40])?;
                cursor.write(&self.public_key);
            }
            KeyType::ENCRYPT => {
                cursor.write(&[18]); // Elliptic Curve.
                let oid: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
                cursor.write(&[oid.len().try_into()?])?;
                cursor.write(&oid)?;
                cursor.write_u16::<BigEndian>(263)?;
                cursor.write(&[0x40])?;
                cursor.write(&self.public_key)?;
                // KDF parameters. Length, Resered, SHA-256, AES-256.
                cursor.write(&[3, 1, 8, 9]);
            }
        }
        let mut data = cursor.get_mut();
        // Now that we have the full length, set it in the packet.
        // The packet header does not count for the total length.
        data[1] = (data.len() - 2).try_into()?;
        Box::new(out.write_all(data))
    }
}

struct PGPBuffer {
    context: PGPContext,
    buffer: Cursor<Vec<u8>>,
}

impl PGPBuffer {
    fn output<W: Write>(self: &mut Self, mut out: BufWriter<W>) -> Result<(), Box<dyn Error>> {
        // Write user id.
        self.output_byte(0xc0 | 13)?;
        self.output_byte(self.context.userid.len().try_into()?)?;
        self.write_all(self.context.userid.as_bytes())?;
        // Flush
        if let Err(err) = out.write(&self.buffer.get_ref()) {
            Err(Box::new(err))
        } else {
            Ok(())
        }
    }

    fn output_byte(self: &mut Self, val: u8) -> Result<(), Box<dyn Error>> {
        let buf: [u8; 1] = [val];
        if let Err(err) = self.buffer.write_all(&buf) {
            Err(Box::new(err))
        } else {
            Ok(())
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    print!("Please input the RFC 2822 User ID");
    let mut userid = String::new();
    std::io::stdin().read_line(&mut userid)?;
    println!("Please input the BIP 39 words separated by spaces:");
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase)?;
    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    let mut hasher = Sha512::new();
    hasher.update(seed.as_bytes());
    let private_key_bytes = hasher.finalize();
    let sign_private_key = SecretKey::from_bytes(&private_key_bytes[..32])?;
    let sign_public_key: PublicKey = (&sign_private_key).into();
    let encrypt_private_key = SecretKey::from_bytes(&private_key_bytes[32..])?;
    let encrypt_public_key: PublicKey = (&sign_private_key).into();
    let context = PGPContext {
        userid,
        sign_public_key: sign_public_key.to_bytes().to_vec(),
        sign_private_key: sign_private_key.to_bytes().to_vec(),
        encrypt_public_key: encrypt_public_key.to_bytes().to_vec(),
        encrypt_private_key: encrypt_private_key.to_bytes().to_vec(),
        created_timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let mut buffer = PGPBuffer {
        context,
        buffer: Cursor::new(Vec::new()),
    };
    buffer.output(BufWriter::new(std::io::stdout()))
}
