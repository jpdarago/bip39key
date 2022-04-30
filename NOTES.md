# BIP39 TO PGP NOTES

## V1 Interface

_Inputs_

* BIP39 seed (12 words --> 128 bits/16 bytes of entropy).
* UserId (e.g. `John Doe <john.doe@gmail.com>`).

_Output_

* OpenPGP key encoded as OpenPGP packets.
* __Unencrypted__: User must encrypt the result using GPG tool.
* Keys do not expire, the user can set the expiration manually.
* Keys are self signed.

## Possible expansions

* Output key encoded with password (using pinentry for the passphrase).
* ASCII Armored Output.
* Use a stronger algorithm (e.g. Argon2id or BCrypt) to expand the 128 bits to 512.
* Expiration for keys.

## Tasks

1. Read list of words.
2. Decode the list of words using the dictionary.
3. Take the 128 bits of entropy and expand them to 512 bits.
    * Use SHA512 to expand the entropy.
    * Need 256 bits for the seed of signature key, and the rest for the encryption key.
4. Generate the public/private key for EdDSA using the entropy.
    * How to generate EdDSA using Rust?
    * Option 1: https://docs.rs/ed25519-dalek/latest/ed25519_dalek.
    * Option 2: Implement [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).
	* [Golang implementation](https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/crypto/ed25519/ed25519.go;drc=b0c49ae9f59d233526f8934262c5bbbe14d4358d;l=123)
	* Requires SHA512 and fixed base scalar multiplication by the `B` generator of ED25519.

```
------------------------------------------------------------------------------
5.1.  Ed25519ph, Ed25519ctx, and Ed25519

   Ed25519 is EdDSA instantiated with:

   +-----------+-------------------------------------------------------+
   | Parameter | Value                                                 |
   +-----------+-------------------------------------------------------+
   |     p     | p of edwards25519 in [RFC7748] (i.e., 2^255 - 19)     |
   |     b     | 256                                                   |
   |  encoding | 255-bit little-endian encoding of {0, 1, ..., p-1}    |
   |  of GF(p) |                                                       |
   |    H(x)   | SHA-512(dom2(phflag,context)||x) [RFC6234]            |
   |     c     | base 2 logarithm of cofactor of edwards25519 in       |
   |           | [RFC7748] (i.e., 3)                                   |
   |     n     | 254                                                   |
   |     d     | d of edwards25519 in [RFC7748] (i.e., -121665/121666  |
   |           | = 370957059346694393431380835087545651895421138798432 |
   |           | 19016388785533085940283555)                           |
   |     a     | -1                                                    |
   |     B     | (X(P),Y(P)) of edwards25519 in [RFC7748] (i.e., (1511 |
   |           | 22213495354007725011514095885315114540126930418572060 |
   |           | 46113283949847762202, 4631683569492647816942839400347 |
   |           | 5163141307993866256225615783033603165251855960))      |
   |     L     | order of edwards25519 in [RFC7748] (i.e.,             |
   |           | 2^252+27742317777372353535851937790883648493).        |
   |   PH(x)   | x (i.e., the identity function)                       |
   +-----------+-------------------------------------------------------+

                      Table 1: Parameters of Ed25519

------------------------------------------------------------------------------
5.1.5.  Key Generation

   The private key is 32 octets (256 bits, corresponding to b) of
   cryptographically secure random data.  See [RFC4086] for a discussion
   about randomness.

   The 32-byte public key is generated by the following steps.

   1.  Hash the 32-byte private key using SHA-512, storing the digest in
       a 64-octet large buffer, denoted h.  Only the lower 32 bytes are
       used for generating the public key.

   2.  Prune the buffer: The lowest three bits of the first octet are
       cleared, the highest bit of the last octet is cleared, and the
       second highest bit of the last octet is set.

   3.  Interpret the buffer as the little-endian integer, forming a
       secret scalar s.  Perform a fixed-base scalar multiplication
       [s]B.

   4.  The public key A is the encoding of the point [s]B.  First,
       encode the y-coordinate (in the range 0 <= y < p) as a little-
       endian string of 32 octets.  The most significant bit of the
       final octet is always zero.  To form the encoding of the point
       [s]B, copy the least significant bit of the x coordinate to the
       most significant bit of the final octet.  The result is the
       public key.
------------------------------------------------------------------------------
```

Fixed scalar multiplication

5. Output the corresponding PGP packets.

* Secret key packet.
    * Tag: 5
    * Type 4.
    * Algo 22.
    * OID 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
* User ID packet, tag 13, eith the ID.
* Signature packet.

* [Signature Public key packet in passphrase2pgp](https://github.com/skeeto/passphrase2pgp/blob/99f508b3c25e56503cd771188eb565464ebc782f/openpgp/signkey.go#L127).
* [Signature Private key packet in passphrase2pgp](https://github.com/skeeto/passphrase2pgp/blob/99f508b3c25e56503cd771188eb565464ebc782f/openpgp/signkey.go#L149)

## PGP key Examples

### Packets for a throwaway Curve25519 key without password.

```sh
# off=0 ctb=94 tag=5 hlen=2 plen=88
:secret key packet:
        version 4, algo 22, created 1637784583, expires 0
        pkey[0]: [80 bits] ed25519 (1..6.1.4.1.11591.15.1)
        pkey[1]: [263 bits]
        skey[2]: [255 bits]
        checksum: 11cb
        keyid: E86764F01833CA22
# off=90 ctb=b4 tag=13 hlen=2 plen=38
:user ID packet: "Juan Pablo Darago <jpdarago@gmail.com>"
# off=130 ctb=88 tag=2 hlen=2 plen=144
:signature packet: algo 22, keyid E86764F01833CA22
        version 4, created 1637784583, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 2d e9
        hashed subpkt 33 len 21 (issuer fpr v4 33E32C509FF054E319E3C423E86764F01833CA22)
        hashed subpkt 2 len 4 (sig created 2021-11-24)
        hashed subpkt 27 len 1 (key flags: 03)
        hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
        hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
        hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
        hashed subpkt 30 len 1 (features: 01)
        hashed subpkt 23 len 1 (keyserver preferences: 80)
        subpkt 16 len 8 (issuer key ID E86764F01833CA22)
        data: [256 bits]
        data: [256 bits]
```

### Packets for a throwaway Curve25519 key with password.

```sh
# off=0 ctb=94 tag=5 hlen=2 plen=134
:secret key packet:
        version 4, algo 22, created 1637869917, expires 0
        pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
        pkey[1]: [263 bits]
        iter+salt S2K, algo: 7, SHA1 protection, hash: 2, salt: 7BDF5E597B923A62
        protect count: 65011712 (255)
        protect IV:  69 a3 bc 6d 5b de 85 b1 42 4d 9b 1f a6 d6 44 4a
        skey[2]: [v4 protected]
        keyid: 17BA2C6E2EC68D55
# off=136 ctb=b4 tag=13 hlen=2 plen=38
:user ID packet: "Juan Pablo Darago <jpdarago@gmail.com>"
# off=176 ctb=88 tag=2 hlen=2 plen=144
:signature packet: algo 22, keyid 17BA2C6E2EC68D55
        version 4, created 1637869917, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 2e 5a
        hashed subpkt 33 len 21 (issuer fpr v4 E482D63532C89C9C33FE9C5717BA2C6E2EC68D55)
        hashed subpkt 2 len 4 (sig created 2021-11-25)
        hashed subpkt 27 len 1 (key flags: 03)
        hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
        hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
        hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
        hashed subpkt 30 len 1 (features: 01)
        hashed subpkt 23 len 1 (keyserver preferences: 80)
        subpkt 16 len 8 (issuer key ID 17BA2C6E2EC68D55)
        data: [255 bits]
        data: [256 bits]
# off=322 ctb=9c tag=7 hlen=2 plen=139
:secret sub key packet:
        version 4, algo 18, created 1637869917, expires 0
        pkey[0]: [88 bits] cv25519 (1.3.6.1.4.1.3029.1.5.1)
        pkey[1]: [263 bits]
        pkey[2]: [32 bits]
        iter+salt S2K, algo: 7, SHA1 protection, hash: 2, salt: 636D9DBFDB52778C
        protect count: 65011712 (255)
        protect IV:  60 db 5b a2 05 4f d4 e8 ed c0 c3 a9 d8 ac 4b 63
        skey[3]: [v4 protected]
        keyid: 136D46F0079486BE
# off=463 ctb=88 tag=2 hlen=2 plen=120
:signature packet: algo 22, keyid 17BA2C6E2EC68D55
        version 4, created 1637869917, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 96 bf
        hashed subpkt 33 len 21 (issuer fpr v4 E482D63532C89C9C33FE9C5717BA2C6E2EC68D55)
        hashed subpkt 2 len 4 (sig created 2021-11-25)
        hashed subpkt 27 len 1 (key flags: 0C)
        subpkt 16 len 8 (issuer key ID 17BA2C6E2EC68D55)
        data: [256 bits]
        data: [256 bits]
```

### Packets for a throwaway Curve25519 key without password with Sign and Encryption

```sh
# off=0 ctb=94 tag=5 hlen=2 plen=88
:secret key packet:
        version 4, algo 22, created 1650302227, expires 0
        pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
        pkey[1]: [263 bits]
        skey[2]: [255 bits]
        checksum: 1172
        keyid: E30A73DD1E2A2221
# off=90 ctb=b4 tag=13 hlen=2 plen=49
:user ID packet: "Hiro Protagonist <hiro.protagonist@snowcrash.com>"
# off=141 ctb=88 tag=2 hlen=2 plen=144
:signature packet: algo 22, keyid E30A73DD1E2A2221
        version 4, created 1650302227, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 17 d2
        hashed subpkt 33 len 21 (issuer fpr v4 8452DD0EBC3B93F4BA0DA799E30A73DD1E2A2221)
        hashed subpkt 2 len 4 (sig created 2022-04-18)
        hashed subpkt 27 len 1 (key flags: 03)
        hashed subpkt 11 len 4 (pref-sym-algos: 9 8 7 2)
        hashed subpkt 21 len 5 (pref-hash-algos: 10 9 8 11 2)
        hashed subpkt 22 len 3 (pref-zip-algos: 2 3 1)
        hashed subpkt 30 len 1 (features: 01)
        hashed subpkt 23 len 1 (keyserver preferences: 80)
        subpkt 16 len 8 (issuer key ID E30A73DD1E2A2221)
        data: [256 bits]
        data: [254 bits]
# off=287 ctb=9c tag=7 hlen=2 plen=93
:secret sub key packet:
        version 4, algo 18, created 1650302227, expires 0
        pkey[0]: [88 bits] cv25519 (1.3.6.1.4.1.3029.1.5.1)
        pkey[1]: [263 bits]
        pkey[2]: [32 bits]
        skey[3]: [255 bits]
        checksum: 127b
        keyid: E39E6C571BA2E59E
# off=382 ctb=88 tag=2 hlen=2 plen=120
:signature packet: algo 22, keyid E30A73DD1E2A2221
        version 4, created 1650302227, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 56 11
        hashed subpkt 33 len 21 (issuer fpr v4 8452DD0EBC3B93F4BA0DA799E30A73DD1E2A2221)
        hashed subpkt 2 len 4 (sig created 2022-04-18)
        hashed subpkt 27 len 1 (key flags: 0C)
        subpkt 16 len 8 (issuer key ID E30A73DD1E2A2221)
        data: [255 bits]
        data: [256 bits]
```

### Packets for a passphrasepgp key

```sh
:secret key packet:
        version 4, algo 22, created 0, expires 0
        pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
        pkey[1]: [263 bits]
        skey[2]: [254 bits]
        checksum: 0fc0
        keyid: E50251E9DE87D13F
# off=90 ctb=cd tag=13 hlen=2 plen=38 new-ctb
:user ID packet: "Juan Pablo Darago <jpdarago@gmail.com>"
# off=130 ctb=c2 tag=2 hlen=2 plen=97 new-ctb
:signature packet: algo 22, keyid E50251E9DE87D13F
        version 4, created 0, md5len 0, sigclass 0x13
        digest algo 8, begin of digest 7a ae
        hashed subpkt 2 len 4 (sig created 1970-01-01)
        hashed subpkt 16 len 8 (issuer key ID E50251E9DE87D13F)
        hashed subpkt 27 len 1 (key flags: 03)
        data: [256 bits]
        data: [256 bits]
```

## Packets for a passphrasegpg key with extra info

```sh
# off=0 ctb=c5 tag=5 hlen=2 plen=88 new-ctb
:secret key packet:
        version 4, algo 22, created 0, expires 0
        pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
        pkey[1]: [263 bits]
        skey[2]: [255 bits]
        checksum: 0fc9
        keyid: 31DDBE7D05A7FE5F
# off=90 ctb=cd tag=13 hlen=2 plen=38 new-ctb
:user ID packet: "Juan Pablo Darago <jpdarago@gmail.com>"
# off=130 ctb=c2 tag=2 hlen=2 plen=100 new-ctb
:signature packet: algo 22, keyid 31DDBE7D05A7FE5F
        version 4, created 0, md5len 0, sigclass 0x13
        digest algo 8, begin of digest e9 30
        hashed subpkt 2 len 4 (sig created 1970-01-01)
        hashed subpkt 16 len 8 (issuer key ID 31DDBE7D05A7FE5F)
        hashed subpkt 27 len 1 (key flags: 03)
        hashed subpkt 30 len 1 (features: 01)
        data: [256 bits]
        data: [255 bits]
# off=232 ctb=c7 tag=7 hlen=2 plen=93 new-ctb
:secret sub key packet:
        version 4, algo 18, created 0, expires 0
        pkey[0]: [88 bits] cv25519 (1.3.6.1.4.1.3029.1.5.1)
        pkey[1]: [263 bits]
        pkey[2]: [32 bits]
        skey[3]: [255 bits]
        checksum: 11ce
        keyid: 9FDEE517BEAA6B6D
# off=327 ctb=c2 tag=2 hlen=2 plen=97 new-ctb
:signature packet: algo 22, keyid 31DDBE7D05A7FE5F
        version 4, created 0, md5len 0, sigclass 0x18
        digest algo 8, begin of digest 78 a3
        hashed subpkt 2 len 4 (sig created 1970-01-01)
        hashed subpkt 16 len 8 (issuer key ID 31DDBE7D05A7FE5F)
        hashed subpkt 27 len 1 (key flags: 0C)
        data: [255 bits]
        data: [255 bits]
```

## Links

* [RFC4880 - OpenPGP packet spec](https://datatracker.ietf.org/doc/html/rfc4880#page-5)
* [RFC4880bis - OpenPGP ECC draft](https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-06.html).
* [Similar tool](https://github.com/skeeto/passphrase2pgp)
* [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)