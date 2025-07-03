use crate::Error;
use crate::ssh_stream::SshStream;
use aes::{
    Aes256,
    cipher::{
        BlockEncrypt, KeyInit,
        consts::{U16, U32},
        generic_array::GenericArray,
    },
};
use hmac::{Hmac, Mac};
use p256::{NistP256, ecdh::EphemeralSecret, elliptic_curve::PublicKey};
use rand_core::OsRng;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
};
use sha2::{Digest, Sha256, Sha512};

/// Indicates successfule key exchange
const SSH_MSG_NEWKEYS: u8 = 21;

/// Indicates start of ecdh key exchange
const SSH_MSG_KEX_ECDH_INIT: u8 = 30;

/// Indicates end of ecdh key exchange
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// A struct containing all information neccessary to encrypt, mac, and compress
/// messages sent and recieved over an SSHStream.
pub struct Encrypter {
    /// Algorithm used for encrypting messages
    encrypt: EncryptAlg,
    /// Algorithm used for macing sent messages
    mac: MacAlg,
    /// Algorithm used for compressing messages
    compress: CompressAlg,
    /// Initial vector for encrypting messages
    iv: Vec<u8>,
    /// Key for encrypting messages
    key: Vec<u8>,
    /// Key for macing messages
    mac_key: Vec<u8>,
    /// Number of packets sent (after initial key exchange)
    pub packet_num: u32,
    /// Unique identifier for the ssh session
    session_id: Vec<u8>,
}

pub struct Decrypter {
    /// Algorithm used for decrypting messages
    decrypt: EncryptAlg,
    /// Algorithm used for varifying macs on recieved messages
    verify: MacAlg,
    /// Algorithm used for decompressing messages
    decompress: CompressAlg,
    /// Initial vector for decrypting messages
    iv: Vec<u8>,
    /// Key for decrypting messages
    key: Vec<u8>,
    /// Key for verifying messages
    verify_key: Vec<u8>,
    /// Number of packets recieved (after initial key exchange)
    pub packet_num: u32,
}

/// Enum representing all supported encryption algorithm types
enum EncryptAlg {
    /// Represents aes256-ctr algorithm
    Aes256Ctr,
}

/// Enum representing all supported mac algorithm types
enum MacAlg {
    /// Represents hmac-sha2-s56 algorithm
    HmacSha256,
}

/// Enum representing all supported compression algorithm types
enum CompressAlg {
    /// Represents no compression
    None,
}

/// Preforms a key exchange using the provided key exchange algorithm and dirives enryption and mac
/// keys. Returns a new Encrypter that can be used to encrypt, mac, and compress packets as needed.
pub fn generate(
    stream: &mut SshStream,
    key_exchange_alg: &'static str,
    host_key_alg: &'static str,
    encrypt_alg: &'static str,
    decrypt_alg: &'static str,
    mac_alg: &'static str,
    verify_alg: &'static str,
    compress_alg: &'static str,
    decompress_alg: &'static str,
    hash_prefix: Vec<u8>,
    mut num_read: u32,
    mut old_enc: Option<Encrypter>,
    old_dec: Option<Decrypter>,
) -> Result<(Encrypter, Decrypter), Error> {
    // Determine encryption information
    let (iv_encrypt_len, encrypt_key_len, encrypt_alg) = match encrypt_alg {
        "aes256-ctr" => (16usize, 32usize, EncryptAlg::Aes256Ctr),
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible encryption algorithm",
            ));
        }
    };

    // Determine decryption information
    let (iv_decrypt_len, decrypt_key_len, decrypt_alg) = match decrypt_alg {
        "aes256-ctr" => (16usize, 32usize, EncryptAlg::Aes256Ctr),
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible encryption algorithm",
            ));
        }
    };

    // Determine mac send information
    let (mac_key_len, mac_alg) = match mac_alg {
        "hmac-sha2-256" => (32usize, MacAlg::HmacSha256),
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible mac send algorithm",
            ));
        }
    };

    // Determine mac recieve information
    let (verify_key_len, verify_alg) = match verify_alg {
        "hmac-sha2-256" => (32usize, MacAlg::HmacSha256),
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible mac recieve algorithm",
            ));
        }
    };

    // Determine compression sending information
    let compress_alg = match compress_alg {
        "none" => CompressAlg::None,
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible compression send algorithm",
            ));
        }
    };

    // Determine compression sending information
    let decompress_alg = match decompress_alg {
        "none" => CompressAlg::None,
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible compression recieve algorithm",
            ));
        }
    };

    // Exchange secret keys
    let (key, exchange_hash, hash_fn) = match key_exchange_alg {
        "ecdh-sha2-nistp256" => ecdh_sha2_nistp256_exchange(
            stream,
            host_key_alg,
            hash_prefix,
            &mut num_read,
            &mut old_enc,
        )?,
        _ => {
            return Err(Error::Other(
                "Made new encrypter for incompattible key exchange algorithm",
            ));
        }
    };

    // Send and recieve the SSH_MSG_NEWKEYS message to validate successfule key exchange
    stream.send(&[SSH_MSG_NEWKEYS], old_enc.as_mut())?;
    let (recieved, new_read) = stream.read_until_no_decrypter(SSH_MSG_NEWKEYS)?;
    num_read += new_read;
    if recieved.len() > 0 {
        return Err(Error::Other("Recieved invalid SSH_MSG_NEWKEYS message"));
    }

    // Extract info if key re-exchange
    let (packet_num_send, session_id) = match old_enc {
        Some(encrypter) => (encrypter.packet_num, encrypter.session_id),
        None => (3, exchange_hash.clone()),
    };

    let packet_num_recieve = match old_dec {
        Some(decrypter) => decrypter.packet_num,
        None => num_read,
    };

    // Calculate encryption IV
    let iv_encrypt = generate_key(
        &key,
        &exchange_hash,
        'A' as u8,
        &session_id,
        &hash_fn,
        iv_encrypt_len,
    );

    //Calculate decryption IV
    let iv_decrypt = generate_key(
        &key,
        &exchange_hash,
        'B' as u8,
        &session_id,
        &hash_fn,
        iv_decrypt_len,
    );

    //Calculate encryption key
    let encrypt_key = generate_key(
        &key,
        &exchange_hash,
        'C' as u8,
        &session_id,
        &hash_fn,
        encrypt_key_len,
    );

    //Calculate decryption key
    let decrypt_key = generate_key(
        &key,
        &exchange_hash,
        'D' as u8,
        &session_id,
        &hash_fn,
        decrypt_key_len,
    );

    //Calculate mac send key
    let mac_key = generate_key(
        &key,
        &exchange_hash,
        'E' as u8,
        &session_id,
        &hash_fn,
        mac_key_len,
    );

    //Calculate mac recieve key
    let verify_key = generate_key(
        &key,
        &exchange_hash,
        'F' as u8,
        &session_id,
        &hash_fn,
        verify_key_len,
    );

    Ok((
        Encrypter {
            encrypt: encrypt_alg,
            mac: mac_alg,
            compress: compress_alg,
            iv: iv_encrypt,
            key: encrypt_key,
            mac_key,
            packet_num: packet_num_send,
            session_id: session_id.clone(),
        },
        Decrypter {
            decrypt: decrypt_alg,
            verify: verify_alg,
            decompress: decompress_alg,
            iv: iv_decrypt,
            key: decrypt_key,
            verify_key,
            packet_num: packet_num_recieve,
        },
    ))
}

/// Preforms ecdh-sha2-nistp256 key exchange on the given stream and uses the
/// given host_key_alg to validate signatures on important values produced
/// during the exchange. The hash_prefix should contain all relavant values
/// to the exchange hash in the proper format so that newly computed values can
/// be appended.
///
/// Results in the shared secret key, the exchange hash, and the hash function to use
/// for key generation.
fn ecdh_sha2_nistp256_exchange(
    stream: &mut SshStream,
    host_key_alg: &'static str,
    mut hash_prefix: Vec<u8>,
    num_read: &mut u32,
    old: &mut Option<Encrypter>,
) -> Result<(Vec<u8>, Vec<u8>, impl Fn(&[u8]) -> Vec<u8> + use<>), Error> {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = secret.public_key().to_sec1_bytes();

    let mut ecdh_init = vec![SSH_MSG_KEX_ECDH_INIT];
    SshStream::append_string(&mut ecdh_init, &*public);

    stream.send(&ecdh_init, old.as_mut())?;

    let (reply, new_read) = stream.read_until_no_decrypter(SSH_MSG_KEX_ECDH_REPLY)?;
    *num_read += new_read;

    let (host_key, reply) = SshStream::extract_string(&reply)?;
    let (server_public, reply) = SshStream::extract_string(&reply)?;
    let (signature, _) = SshStream::extract_string(&reply)?;

    let pub_key = match PublicKey::<NistP256>::from_sec1_bytes(&server_public) {
        Ok(key) => key,
        Err(_) => return Err(Error::Other("Failed to parse ecdh public key")),
    };

    let key = secret.diffie_hellman(&pub_key).raw_secret_bytes().to_vec();

    // Update exchange hash
    SshStream::append_string(&mut hash_prefix, &host_key);
    SshStream::append_string(&mut hash_prefix, &*public);
    SshStream::append_string(&mut hash_prefix, &server_public);
    SshStream::append_mpint(&mut hash_prefix, &key, true);

    // Compute exchange hash
    let exchang_hash = Sha256::digest(hash_prefix).to_vec();

    // Verify exchange hash
    verify_hash(host_key_alg, host_key, &exchang_hash, signature)?;

    let hash_fn = |x: &[u8]| Sha256::digest(x).to_vec();

    Ok((key, exchang_hash, hash_fn))
}

/// Generates a new key based on the shared secret, exchange hash, session id, and byte value given in
/// accordance with SSH key generation. Creates a key of the specified length.
fn generate_key(
    key: &[u8],
    exchange_hash: &[u8],
    char: u8,
    session_id: &[u8],
    hash_fn: impl Fn(&[u8]) -> Vec<u8>,
    output_len: usize,
) -> Vec<u8> {
    let mut hash_data = Vec::new();
    SshStream::append_mpint(&mut hash_data, key, true);
    hash_data.extend(exchange_hash);
    hash_data.push(char);
    hash_data.extend(session_id);

    let mut result = hash_fn(&hash_data);

    while result.len() < output_len {
        let mut hash_data = Vec::from(key);
        hash_data.extend(exchange_hash);
        hash_data.extend(&result);

        result.extend(hash_fn(&hash_data));
    }

    result.truncate(output_len);

    result
}

/// Verifies an exchange hash (or any relavant message) with the host key and the specified
/// host key algorithm. The host key and the signature need to be in the exact form they were
/// sent over in.
///
/// Host Key: \
/// string ssh-rsa \
/// mpint e \
/// mpint n
///
/// Signature: \
/// string ssh-rsa2-512 \
/// string signature
fn verify_hash(
    host_key_alg: &'static str,
    host_key: Vec<u8>,
    hash: &[u8],
    signature: Vec<u8>,
) -> Result<(), Error> {
    match host_key_alg {
        "rsa-sha2-512" => rsa_sha2_512_verify(host_key, hash, signature),
        _ => Err(Error::Other(
            "Made new encrypter with invalid host key algorithm",
        )),
    }
}

/// Uses rsa-sha2-512 to verify a signature on a value using the given host key.
/// The host key and signature should be in the SSH format that it was sent as:
///
/// string ssh-rsa
/// mpint e
/// mpint n
///
/// and the signature should also be in the SSH format it was sent as:
///
/// string ssh-rsa2-512
/// string signature
///
/// The value of hash should simply be the unhashed message that needs to be verified
fn rsa_sha2_512_verify(host_key: Vec<u8>, hash: &[u8], signature: Vec<u8>) -> Result<(), Error> {
    // Check for valid key type
    let (key_type, host_key) = SshStream::extract_string(&host_key)?;
    if key_type != b"ssh-rsa" {
        return Err(Error::Other("Invalid host key type: Expected ssh-rsa"));
    }

    // Create rsa verifying key
    let (e, host_key) = SshStream::extract_mpint_unsigned(host_key)?;
    let (n, _) = SshStream::extract_mpint_unsigned(host_key)?;
    let pub_key = match RsaPublicKey::new(n, e) {
        Ok(key) => key,
        Err(_) => return Err(Error::Other("Invalid RSA host key")),
    };
    let verifying_key = VerifyingKey::<Sha512>::new(pub_key);

    // Extract signature
    let (sig_type, signature) = SshStream::extract_string(&signature)?;
    if sig_type != b"rsa-sha2-512" {
        return Err(Error::Other(
            "Invalid signature type: Expected rsa-sha2-512",
        ));
    }
    let (signature, _) = SshStream::extract_string(signature)?;
    let signature = Signature::try_from(signature.as_slice()).unwrap();

    // Verify signature
    match verifying_key.verify(hash, &signature) {
        Ok(()) => Ok(()),
        Err(_) => Err(Error::Other(
            "Failed to validate signature of exchange hash",
        )),
    }
}

/// Incraments a counter in the form of an array slice in place
fn increment_counter(counter: &mut [u8]) {
    for digit in counter.iter_mut().rev() {
        if *digit == 0xFF {
            *digit = 0;
        } else {
            *digit += 1;
            return;
        }
    }
}

impl Encrypter {
    // Encryption Functions

    /// Encrypts a plaintext vector for sending over ssh
    pub fn encrypt(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.encrypt {
            EncryptAlg::Aes256Ctr => self.aes256_ctr(plaintext),
        }
    }

    /// Returns the block size needed for the encryption algorithm
    pub fn block_size(&self) -> u32 {
        match self.encrypt {
            EncryptAlg::Aes256Ctr => 16,
        }
    }

    /// Encrypts a plaintext vector using aes256-ctr according to ssh specifications
    fn aes256_ctr(&mut self, mut plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Check if plaintext is a multiple of the block size
        if plaintext.len() % 16 != 0 {
            return Err(Error::Other(
                "Tried to encrypt block with bad size: Expected multiple of 16",
            ));
        }

        // If plaintext is empty then we are done
        if plaintext.len() == 0 {
            return Ok(Vec::new());
        }

        // Check for valid key length
        if self.key.len() != 32 {
            return Err(Error::Other(
                "Tried to encrypt with invalid key length: Expect 32 bytes",
            ));
        }

        // Check for valid iv length
        if self.iv.len() != 16 {
            return Err(Error::Other(
                "Tried to encrypt with invalid iv length: Expect 16 bytes",
            ));
        }

        // Create cypher
        let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&self.key);
        let cypher = Aes256::new(&key);

        // Encrypt plaintext
        for chunk in plaintext.chunks_mut(16) {
            let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&self.iv);
            cypher.encrypt_block(&mut block);
            for (c, k) in chunk.iter_mut().zip(block.iter()) {
                *c ^= k;
            }
            increment_counter(&mut self.iv);
        }

        Ok(plaintext)
    }

    // Mac functions

    /// Generates a mac for a message
    pub fn mac(&mut self, message: &[u8]) -> Vec<u8> {
        let result = match self.mac {
            MacAlg::HmacSha256 => self.hmac_sha256(message),
        };
        self.packet_num += 1;
        result
    }

    /// Uses hmac-sha2-256 to generate a mac for a message
    fn hmac_sha256(&mut self, message: &[u8]) -> Vec<u8> {
        // Create message to mac
        let mut mac_message: Vec<u8> = Vec::from(self.packet_num.to_be_bytes());
        mac_message.extend(message);

        // Mac message
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.mac_key)
            .expect("HMAC can take key of any size");
        mac.update(&mac_message);
        let result = mac.finalize();

        result.into_bytes().to_vec()
    }

    // Compression functions

    /// Uses the negotiated compression algorithm to compress a payload
    pub fn compress(&self, payload: &[u8]) -> Vec<u8> {
        match self.compress {
            CompressAlg::None => payload.to_vec(),
        }
    }
}

impl Decrypter {
    // Decryption Functions

    /// decrypts a cyphertext vector recieved over an ssh stream
    pub fn decrypt(&mut self, cyphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.decrypt {
            EncryptAlg::Aes256Ctr => self.aes256_ctr(cyphertext),
        }
    }

    /// Returns the block size needed for the encryption algorithm
    pub fn block_size(&self) -> u32 {
        match self.decrypt {
            EncryptAlg::Aes256Ctr => 16,
        }
    }

    /// Decrypts a cyphertext vector using aes256-ctr according to ssh specifications
    fn aes256_ctr(&mut self, mut cyphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Check if cyphertext is a multiple of the block size
        if cyphertext.len() % 16 != 0 {
            return Err(Error::Other(
                "Tried to decrypt block with bad size: Expected multiple of 16",
            ));
        }

        // If cyphertext is empty then we are done
        if cyphertext.len() == 0 {
            return Ok(Vec::new());
        }

        // Check for valid key length
        if self.key.len() != 32 {
            return Err(Error::Other(
                "Tried to decrypt with invalid key length: Expect 32 bytes",
            ));
        }

        // Check for valid iv length
        if self.iv.len() != 16 {
            return Err(Error::Other(
                "Tried to decrypt with invalid iv length: Expect 16 bytes",
            ));
        }

        // Create cypher
        let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&self.key);
        let cypher = Aes256::new(&key);

        // Encrypt plaintext
        for chunk in cyphertext.chunks_mut(16) {
            let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&self.iv);
            cypher.encrypt_block(&mut block);
            for (p, k) in chunk.iter_mut().zip(block.iter()) {
                *p ^= k;
            }
            increment_counter(&mut self.iv);
        }

        Ok(cyphertext)
    }

    // Mac Verification Functions

    /// Verifies a mac for a message
    pub fn verify(&mut self, message: &[u8], mac: &[u8]) -> bool {
        let result = match self.verify {
            MacAlg::HmacSha256 => self.hmac_sha256(message, mac),
        };
        self.packet_num += 1;
        result
    }

    /// The length of the mac expected by verify
    pub fn verify_length(&self) -> usize {
        match self.verify {
            MacAlg::HmacSha256 => 32,
        }
    }

    /// Uses hmac-sha2-256 to verify a mac on a message
    fn hmac_sha256(&mut self, message: &[u8], mac: &[u8]) -> bool {
        // Create message to verify
        let mut mac_message: Vec<u8> = Vec::from(self.packet_num.to_be_bytes());
        mac_message.extend(message);

        // Verify message
        let mut verifyer =
            <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.verify_key)
                .expect("HMAC can take key of any size");
        verifyer.update(&mac_message);

        match verifyer.verify_slice(mac) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    // Decompression Functions

    /// Uses the negotiated compression algorithm to decompress a payload
    pub fn decompress(&self, payload: &[u8]) -> Vec<u8> {
        match self.decompress {
            CompressAlg::None => payload.to_vec(),
        }
    }
}
