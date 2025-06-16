use crate::Error;
use crate::ssh_stream::SshStream;
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
    encrypt_alg: EncryptAlg,
    /// Algorithm used for decrypting messages
    decrypt_alg: EncryptAlg,
    /// Algorithm used for macing sent messages
    mac_alg_send: MacAlg,
    /// Algorithm used for varifying macs on recieved messages
    mac_alg_recieve: MacAlg,
    /// Algorithm used for compressing messages
    compress_alg: CompressAlg,
    /// Algorithm used for decompressing messages
    decompress_alg: CompressAlg,
    /// Initial vector for encrypting messages
    iv_encrypt: Vec<u8>,
    /// Initial vector for decrypting messages
    iv_decrypt: Vec<u8>,
    /// Key for encrypting messages
    encrypt_key: Vec<u8>,
    /// Key for decrypting messages
    decrypt_key: Vec<u8>,
    /// Key for macing messages
    mac_key_send: Vec<u8>,
    /// Key for verifying messages
    mac_key_recieve: Vec<u8>,
    /// Number of packets sent (after initial key exchange)
    packet_num_send: u32,
    /// Number of packets recieved (after initial key exchange)
    packet_num_recieve: u32,
    /// Unique identifier for the ssh session
    session_id: Vec<u8>,
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

impl Encrypter {
    /// Preforms a key exchange using the provided key exchange algorithm and dirives enryption and mac
    /// keys. Returns a new Encrypter that can be used to encrypt, mac, and compress packets as needed.
    pub fn new(
        stream: &mut SshStream,
        key_exchange_alg: &'static str,
        host_key_alg: &'static str,
        encrypt_alg: &'static str,
        decrypt_alg: &'static str,
        mac_alg_send: &'static str,
        mac_alg_recieve: &'static str,
        compress_alg: &'static str,
        decompress_alg: &'static str,
        hash_prefix: Vec<u8>,
        old: Option<Encrypter>,
    ) -> Result<Self, Error> {
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
        let (mac_key_send_len, mac_alg_send) = match mac_alg_send {
            "hmac-sha2-256" => (32usize, MacAlg::HmacSha256),
            _ => {
                return Err(Error::Other(
                    "Made new encrypter for incompattible mac send algorithm",
                ));
            }
        };

        // Determine mac recieve information
        let (mac_key_recieve_len, mac_alg_recieve) = match mac_alg_recieve {
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
            "ecdh-sha2-nistp256" => {
                Encrypter::ecdh_sha2_nistp256_exchange(stream, host_key_alg, hash_prefix)?
            }
            _ => {
                return Err(Error::Other(
                    "Made new encrypter for incompattible key exchange algorithm",
                ));
            }
        };

        // Send and recieve the SSH_MSG_NEWKEYS message to validate successfule key exchange
        stream.send(&[SSH_MSG_NEWKEYS])?;
        let recieved = stream.read_until(SSH_MSG_NEWKEYS)?;
        if recieved.len() > 0 {
            return Err(Error::Other("Recieved invalid SSH_MSG_NEWKEYS message"));
        }

        // Extract info if key re-exchange
        let (packet_num_send, packet_num_recieve, session_id) = match old {
            Some(encrypter) => (
                encrypter.packet_num_send,
                encrypter.packet_num_recieve,
                encrypter.session_id,
            ),
            None => (0, 0, exchange_hash.clone()),
        };

        // Calculate encryption IV
        let iv_encrypt = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'A' as u8,
            &session_id,
            &hash_fn,
            iv_encrypt_len,
        );

        //Calculate decryption IV
        let iv_decrypt = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'B' as u8,
            &session_id,
            &hash_fn,
            iv_decrypt_len,
        );

        //Calculate encryption key
        let encrypt_key = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'C' as u8,
            &session_id,
            &hash_fn,
            encrypt_key_len,
        );

        //Calculate decryption key
        let decrypt_key = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'D' as u8,
            &session_id,
            &hash_fn,
            decrypt_key_len,
        );

        //Calculate mac send key
        let mac_key_send = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'E' as u8,
            &session_id,
            &hash_fn,
            mac_key_send_len,
        );

        //Calculate mac recieve key
        let mac_key_recieve = Encrypter::generate_key(
            &key,
            &exchange_hash,
            'F' as u8,
            &session_id,
            &hash_fn,
            mac_key_recieve_len,
        );

        Ok(Encrypter {
            encrypt_alg,
            decrypt_alg,
            mac_alg_send,
            mac_alg_recieve,
            compress_alg,
            decompress_alg,
            iv_encrypt,
            iv_decrypt,
            encrypt_key,
            decrypt_key,
            mac_key_send,
            mac_key_recieve,
            packet_num_send,
            packet_num_recieve,
            session_id,
        })
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
        let mut hash_data = Vec::from(key);
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
            "rsa-sha2-512" => Encrypter::rsa_sha2_512_verify(host_key, hash, signature),
            _ => Err(Error::Other(
                "Made new encrypter with invalid host key algorithm",
            )),
        }
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
    ) -> Result<(Vec<u8>, Vec<u8>, impl Fn(&[u8]) -> Vec<u8> + use<>), Error> {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key().to_sec1_bytes();

        let mut ecdh_init = vec![SSH_MSG_KEX_ECDH_INIT];
        SshStream::append_string(&mut ecdh_init, &*public);

        stream.send(&ecdh_init)?;

        let reply = stream.read_until(SSH_MSG_KEX_ECDH_REPLY)?;

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
        Encrypter::verify_hash(host_key_alg, host_key, &exchang_hash, signature)?;

        let hash_fn = |x: &[u8]| Sha256::digest(x).to_vec();

        Ok((key, exchang_hash, hash_fn))
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
    fn rsa_sha2_512_verify(
        host_key: Vec<u8>,
        hash: &[u8],
        signature: Vec<u8>,
    ) -> Result<(), Error> {
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
}
