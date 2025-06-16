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

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

pub struct Encrypter {
    iv_encrypt: Vec<u8>,
    iv_decrypt: Vec<u8>,
    encrypt_key: Vec<u8>,
    decrypt_key: Vec<u8>,
    mac_key_send: Vec<u8>,
    mac_key_recieve: Vec<u8>,
    packet_num: u32,
    session_id: Vec<u8>,
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
        compress_alg_send: &'static str,
        compress_alg_recieve: &'static str,
        hash_prefix: Vec<u8>,
        old: Option<Encrypter>,
    ) -> Result<(), Error> {
        let (key, exchang_hash, hash_fn) = match key_exchange_alg {
            "ecdh-sha2-nistp256" => {
                Encrypter::ecdh_sha2_nistp256_exchange(stream, host_key_alg, hash_prefix)?
            }
            _ => panic!("Made new encrypter for incompattible encryption algorithm"),
        };
        Ok(())
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
    ) -> Result<(Vec<u8>, Vec<u8>, impl Fn(&[u8]) -> Vec<u8>), Error> {
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
