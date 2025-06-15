use crate::Error;
use crate::ssh_stream::SshStream;
use p256::{NistP256, ecdh::EphemeralSecret, elliptic_curve::PublicKey};
use rand_core::OsRng;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Pkcs1v15Sign, Signature, VerifyingKey},
    signature::{self, Verifier},
};
use sha2::{Digest, Sha256, Sha512};

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

pub struct Encrypter {
    encrypt_key_cts: Vec<u8>,
    encrypt_key_stc: Vec<u8>,
    mac_key_cts: Vec<u8>,
    mac_key_stc: Vec<u8>,
    compress_key_cts: Vec<u8>,
    compress_key_stc: Vec<u8>,
}

impl Encrypter {
    /// Preforms a key exchange using the provided key exchange algorithm and dirives enryption and mac
    /// keys. Returns a new Encrypter that can be used to encrypt, mac, and compress packets as needed.
    pub fn new(
        stream: &mut SshStream,
        key_exchange_alg: &'static str,
        host_key_alg: &'static str,
        encrypt_alg_cts: &'static str,
        encrypt_alg_stc: &'static str,
        mac_alg_cts: &'static str,
        mac_alg_stc: &'static str,
        compress_alg_cts: &'static str,
        compress_alg_stc: &'static str,
        hash_prefix: Vec<u8>,
    ) -> Result<(), Error> {
        match key_exchange_alg {
            "ecdh-sha2-nistp256" => {
                Encrypter::ecdh_sha2_nistp256_exchange(stream, host_key_alg, hash_prefix)
            }
            _ => panic!("Made new encrypter for incompattible encryption algorithm"),
        }
    }

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

    fn ecdh_sha2_nistp256_exchange(
        stream: &mut SshStream,
        host_key_alg: &'static str,
        mut hash_prefix: Vec<u8>,
    ) -> Result<(), Error> {
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

        let K = secret.diffie_hellman(&pub_key).raw_secret_bytes().to_vec();

        // Update exchange hash
        SshStream::append_string(&mut hash_prefix, &host_key);
        SshStream::append_string(&mut hash_prefix, &*public);
        SshStream::append_string(&mut hash_prefix, &server_public);
        SshStream::append_mpint(&mut hash_prefix, &K, true);

        // Compute exchange hash
        let H = Sha256::digest(hash_prefix).to_vec();

        // Verify exchange hash
        Encrypter::verify_hash(host_key_alg, host_key, &H, signature)?;

        Ok(())
    }

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
        let (n, host_key) = SshStream::extract_mpint_unsigned(host_key)?;
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
