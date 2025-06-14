use crate::Error;
use crate::ssh_stream::SshStream;
use p256::{NistP256, ecdh::EphemeralSecret, elliptic_curve::PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

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
    ) {
        let _ = match key_exchange_alg {
            "ecdh-sha2-nistp256" => Encrypter::ecdh_sha2_nistp256_exchange(stream, hash_prefix),
            _ => panic!("Made new encrypter for incompattible encryption algorithm"),
        };
    }

    fn ecdh_sha2_nistp256_exchange(
        stream: &mut SshStream,
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
        let H = Sha256::digest(hash_prefix);

        // Verify exchange hash
        println!("{host_key:?}");

        Ok(())
    }
}
