use crate::Error;
use crate::ssh_stream::SshStream;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand_core::OsRng;

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;

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
        hash_prefix: Vec<u8>,
    ) -> Result<(), Error> {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key().to_sec1_bytes();

        let mut ecdh_init = vec![SSH_MSG_KEX_ECDH_INIT];
        ecdh_init.extend((public.len() as u32).to_be_bytes());
        ecdh_init.extend(public);

        stream.send(&ecdh_init)?;

        Ok(())
    }
}
