mod encrypter;
mod ssh_stream;

use encrypter::Encrypter;
use rand::Rng;
use rand_core::OsRng;
use ssh_stream::SshStream;
use std::array::TryFromSliceError;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;

// Packet Types
/// Indicates a packet intends to disconnect
const SSH_MSG_DISCONNECT: u8 = 1;
/// Indicates that a pecket contains key exchange negotiation info
const SSH_MSG_KEXINIT: u8 = 20;

/// List of supported key exchange algorithms
const KEX_ALGS: [&'static str; 1] = ["ecdh-sha2-nistp256"];

/// List of supported host key varification algorithms
/// these must be compatible with all kex algorithms for now
const HOST_KEY_ALGS: [&'static str; 1] = ["rsa-sha2-512"];

/// List of all supported encryption algorithms
/// (both server to client and client to server)
const ENCRYPT_ALGS: [&'static str; 1] = ["aes256-ctr"];

/// List of all supported mac algorithms
/// (both server to client and client to server)
const MAC_ALGS: [&'static str; 1] = ["hmac-sha2-256"];

/// List of all supported compression algorithms
/// (both server to client and client to server)
const COMPRESS_ALGS: [&'static str; 1] = ["none"];

/// The arguments used when first run
pub struct Args<'a> {
    /// The username to sign in as via SSH
    pub username: &'a str,
    /// The name or ip adress of the host server for
    /// establishing TCP/IP connection
    pub hostname: &'a str,
}

/// The types of errors that can be returned by running tssh
pub enum Error {
    Io(io::Error),
    TryFromSliceError(TryFromSliceError),
    Other(&'static str),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        Error::TryFromSliceError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::TryFromSliceError(e) => write!(f, "{e}"),
            Error::Other(e) => write!(f, "Custom error: {e}"),
        }
    }
}

/// Establishes a connection to a given host and procedes with SSH authentication and connection
pub fn run(args: Args) -> Result<(), Error> {
    // Establish connection
    let mut stream = TcpStream::connect(format!("{}:22", args.hostname))?;

    // Runs the SSH version exchange protocol and saves version info for exchange hash
    let hash_prefix = exchange_versions(&mut stream)?;

    // Set up SSH stream
    let mut stream = SshStream::new(stream);

    exchange_keys(&mut stream, hash_prefix.clone())
}

/// Exchanges version information via the SSH-2.0 version exchange protocol over the given TCP stream
fn exchange_versions(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    const CLIENT_VERSION: &[u8; 16] = b"SSH-2.0-TSSH_1.0";

    // Send version info to host
    stream.write_all(CLIENT_VERSION)?;
    stream.write(b"\r\n")?;

    // Recieve version info from host
    let mut reader = BufReader::new(stream);

    let mut host_version = String::new();
    let mut num_read = reader.read_line(&mut host_version)?;

    // Ignore header information
    while !host_version.starts_with("SSH-") {
        // Check if reached end of data stream
        if num_read == 0 {
            return Err(Error::Other("Did not recieve version info from host"));
        }

        host_version = String::new();
        num_read = reader.read_line(&mut host_version)?;
    }

    // Validate host version format
    if !host_version.ends_with("\r\n") || num_read > 255 {
        eprintln!("{host_version}");
        return Err(Error::Other(
            "Recieved invalid version info: Host did not follow SSH version exchange protocol",
        ));
    }

    // Ensure host is using SSH-2.0 or greater
    if !host_version.starts_with("SSH-2.") {
        return Err(Error::Other(
            "Incompatible version: Host is not using SSH-2.0 but TSSH is",
        ));
    }

    // Remove return characters from host_version string
    host_version.truncate(host_version.len() - 2);

    // Save version info for exchange hash
    let mut hash_prefix = Vec::new();
    SshStream::append_string(&mut hash_prefix, CLIENT_VERSION);
    SshStream::append_string(&mut hash_prefix, host_version.as_bytes());

    Ok(hash_prefix)
}

/// Runs the secret key exchange portion of the SSH transport layer
fn exchange_keys(stream: &mut SshStream, mut hash_prefix: Vec<u8>) -> Result<(), Error> {
    // Generate kexinit payload and add it to exchange hash prefix
    let payload = gen_kexinit_payload();
    SshStream::append_string(&mut hash_prefix, &payload);

    // Send key negotiation information
    stream.send(&payload)?;

    // Wait until recieved key exchange packet each packet
    let mut packet = stream.read_until(SSH_MSG_KEXINIT)?;

    // Ensure packet can be a key exchange packet
    if packet.len() < 61 {
        return Err(Error::Other(
            "Key exchange packet is not large enough to contain all key exchange info",
        ));
    }

    // Add packet to exchange hash prefix
    packet.insert(0, SSH_MSG_KEXINIT);
    SshStream::append_string(&mut hash_prefix, &packet);
    packet.remove(0);

    // Extract packet information

    // Don't need cookie but here incase needed later
    // let cookie = &packet[..16];

    let (key_exchange_algs, packet) = SshStream::extract_name_list(&packet[16..])?;

    let (host_key_algs, packet) = SshStream::extract_name_list(packet)?;

    let (encrypt_algs_cts, packet) = SshStream::extract_name_list(packet)?;
    let (encrypt_algs_stc, packet) = SshStream::extract_name_list(packet)?;

    let (mac_algs_cts, packet) = SshStream::extract_name_list(packet)?;
    let (mac_algs_stc, packet) = SshStream::extract_name_list(packet)?;

    let (compress_algs_cts, packet) = SshStream::extract_name_list(packet)?;
    let (compress_algs_stc, packet) = SshStream::extract_name_list(packet)?;

    // Disregard language information
    let (_, packet) = SshStream::extract_name_list(packet)?;
    let (_, _) = SshStream::extract_name_list(packet)?;

    // Only valid guess requires client send first so for now this is irrelevant
    // let server_guess: bool = packet[0] != 0;

    // Begin negotiating shared algorithm
    let key_exchange_alg = negotiate_alg(&KEX_ALGS, &key_exchange_algs)?;

    let host_key_alg = negotiate_alg(&HOST_KEY_ALGS, &host_key_algs)?;

    let encrypt_alg_cts = negotiate_alg(&ENCRYPT_ALGS, &encrypt_algs_cts)?;
    let encrypt_alg_stc = negotiate_alg(&ENCRYPT_ALGS, &encrypt_algs_stc)?;

    let mac_alg_cts = negotiate_alg(&MAC_ALGS, &mac_algs_cts)?;
    let mac_alg_stc = negotiate_alg(&MAC_ALGS, &mac_algs_stc)?;

    let compress_alg_cts = negotiate_alg(&COMPRESS_ALGS, &compress_algs_cts)?;
    let compress_alg_stc = negotiate_alg(&COMPRESS_ALGS, &compress_algs_stc)?;

    println!("{encrypt_alg_cts}");
    println!("{encrypt_alg_stc}");
    println!("{mac_alg_cts}");
    println!("{mac_alg_stc}");
    println!("{compress_alg_cts}");
    println!("{compress_alg_stc}");

    // Normally you check for incorrect kex guesses here but the only implemented algorithm requires client to move first

    Encrypter::new(
        stream,
        key_exchange_alg,
        host_key_alg,
        encrypt_alg_cts,
        encrypt_alg_stc,
        mac_alg_cts,
        mac_alg_stc,
        compress_alg_cts,
        compress_alg_stc,
        hash_prefix,
    )?;

    Ok(())
}

/// Generates the payload for the ssh key exchange init packet
fn gen_kexinit_payload() -> Vec<u8> {
    // Create initial payload
    let mut payload = vec![SSH_MSG_KEXINIT];

    // Create and add cookie
    let mut cookie = [0u8; 16];
    OsRng.fill(&mut cookie);
    payload.extend(cookie);

    // Add algorithm name lists
    SshStream::append_name_list(&mut payload, &KEX_ALGS);
    SshStream::append_name_list(&mut payload, &HOST_KEY_ALGS);
    SshStream::append_name_list(&mut payload, &ENCRYPT_ALGS);
    SshStream::append_name_list(&mut payload, &ENCRYPT_ALGS);
    SshStream::append_name_list(&mut payload, &MAC_ALGS);
    SshStream::append_name_list(&mut payload, &MAC_ALGS);
    SshStream::append_name_list(&mut payload, &COMPRESS_ALGS);
    SshStream::append_name_list(&mut payload, &COMPRESS_ALGS);

    // Add empty language fields, a false guess byte, and a 0 extention
    payload.extend([0u8; 13]);

    payload
}

/// Runs the ssh negotioation algorithm on a list of client algorithms and a vector of server algorithms
/// and returns the first client algorithm that appears in the server list or throws an error if is found.
fn negotiate_alg(client: &[&'static str], server: &Vec<String>) -> Result<&'static str, Error> {
    match client.iter().find(
        |alg: &&&str| match server.iter().find(|s: &&String| s == alg) {
            Some(_) => true,
            None => false,
        },
    ) {
        Some(alg) => Ok(*alg),
        None => return Err(Error::Other("Could not find compatible algorithms")),
    }
}
