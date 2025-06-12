mod ssh_stream;

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

/// Version bytes to send to host during version exchange
const SSH_VERSION: &[u8; 18] = b"SSH-2.0-TSSH_1.0\r\n";

/// The payload containing all key exchange preferences
const KEX_PAYLOAD: &[u8; 146] = b"\x140123456789abcdef\
    \x00\x00\x00\x12ecdh-sha2-nistp256\
    \x00\x00\x00\x0crsa-sha2-512\
    \x00\x00\x00\x0aaes256-ctr\
    \x00\x00\x00\x0aaes256-ctr\
    \x00\x00\x00\x0dhmac-sha2-256\
    \x00\x00\x00\x0dhmac-sha2-256\
    \x00\x00\x00\x04none\
    \x00\x00\x00\x04none\
    \x00\x00\x00\x00\
    \x00\x00\x00\x00\
    \x00\
    \x00\x00\x00\x00";

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

    // Runs the SSH version exchange protocol
    exchange_versions(&mut stream)?;

    // Set up SSH stream
    let mut stream = SshStream::new(stream);

    exchange_keys(&mut stream)
}

/// Exchanges version information via the SSH-2.0 version exchange protocol over the given TCP stream
fn exchange_versions(stream: &mut TcpStream) -> Result<(), Error> {
    // Send version info to host
    stream.write_all(SSH_VERSION)?;

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

    Ok(())
}

/// Runs the secret key exchange portion of the SSH transport layer
fn exchange_keys(stream: &mut SshStream) -> Result<(), Error> {
    // Send key negotiation information
    stream.send(KEX_PAYLOAD, 8)?;

    // Wait until recieved key exchange packet each packet
    let packet = stream.read_until(SSH_MSG_KEXINIT)?;

    // Ensure packet can be a key exchange packet
    if packet.len() < 61 {
        return Err(Error::Other(
            "Key exchange packet is not large enough to contain all key exchange info",
        ));
    }

    // Extract packet information

    // Don't need cookie but here incase needed later
    // let cookie = &packet[..16];

    let (key_exchange_algs, packet) = extract_name_list(&packet[16..])?;

    let (host_key_algs, packet) = extract_name_list(packet)?;

    let (encrypt_algs_cts, packet) = extract_name_list(packet)?;
    let (encrypt_algs_stc, packet) = extract_name_list(packet)?;

    let (mac_algs_cts, packet) = extract_name_list(packet)?;
    let (mac_algs_stc, packet) = extract_name_list(packet)?;

    let (compress_algs_cts, packet) = extract_name_list(packet)?;
    let (compress_algs_stc, packet) = extract_name_list(packet)?;

    // Disregard language information
    let (_, packet) = extract_name_list(packet)?;
    let (_, _) = extract_name_list(packet)?;

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

    println!("{key_exchange_alg}");
    println!("{host_key_alg}");
    println!("{encrypt_alg_cts}");
    println!("{encrypt_alg_stc}");
    println!("{mac_alg_cts}");
    println!("{mac_alg_stc}");
    println!("{compress_alg_cts}");
    println!("{compress_alg_stc}");

    // Normally you check for incorrect kex guesses here but the only implemented algorithm requires client to move first

    Ok(())
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

/// Parses an SSH name-list field into a vector of the string contents in the list.
/// What is leftover of the packet the contains the list is returned along with the vector list.
fn extract_name_list(start: &[u8]) -> Result<(Vec<String>, &[u8]), Error> {
    // extract list length
    let list_length = u32::from_be_bytes((&start[0..4]).try_into()?) as usize;

    // Get the rest of the list
    let new_start = &start[(list_length + 4)..];
    let list_string = String::from_utf8_lossy(&start[4..(list_length + 4)]).to_string();
    let list: Vec<String> = list_string.split(",").map(|s| s.to_string()).collect();

    Ok((list, new_start))
}
