use rand::Rng;
use std::array::TryFromSliceError;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

// Packet Types
const SSH_MSG_DISCONNECT: u8 = 1;
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
fn exchange_keys(stream: &mut TcpStream) -> Result<(), Error> {
    // Send key negotiation information
    send_packet(stream, KEX_PAYLOAD, 8, &[])?;

    // Wait until recieved key exchange packet each packet
    let packet = wait_for_packet(stream, SSH_MSG_KEXINIT)?;

    // Ensure packet can be a key exchange packet
    if packet.len() < 61 {
        return Err(Error::Other(
            "Key exchange packet is not large enough to contain all key exchange info",
        ));
    }

    let cookie = &packet[..16];

    let (key_exchange_algs, packet) = extract_name_list(&packet[16..])?;

    let (host_key_algs, packet) = extract_name_list(packet)?;

    let (encrypt_algs_cts, packet) = extract_name_list(packet)?;
    let (encrypt_algs_stc, packet) = extract_name_list(packet)?;

    let (mac_algs_cts, packet) = extract_name_list(packet)?;
    let (mac_algs_stc, packet) = extract_name_list(packet)?;

    let (compress_algs_cts, packet) = extract_name_list(packet)?;
    let (compress_algs_stc, packet) = extract_name_list(packet)?;

    let (_, packet) = extract_name_list(packet)?;
    let (_, packet) = extract_name_list(packet)?;

    let server_guess: bool = packet[0] != 0;

    // Begin negotiating shared algorithm
    let key_exchange_alg = negotiate_alg(&KEX_ALGS, key_exchange_algs)?;

    let host_key_alg = negotiate_alg(&HOST_KEY_ALGS, host_key_algs)?;

    let encrypt_alg_cts = negotiate_alg(&ENCRYPT_ALGS, encrypt_algs_cts)?;
    let encrypt_alg_stc = negotiate_alg(&ENCRYPT_ALGS, encrypt_algs_stc)?;

    let mac_alg_cts = negotiate_alg(&MAC_ALGS, mac_algs_cts)?;
    let mac_alg_stc = negotiate_alg(&MAC_ALGS, mac_algs_stc)?;

    let compress_alg_cts = negotiate_alg(&COMPRESS_ALGS, compress_algs_cts)?;
    let compress_alg_stc = negotiate_alg(&COMPRESS_ALGS, compress_algs_stc)?;

    println!("{key_exchange_alg}");
    println!("{host_key_alg}");
    println!("{encrypt_alg_cts}");
    println!("{encrypt_alg_stc}");
    println!("{mac_alg_cts}");
    println!("{mac_alg_stc}");
    println!("{compress_alg_cts}");
    println!("{compress_alg_stc}");

    Ok(())
}

/// Continuously reads SSH packets from a TcpStream until it finds one with an ssh code that matches
/// the wait type. If it runs into an SSH_MSG_DISCONNECT packet it returns with an error.
fn wait_for_packet(stream: &mut TcpStream, wait_type: u8) -> Result<Vec<u8>, Error> {
    loop {
        // Read next packet
        let (packet_type, packet) = read_packet(stream)?;

        // Check if recieved desired packet
        if packet_type == wait_type {
            return Ok(packet);
        }

        // Check if recieved disconnect
        if packet_type == SSH_MSG_DISCONNECT {
            return Err(Error::Other("Host sent ssh disconnect message"));
        }
    }
}

/// Runs the ssh negotioation algorithm on a list of client algorithms and a vector of server algorithms
/// and returns the first client algorithm that appears in the server list or throws an error if is found.
fn negotiate_alg(client: &[&'static str], server: Vec<String>) -> Result<&'static str, Error> {
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

/// Sends an SSH packet (payload must already be encrpted)
fn send_packet(
    stream: &mut TcpStream,
    payload: &[u8],
    block_size: u32,
    mac: &[u8],
) -> Result<(), Error> {
    // Min block size must be 8
    let block_size = block_size.max(8);

    // Get payload length
    let payload_length = payload.len() as u32;

    let mac_length = mac.len();

    // Calculate the amount of padding required (must be at least 4 bytes)
    let mut padding_length = (block_size - ((payload_length + 5) % block_size)) as u8;
    if padding_length < 4 {
        padding_length += block_size as u8;
    }

    // Fill padding with random bytes
    let mut rng = rand::thread_rng();
    let padding: Vec<u8> = (0..padding_length).map(|_| rng.r#gen()).collect();

    // Calculate the total packet length (excluding this field and the mac field)
    let packet_length = payload_length + (padding_length as u32) + 1;

    // Construct packet
    let mut packet = Vec::with_capacity(packet_length as usize + mac_length + 4);
    packet.extend(packet_length.to_be_bytes());
    packet.extend([padding_length]);
    packet.extend(payload);
    packet.extend(padding);
    packet.extend(mac);

    // Send packet
    stream.write_all(&packet)?;

    Ok(())
}

/// Returns the payload of an ssh packet.
/// Requires that the packet (not just the buffer that contains it) meet
/// the minimum length requirement of 16 bytes and the maximum length requirement
/// of 35000 bytes.
fn read_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Error> {
    // Get padding length
    let mut len_buf: [u8; 4] = [0; 4];
    stream.read_exact(&mut len_buf)?;

    // Extract the packet length
    let packet_length: usize = u32::from_be_bytes(len_buf) as usize;
    if packet_length < 12 {
        return Err(Error::Other(
            "Packet length is too small: Expected at least 12 bytes",
        ));
    }
    if packet_length + 4 > 35000 {
        return Err(Error::Other(
            "Packet length is too largs: Expected at most 35000 bytes",
        ));
    }

    // Get rest of packet
    let mut packet = vec![0u8; packet_length];
    stream.read_exact(&mut packet)?;

    // Extract padding length
    let padding_length: usize = packet[0] as usize;
    if padding_length < 4 {
        return Err(Error::Other(
            "Packet has too little padding: Expected at least 4",
        ));
    }
    if packet_length - 2 < padding_length {
        return Err(Error::Other(
            "Invalid Padding length: Expected payload is less than 1",
        ));
    }

    // Get the slice containing the payload and its packet type
    packet.remove(0);
    let packet_type = packet.remove(0);
    let payload_length = (packet_length - padding_length - 1) as usize;
    packet.truncate(payload_length);
    Ok((packet_type, packet))
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
