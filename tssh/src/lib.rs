use rand::Rng;
use std::array::TryFromSliceError;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// Version bytes to send to host during version exchange
const SSH_VERSION: &[u8; 18] = b"SSH-2.0-TSSH_1.0\r\n";

/// The payload containing all key exchange preferences
const KEX_PAYLOAD: &[u8; 152] = b"\x140123456789abcdef\
    \x00\x00\x00\x1ddiffie-hellman-group16-sha256\
    \x00\x00\x00\x07ssh-rsa\
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

/// The arguments used
pub struct Args<'a> {
    pub username: &'a str,
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

    // Runs SSH key exchange protocol
    exchange_keys(&mut stream)?;

    Ok(())
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

    print!("{host_version}");

    Ok(())
}

fn exchange_keys(stream: &mut TcpStream) -> Result<(), Error> {
    //send_packet(stream, KEX_PAYLOAD, 8, &[])?;

    // Read key exchange info
    let mut buf: [u8; 35000] = [0; 35000];
    if stream.read(&mut buf)? < 16 {
        return Err(Error::Other(
            "Did not recieve key exchange information from host",
        ));
    };

    let packet = parse_packet(&buf)?;

    println!("{}", buf[5]);

    Ok(())
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
    stream.write(&packet)?;

    Ok(())
}

/// Returns the payload of an ssh packet unencrypted and uncompressed.
/// Requires that the packet (not just the buffer that contains it) meet
/// the minimum length requirement of 16 bytes and the maximum length requirement
/// of 35000 bytes.
///
/// Throws an error on failiure to verify mac
fn parse_packet(packet: &[u8]) -> Result<&[u8], Error> {
    let packet_length: u32 = u32::from_be_bytes((&packet[0..4]).try_into()?);

    Ok(&packet[0..4])
}
