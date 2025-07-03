mod encrypter;
mod ssh_stream;

use encrypter::{Decrypter, Encrypter, generate};
use rand::Rng;
use rand_core::OsRng;
use rpassword;
use ssh_stream::SshStream;
use std::array::TryFromSliceError;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use terminal_size::{Height, Width, terminal_size};

// Packet Types
/// Indicates a packet intends to disconnect
const SSH_MSG_DISCONNECT: u8 = 1;
/// Indicates that a pecket contains key exchange negotiation info
const SSH_MSG_KEXINIT: u8 = 20;
/// Indicates that a packet is a request for a specific service
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// Indicates that a packet is accepting a request for a service
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// Indicates that a packet is requesting user authentication
const SSH_USERAUTH_REQUEST: u8 = 50;
/// Indicates that a packet is responding to a failed authentication attempt
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// Indicates that a packet is responding to a successful authentication attempt
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// Indicates that a packet contains a special banner to display to the user
const SSH_MSG_USERAUTH_BANNER: u8 = 53;
/// Indicates that a user tried to authenticate with an expired passwords and needs to change it
const SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
/// Indicates that a general ssh request has been made
const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// Indicates that a global request has been processed successfully
const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
/// Indicates a failure to process a global request
const SSH_MSG_REQUEST_FAILURE: u8 = 82;
/// Indicates an attempt to open a channel
const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// Confirms the success of an open channel request
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// Indicates that a channel could not be opened
const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// Indicates that the reciever of data can recieve more data
const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// Indicates data meant to be processed by a channel
const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// Indicates data meant to be processed by a channel that is seperate
/// from the normal stram (usually stderr)
const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// Indicates a request to run a program via an open channel
const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// Indicates that a channel request has been processed successfully
const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// Indicates that a channel request failed to be processed
const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// Indicates the reason for a failure to open a channel was because it was unauthorized
const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: [u8; 4] = [0, 0, 0, 1];

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
    pub username: String,
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

#[derive(Clone, Copy)]
pub enum WaitingFor {
    None,
    Pty,
    Shell,
}

/// Establishes a connection to a given host and procedes with SSH authentication and connection
pub fn run(args: Args) -> Result<(), Error> {
    // Establish connection
    let mut stream = TcpStream::connect(format!("{}:22", args.hostname))?;

    // Runs the SSH version exchange protocol and saves version info for exchange hash
    let hash_prefix = exchange_versions(&mut stream)?;

    // Set up SSH stream
    let mut stream = SshStream::new(stream);

    // Exchange key information
    let (mut encrypter, mut decrypter) = exchange_keys(&mut stream, hash_prefix.clone())?;

    // Begin authentication stage
    authenticate(&mut stream, &mut encrypter, &mut decrypter, args.username)?;

    // Start a session window
    let mut local_window = open_channel(&mut stream, &mut encrypter)?;

    let mut server_channel: u32 = 0u32;
    let mut state: WaitingFor = WaitingFor::None;

    // Shared state with reading and writing thread
    let mut server_packet_max: u32 = 0;
    let remote_window: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let encrypter = Arc::new(Mutex::new(encrypter));

    loop {
        let (packet_type, data) = stream.read(Some(&mut decrypter))?;
        match packet_type {
            SSH_MSG_DISCONNECT => return Err(Error::Other("Host sent ssh disconnect message")),
            SSH_MSG_GLOBAL_REQUEST => process_global_request(data)?,
            SSH_MSG_CHANNEL_OPEN => deny_channel_open(data, &mut stream, &encrypter)?,
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                let (channel, window, packet_max) =
                    confirm_channel_open(data, &mut stream, &encrypter)?;
                server_channel = channel;
                server_packet_max = packet_max;
                state = WaitingFor::Pty;
                let mut size = remote_window.lock().unwrap();
                *size = window;
            }
            SSH_MSG_CHANNEL_OPEN_FAILURE => handle_channel_open_fail(data)?,
            SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                let add_amount = adjust_window(data)?;
                let mut size = remote_window.lock().unwrap();
                *size += add_amount;
            }
            SSH_MSG_CHANNEL_DATA => {
                local_window = process_channel_data(
                    data,
                    &mut stream,
                    &encrypter,
                    server_channel,
                    local_window,
                )?
            }
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                local_window = process_extended_channel_data(
                    data,
                    &mut stream,
                    &encrypter,
                    server_channel,
                    local_window,
                )?
            }
            SSH_MSG_CHANNEL_REQUEST => {
                process_channel_request(data, server_channel, &mut stream, &encrypter)?
            }
            SSH_MSG_CHANNEL_SUCCESS => {
                state =
                    handle_request_success(data, server_channel, state, &mut stream, &encrypter)?
            }
            SSH_MSG_CHANNEL_FAILURE => handle_request_fail(data, state)?,
            _ => println!("Recieved packet of type {packet_type}"),
        }
    }
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
fn exchange_keys(
    stream: &mut SshStream,
    mut hash_prefix: Vec<u8>,
) -> Result<(Encrypter, Decrypter), Error> {
    // Generate kexinit payload and add it to exchange hash prefix
    let payload = gen_kexinit_payload();
    SshStream::append_string(&mut hash_prefix, &payload);

    // Send key negotiation information
    stream.send(&payload, None)?;

    // Wait until recieved key exchange packet each packet
    let (mut packet, num_read) = stream.read_until_no_decrypter(SSH_MSG_KEXINIT)?;

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

    let encrypt_alg = negotiate_alg(&ENCRYPT_ALGS, &encrypt_algs_cts)?;
    let decrypt_alg = negotiate_alg(&ENCRYPT_ALGS, &encrypt_algs_stc)?;

    let mac_alg_send = negotiate_alg(&MAC_ALGS, &mac_algs_cts)?;
    let verify_alg = negotiate_alg(&MAC_ALGS, &mac_algs_stc)?;

    let compress_alg = negotiate_alg(&COMPRESS_ALGS, &compress_algs_cts)?;
    let decompress_alg = negotiate_alg(&COMPRESS_ALGS, &compress_algs_stc)?;

    // Normally you check for incorrect kex guesses here but the only implemented algorithm requires client to move first

    generate(
        stream,
        key_exchange_alg,
        host_key_alg,
        encrypt_alg,
        decrypt_alg,
        mac_alg_send,
        verify_alg,
        compress_alg,
        decompress_alg,
        hash_prefix,
        num_read,
        None,
        None,
    )
}

fn authenticate(
    stream: &mut SshStream,
    encrypter: &mut Encrypter,
    decrypter: &mut Decrypter,
    username: String,
) -> Result<(), Error> {
    // Request user authentication
    stream.send(b"\x05\x00\x00\x00\x0cssh-userauth", Some(encrypter))?;
    let payload = stream.read_until(SSH_MSG_SERVICE_ACCEPT, decrypter)?;
    let (service, _) = SshStream::extract_string(&payload)?;
    if service != b"ssh-userauth" {
        return Err(Error::Other(
            "Invalid service accept message: Expected ssh-userauth",
        ));
    }

    // Send initial request to get authentication methods
    let mut initial_request = gen_userauth_header(&username);
    SshStream::append_string(&mut initial_request, b"none");
    stream.send(&initial_request, Some(encrypter))?;

    // Get response from host
    let mut attempt_counter: u8 = 0;
    loop {
        let (code, response) = stream.read(Some(decrypter))?;
        match code {
            SSH_MSG_DISCONNECT => return Err(Error::Other("Host sent ssh disconnect message")),
            SSH_MSG_USERAUTH_SUCCESS => return Ok(()),
            SSH_MSG_USERAUTH_FAILURE => {
                // Check that password is a valid authentication method
                let (methods, _) = SshStream::extract_name_list(&response)?;
                if !methods.contains(&"password".to_string()) {
                    return Err(Error::Other(
                        "Host does not support password authentication",
                    ));
                }

                if attempt_counter == 3 {
                    return Err(Error::Other("Too many failed login attempts"));
                }
                attempt_counter += 1;

                // Prompt user for password
                let password =
                    rpassword::prompt_password("Password: ").expect("Unable to parse password");

                // Send authentication request
                let mut request = gen_userauth_header(&username);
                SshStream::append_string(&mut request, b"password");
                request.push(0); // false boolean field
                SshStream::append_string(&mut request, password.as_bytes());
                stream.send(&request, Some(encrypter))?;
            }
            SSH_MSG_USERAUTH_BANNER => {
                let (banner, _) = SshStream::extract_string(&response)?;
                let banner = String::from_utf8_lossy(&banner);
                println!("{banner}");
            }
            SSH_MSG_USERAUTH_PASSWD_CHANGEREQ => {
                return Err(Error::Other(
                    "Password expired and tssh does not support password changes",
                ));
            }
            _ => (),
        }
    }
}

/// Processes an ssh global request
fn process_global_request(data: Vec<u8>) -> Result<(), Error> {
    let (request, data) = SshStream::extract_string(&data)?;
    println!("Global Request: {}", String::from_utf8_lossy(&request));

    if let Some(want_reply) = data.get(0) {
        println!("Want Reply: {}\n", *want_reply != 0);
    }

    Ok(())
}

/// Opens a new channel of type session
fn open_channel(stream: &mut SshStream, encrypter: &mut Encrypter) -> Result<u64, Error> {
    let mut payload = vec![SSH_MSG_CHANNEL_OPEN];
    SshStream::append_string(&mut payload, b"session");
    payload.extend(0u32.to_be_bytes()); // session id
    payload.extend(2097152u32.to_be_bytes()); // client window size
    payload.extend(32768u32.to_be_bytes()); // max packet size

    stream.send(&payload, Some(encrypter))?;

    Ok(2097152u64)
}

/// Responds to any channel open request with a fail response
fn deny_channel_open(
    data: Vec<u8>,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
) -> Result<(), Error> {
    let (_, data) = SshStream::extract_string(&data)?;
    if data.len() < 4 {
        return Err(Error::Other(
            "Recieved corrupt channel open packet: Expected channel number",
        ));
    }

    let mut response = vec![SSH_MSG_CHANNEL_OPEN_FAILURE];
    response.extend(&data[0..4]);
    response.extend(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
    SshStream::append_string(
        &mut response,
        b"Client does not permit host to open channels",
    );
    SshStream::append_string(&mut response, b"");

    let mut encrypter = encrypter.lock().unwrap();
    stream.send(&response, Some(&mut encrypter))
}

/// Verifies that the confirmed channel was the one requested and proceeds with requesting a psudo terminal session
fn confirm_channel_open(
    data: Vec<u8>,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
) -> Result<(u32, u64, u32), Error> {
    if data.len() < 16 {
        return Err(Error::Other(
            "Recieved corrupt channel open failure packet: Expected length of at least 16 bytes",
        ));
    }
    let client_channel = u32::from_be_bytes(data[0..4].try_into()?);
    if client_channel != 0 {
        return Err(Error::Other(
            "Recieved confirmation for openning of unrequested channel",
        ));
    }

    let server_channel = u32::from_be_bytes(data[4..8].try_into()?);
    let window_size = u32::from_be_bytes(data[8..12].try_into()?);
    let packet_max = u32::from_be_bytes(data[12..16].try_into()?);

    // Request a pseudo-terminal
    let mut request = vec![SSH_MSG_CHANNEL_REQUEST];
    request.extend(server_channel.to_be_bytes()); // server channel num
    SshStream::append_string(&mut request, b"pty-req"); // request pty
    request.push(1); // want_reply = true
    SshStream::append_string(&mut request, b"xterm-256color"); // terminal type is xterm 

    // Get terminal width and height in characters
    let size = terminal_size();
    let (width, height) = if let Some((Width(w), Height(h))) = size {
        (w, h)
    } else {
        return Err(Error::Other("Could not fetch terminal information"));
    };
    request.extend((width as u32).to_be_bytes());
    request.extend((height as u32).to_be_bytes());
    request.extend([0; 8]); // ignore pixel measurement parameters
    SshStream::append_string(
        &mut request,
        &[
            1, 0, 0, 0, 3, 3, 0, 0, 0, 127, 4, 0, 0, 0, 21, 5, 0, 0, 0, 4, 9, 0, 0, 0, 19, 10, 0,
            0, 0, 26, 35, 0, 0, 0, 1, 50, 0, 0, 0, 1, 51, 0, 0, 0, 1, 53, 0, 0, 0, 1, 0,
        ],
    ); // add terminal settings

    let mut encrypter = encrypter.lock().unwrap();
    stream.send(&request, Some(&mut encrypter))?;

    Ok((server_channel, window_size as u64, packet_max))
}

/// Handles the case when a channel has failed to open and prints the error to user
fn handle_channel_open_fail(data: Vec<u8>) -> Result<(), Error> {
    if data.len() < 16 {
        return Err(Error::Other(
            "Recieved corrupt channel open failure packet: Expected length of at least 16 bytes",
        ));
    }

    let reason_code = u32::from_be_bytes(data[4..8].try_into()?);
    let (bytes, _) = SshStream::extract_string(&data[8..])?;
    let description = String::from_utf8_lossy(&bytes);

    eprintln!("Failed to open channel with reason code {reason_code}: {description}");

    Ok(())
}

/// Processes the amount to adjust a window by if the adjustment is for a valid channel
/// and ignores the packet otherwise. If the packet is malformed (not big enough) it
/// returns an error.
fn adjust_window(data: Vec<u8>) -> Result<u64, Error> {
    if data.len() < 8 {
        return Err(Error::Other(
            "Recieved corrupt window adjust packet: Expected length of at least 8 bytes",
        ));
    }

    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel != 0 {
        eprintln!("Recieved window adjustment for unopened channel");
        return Ok(0);
    }

    let amount = u32::from_be_bytes(data[4..8].try_into()?);
    Ok(amount as u64)
}

fn process_channel_data(
    data: Vec<u8>,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
    server_channel: u32,
    window_size: u64,
) -> Result<u64, Error> {
    if data.len() < 8 {
        return Err(Error::Other(
            "Recieved corrupt channel data packet: Expected length of at least 8 bytes",
        ));
    }

    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel != 0 {
        eprintln!("Recieved channel data packet for unopened channel");
        return Ok(window_size);
    }

    let (data, _) = SshStream::extract_string(&data[4..])?;
    print!("{}", String::from_utf8_lossy(&data));
    io::stdout().flush()?;

    // update window
    let len = data.len() as u64;
    // If window is too small after processing data adjust window size
    if len > window_size || window_size - len < 100 {
        let mut request = vec![SSH_MSG_CHANNEL_WINDOW_ADJUST];
        request.extend(server_channel.to_be_bytes());
        request.extend(2097152u32.to_be_bytes());

        let mut encrypter = encrypter.lock().unwrap();
        stream.send(&request, Some(&mut encrypter))?;
        return Ok(window_size + 2097152u64 - len);
    }

    Ok(window_size - len)
}

fn process_extended_channel_data(
    data: Vec<u8>,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
    server_channel: u32,
    window_size: u64,
) -> Result<u64, Error> {
    if data.len() < 12 {
        return Err(Error::Other(
            "Recieved corrupt extended channel data packet: Expected length of at least 12 bytes",
        ));
    }

    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel != 0 {
        eprintln!("Recieved extended channel data packet for unopened channel");
        return Ok(window_size);
    }

    let data_type = u32::from_be_bytes(data[4..8].try_into()?);
    let (data, _) = SshStream::extract_string(&data[8..])?;

    // If data type is stderr then print to stderr
    if data_type == 1 {
        eprint!("{}", String::from_utf8_lossy(&data));
    } else {
        print!("{}", String::from_utf8_lossy(&data));
    }
    io::stdout().flush()?;

    // update window
    let len = data.len() as u64;
    // If window is too small after processing data adjust window size
    if len > window_size || window_size - len < 100 {
        let mut request = vec![SSH_MSG_CHANNEL_WINDOW_ADJUST];
        request.extend(server_channel.to_be_bytes());
        request.extend(2097152u32.to_be_bytes());

        let mut encrypter = encrypter.lock().unwrap();
        stream.send(&request, Some(&mut encrypter))?;
        return Ok(window_size + 2097152u64 - len);
    }

    Ok(window_size - len)
}

/// Handles channel specific requests
fn process_channel_request(
    data: Vec<u8>,
    server_channel: u32,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
) -> Result<(), Error> {
    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel != 0 {
        return Err(Error::Other("Recieved channel request for invalid channel"));
    }

    let (_, data) = SshStream::extract_string(&data[4..])?;

    if data[0] != 0 {
        let mut response = vec![SSH_MSG_CHANNEL_FAILURE];
        response.extend(server_channel.to_be_bytes());

        let mut encrypter = encrypter.lock().unwrap();
        return stream.send(&response, Some(&mut encrypter));
    }

    Ok(())
}

/// Hadles success responsed to channel requests. If the success is in response to a terminal request, it requests a shell and updates state.
/// Ignores responses to unsent messages and unopened channels
fn handle_request_success(
    data: Vec<u8>,
    server_channel: u32,
    state: WaitingFor,
    stream: &mut SshStream,
    encrypter: &Arc<Mutex<Encrypter>>,
) -> Result<WaitingFor, Error> {
    if data.len() < 4 {
        return Err(Error::Other(
            "Recieved corrupt channel request failure packet: Expected length of at least 4 bytes",
        ));
    }

    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel != 0 {
        eprintln!("Recieved channel request success packet for unopened channel");
        return Ok(state);
    }

    match state {
        WaitingFor::Pty => {
            let mut request = vec![SSH_MSG_CHANNEL_REQUEST];
            request.extend(server_channel.to_be_bytes());
            SshStream::append_string(&mut request, b"shell");
            request.push(1); // want_reply = true

            let mut encrypter = encrypter.lock().unwrap();
            stream.send(&request, Some(&mut encrypter))?;

            return Ok(WaitingFor::Shell);
        }
        WaitingFor::Shell => return Ok(WaitingFor::None),
        WaitingFor::None => {
            eprintln!("Recieved channel request success packet for request that has not been sent");
            return Ok(state);
        }
    }
}

/// Hnadles fail responses from channel requests mainly opening a terminal
fn handle_request_fail(data: Vec<u8>, state: WaitingFor) -> Result<(), Error> {
    if data.len() < 4 {
        return Err(Error::Other(
            "Recieved corrupt channel request failure packet: Expected length of at least 4 bytes",
        ));
    }

    let channel = u32::from_be_bytes(data[0..4].try_into()?);
    if channel == 0 {
        match state {
            WaitingFor::Pty => return Err(Error::Other("Failed to open remote terminal")),
            WaitingFor::Shell => return Err(Error::Other("Failed to open a remote shell")),
            WaitingFor::None => {
                eprintln!(
                    "Recieved channel request failure packet for request that has not been sent"
                );
                return Ok(());
            }
        }
    }

    eprintln!("Recieved channel request failure packet for unopened channel");
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

/// Generates the header for a userauthenctication payload. Expects a method name and
/// related fields to be appended before being sent.
fn gen_userauth_header(username: &str) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(SSH_USERAUTH_REQUEST);
    SshStream::append_string(&mut header, username.as_bytes());
    SshStream::append_string(&mut header, b"ssh-connection");
    header
}
