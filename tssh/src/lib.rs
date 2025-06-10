use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// The arguments used
pub struct Args<'a> {
    pub username: &'a str,
    pub hostname: &'a str,
}

/// The types of errors that can be returned by running tssh
pub enum Error {
    Io(io::Error),
    Other(&'static str),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Other(e) => write!(f, "Custom error: {e}"),
        }
    }
}

pub fn run(args: Args) -> Result<(), Error> {
    // Establish connection
    let mut stream = TcpStream::connect(format!("{}:22", args.hostname))?;

    // <------------------------------------ Exchage version information ------------------------------------>
    stream.write_all(b"SSH-2.0-TSSH_1.0\r\n")?;

    let mut buf: [u8; 512] = [0; 512];

    let num_read = stream.read(&mut buf)?;

    let host_version = String::from_utf8_lossy(&buf[..num_read]);

    // Validate host version format
    if !host_version.starts_with("SSH") || !host_version.ends_with("\n") {
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
