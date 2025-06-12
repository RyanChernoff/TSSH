use crate::{Error, SSH_MSG_DISCONNECT};
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;

/// Represents an SshStream for the purposes of sending and recieving SSH packets
pub struct SshStream(TcpStream);

impl SshStream {
    /// Creates a new SshStream across the given TcpStream
    pub fn new(stream: TcpStream) -> Self {
        SshStream(stream)
    }

    /// Continuously reads SSH packets until it finds one with an ssh code that matches
    /// the wait type. If it runs into an SSH_MSG_DISCONNECT packet it returns with an error.
    pub fn read_until(&mut self, wait_type: u8) -> Result<Vec<u8>, Error> {
        loop {
            // Read next packet
            let (packet_type, packet) = self.read()?;

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

    /// Returns the payload of the next ssh packet.
    /// Requires that the packet (not just the buffer that contains it) meet
    /// the minimum length requirement of 16 bytes and the maximum length requirement
    /// of 35000 bytes.
    pub fn read(&mut self) -> Result<(u8, Vec<u8>), Error> {
        let SshStream(stream) = self;

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

    /// Sends a single SSH packet with the given payload
    pub fn send(&mut self, payload: &[u8], block_size: u32) -> Result<(), Error> {
        let SshStream(stream) = self;

        // Min block size must be 8
        let block_size = block_size.max(8);

        // Get payload length
        let payload_length = payload.len() as u32;

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
        let mut packet = Vec::with_capacity(packet_length as usize + 4);
        packet.extend(packet_length.to_be_bytes());
        packet.extend([padding_length]);
        packet.extend(payload);
        packet.extend(padding);

        // Send packet
        stream.write_all(&packet)?;

        Ok(())
    }
}
