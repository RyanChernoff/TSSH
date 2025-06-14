use crate::{Error, SSH_MSG_DISCONNECT};
use std::io::{Read, Write};
use std::net::TcpStream;

/// Represents an SshStream for the purposes of sending and recieving SSH packets
pub struct SshStream(TcpStream);

impl SshStream {
    /// Creates a new SshStream across the given TcpStream
    pub fn new(stream: TcpStream) -> Self {
        SshStream(stream)
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
        let payload_length = (packet_length - padding_length - 2) as usize;
        packet.truncate(payload_length);
        Ok((packet_type, packet))
    }

    /// Sends a single SSH packet with the given payload
    pub fn send(&mut self, payload: &Vec<u8>) -> Result<(), Error> {
        let SshStream(stream) = self;

        // Min block size must be 8
        let block_size = 8;

        // Get payload length
        let payload_length = payload.len() as u32;

        // Calculate the amount of padding required (must be at least 4 bytes)
        let mut padding_length = (block_size - ((payload_length + 5) % block_size)) as u8;
        if padding_length < 4 {
            padding_length += block_size as u8;
        }

        // Fill padding with 0's
        let padding: Vec<u8> = (0..padding_length).collect();

        // Calculate the total packet length (excluding this field and the mac field)
        let packet_length = payload_length + (padding_length as u32) + 1;

        // Construct packet
        let mut packet = Vec::with_capacity(packet_length as usize + 4);
        packet.extend(packet_length.to_be_bytes());
        packet.push(padding_length);
        packet.extend(payload);
        packet.extend(padding);

        // Send packet
        stream.write_all(&packet)?;

        Ok(())
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

    /// Appends an ssh name_list to a vector from a reference to an array
    pub fn append_name_list(payload: &mut Vec<u8>, list: &[&'static str]) {
        let mut name_list: Vec<u8> = Vec::new();
        let mut length: usize = 0;

        for (i, name) in list.iter().enumerate() {
            let bytes = name.as_bytes();
            length += bytes.len();
            name_list.extend(bytes);

            // Add a , seperator if not last item in list
            if i + 1 < list.len() {
                name_list.push(44);
                length += 1;
            }
        }

        // Add length
        payload.extend((length as u32).to_be_bytes());

        // Add name list
        payload.append(&mut name_list);
    }

    /// Parses an SSH name-list field into a vector of the string contents in the list.
    /// What is leftover of the packet the contains the list is returned along with the vector list.
    pub fn extract_name_list(start: &[u8]) -> Result<(Vec<String>, &[u8]), Error> {
        // extract list length
        let list_length = u32::from_be_bytes((&start[0..4]).try_into()?) as usize;

        // Get the rest of the list
        let new_start = &start[(list_length + 4)..];
        let list_string = String::from_utf8_lossy(&start[4..(list_length + 4)]).to_string();
        let list: Vec<String> = list_string.split(",").map(|s| s.to_string()).collect();

        Ok((list, new_start))
    }

    /// Parses an SSH string field into a string.
    /// What is leftover of the packet the contains the string is returned along with the string.
    pub fn extract_string(start: &[u8]) -> Result<(String, &[u8]), Error> {
        // extract list length
        let string_length = u32::from_be_bytes((&start[0..4]).try_into()?) as usize;

        // Get the rest of the string
        let new_start = &start[(string_length + 4)..];
        let string = String::from_utf8_lossy(&start[4..(string_length + 4)]).to_string();
        
        Ok((string, new_start))
    }

}
