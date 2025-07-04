use crate::{
    Error, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_REQUEST, encrypter::Encrypter,
    ssh_stream::SshStream,
};
use crossterm::{
    event::{Event, KeyCode, KeyEventKind, KeyModifiers, poll, read},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::panic;
use std::process;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub fn spawn(
    mut stream: SshStream,
    encrypter: Arc<Mutex<Encrypter>>,
    window: Arc<Mutex<u64>>,
    packet_max: u32,
    channel: u32,
    stop_flag: Arc<AtomicBool>,
) -> Result<(), Error> {
    // Check that packet max is acceptible
    if packet_max < 16 {
        return Err(Error::Other("Server maximum packet size is too small"));
    }

    // Exit the process if this thread panics
    panic::set_hook(Box::new(|info| {
        let _ = disable_raw_mode();
        eprintln!("Writing thread panicked: {}", info);
        process::exit(1);
    }));

    thread::spawn(move || {
        enable_raw_mode().unwrap();

        while !stop_flag.load(Ordering::Relaxed) {
            if poll(Duration::from_millis(100)).unwrap() {
                // Capture key pressed
                match read().unwrap() {
                    Event::Key(event) => {
                        // Ignore key release events
                        if event.kind == KeyEventKind::Release {
                            continue;
                        }

                        let mut data: Vec<u8> = Vec::new();
                        match event.code {
                            KeyCode::Char(c) => {
                                if event.modifiers.contains(KeyModifiers::CONTROL) {
                                    let upper = c.to_ascii_uppercase();
                                    if upper >= 'A' && upper <= '_' {
                                        data.push((upper as u8) & 0x1F);
                                    } else {
                                        data.extend(c.encode_utf8(&mut [0; 4]).as_bytes());
                                    }
                                } else {
                                    data.extend(c.encode_utf8(&mut [0; 4]).as_bytes());
                                }
                            }
                            KeyCode::Enter => data.push(b'\n'),
                            KeyCode::Tab => data.push(b'\t'),
                            KeyCode::Backspace => data.push(b'\x7F'),
                            KeyCode::Esc => data.push(b'\x1B'),
                            KeyCode::Left => data.extend(b"\x1B[D"),
                            KeyCode::Right => data.extend(b"\x1B[C"),
                            KeyCode::Up => data.extend(b"\x1B[A"),
                            KeyCode::Down => data.extend(b"\x1B[B"),
                            KeyCode::Insert => data.extend(b"\x1B[2~"),
                            KeyCode::Delete => data.push(b'\x7F'),
                            KeyCode::Home => data.extend(b"\x1B[H"),
                            KeyCode::End => data.extend(b"\x1B[F"),
                            KeyCode::PageUp => data.extend(b"\x1B[5~"),
                            KeyCode::PageDown => data.extend(b"\x1B[6~"),
                            _ => (),
                        }

                        for byte in data {
                            // Wait until we can send data
                            wait_for_window(&window);

                            // Assemble data packet
                            let mut packet = vec![SSH_MSG_CHANNEL_DATA];
                            packet.extend(channel.to_be_bytes());
                            packet.extend(b"\x00\x00\x00\x01");
                            packet.push(byte);

                            // Send packet
                            let mut enc = encrypter.lock().unwrap();
                            stream.send(&packet, Some(&mut enc)).unwrap();
                        }

                        // temperary escape sequence to allow for quitting
                        if event.code == KeyCode::Esc {
                            break;
                        }
                    }
                    Event::Resize(width, height) => {
                        let mut request = vec![SSH_MSG_CHANNEL_REQUEST];
                        request.extend(channel.to_be_bytes());
                        SshStream::append_string(&mut request, b"window-change");
                        request.push(0);
                        request.extend((width as u32).to_be_bytes());
                        request.extend((height as u32).to_be_bytes());
                        request.extend([0, 0, 0, 0, 0, 0, 0, 0]);

                        let mut enc = encrypter.lock().unwrap();
                        stream.send(&request, Some(&mut enc)).unwrap();
                    }
                    _ => (),
                }
            }
        }

        disable_raw_mode().unwrap();
    });

    Ok(())
}

/// Thjs function blocks the thread until the window is non-zero and decriments it by one
fn wait_for_window(window: &Arc<Mutex<u64>>) {
    loop {
        let mut window = window.lock().unwrap();
        if *window != 0 {
            *window -= 1;
            return;
        }
    }
}
