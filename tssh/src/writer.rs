use crate::{encrypter::Encrypter, ssh_stream::SshStream};
use crossterm::{
    event::{Event, KeyCode, KeyEventKind, KeyModifiers, poll, read},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub fn spawn(
    stream: SshStream,
    encrypter: Arc<Mutex<Encrypter>>,
    window: Arc<Mutex<u64>>,
    packet_max: u32,
    stop_flag: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        enable_raw_mode().unwrap();

        while !stop_flag.load(Ordering::Relaxed) {
            if poll(Duration::from_millis(100)).unwrap() {
                match read().unwrap() {
                    Event::Key(event) => {
                        // Ignore key release events
                        if event.kind == KeyEventKind::Release {
                            continue;
                        }

                        let mut output: String = String::from('\u{FFFD}');
                        match event.code {
                            KeyCode::Char(c) => {
                                if event.modifiers.contains(KeyModifiers::CONTROL) {
                                    let upper = c.to_ascii_uppercase();
                                    if upper >= 'A' && upper <= '_' {
                                        output = String::from_utf8_lossy(&[(upper as u8) & 0x1F])
                                            .to_string();
                                    } else {
                                        output = String::from(c);
                                    }
                                } else {
                                    output = String::from(c);
                                }
                            }
                            KeyCode::Enter => output = String::from('\n'),
                            KeyCode::Tab => output = String::from('\t'),
                            KeyCode::Backspace => output = "\x08 \x08".to_string(),
                            KeyCode::Esc => output = "\x1B".to_string(),
                            KeyCode::Left => output = "\x1B[D".to_string(),
                            KeyCode::Right => output = "\x1B[C".to_string(),
                            KeyCode::Up => output = "\x1B[A".to_string(),
                            KeyCode::Down => output = "\x1B[B".to_string(),
                            KeyCode::Insert => output = "\x1B[2~".to_string(),
                            KeyCode::Delete => output = "\x1B[3~".to_string(),
                            KeyCode::Home => output = "\x1B[H".to_string(),
                            KeyCode::End => output = "\x1B[F".to_string(),
                            KeyCode::PageUp => output = "\x1B[5~".to_string(),
                            KeyCode::PageDown => output = "\x1B[6~".to_string(),
                            _ => (),
                        }

                        write!(io::stdout(), "{}", output).unwrap();
                        io::stdout().flush().unwrap();

                        // temperary escape sequence to allow for quitting
                        if event.code == KeyCode::Esc {
                            break;
                        }
                    }
                    Event::Resize(_, _) => (),
                    _ => (),
                }
            }
        }

        disable_raw_mode().unwrap();
    });
}
