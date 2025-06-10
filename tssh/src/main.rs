use std::env;
use tssh::Args;

/// Extracts username and hostname and passes it to tssh for processing and prints any runtime errors
fn main() {
    let cmd_line: Vec<String> = env::args().collect();
    if let Some(args) = parse_args(&cmd_line) {
        if let Err(err) = tssh::run(args) {
            eprintln!("{err}");
        }
    }
}

/// Reads the command line arguments and parses them into the argument struct
/// required for tssh to run. If an error occurs when parsing then it returns
/// None and prints a message to stderr.
fn parse_args<'a>(cmd_line: &'a Vec<String>) -> Option<Args<'a>> {
    // Extract argument containing username@hostname or just hostname
    if cmd_line.len() != 2 {
        eprintln!(
            "Invalid number of arguments: expected 1 found {}",
            cmd_line.len() - 1
        );
        return None;
    }

    // Ensure username and hostname are in proper format
    let args: Vec<&str> = cmd_line[1].split("@").collect();

    // Too many @ symbols in argument
    if args.len() > 2 {
        eprintln!("Too many @ symbols in argument: Expected at most 1");
        return None;
    }

    // username and hostname were specified
    if args.len() == 2 {
        return Some(Args {
            username: args[0],
            hostname: args[1],
        });
    }

    // username was not specified
    Some(Args {
        username: "",
        hostname: args[0],
    })
}
