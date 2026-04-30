mod analyzer;

use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("analyze") => {
            let path = args.next().unwrap_or_else(|| ".".to_string());

            let path = PathBuf::from(path);
            match analyzer::analyze_path(&path) {
                Ok(report) => println!("{}", report.render()),
                Err(error) => {
                    eprintln!("warpcore: {}", error);
                    process::exit(1);
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("Warpcore");
            println!();
            println!("Usage:");
            println!("  warpcore analyze [program-path]");
            println!();
            println!("Example:");
            println!("  warpcore analyze ./programs/my_solana_program");
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Usage: warpcore analyze [program-path]");
            process::exit(2);
        }
    }
}
