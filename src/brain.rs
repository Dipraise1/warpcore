use std::env;
use std::path::PathBuf;
use std::process;
use warpcore::analyzer;

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("analyze") => {
            let mut output_json = false;
            let mut path = None;

            for arg in args {
                match arg.as_str() {
                    "--json" | "-j" => output_json = true,
                    _ if path.is_none() => path = Some(arg),
                    other => {
                        eprintln!("Unknown flag or extra argument: {}", other);
                        eprintln!("Usage: warpcore analyze [--json] [program-path]");
                        process::exit(2);
                    }
                }
            }

            let path = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));

            match analyzer::analyze_path(&path) {
                Ok(report) => {
                    if output_json {
                        match serde_json::to_string_pretty(&report) {
                            Ok(json) => println!("{}", json),
                            Err(error) => {
                                eprintln!("warpcore: failed to serialize report: {}", error);
                                process::exit(1);
                            }
                        }
                    } else {
                        println!("{}", report.render());
                    }
                }
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
            println!("  warpcore analyze [--json] [program-path]");
            println!();
            println!("Example:");
            println!("  warpcore analyze ./programs/my_solana_program");
            println!("  warpcore analyze ./target/idl/my_program.json");
            println!("  warpcore analyze --json ./target/idl/my_program.json");
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Usage: warpcore analyze [--json] [program-path]");
            process::exit(2);
        }
    }
}
