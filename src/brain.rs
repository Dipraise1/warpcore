use std::env;
use std::path::PathBuf;
use std::process;

use warpcore::analyzer::{self, ConflictSeverity, ReportFilters};

#[derive(Debug, Clone)]
struct AnalyzeCli {
    path: PathBuf,
    json: bool,
    filters: ReportFilters,
    fail_on: Option<ConflictSeverity>,
}

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("analyze") => {
            let cli = match parse_analyze_args(args) {
                Ok(cli) => cli,
                Err(message) => {
                    eprintln!("{}", message);
                    eprintln!("Usage: warpcore analyze [--json] [--severity low|medium|high] [--top N] [--fail-on none|low|medium|high] [program-path]");
                    process::exit(2);
                }
            };

            match analyzer::analyze_path(&cli.path) {
                Ok(report) => {
                    let view = report.view(cli.filters);

                    if cli.json {
                        match serde_json::to_string_pretty(&view) {
                            Ok(json) => println!("{}", json),
                            Err(error) => {
                                eprintln!("warpcore: failed to serialize report: {}", error);
                                process::exit(1);
                            }
                        }
                    } else {
                        println!("{}", view.render());
                    }

                    if let Some(fail_on) = cli.fail_on {
                        if report.has_blocking_conflicts(fail_on) {
                            process::exit(1);
                        }
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
            println!("  warpcore analyze [--json] [--severity low|medium|high] [--top N] [--fail-on none|low|medium|high] [program-path]");
            println!();
            println!("Example:");
            println!("  warpcore analyze ./programs/my_solana_program");
            println!("  warpcore analyze ./target/idl/my_program.json");
            println!("  warpcore analyze --json ./target/idl/my_program.json");
            println!("  warpcore analyze --severity high --top 5 ./target/idl/my_program.json");
            println!("  warpcore analyze --fail-on high ./target/idl/my_program.json");
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Usage: warpcore analyze [--json] [--severity low|medium|high] [--top N] [--fail-on none|low|medium|high] [program-path]");
            process::exit(2);
        }
    }
}

fn parse_analyze_args<I>(args: I) -> Result<AnalyzeCli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut json = false;
    let mut severity_cutoff = ConflictSeverity::Low;
    let mut top = None;
    let mut fail_on = Some(ConflictSeverity::High);
    let mut path = None;

    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" | "-j" => json = true,
            "--severity" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "Missing value for --severity".to_string())?;
                severity_cutoff = parse_severity(&value)?
            }
            "--top" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "Missing value for --top".to_string())?;
                top = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| format!("Invalid value for --top: {}", value))?,
                );
            }
            "--fail-on" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "Missing value for --fail-on".to_string())?;
                fail_on = parse_fail_on(&value)?;
            }
            "--no-fail" => fail_on = None,
            _ if arg.starts_with('-') => {
                return Err(format!("Unknown flag: {}", arg));
            }
            _ if path.is_none() => path = Some(arg),
            _ => {
                return Err(format!("Unexpected extra argument: {}", arg));
            }
        }
    }

    Ok(AnalyzeCli {
        path: PathBuf::from(path.unwrap_or_else(|| ".".to_string())),
        json,
        filters: ReportFilters {
            severity_cutoff,
            top,
        },
        fail_on,
    })
}

fn parse_severity(value: &str) -> Result<ConflictSeverity, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(ConflictSeverity::Low),
        "medium" => Ok(ConflictSeverity::Medium),
        "high" => Ok(ConflictSeverity::High),
        other => Err(format!("Invalid severity: {}", other)),
    }
}

fn parse_fail_on(value: &str) -> Result<Option<ConflictSeverity>, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(None),
        "low" => Ok(Some(ConflictSeverity::Low)),
        "medium" => Ok(Some(ConflictSeverity::Medium)),
        "high" => Ok(Some(ConflictSeverity::High)),
        other => Err(format!("Invalid fail-on severity: {}", other)),
    }
}
