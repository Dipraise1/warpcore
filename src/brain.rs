// written by divine
// support: 8sffXwByk4T7BCrhWsrVWR2mrweVRysGikZWr1ZAZQVg (SOL)

use std::fs;
use std::io::{self, IsTerminal, Write as IoWrite};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use warpcore::analyzer::{self, ConflictSeverity, ReportFilters};

/// Solana program parallelism analyzer.
///
/// Finds account-lock conflicts that prevent transactions from executing in
/// parallel on Solana. Supports Anchor IDL JSON files and raw Rust source.
/// Also flags common security issues: missing signers, unchecked accounts, etc.
///
/// Support the author (SOL): 8sffXwByk4T7BCrhWsrVWR2mrweVRysGikZWr1ZAZQVg
#[derive(Parser)]
#[command(
    name = "warpcore",
    version,
    propagate_version = true,
    after_help = "Support the author (SOL): 8sffXwByk4T7BCrhWsrVWR2mrweVRysGikZWr1ZAZQVg"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a Solana program or Anchor IDL for parallelism conflicts and security issues
    Analyze(AnalyzeArgs),
    /// Compare two analyses to measure improvement (e.g. before vs. after a refactor)
    Compare(CompareArgs),
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    /// Anchor IDL (.json), directory of IDL files, or Rust source directory
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit machine-readable JSON (useful for CI pipelines and tooling)
    #[arg(long, short = 'j')]
    json: bool,

    /// Only include conflicts at or above this severity
    #[arg(long, value_enum, default_value_t = SeverityArg::Low, value_name = "LEVEL")]
    severity: SeverityArg,

    /// Limit output to the N highest-severity conflicts
    #[arg(long, value_name = "N")]
    top: Option<usize>,

    /// Exit 1 when any conflict at or above LEVEL is found; use 'none' to disable
    #[arg(long, value_enum, default_value_t = FailOnArg::High, value_name = "LEVEL")]
    fail_on: FailOnArg,

    /// Suppress all output; rely on exit code alone (good for scripting)
    #[arg(long, short = 'q')]
    quiet: bool,

    /// Write output to FILE instead of stdout
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(clap::Args)]
struct CompareArgs {
    /// Path to analyze as the baseline (before)
    before: PathBuf,

    /// Path to analyze as the target (after)
    after: PathBuf,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum SeverityArg {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum FailOnArg {
    None,
    Low,
    Medium,
    #[default]
    High,
}

impl From<SeverityArg> for ConflictSeverity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => ConflictSeverity::Low,
            SeverityArg::Medium => ConflictSeverity::Medium,
            SeverityArg::High => ConflictSeverity::High,
        }
    }
}

impl FailOnArg {
    fn into_severity(self) -> Option<ConflictSeverity> {
        match self {
            FailOnArg::None => None,
            FailOnArg::Low => Some(ConflictSeverity::Low),
            FailOnArg::Medium => Some(ConflictSeverity::Medium),
            FailOnArg::High => Some(ConflictSeverity::High),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze(args) => run_analyze(args),
        Command::Compare(args) => run_compare(args),
    }
}

fn use_color(no_color_flag: bool, output_file: Option<&PathBuf>) -> bool {
    if no_color_flag || std::env::var("NO_COLOR").is_ok() || output_file.is_some() {
        return false;
    }
    io::stdout().is_terminal()
}

fn run_analyze(args: AnalyzeArgs) {
    if !args.path.exists() {
        eprintln!("error: path not found: {}", args.path.display());
        eprintln!(
            "hint: pass an Anchor IDL (.json), a directory of IDL files, \
             or a Rust source directory"
        );
        process::exit(2);
    }

    let report = match analyzer::analyze_path(&args.path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {}", error);
            print_analyze_hint(&args.path);
            process::exit(1);
        }
    };

    let view = report.view(ReportFilters {
        severity_cutoff: args.severity.into(),
        top: args.top,
    });

    if !args.quiet {
        let color = use_color(args.no_color, args.output.as_ref());

        let text = if args.json {
            match serde_json::to_string_pretty(&view) {
                Ok(json) => json,
                Err(error) => {
                    eprintln!("error: failed to serialize report: {}", error);
                    process::exit(1);
                }
            }
        } else {
            format!(
                "{}\n\nSupport the author (SOL): 8sffXwByk4T7BCrhWsrVWR2mrweVRysGikZWr1ZAZQVg",
                view.render_colored(color).trim_end()
            )
        };

        if let Some(out_path) = &args.output {
            if let Err(error) = fs::write(out_path, &text) {
                eprintln!(
                    "error: could not write to {}: {}",
                    out_path.display(),
                    error
                );
                process::exit(1);
            }
        } else {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            if let Err(error) = writeln!(out, "{}", text.trim_end()) {
                if error.kind() != io::ErrorKind::BrokenPipe {
                    eprintln!("error: {}", error);
                    process::exit(1);
                }
            }
        }
    }

    if let Some(threshold) = args.fail_on.into_severity() {
        if report.has_blocking_conflicts(threshold) {
            process::exit(1);
        }
    }
}

fn run_compare(args: CompareArgs) {
    for path in [&args.before, &args.after] {
        if !path.exists() {
            eprintln!("error: path not found: {}", path.display());
            process::exit(2);
        }
    }

    let before = match analyzer::analyze_path(&args.before) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error analyzing {}: {}", args.before.display(), e);
            process::exit(1);
        }
    };
    let after = match analyzer::analyze_path(&args.after) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error analyzing {}: {}", args.after.display(), e);
            process::exit(1);
        }
    };

    let color = use_color(args.no_color, None);
    let bold = if color { "\x1b[1m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let red = if color { "\x1b[31m" } else { "" };
    let yellow = if color { "\x1b[33m" } else { "" };
    let green = if color { "\x1b[32m" } else { "" };

    println!("{bold}Warpcore comparison{reset}");
    println!("===================\n");
    println!("Before: {}", args.before.display());
    println!("After:  {}\n", args.after.display());

    let delta = after.score as i32 - before.score as i32;
    let delta_str = if delta > 0 {
        format!("{green}+{delta}{reset}")
    } else if delta < 0 {
        format!("{red}{delta}{reset}")
    } else {
        format!("{yellow}no change{reset}")
    };
    let score_color = |s: u8| {
        if !color {
            return ("", "");
        }
        if s >= 70 {
            (green, reset)
        } else if s >= 40 {
            (yellow, reset)
        } else {
            (red, reset)
        }
    };
    let (bc, br) = score_color(before.score);
    let (ac, ar) = score_color(after.score);
    println!(
        "Score: {bc}{bold}{}/100{br}{reset} → {ac}{bold}{}/100{ar}{reset} ({delta_str})\n",
        before.score, after.score
    );

    // Conflict comparison
    let before_conflicts: std::collections::BTreeSet<(String, String)> = before
        .conflicts
        .iter()
        .map(|c| (c.left_context.clone(), c.right_context.clone()))
        .collect();
    let after_conflicts: std::collections::BTreeSet<(String, String)> = after
        .conflicts
        .iter()
        .map(|c| (c.left_context.clone(), c.right_context.clone()))
        .collect();

    let resolved: Vec<_> = before
        .conflicts
        .iter()
        .filter(|c| !after_conflicts.contains(&(c.left_context.clone(), c.right_context.clone())))
        .collect();
    let introduced: Vec<_> = after
        .conflicts
        .iter()
        .filter(|c| !before_conflicts.contains(&(c.left_context.clone(), c.right_context.clone())))
        .collect();
    let remaining: Vec<_> = after
        .conflicts
        .iter()
        .filter(|c| before_conflicts.contains(&(c.left_context.clone(), c.right_context.clone())))
        .collect();

    println!("{bold}Conflicts resolved ({}):{reset}", resolved.len());
    if resolved.is_empty() {
        println!("  none");
    } else {
        for c in &resolved {
            println!(
                "  {green}✓{reset} {} <-> {} ({})",
                c.left_context,
                c.right_context,
                c.shared_accounts.join(", ")
            );
        }
    }

    println!("\n{bold}Conflicts introduced ({}):{reset}", introduced.len());
    if introduced.is_empty() {
        println!("  none");
    } else {
        for c in &introduced {
            println!(
                "  {red}✗{reset} {} <-> {} ({})",
                c.left_context,
                c.right_context,
                c.shared_accounts.join(", ")
            );
        }
    }

    println!("\n{bold}Conflicts remaining ({}):{reset}", remaining.len());
    if remaining.is_empty() {
        println!("  none");
    } else {
        for c in &remaining {
            let sev = match c.severity {
                ConflictSeverity::High => format!("{red}{bold}high{reset}"),
                ConflictSeverity::Medium => format!("{yellow}medium{reset}"),
                ConflictSeverity::Low => format!("{green}low{reset}"),
            };
            println!(
                "  {yellow}~{reset} {} <-> {} [{}]",
                c.left_context, c.right_context, sev
            );
        }
    }

    // Security warning comparison
    let before_warnings: std::collections::BTreeSet<String> = before
        .security_warnings
        .iter()
        .map(|w| format!("{}/{}/{}", w.kind.label(), w.instruction, w.account))
        .collect();
    let after_warnings: std::collections::BTreeSet<String> = after
        .security_warnings
        .iter()
        .map(|w| format!("{}/{}/{}", w.kind.label(), w.instruction, w.account))
        .collect();

    let sec_resolved: Vec<_> = before
        .security_warnings
        .iter()
        .filter(|w| {
            !after_warnings
                .contains(&format!("{}/{}/{}", w.kind.label(), w.instruction, w.account))
        })
        .collect();
    let sec_introduced: Vec<_> = after
        .security_warnings
        .iter()
        .filter(|w| {
            !before_warnings
                .contains(&format!("{}/{}/{}", w.kind.label(), w.instruction, w.account))
        })
        .collect();

    println!(
        "\n{bold}Security warnings resolved ({}):{reset}",
        sec_resolved.len()
    );
    if sec_resolved.is_empty() {
        println!("  none");
    } else {
        for w in &sec_resolved {
            println!("  {green}✓{reset} [{}] {}", w.kind.label(), w.message);
        }
    }

    println!(
        "\n{bold}Security warnings introduced ({}):{reset}",
        sec_introduced.len()
    );
    if sec_introduced.is_empty() {
        println!("  none");
    } else {
        for w in &sec_introduced {
            println!("  {red}✗{reset} [{}] {}", w.kind.label(), w.message);
        }
    }

    println!("\nSupport the author (SOL): 8sffXwByk4T7BCrhWsrVWR2mrweVRysGikZWr1ZAZQVg");

    // Exit 1 if score got worse or new issues were introduced
    if delta < 0 || !sec_introduced.is_empty() {
        process::exit(1);
    }
}

fn print_analyze_hint(path: &PathBuf) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    if ext == "json" {
        eprintln!("hint: make sure this is a valid Anchor IDL file");
        eprintln!("hint: generate one with `anchor build` (output: target/idl/)");
    } else if path.is_dir() {
        eprintln!("hint: directory should contain .json IDL files or .rs source files");
        eprintln!("hint: try pointing at target/idl/ after running `anchor build`");
    }
}
