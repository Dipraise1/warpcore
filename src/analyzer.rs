use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const SHARED_ACCOUNT_HINTS: &[&str] = &[
    "admin",
    "authority",
    "config",
    "escrow",
    "global",
    "market",
    "pool",
    "registry",
    "treasury",
    "vault",
];

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub account_structs: usize,
    pub total_accounts: usize,
    pub mutable_accounts: Vec<AccountFinding>,
    pub shared_accounts: Vec<AccountFinding>,
    pub repeated_accounts: Vec<(String, usize)>,
    pub score: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AccountFinding {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
    pub reason: String,
}

pub fn analyze_path(path: &Path) -> io::Result<AnalysisReport> {
    let mut files = Vec::new();
    collect_rust_files(path, &mut files)?;

    let mut account_structs = 0;
    let mut total_accounts = 0;
    let mut mutable_accounts = BTreeSet::new();
    let mut shared_accounts = BTreeSet::new();
    let mut account_frequency = BTreeMap::<String, usize>::new();

    for file in &files {
        let source = fs::read_to_string(file)?;
        let file_report = analyze_source(file, &source);
        account_structs += file_report.account_structs;
        total_accounts += file_report.total_accounts;

        for finding in file_report.mutable_accounts {
            mutable_accounts.insert(finding);
        }

        for finding in file_report.shared_accounts {
            shared_accounts.insert(finding);
        }

        for account in file_report.account_names {
            *account_frequency.entry(account).or_default() += 1;
        }
    }

    let repeated_accounts = account_frequency
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .collect::<Vec<_>>();

    let score = score_parallelism(
        total_accounts,
        mutable_accounts.len(),
        shared_accounts.len(),
        repeated_accounts.len(),
    );

    Ok(AnalysisReport {
        path: path.to_path_buf(),
        files_scanned: files.len(),
        account_structs,
        total_accounts,
        mutable_accounts: mutable_accounts.into_iter().collect(),
        shared_accounts: shared_accounts.into_iter().collect(),
        repeated_accounts,
        score,
    })
}

impl AnalysisReport {
    pub fn render(&self) -> String {
        let mut output = String::new();

        output.push_str("Warpcore analysis\n");
        output.push_str("=================\n\n");
        output.push_str(&format!("Path: {}\n", self.path.display()));
        output.push_str(&format!("Rust files scanned: {}\n", self.files_scanned));
        output.push_str(&format!(
            "Account structs found: {}\n",
            self.account_structs
        ));
        output.push_str(&format!("Accounts inspected: {}\n\n", self.total_accounts));
        output.push_str(&format!("Parallelism score: {}/100\n", self.score));
        output.push_str(&format!("Expected gain: {}\n\n", self.expected_gain()));

        if self.total_accounts == 0 {
            output.push_str("No Anchor-style accounts were detected yet.\n");
            output.push_str(
                "Next step: point Warpcore at a Solana program with #[derive(Accounts)] structs.\n",
            );
            return output;
        }

        output.push_str("What is blocking parallelism\n");
        output.push_str("----------------------------\n");

        if self.mutable_accounts.is_empty()
            && self.shared_accounts.is_empty()
            && self.repeated_accounts.is_empty()
        {
            output.push_str("- No obvious write-lock bottlenecks found by the basic scanner.\n");
        } else {
            for finding in self.mutable_accounts.iter().take(8) {
                output.push_str(&format!(
                    "- {}:{} `{}` is mutable, so Solana must write-lock it.\n",
                    finding.file.display(),
                    finding.line,
                    finding.name
                ));
            }

            for finding in self.shared_accounts.iter().take(8) {
                output.push_str(&format!(
                    "- {}:{} `{}` looks like shared state: {}.\n",
                    finding.file.display(),
                    finding.line,
                    finding.name,
                    finding.reason
                ));
            }

            for (name, count) in self.repeated_accounts.iter().take(8) {
                output.push_str(&format!(
                    "- `{}` appears in {} account contexts, which may serialize unrelated transactions.\n",
                    name, count
                ));
            }
        }

        output.push_str("\nWhy it is happening\n");
        output.push_str("-------------------\n");
        output.push_str("- Mutable accounts create write locks.\n");
        output.push_str("- Shared/global accounts force unrelated users through the same state.\n");
        output.push_str(
            "- Reused account names across instructions can indicate hidden contention.\n",
        );

        output.push_str("\nHow to fix it\n");
        output.push_str("-------------\n");
        output.push_str("- Make accounts read-only when the instruction only reads them.\n");
        output.push_str("- Split global state into user, market, pool, or shard PDAs.\n");
        output.push_str("- Keep hot counters and balances away from config/admin accounts.\n");
        output.push_str(
            "- Design account sets so unrelated users touch different writable accounts.\n",
        );

        output.push_str("\nPrototype note: this is a static heuristic scanner, not a full Solana runtime profiler yet.\n");
        output
    }

    fn expected_gain(&self) -> &'static str {
        if self.total_accounts == 0 {
            return "unknown - no Anchor-style accounts detected";
        }

        expected_gain(self.score)
    }
}

#[derive(Debug)]
struct SourceReport {
    account_structs: usize,
    total_accounts: usize,
    mutable_accounts: Vec<AccountFinding>,
    shared_accounts: Vec<AccountFinding>,
    account_names: Vec<String>,
}

fn analyze_source(file: &Path, source: &str) -> SourceReport {
    let mut account_structs = 0;
    let mut total_accounts = 0;
    let mut mutable_accounts = Vec::new();
    let mut shared_accounts = Vec::new();
    let mut account_names = Vec::new();

    let mut in_accounts_struct = false;
    let mut saw_accounts_derive = false;
    let mut brace_depth = 0usize;
    let mut pending_mut = false;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();

        if line.starts_with("#[cfg(test)]") {
            break;
        }

        if line.contains("#[derive") && line.contains("Accounts") {
            saw_accounts_derive = true;
        }

        if saw_accounts_derive && line.starts_with("pub struct ") {
            in_accounts_struct = true;
            saw_accounts_derive = false;
            account_structs += 1;
            brace_depth = count_char(line, '{').saturating_sub(count_char(line, '}'));
            continue;
        }

        if !in_accounts_struct {
            continue;
        }

        brace_depth = brace_depth
            .saturating_add(count_char(line, '{'))
            .saturating_sub(count_char(line, '}'));

        if line.starts_with("#[account") && has_mut_attribute(line) {
            pending_mut = true;
        }

        if let Some(account_name) = parse_account_field(line) {
            total_accounts += 1;
            account_names.push(account_name.clone());

            if pending_mut {
                mutable_accounts.push(AccountFinding {
                    name: account_name.clone(),
                    file: file.to_path_buf(),
                    line: line_number,
                    reason: "marked mut".to_string(),
                });
                pending_mut = false;
            }

            if let Some(hint) = shared_account_hint(&account_name) {
                shared_accounts.push(AccountFinding {
                    name: account_name,
                    file: file.to_path_buf(),
                    line: line_number,
                    reason: format!("name contains `{}`", hint),
                });
            }
        }

        if brace_depth == 0 {
            in_accounts_struct = false;
            pending_mut = false;
        }
    }

    SourceReport {
        account_structs,
        total_accounts,
        mutable_accounts,
        shared_accounts,
        account_names,
    }
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("path does not exist: {}", path.display()),
        ));
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();

        if should_skip(&child) {
            continue;
        }

        if child.is_dir() {
            collect_rust_files(&child, files)?;
        } else if child.extension().is_some_and(|extension| extension == "rs") {
            files.push(child);
        }
    }

    Ok(())
}

fn should_skip(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    matches!(name, ".git" | "node_modules" | "target")
}

fn parse_account_field(line: &str) -> Option<String> {
    if !line.starts_with("pub ") || !line.contains(':') {
        return None;
    }

    let before_type = line.split(':').next()?;
    let name = before_type
        .trim_start_matches("pub")
        .trim()
        .trim_start_matches("mut")
        .trim();

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn has_mut_attribute(line: &str) -> bool {
    line.contains("mut") && !line.contains("immutable")
}

fn shared_account_hint(account_name: &str) -> Option<&'static str> {
    let normalized = account_name.to_ascii_lowercase();

    if matches!(
        normalized.as_str(),
        "state" | "app_state" | "program_state" | "shared_state"
    ) {
        return Some("state");
    }

    SHARED_ACCOUNT_HINTS
        .iter()
        .copied()
        .find(|hint| normalized.contains(hint))
}

fn score_parallelism(
    total_accounts: usize,
    mutable_accounts: usize,
    shared_accounts: usize,
    repeated_accounts: usize,
) -> u8 {
    if total_accounts == 0 {
        return 0;
    }

    let mut score = 100i32;
    score -= ((mutable_accounts as f32 / total_accounts as f32) * 45.0).round() as i32;
    score -= ((shared_accounts as f32 / total_accounts as f32) * 35.0).round() as i32;
    score -= (repeated_accounts as i32 * 6).min(20);
    score.clamp(5, 100) as u8
}

fn expected_gain(score: u8) -> &'static str {
    match score {
        0..=39 => "high - account design is probably serializing traffic",
        40..=69 => "medium - some account hot spots are likely fixable",
        _ => "low - the basic scanner found limited contention",
    }
}

fn count_char(line: &str, target: char) -> usize {
    line.chars()
        .filter(|character| *character == target)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mutable_and_shared_accounts() {
        let source = r#"
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub global_state: Account<'info, GlobalState>,
    pub user_state: Account<'info, UserState>,
}
"#;

        let report = analyze_source(Path::new("program.rs"), source);

        assert_eq!(report.account_structs, 1);
        assert_eq!(report.total_accounts, 2);
        assert_eq!(report.mutable_accounts[0].name, "global_state");
        assert_eq!(report.shared_accounts.len(), 1);
    }
}
