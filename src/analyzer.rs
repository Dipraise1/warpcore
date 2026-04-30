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
    pub instruction_contexts: usize,
    pub total_accounts: usize,
    pub mutable_accounts: Vec<AccountFinding>,
    pub shared_accounts: Vec<AccountFinding>,
    pub repeated_accounts: Vec<(String, usize)>,
    pub hotspots: Vec<AccountHotspot>,
    pub conflicts: Vec<ConflictPair>,
    pub score: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AccountFinding {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
    pub context: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AccountHotspot {
    pub name: String,
    pub total_occurrences: usize,
    pub writable_occurrences: usize,
    pub context_count: usize,
    pub contexts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConflictPair {
    pub left_context: String,
    pub right_context: String,
    pub shared_accounts: Vec<String>,
}

pub fn analyze_path(path: &Path) -> io::Result<AnalysisReport> {
    let mut files = Vec::new();
    collect_rust_files(path, &mut files)?;

    let mut instruction_contexts = Vec::new();
    let mut total_accounts = 0;
    let mut mutable_accounts = BTreeSet::new();
    let mut shared_accounts = BTreeSet::new();
    let mut account_frequency = BTreeMap::<String, usize>::new();
    let mut account_stats = BTreeMap::<String, AccountStats>::new();

    for file in &files {
        let source = fs::read_to_string(file)?;
        let file_report = analyze_source(file, &source);
        instruction_contexts.extend(file_report.instruction_contexts);
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

    let hotspots = build_hotspots(&instruction_contexts, &mut account_stats);
    let conflicts = build_conflicts(&instruction_contexts);

    let score = score_parallelism(
        total_accounts,
        mutable_accounts.len(),
        shared_accounts.len(),
        repeated_accounts.len(),
        hotspots.len(),
        conflicts.len(),
    );

    Ok(AnalysisReport {
        path: path.to_path_buf(),
        files_scanned: files.len(),
        instruction_contexts: instruction_contexts.len(),
        total_accounts,
        mutable_accounts: mutable_accounts.into_iter().collect(),
        shared_accounts: shared_accounts.into_iter().collect(),
        repeated_accounts,
        hotspots,
        conflicts,
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
            "Instruction contexts found: {}\n",
            self.instruction_contexts
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

        output.push_str("Hot accounts\n");
        output.push_str("------------\n");

        if self.hotspots.is_empty() {
            output.push_str("- No obvious account hot spots found by the basic scanner.\n");
        } else {
            for hotspot in self.hotspots.iter().take(8) {
                let sample_contexts = hotspot
                    .contexts
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                output.push_str(&format!(
                    "- `{}` appears {} times across {} contexts ({} writable occurrences){}\n",
                    hotspot.name,
                    hotspot.total_occurrences,
                    hotspot.context_count,
                    hotspot.writable_occurrences,
                    if sample_contexts.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", sample_contexts)
                    }
                ));
            }
        }

        output.push_str("\nConflicting contexts\n");
        output.push_str("--------------------\n");

        if self.conflicts.is_empty() {
            output.push_str(
                "- No shared writable accounts were found between instruction contexts.\n",
            );
        } else {
            for conflict in self.conflicts.iter().take(8) {
                output.push_str(&format!(
                    "- {} <-> {} share `{}`\n",
                    conflict.left_context,
                    conflict.right_context,
                    conflict.shared_accounts.join("`, `")
                ));
            }
        }

        if !self.mutable_accounts.is_empty() || !self.shared_accounts.is_empty() {
            output.push_str("\nWrite lock signals\n");
            output.push_str("------------------\n");

            for finding in self.mutable_accounts.iter().take(6) {
                output.push_str(&format!(
                    "- {}:{} {} -> `{}` is mutable.\n",
                    finding.file.display(),
                    finding.line,
                    finding.context,
                    finding.name
                ));
            }

            for finding in self.shared_accounts.iter().take(6) {
                output.push_str(&format!(
                    "- {}:{} {} -> `{}` looks shared ({})\n",
                    finding.file.display(),
                    finding.line,
                    finding.context,
                    finding.name,
                    finding.reason
                ));
            }
        }

        if !self.repeated_accounts.is_empty() {
            output.push_str("\nRepeated accounts\n");
            output.push_str("-----------------\n");

            for (name, count) in self.repeated_accounts.iter().take(6) {
                output.push_str(&format!(
                    "- `{}` appears in {} account contexts.\n",
                    name, count
                ));
            }
        }

        output.push_str("\nHow to fix it\n");
        output.push_str("-------------\n");
        output.push_str("- Make accounts read-only when the instruction only reads them.\n");
        output.push_str("- Split global state into user, market, pool, or shard PDAs.\n");
        output.push_str("- Keep hot counters and balances away from config/admin accounts.\n");
        output.push_str(
            "- Design account sets so unrelated users touch different writable accounts.\n",
        );

        output.push_str(
            "\nPrototype note: this is a static heuristic scanner, not a full Solana runtime profiler yet.\n",
        );
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
    instruction_contexts: Vec<InstructionContext>,
    total_accounts: usize,
    mutable_accounts: Vec<AccountFinding>,
    shared_accounts: Vec<AccountFinding>,
    account_names: Vec<String>,
}

#[derive(Debug, Clone)]
struct InstructionContext {
    name: String,
    file: PathBuf,
    line: usize,
    accounts: Vec<AccountOccurrence>,
}

#[derive(Debug, Clone)]
struct AccountOccurrence {
    name: String,
    mutable: bool,
}

#[derive(Debug, Default)]
struct AccountStats {
    total_occurrences: usize,
    writable_occurrences: usize,
    contexts: BTreeSet<String>,
}

fn analyze_source(file: &Path, source: &str) -> SourceReport {
    let mut instruction_contexts = Vec::new();
    let mut total_accounts = 0;
    let mut mutable_accounts = Vec::new();
    let mut shared_accounts = Vec::new();
    let mut account_names = Vec::new();

    let mut in_accounts_struct = false;
    let mut saw_accounts_derive = false;
    let mut brace_depth = 0usize;
    let mut pending_mut = false;
    let mut current_context: Option<InstructionContext> = None;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();

        if line.starts_with("#[cfg(test)]") {
            break;
        }

        if line.contains("#[derive") && line.contains("Accounts") {
            saw_accounts_derive = true;
            continue;
        }

        if saw_accounts_derive && line.starts_with("pub struct ") {
            in_accounts_struct = true;
            saw_accounts_derive = false;
            let context_name = parse_struct_name(line).unwrap_or_else(|| "Accounts".to_string());
            brace_depth = count_char(line, '{').saturating_sub(count_char(line, '}'));
            current_context = Some(InstructionContext {
                name: context_name,
                file: file.to_path_buf(),
                line: line_number,
                accounts: Vec::new(),
            });
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

            let mutable = pending_mut;
            let context_name = current_context
                .as_ref()
                .map(|context| context.name.clone())
                .unwrap_or_else(|| "Accounts".to_string());
            let context_file = file.to_path_buf();

            if pending_mut {
                mutable_accounts.push(AccountFinding {
                    name: account_name.clone(),
                    file: context_file.clone(),
                    line: line_number,
                    context: context_name.clone(),
                    reason: "marked mut".to_string(),
                });
            }

            if let Some(hint) = shared_account_hint(&account_name) {
                shared_accounts.push(AccountFinding {
                    name: account_name.clone(),
                    file: context_file.clone(),
                    line: line_number,
                    context: context_name,
                    reason: format!("name contains `{}`", hint),
                });
            }

            if let Some(context) = current_context.as_mut() {
                context.accounts.push(AccountOccurrence {
                    name: account_name.clone(),
                    mutable,
                });
            }

            pending_mut = false;
        }

        if brace_depth == 0 {
            in_accounts_struct = false;
            pending_mut = false;
            if let Some(context) = current_context.take() {
                instruction_contexts.push(context);
            }
        }
    }

    if let Some(context) = current_context.take() {
        instruction_contexts.push(context);
    }

    SourceReport {
        instruction_contexts,
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

fn parse_struct_name(line: &str) -> Option<String> {
    if !line.starts_with("pub struct ") {
        return None;
    }

    let rest = line.trim_start_matches("pub struct ").trim();
    let name = rest
        .split(|character: char| character == '<' || character == '{' || character.is_whitespace())
        .next()?;

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
    hotspots: usize,
    conflicts: usize,
) -> u8 {
    if total_accounts == 0 {
        return 0;
    }

    let mut score = 100i32;
    score -= ((mutable_accounts as f32 / total_accounts as f32) * 45.0).round() as i32;
    score -= ((shared_accounts as f32 / total_accounts as f32) * 35.0).round() as i32;
    score -= (repeated_accounts as i32 * 6).min(20);
    score -= (hotspots as i32 * 3).min(18);
    score -= (conflicts as i32 * 2).min(18);
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

fn build_hotspots(
    contexts: &[InstructionContext],
    stats: &mut BTreeMap<String, AccountStats>,
) -> Vec<AccountHotspot> {
    for context in contexts {
        let context_label = context.label();
        for account in &context.accounts {
            let entry = stats.entry(account.name.clone()).or_default();
            entry.total_occurrences += 1;
            entry.contexts.insert(context_label.clone());
            if account.mutable {
                entry.writable_occurrences += 1;
            }
        }
    }

    let mut hotspots = stats
        .iter()
        .filter(|(_, stat)| stat.contexts.len() > 1 || stat.writable_occurrences > 1)
        .map(|(name, stat)| AccountHotspot {
            name: name.clone(),
            total_occurrences: stat.total_occurrences,
            writable_occurrences: stat.writable_occurrences,
            context_count: stat.contexts.len(),
            contexts: stat.contexts.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();

    hotspots.sort_by(|left, right| {
        right
            .context_count
            .cmp(&left.context_count)
            .then_with(|| right.writable_occurrences.cmp(&left.writable_occurrences))
            .then_with(|| left.name.cmp(&right.name))
    });

    hotspots
}

fn build_conflicts(contexts: &[InstructionContext]) -> Vec<ConflictPair> {
    let mut conflicts = Vec::new();

    for left_index in 0..contexts.len() {
        for right_index in (left_index + 1)..contexts.len() {
            let left = &contexts[left_index];
            let right = &contexts[right_index];
            let shared_accounts = shared_writable_accounts(left, right);

            if !shared_accounts.is_empty() {
                conflicts.push(ConflictPair {
                    left_context: left.label(),
                    right_context: right.label(),
                    shared_accounts,
                });
            }
        }
    }

    conflicts.sort_by(|left, right| {
        right
            .shared_accounts
            .len()
            .cmp(&left.shared_accounts.len())
            .then_with(|| left.left_context.cmp(&right.left_context))
            .then_with(|| left.right_context.cmp(&right.right_context))
    });

    conflicts
}

fn shared_writable_accounts(left: &InstructionContext, right: &InstructionContext) -> Vec<String> {
    let left_accounts = left.account_names();
    let right_accounts = right.account_names();

    left_accounts
        .intersection(&right_accounts)
        .filter(|name| left.is_writable(name) || right.is_writable(name))
        .cloned()
        .collect()
}

impl InstructionContext {
    fn label(&self) -> String {
        format!("{} @ {}:{}", self.name, self.file.display(), self.line)
    }

    fn account_names(&self) -> BTreeSet<String> {
        self.accounts
            .iter()
            .map(|account| account.name.clone())
            .collect()
    }

    fn is_writable(&self, account_name: &str) -> bool {
        self.accounts
            .iter()
            .any(|account| account.name == account_name && account.mutable)
    }
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

        assert_eq!(report.instruction_contexts.len(), 1);
        assert_eq!(report.total_accounts, 2);
        assert_eq!(report.mutable_accounts[0].name, "global_state");
        assert_eq!(report.shared_accounts.len(), 1);
    }

    #[test]
    fn builds_conflicts_for_shared_writable_accounts() {
        let left = InstructionContext {
            name: "Swap".to_string(),
            file: PathBuf::from("swap.rs"),
            line: 1,
            accounts: vec![AccountOccurrence {
                name: "vault".to_string(),
                mutable: true,
            }],
        };
        let right = InstructionContext {
            name: "Deposit".to_string(),
            file: PathBuf::from("deposit.rs"),
            line: 1,
            accounts: vec![AccountOccurrence {
                name: "vault".to_string(),
                mutable: true,
            }],
        };

        let conflicts = build_conflicts(&[left, right]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].shared_accounts, vec!["vault".to_string()]);
    }
}
