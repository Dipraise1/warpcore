use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub path: PathBuf,
    pub analysis_mode: AnalysisMode,
    pub files_scanned: usize,
    pub instruction_contexts: usize,
    pub total_accounts: usize,
    pub mutable_accounts: Vec<AccountFinding>,
    pub shared_accounts: Vec<AccountFinding>,
    pub repeated_accounts: Vec<(String, usize)>,
    pub hotspots: Vec<AccountHotspot>,
    pub conflicts: Vec<ConflictPair>,
    pub conflict_graph: ConflictGraph,
    pub score: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AnalysisMode {
    AnchorIdl,
    RustHeuristic,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct AccountFinding {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
    pub context: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountHotspot {
    pub name: String,
    pub total_occurrences: usize,
    pub writable_occurrences: usize,
    pub context_count: usize,
    pub contexts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictPair {
    pub left_context: String,
    pub right_context: String,
    pub shared_accounts: Vec<String>,
    pub severity: ConflictSeverity,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictGraph {
    pub nodes: Vec<ConflictNode>,
    pub edges: Vec<ConflictEdge>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictNode {
    pub context: String,
    pub file: PathBuf,
    pub line: usize,
    pub account_count: usize,
    pub writable_account_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictEdge {
    pub left_context: String,
    pub right_context: String,
    pub shared_accounts: Vec<String>,
    pub severity: ConflictSeverity,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ConflictSeverity {
    Low,
    Medium,
    High,
}

pub fn analyze_path(path: &Path) -> io::Result<AnalysisReport> {
    if path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        return analyze_idl_file(path);
    }

    if path.is_dir() {
        let mut json_files = Vec::new();
        collect_files_with_extension(path, "json", &mut json_files)?;
        if !json_files.is_empty() {
            return analyze_idl_directory(path, json_files);
        }
    }

    analyze_rust_path(path)
}

fn analyze_rust_path(path: &Path) -> io::Result<AnalysisReport> {
    let mut files = Vec::new();
    collect_rust_files(path, &mut files)?;

    let mut instruction_contexts = Vec::new();
    let mut total_accounts = 0;
    let mut mutable_accounts = BTreeSet::new();
    let mut shared_accounts = BTreeSet::new();
    let mut account_frequency = BTreeMap::<String, usize>::new();

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

    let mut account_stats = BTreeMap::<String, AccountStats>::new();
    let hotspots = build_hotspots(&instruction_contexts, &mut account_stats);
    let conflict_graph = build_conflict_graph(&instruction_contexts);
    let conflicts = conflict_graph
        .edges
        .iter()
        .cloned()
        .map(|edge| ConflictPair {
            left_context: edge.left_context,
            right_context: edge.right_context,
            shared_accounts: edge.shared_accounts,
            severity: edge.severity,
            suggestions: edge.suggestions,
        })
        .collect::<Vec<_>>();

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
        analysis_mode: AnalysisMode::RustHeuristic,
        files_scanned: files.len(),
        instruction_contexts: instruction_contexts.len(),
        total_accounts,
        mutable_accounts: mutable_accounts.into_iter().collect(),
        shared_accounts: shared_accounts.into_iter().collect(),
        repeated_accounts,
        hotspots,
        conflicts,
        conflict_graph,
        score,
    })
}

fn analyze_idl_file(path: &Path) -> io::Result<AnalysisReport> {
    let source = fs::read_to_string(path)?;
    let parts = analyze_idl_source(path, &source)?;
    build_report(
        path,
        AnalysisMode::AnchorIdl,
        1,
        parts.instruction_contexts,
        parts.total_accounts,
        parts.mutable_accounts,
        parts.shared_accounts,
        parts.account_frequency,
    )
}

fn analyze_idl_directory(path: &Path, json_files: Vec<PathBuf>) -> io::Result<AnalysisReport> {
    let mut merged = IdlAnalysisParts::default();

    for file in &json_files {
        let source = fs::read_to_string(file)?;
        let mut parts = analyze_idl_source(file, &source)?;
        merged
            .instruction_contexts
            .append(&mut parts.instruction_contexts);
        merged.total_accounts += parts.total_accounts;
        merged.mutable_accounts.extend(parts.mutable_accounts);
        merged.shared_accounts.extend(parts.shared_accounts);
        for (name, count) in parts.account_frequency {
            *merged.account_frequency.entry(name).or_default() += count;
        }
    }

    merged.shared_accounts.extend(build_context_shared_accounts(
        &merged.instruction_contexts,
        path,
    ));

    build_report(
        path,
        AnalysisMode::AnchorIdl,
        json_files.len(),
        merged.instruction_contexts,
        merged.total_accounts,
        merged.mutable_accounts,
        merged.shared_accounts,
        merged.account_frequency,
    )
}

fn analyze_idl_source(path: &Path, source: &str) -> io::Result<IdlAnalysisParts> {
    let idl: AnchorIdl = serde_json::from_str(&source).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse Anchor IDL {}: {}", path.display(), error),
        )
    })?;

    let mut instruction_contexts = Vec::new();
    let mut total_accounts = 0;
    let mut mutable_accounts = BTreeSet::new();
    let mut shared_accounts = BTreeSet::new();
    let mut account_frequency = BTreeMap::<String, usize>::new();

    for instruction in idl.instructions {
        let mut context = InstructionContext {
            name: instruction.name,
            file: path.to_path_buf(),
            line: 0,
            accounts: Vec::new(),
        };

        for account in flatten_idl_accounts(&instruction.accounts) {
            total_accounts += 1;
            *account_frequency.entry(account.name.clone()).or_default() += 1;

            if account.is_mut {
                mutable_accounts.insert(AccountFinding {
                    name: account.name.clone(),
                    file: path.to_path_buf(),
                    line: 0,
                    context: context.name.clone(),
                    reason: "declared mutable in Anchor IDL".to_string(),
                });
            }

            context.accounts.push(AccountOccurrence {
                name: account.name,
                mutable: account.is_mut,
            });
        }

        instruction_contexts.push(context);
    }

    shared_accounts.extend(build_context_shared_accounts(&instruction_contexts, path));

    Ok(IdlAnalysisParts {
        instruction_contexts,
        total_accounts,
        mutable_accounts,
        shared_accounts,
        account_frequency,
    })
}

fn build_report(
    path: &Path,
    analysis_mode: AnalysisMode,
    files_scanned: usize,
    instruction_contexts: Vec<InstructionContext>,
    total_accounts: usize,
    mutable_accounts: BTreeSet<AccountFinding>,
    shared_accounts: BTreeSet<AccountFinding>,
    account_frequency: BTreeMap<String, usize>,
) -> io::Result<AnalysisReport> {
    let repeated_accounts = account_frequency
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .collect::<Vec<_>>();

    let mut account_stats = BTreeMap::<String, AccountStats>::new();
    let hotspots = build_hotspots(&instruction_contexts, &mut account_stats);
    let conflict_graph = build_conflict_graph(&instruction_contexts);
    let conflicts = conflict_graph
        .edges
        .iter()
        .cloned()
        .map(|edge| ConflictPair {
            left_context: edge.left_context,
            right_context: edge.right_context,
            shared_accounts: edge.shared_accounts,
            severity: edge.severity,
            suggestions: edge.suggestions,
        })
        .collect::<Vec<_>>();

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
        analysis_mode,
        files_scanned,
        instruction_contexts: instruction_contexts.len(),
        total_accounts,
        mutable_accounts: mutable_accounts.into_iter().collect(),
        shared_accounts: shared_accounts.into_iter().collect(),
        repeated_accounts,
        hotspots,
        conflicts,
        conflict_graph,
        score,
    })
}

impl AnalysisReport {
    pub fn render(&self) -> String {
        let mut output = String::new();

        output.push_str("Warpcore analysis\n");
        output.push_str("=================\n\n");
        output.push_str(&format!("Path: {}\n", self.path.display()));
        output.push_str(&format!("Analysis mode: {}\n", self.analysis_mode.label()));
        output.push_str(&format!("Files scanned: {}\n", self.files_scanned));
        output.push_str(&format!(
            "Instruction contexts found: {}\n",
            self.instruction_contexts
        ));
        output.push_str(&format!("Accounts inspected: {}\n\n", self.total_accounts));
        output.push_str(&format!("Parallelism score: {}/100\n", self.score));
        output.push_str(&format!("Expected gain: {}\n\n", self.expected_gain()));

        if self.total_accounts == 0 {
            match self.analysis_mode {
                AnalysisMode::AnchorIdl => {
                    output.push_str("No IDL instructions with accounts were detected yet.\n");
                    output.push_str(
                        "Next step: point Warpcore at an exported Anchor IDL JSON file.\n",
                    );
                }
                AnalysisMode::RustHeuristic => {
                    output.push_str("No Anchor-style accounts were detected yet.\n");
                    output.push_str(
                        "Next step: point Warpcore at a Solana program with #[derive(Accounts)] structs.\n",
                    );
                }
            }
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

        output.push_str("\nConflict graph\n");
        output.push_str("--------------\n");

        if self.conflicts.is_empty() {
            output.push_str(
                "- No shared writable accounts were found between instruction contexts.\n",
            );
        } else {
            for conflict in self.conflicts.iter().take(8) {
                output.push_str(&format!(
                    "- [{}] {} <-> {} share `{}`\n",
                    conflict.severity.label(),
                    conflict.left_context,
                    conflict.right_context,
                    conflict.shared_accounts.join("`, `")
                ));
                for suggestion in conflict.suggestions.iter().take(3) {
                    output.push_str(&format!("  - {}\n", suggestion));
                }
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
            "\nPrototype note: this is an analyzer prototype. IDL mode uses Anchor metadata; Rust mode is still heuristic.\n",
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

impl AnalysisMode {
    fn label(self) -> &'static str {
        match self {
            AnalysisMode::AnchorIdl => "Anchor IDL",
            AnalysisMode::RustHeuristic => "Rust source heuristic",
        }
    }
}

impl ConflictSeverity {
    fn label(self) -> &'static str {
        match self {
            ConflictSeverity::Low => "low",
            ConflictSeverity::Medium => "medium",
            ConflictSeverity::High => "high",
        }
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

#[derive(Debug, Default)]
struct IdlAnalysisParts {
    instruction_contexts: Vec<InstructionContext>,
    total_accounts: usize,
    mutable_accounts: BTreeSet<AccountFinding>,
    shared_accounts: BTreeSet<AccountFinding>,
    account_frequency: BTreeMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct AnchorIdl {
    #[serde(default)]
    instructions: Vec<AnchorIdlInstruction>,
}

#[derive(Debug, Deserialize)]
struct AnchorIdlInstruction {
    name: String,
    #[serde(default)]
    accounts: Vec<AnchorIdlAccountItem>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnchorIdlAccountItem {
    Group {
        #[serde(rename = "name")]
        _name: String,
        accounts: Vec<AnchorIdlAccountItem>,
    },
    Account {
        name: String,
        #[serde(default, rename = "isMut", alias = "mut")]
        is_mut: bool,
    },
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

fn collect_files_with_extension(
    path: &Path,
    extension: &str,
    files: &mut Vec<PathBuf>,
) -> io::Result<()> {
    if path.is_file() {
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
        {
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
            collect_files_with_extension(&child, extension, files)?;
        } else if child
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
        {
            files.push(child);
        }
    }

    Ok(())
}

fn build_context_shared_accounts(
    instruction_contexts: &[InstructionContext],
    file: &Path,
) -> BTreeSet<AccountFinding> {
    let mut occurrences = BTreeMap::<String, BTreeSet<String>>::new();

    for context in instruction_contexts {
        let context_label = context.label();
        let mut seen = BTreeSet::new();

        for account in &context.accounts {
            if seen.insert(account.name.clone()) {
                occurrences
                    .entry(account.name.clone())
                    .or_default()
                    .insert(context_label.clone());
            }
        }
    }

    occurrences
        .into_iter()
        .filter(|(_, contexts)| contexts.len() > 1)
        .map(|(name, contexts)| AccountFinding {
            name,
            file: file.to_path_buf(),
            line: 0,
            context: "IDL".to_string(),
            reason: format!("appears in {} instruction contexts", contexts.len()),
        })
        .collect()
}

fn should_skip(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    matches!(name, ".git" | "node_modules" | "target")
}

#[derive(Debug, Clone)]
struct FlattenedIdlAccount {
    name: String,
    is_mut: bool,
}

fn flatten_idl_accounts(items: &[AnchorIdlAccountItem]) -> Vec<FlattenedIdlAccount> {
    let mut flattened = Vec::new();

    for item in items {
        match item {
            AnchorIdlAccountItem::Account { name, is_mut } => {
                flattened.push(FlattenedIdlAccount {
                    name: name.clone(),
                    is_mut: *is_mut,
                });
            }
            AnchorIdlAccountItem::Group { accounts, .. } => {
                flattened.extend(flatten_idl_accounts(accounts));
            }
        }
    }

    flattened
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

fn build_conflict_graph(contexts: &[InstructionContext]) -> ConflictGraph {
    let mut nodes = Vec::with_capacity(contexts.len());
    let mut edges = Vec::new();

    for context in contexts {
        nodes.push(ConflictNode {
            context: context.label(),
            file: context.file.clone(),
            line: context.line,
            account_count: context.accounts.len(),
            writable_account_count: context.writable_count(),
        });
    }

    for left_index in 0..contexts.len() {
        for right_index in (left_index + 1)..contexts.len() {
            let left = &contexts[left_index];
            let right = &contexts[right_index];
            let shared_accounts = shared_writable_accounts(left, right);

            if !shared_accounts.is_empty() {
                let severity = classify_conflict_severity(left, right, &shared_accounts);
                let suggestions = build_conflict_suggestions(&shared_accounts, severity);
                edges.push(ConflictEdge {
                    left_context: left.label(),
                    right_context: right.label(),
                    shared_accounts,
                    severity,
                    suggestions,
                });
            }
        }
    }

    edges.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| right.shared_accounts.len().cmp(&left.shared_accounts.len()))
            .then_with(|| left.left_context.cmp(&right.left_context))
            .then_with(|| left.right_context.cmp(&right.right_context))
    });

    ConflictGraph { nodes, edges }
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

fn classify_conflict_severity(
    left: &InstructionContext,
    right: &InstructionContext,
    shared_accounts: &[String],
) -> ConflictSeverity {
    if shared_accounts.len() >= 2
        || shared_accounts
            .iter()
            .any(|name| shared_account_hint(name).is_some())
        || left.writable_count() > 1
        || right.writable_count() > 1
    {
        ConflictSeverity::High
    } else if shared_accounts.len() == 1 {
        ConflictSeverity::Medium
    } else {
        ConflictSeverity::Low
    }
}

fn build_conflict_suggestions(
    shared_accounts: &[String],
    severity: ConflictSeverity,
) -> Vec<String> {
    let mut suggestions = Vec::new();
    let shared_list = shared_accounts.join("`, `");

    match shared_accounts {
        [name] => {
            if shared_account_hint(name).is_some() {
                suggestions.push(format!(
                    "Split `{}` into narrower PDAs so unrelated instructions stop sharing it.",
                    name
                ));
            } else {
                suggestions.push(format!(
                    "Make `{}` read-only where possible, or move instruction-specific data into separate PDAs.",
                    name
                ));
            }
        }
        _ => {
            suggestions.push(format!(
                "Split `{}` into per-user, per-market, or per-shard PDAs.",
                shared_list
            ));
        }
    }

    match severity {
        ConflictSeverity::High => {
            suggestions.push(
                "Remove unnecessary `mut` annotations from any account that is only read."
                    .to_string(),
            );
            suggestions.push(
                "Separate hot state from configuration and admin flows so unrelated traffic stops contending."
                    .to_string(),
            );
        }
        ConflictSeverity::Medium => {
            suggestions.push(
                "Check whether one side can read the account instead of writing it.".to_string(),
            );
        }
        ConflictSeverity::Low => {
            suggestions.push("Keep the shared account narrow and avoid reusing it across unrelated instructions.".to_string());
        }
    }

    suggestions
}

fn severity_rank(severity: ConflictSeverity) -> usize {
    match severity {
        ConflictSeverity::Low => 0,
        ConflictSeverity::Medium => 1,
        ConflictSeverity::High => 2,
    }
}

impl InstructionContext {
    fn label(&self) -> String {
        if self.line == 0 {
            format!("{} @ {}", self.name, self.file.display())
        } else {
            format!("{} @ {}:{}", self.name, self.file.display(), self.line)
        }
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

    fn writable_count(&self) -> usize {
        self.accounts
            .iter()
            .filter(|account| account.mutable)
            .count()
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
                name: "position".to_string(),
                mutable: true,
            }],
        };
        let right = InstructionContext {
            name: "Deposit".to_string(),
            file: PathBuf::from("deposit.rs"),
            line: 1,
            accounts: vec![AccountOccurrence {
                name: "position".to_string(),
                mutable: true,
            }],
        };

        let graph = build_conflict_graph(&[left, right]);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].shared_accounts, vec!["position".to_string()]);
        assert_eq!(graph.edges[0].severity.label(), "medium");
        assert!(!graph.edges[0].suggestions.is_empty());
    }

    #[test]
    fn classifies_shared_global_accounts_as_high_severity() {
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

        let graph = build_conflict_graph(&[left, right]);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].severity.label(), "high");
        assert!(graph.edges[0]
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains("vault")));
    }

    #[test]
    fn analyzes_anchor_idl_json() {
        let fixture =
            std::env::temp_dir().join(format!("warpcore-idl-{}.json", std::process::id()));
        let json = r#"
{
  "instructions": [
    {
      "name": "deposit",
      "accounts": [
        { "name": "vault", "isMut": true },
        { "name": "user", "isMut": false }
      ]
    },
    {
      "name": "withdraw",
      "accounts": [
        { "name": "vault", "isMut": true },
        { "name": "user", "isMut": false }
      ]
    }
  ]
}
"#;

        std::fs::write(&fixture, json).expect("write fixture");
        let report = analyze_path(&fixture).expect("analyze idl");
        let _ = std::fs::remove_file(&fixture);

        assert_eq!(report.analysis_mode, AnalysisMode::AnchorIdl);
        assert_eq!(report.instruction_contexts, 2);
        assert_eq!(report.total_accounts, 4);
        assert_eq!(report.conflicts.len(), 1);
        assert!(report
            .repeated_accounts
            .iter()
            .any(|(name, count)| name == "vault" && *count == 2));
    }
}
