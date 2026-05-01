# Warpcore

Warpcore is a developer tool for finding Solana account-lock bottlenecks.
It helps answer one question:

> Why is this Solana program not running in parallel?

This is the first real product slice. It can analyze exported Anchor IDL JSON
files directly, and it still supports a Rust-source heuristic fallback.

## Run

```bash
cargo run -- analyze ./target/idl/my_program.json
```

Or run the named binary directly:

```bash
cargo run --bin brain -- analyze ./target/idl/my_program.json
```

Add `--json` to emit machine-readable output:

```bash
cargo run -- analyze --json ./target/idl/my_program.json
```

The JSON report includes the conflict graph, severity, and fix suggestions.

Filter the visible conflicts by severity, cap the list length, and fail the
command when blocking conflicts are present:

```bash
cargo run -- analyze --severity medium --top 5 --fail-on high ./target/idl/my_program.json
```

You can also point it at any Rust file or folder, or omit the path to scan the
current directory. If the directory contains Anchor IDL JSON files, Warpcore
analyzes those first:

```bash
cargo run -- analyze ./src
cargo run -- analyze
cargo run -- analyze ./target/idl/my_program.json
```

## Example Output

```text
Warpcore analysis
=================

Parallelism score: 42/100
Expected gain: medium - some account hot spots are likely fixable

What is blocking parallelism
----------------------------
- programs/dex/src/lib.rs:18 `global_state` is mutable, so Solana must write-lock it.
- `vault` appears in 3 account contexts, which may serialize unrelated transactions.
```

## What It Checks Today

- Anchor IDL instruction accounts and mutability
- Mutable Anchor accounts using `#[account(mut)]`
- Account names that look shared, such as `global_state`, `config`, `vault`, or `treasury`
- Repeated account names across account contexts
- Hot accounts that appear in multiple instruction contexts
- Shared writable conflicts between instruction contexts
- Per-conflict severity and fix suggestions
- A rough parallelism score from `0` to `100`

By default the CLI exits with code `1` when a `high` severity conflict is
present. Use `--fail-on none` to disable that check.

## Roadmap

- Build transaction conflict graphs
- Export JSON reports for automation
- Detect unnecessary writable accounts
- Suggest PDA sharding strategies
- Compare before/after expected throughput
