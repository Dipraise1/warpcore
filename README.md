# Warpcore

Warpcore is a developer tool for finding Solana account-lock bottlenecks.
It helps answer one question:

> Why is this Solana program not running in parallel?

This is the first basic prototype. It scans Rust/Anchor-style account structs
and reports likely parallelism blockers such as mutable accounts, shared/global
state, and repeated account names.

## Run

```bash
cargo run -- analyze ./program
```

Or run the named binary directly:

```bash
cargo run --bin brain -- analyze ./program
```

You can also point it at any Rust file or folder:

```bash
cargo run -- analyze ./src
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

- Mutable Anchor accounts using `#[account(mut)]`
- Account names that look shared, such as `global_state`, `config`, `vault`, or `treasury`
- Repeated account names across account contexts
- A rough parallelism score from `0` to `100`

## Roadmap

- Parse full Anchor IDLs
- Build transaction conflict graphs
- Detect unnecessary writable accounts
- Suggest PDA sharding strategies
- Compare before/after expected throughput
