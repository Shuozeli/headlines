---
title: "Notes on Building a Small CLI in Rust: Followup Notes"
author_name: "Hua Park"
author_url: "https://example.com"
created_at: "2026-04-21T05:44:00Z"
state: "live"
---

*Continued from the earlier post.* Skim that one first if you haven't.


Rust's CLI story has matured into one of the most pleasant in any
ecosystem. `clap` for argument parsing, `anyhow` for error handling,
`tokio` for async, and `serde` for any I/O — these four crates compose
into a tight, fast binary in a couple of hundred lines of code.

```
tokenctl/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── cli.rs
    └── client.rs
```

## Project layout

This post walks through building `tokenctl`, a small tool that talks to
our internal token-mint service.

`main.rs` parses args, dispatches to the right subcommand. `cli.rs`
defines the `clap` derive structs. `client.rs` wraps the HTTP client.

## The clap derive

```rust
#[derive(Parser)]
#[command(name = "tokenctl", version)]
struct Cli {
    #[arg(long)] endpoint: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Mint { #[arg(long)] subject: String },
    Revoke { #[arg(long)] id: String },
}
```

That's the whole CLI surface. `clap` generates `--help`, `--version`,
typed parsing, error messages, all of it.

## Conclusion

We've shipped four internal tools using this template. Total LOC across
all four is under 1500. They start in milliseconds, ship as static
binaries, and have not produced a single runtime panic in production.
