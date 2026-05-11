//! Demo-data seed pipeline.
//!
//! Walks `demo/` and bootstraps a fully-populated headlines instance via the
//! gRPC API surface. Idempotent — every step checks for prior state before
//! creating new rows so a re-run after partial completion picks up where it
//! left off.
//!
//! See `demo/README.md` for what the seed produces and the scope of the demo
//! flow it covers.

pub mod articles;
pub mod content_md;
pub mod frontmatter;
pub mod keys;
pub mod plan;
pub mod runner;
pub mod state;

pub use runner::run_seed;
