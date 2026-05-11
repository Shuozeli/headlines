//! Persistent record of seed runs — `demo/seed-state.json`.
//!
//! Tracks the ids assigned to demo accounts/users/articles so subsequent
//! seed runs can detect "already done" and the curl-examples helper can
//! refer back to real ids.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeedState {
    /// Map name → record (account/user/system).
    #[serde(default)]
    pub accounts: BTreeMap<String, IdRecord>,
    #[serde(default)]
    pub users: BTreeMap<String, IdRecord>,
    #[serde(default)]
    pub systems: BTreeMap<String, IdRecord>,
    /// Map (account_name, article filename) → article uuid.
    #[serde(default)]
    pub articles: BTreeMap<String, String>,
    /// Drafts published as articles (kept separate so we can avoid reseeding
    /// drafts whose status changed).
    #[serde(default)]
    pub drafts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdRecord {
    pub id: String,
    pub key_id: String,
}

impl SeedState {
    pub fn load_or_default(demo_path: &Path) -> anyhow::Result<(Self, PathBuf)> {
        let path = demo_path.join("seed-state.json");
        if !path.exists() {
            return Ok((SeedState::default(), path));
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let state: SeedState =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        Ok((state, path))
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let raw = serde_json::to_string_pretty(self).context("serialize seed state")?;
        std::fs::write(path, raw).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}
