//! Load Ed25519 keypairs from disk and (re)generate any missing pairs.
//!
//! Files are written as base64(raw 32 bytes). Two files per identity:
//! `<name>.public` and `<name>.private`.

use std::path::Path;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct LoadedKey {
    pub name: String,
    pub signing_key: SigningKey,
    pub public_b64: String,
}

/// Load all keypairs in `<demo_path>/keys/<kind>/` (where kind is one of
/// system|account|user). Returns the keys keyed by the file stem.
pub fn load_kind(demo_path: &Path, kind: &str) -> anyhow::Result<Vec<LoadedKey>> {
    let dir = demo_path.join("keys").join(kind);
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|s| s == "private").unwrap_or(false)
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            names.push(stem.to_owned());
        }
    }
    names.sort();
    for name in names {
        let priv_path = dir.join(format!("{name}.private"));
        let pub_path = dir.join(format!("{name}.public"));
        out.push(load_pair(&name, &priv_path, &pub_path)?);
    }
    Ok(out)
}

/// Read a single keypair from disk.
pub fn load_pair(name: &str, priv_path: &Path, pub_path: &Path) -> anyhow::Result<LoadedKey> {
    let priv_b64 = std::fs::read_to_string(priv_path)
        .with_context(|| format!("read {}", priv_path.display()))?
        .trim()
        .to_owned();
    let priv_bytes = B64
        .decode(priv_b64.as_bytes())
        .with_context(|| format!("decode private key {}", priv_path.display()))?;
    if priv_bytes.len() != 32 {
        return Err(anyhow!(
            "expected 32 bytes for {}, got {}",
            priv_path.display(),
            priv_bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&priv_bytes);
    let sk = SigningKey::from_bytes(&arr);

    let pub_b64 = std::fs::read_to_string(pub_path)
        .with_context(|| format!("read {}", pub_path.display()))?
        .trim()
        .to_owned();

    Ok(LoadedKey {
        name: name.to_owned(),
        signing_key: sk,
        public_b64: pub_b64,
    })
}

/// Generate any missing keypairs for the given names under
/// `<demo_path>/keys/<kind>/`. Existing files are left alone.
pub fn ensure_keys(demo_path: &Path, kind: &str, names: &[&str]) -> anyhow::Result<()> {
    let dir = demo_path.join("keys").join(kind);
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    for name in names {
        let priv_path = dir.join(format!("{name}.private"));
        let pub_path = dir.join(format!("{name}.public"));
        if priv_path.exists() && pub_path.exists() {
            continue;
        }
        let sk = SigningKey::generate(&mut OsRng);
        let priv_b64 = B64.encode(sk.to_bytes());
        let pub_b64 = B64.encode(sk.verifying_key().as_bytes());
        std::fs::write(&priv_path, format!("{priv_b64}\n"))
            .with_context(|| format!("write {}", priv_path.display()))?;
        std::fs::write(&pub_path, format!("{pub_b64}\n"))
            .with_context(|| format!("write {}", pub_path.display()))?;
        tracing::info!(name, kind, "generated missing demo keypair");
    }
    Ok(())
}

/// Convenience: generate the canonical demo identity set.
pub fn ensure_canonical_keys(demo_path: &Path) -> anyhow::Result<()> {
    ensure_keys(demo_path, "system", &["demo-ranker", "demo-admin"])?;
    ensure_keys(
        demo_path,
        "account",
        &["techblog", "worldnews", "tutorials", "opinion", "videos"],
    )?;
    ensure_keys(
        demo_path,
        "user",
        &["alice", "bob", "carol", "dave", "eve", "frank", "grace"],
    )?;
    Ok(())
}
