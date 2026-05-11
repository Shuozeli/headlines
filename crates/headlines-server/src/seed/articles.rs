//! Walk `<demo_path>/articles/<account>/*.md` and yield parsed articles in
//! filename order, plus the same for `<demo_path>/drafts/...`.

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::frontmatter::{Article, parse_article};

#[derive(Debug, Clone)]
pub struct LoadedArticle {
    /// Owning account short-name. Kept for diagnostics / logging even when
    /// the runner reaches it via the surrounding loop variable.
    #[allow(dead_code)]
    pub account: String,
    pub filename: String,
    pub article: Article,
}

pub fn load_account_articles(
    demo_path: &Path,
    account: &str,
    subdir: &str,
) -> anyhow::Result<Vec<LoadedArticle>> {
    let dir: PathBuf = demo_path.join(subdir).join(account);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|s| s == "md").unwrap_or(false))
        .collect();
    paths.sort();
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let article = parse_article(&raw);
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_owned();
        out.push(LoadedArticle {
            account: account.to_owned(),
            filename,
            article,
        });
    }
    Ok(out)
}
