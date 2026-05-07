//! `ArticleServiceImpl` — gRPC handler for `headlines.v1.ArticleService`.
//!
//! Authoritative spec: `docs/design/articles.md`.
//!
//! The handler validates input (per the spec's "Validation" table), enforces
//! per-RPC authorization (account self vs. system scope), and rejects
//! transitions on tombstoned articles. State-machine bookkeeping
//! (versioning, articles_live <-> articles_tombstone, watermark bump on
//! current-version redaction) lives entirely in `PgArticleRepo`.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use serde_json::{Map, Value as Json};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::accounts::{AccountRepo, AccountStatus};
use headlines_core::repo::articles::{
    Article as DomainArticle, ArticleEdit as DomainArticleEdit, ArticleRepo,
    ArticleState as DomainArticleState, ArticleSummary as DomainArticleSummary, NewArticle,
};
use headlines_proto::v1::{
    Article as ProtoArticle, ArticleEdit as ProtoArticleEdit, ArticleLive as ProtoArticleLive,
    ArticleLiveSummary as ProtoArticleLiveSummary, ArticleState as ProtoArticleState,
    ArticleSummary as ProtoArticleSummary, ArticleTombstone as ProtoArticleTombstone,
    ArticleTombstoneSummary as ProtoArticleTombstoneSummary, EditArticleRequest, GetArticleRequest,
    ListAccountArticlesRequest, ListAccountArticlesResponse, Node as ProtoNode,
    NodeElement as ProtoNodeElement, PublishArticleRequest, RedactArticleVersionRequest,
    TombstoneArticleRequest, article::StateData as ProtoArticleStateData,
    article_service_server::ArticleService, article_summary::StateData as ProtoSummaryStateData,
    node::Kind as ProtoNodeKind,
};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

const TITLE_MIN: usize = 1;
const TITLE_MAX: usize = 256;
const AUTHOR_NAME_MAX: usize = 128;
const AUTHOR_URL_MAX: usize = 512;
const TOMBSTONE_REASON_MAX: usize = 512;
const REDACTION_REASON_MIN: usize = 1;
const REDACTION_REASON_MAX: usize = 512;

/// Default `articles.content_max_bytes` (20 MiB) per `articles.md`.
pub const DEFAULT_CONTENT_MAX_BYTES: usize = 20 * 1024 * 1024;

/// Allow-list of HTML-ish tags accepted in `Node.element.tag`.
const ALLOWED_TAGS: &[&str] = &[
    "p",
    "h3",
    "h4",
    "a",
    "img",
    "figure",
    "figcaption",
    "blockquote",
    "aside",
    "pre",
    "code",
    "em",
    "strong",
    "s",
    "u",
    "iframe",
    "video",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
];

/// Per-tag allow-list of attribute names. Tags not listed here may carry
/// **no** attributes; tags listed here may carry only the attributes named.
fn allowed_attrs_for(tag: &str) -> Option<&'static [&'static str]> {
    match tag {
        "a" => Some(&["href"]),
        "img" => Some(&["src", "alt"]),
        "iframe" => Some(&["src"]),
        "video" => Some(&["src"]),
        _ => Some(&[]),
    }
}

/// Whitelisted `update_mask` paths for `EditArticle`.
const ALLOWED_MASK_PATHS: &[&str] = &["title", "author_name", "author_url", "content"];

// ---------------------------------------------------------------------------
// Concrete service
// ---------------------------------------------------------------------------

/// Concrete `ArticleService` impl.
///
/// `content_max_bytes` is configurable so deployments (and tests) can lower
/// it without 20 MiB blobs. `metrics` defaults to a no-op `DomainMetrics`;
/// the binary calls `with_metrics(...)` to wire the real meter.
pub struct ArticleServiceImpl<A, R> {
    pub accounts: Arc<A>,
    pub articles: Arc<R>,
    pub content_max_bytes: usize,
    pub metrics: std::sync::Arc<crate::metrics::DomainMetrics>,
}

impl<A, R> ArticleServiceImpl<A, R> {
    pub fn new(accounts: Arc<A>, articles: Arc<R>, content_max_bytes: usize) -> Self {
        Self {
            accounts,
            articles,
            content_max_bytes,
            metrics: crate::metrics::DomainMetrics::shared_no_op(),
        }
    }

    /// Override the default no-op `DomainMetrics`. Builder-style so the
    /// binary can wire the real meter in one line.
    pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::DomainMetrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn parse_uuid(field: &str, raw: &str) -> Result<Uuid, HeadlinesError> {
    Uuid::parse_str(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: field.into(),
        reason: format!("invalid uuid: {e}"),
    })
}

pub(crate) fn validate_title(raw: &str) -> Result<String, HeadlinesError> {
    let trimmed = raw.trim().to_owned();
    let char_count = trimmed.chars().count();
    if !(TITLE_MIN..=TITLE_MAX).contains(&char_count) {
        return Err(HeadlinesError::InvalidArgument {
            field: "title".into(),
            reason: format!("length must be {TITLE_MIN}..={TITLE_MAX} characters"),
        });
    }
    Ok(trimmed)
}

pub(crate) fn validate_author_name(raw: &str) -> Result<String, HeadlinesError> {
    if raw.chars().count() > AUTHOR_NAME_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_name".into(),
            reason: format!("length must be <= {AUTHOR_NAME_MAX} characters"),
        });
    }
    Ok(raw.to_owned())
}

pub(crate) fn validate_author_url(raw: &str) -> Result<String, HeadlinesError> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.len() > AUTHOR_URL_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_url".into(),
            reason: format!("length must be <= {AUTHOR_URL_MAX}"),
        });
    }
    let parsed = url::Url::parse(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: "author_url".into(),
        reason: format!("invalid URL: {e}"),
    })?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(HeadlinesError::InvalidArgument {
            field: "author_url".into(),
            reason: "scheme must be http or https".into(),
        });
    }
    Ok(raw.to_owned())
}

fn validate_tombstone_reason(raw: &str) -> Result<Option<String>, HeadlinesError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > TOMBSTONE_REASON_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "reason".into(),
            reason: format!("length must be <= {TOMBSTONE_REASON_MAX}"),
        });
    }
    Ok(Some(raw.to_owned()))
}

fn validate_redaction_reason(raw: &str) -> Result<String, HeadlinesError> {
    if raw.len() < REDACTION_REASON_MIN || raw.len() > REDACTION_REASON_MAX {
        return Err(HeadlinesError::InvalidArgument {
            field: "redaction_reason".into(),
            reason: format!("length must be {REDACTION_REASON_MIN}..={REDACTION_REASON_MAX}"),
        });
    }
    Ok(raw.to_owned())
}

/// Validate every `Node` in `content` recursively against the tag/attr
/// allow-lists. Returns the JSON encoding ready for the repo (jsonb).
pub(crate) fn validate_and_encode_content(
    content: &[ProtoNode],
    max_bytes: usize,
) -> Result<Json, HeadlinesError> {
    if content.is_empty() {
        return Err(HeadlinesError::InvalidArgument {
            field: "content".into(),
            reason: "must be non-empty".into(),
        });
    }
    for n in content {
        validate_node(n)?;
    }
    let json = nodes_to_json(content);
    let serialized = serde_json::to_vec(&json)
        .map_err(|e| HeadlinesError::Internal(anyhow::anyhow!("serialize content as json: {e}")))?;
    if serialized.len() > max_bytes {
        return Err(HeadlinesError::ContentTooLarge {
            actual: serialized.len(),
            max: max_bytes,
        });
    }
    Ok(json)
}

fn validate_node(node: &ProtoNode) -> Result<(), HeadlinesError> {
    match node.kind.as_ref() {
        Some(ProtoNodeKind::Text(_)) | None => Ok(()),
        Some(ProtoNodeKind::Element(el)) => validate_element(el),
    }
}

fn validate_element(el: &ProtoNodeElement) -> Result<(), HeadlinesError> {
    if !ALLOWED_TAGS.contains(&el.tag.as_str()) {
        return Err(HeadlinesError::InvalidNodeTag {
            tag: el.tag.clone(),
        });
    }
    let allowed = allowed_attrs_for(&el.tag).unwrap_or(&[]);
    for k in el.attrs.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(HeadlinesError::InvalidNodeAttr {
                tag: el.tag.clone(),
                attr: k.clone(),
            });
        }
    }
    for child in &el.children {
        validate_node(child)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Node ↔ JSON conversion (recursive). Stable shape used for jsonb storage.
// ---------------------------------------------------------------------------

pub(crate) fn nodes_to_json(nodes: &[ProtoNode]) -> Json {
    Json::Array(nodes.iter().map(node_to_json).collect())
}

pub(crate) fn node_to_json(node: &ProtoNode) -> Json {
    match node.kind.as_ref() {
        None => Json::Null,
        Some(ProtoNodeKind::Text(t)) => {
            let mut obj = Map::new();
            obj.insert("text".into(), Json::String(t.clone()));
            Json::Object(obj)
        }
        Some(ProtoNodeKind::Element(el)) => {
            let mut obj = Map::new();
            obj.insert("tag".into(), Json::String(el.tag.clone()));
            if !el.attrs.is_empty() {
                let mut attrs = Map::new();
                // Stable order so storage round-trips deterministically.
                let mut keys: Vec<&String> = el.attrs.keys().collect();
                keys.sort();
                for k in keys {
                    if let Some(v) = el.attrs.get(k) {
                        attrs.insert(k.clone(), Json::String(v.clone()));
                    }
                }
                obj.insert("attrs".into(), Json::Object(attrs));
            }
            if !el.children.is_empty() {
                obj.insert("children".into(), nodes_to_json(&el.children));
            }
            Json::Object(obj)
        }
    }
}

pub(crate) fn json_to_nodes(value: &Json) -> Vec<ProtoNode> {
    match value {
        Json::Array(arr) => arr.iter().map(json_to_node).collect(),
        _ => Vec::new(),
    }
}

fn json_to_node(value: &Json) -> ProtoNode {
    let Json::Object(obj) = value else {
        return ProtoNode::default();
    };
    if let Some(Json::String(t)) = obj.get("text") {
        return ProtoNode {
            kind: Some(ProtoNodeKind::Text(t.clone())),
        };
    }
    let tag = obj
        .get("tag")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    let attrs = obj
        .get("attrs")
        .and_then(Json::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let children = obj.get("children").map(json_to_nodes).unwrap_or_default();
    ProtoNode {
        kind: Some(ProtoNodeKind::Element(ProtoNodeElement {
            tag,
            attrs,
            children,
        })),
    }
}

// ---------------------------------------------------------------------------
// Domain ↔ proto mapping
// ---------------------------------------------------------------------------

fn ts_to_proto(t: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn article_to_proto(a: DomainArticle) -> ProtoArticle {
    let summary = a.summary;
    let state = match summary.state {
        DomainArticleState::Live => ProtoArticleState::Live,
        DomainArticleState::Tombstone => ProtoArticleState::Tombstone,
    } as i32;
    let state_data = match summary.state {
        DomainArticleState::Live => Some(ProtoArticleStateData::Live(ProtoArticleLive {
            current_version: summary.current_version.unwrap_or(0),
            title: summary.title.clone().unwrap_or_default(),
            author_name: summary.author_name.clone().unwrap_or_default(),
            author_url: summary.author_url.clone().unwrap_or_default(),
            content: a.content.as_ref().map(json_to_nodes).unwrap_or_default(),
            redacted: summary.redacted,
            published_at: summary.published_at.map(ts_to_proto),
            updated_at: summary.updated_at.map(ts_to_proto),
        })),
        DomainArticleState::Tombstone => {
            Some(ProtoArticleStateData::Tombstone(ProtoArticleTombstone {
                reason: summary.tombstone_reason.clone().unwrap_or_default(),
                tombstoned_at: summary.tombstoned_at.map(ts_to_proto),
            }))
        }
    };
    ProtoArticle {
        id: summary.id.to_string(),
        account_id: summary.account_id.to_string(),
        state,
        created_at: Some(ts_to_proto(summary.created_at)),
        state_data,
    }
}

fn article_summary_to_proto(s: DomainArticleSummary) -> ProtoArticleSummary {
    let state = match s.state {
        DomainArticleState::Live => ProtoArticleState::Live,
        DomainArticleState::Tombstone => ProtoArticleState::Tombstone,
    } as i32;
    let state_data = match s.state {
        DomainArticleState::Live => Some(ProtoSummaryStateData::Live(ProtoArticleLiveSummary {
            current_version: s.current_version.unwrap_or(0),
            title: s.title.clone().unwrap_or_default(),
            author_name: s.author_name.clone().unwrap_or_default(),
            author_url: s.author_url.clone().unwrap_or_default(),
            redacted: s.redacted,
            published_at: s.published_at.map(ts_to_proto),
            updated_at: s.updated_at.map(ts_to_proto),
        })),
        DomainArticleState::Tombstone => Some(ProtoSummaryStateData::Tombstone(
            ProtoArticleTombstoneSummary {
                reason: s.tombstone_reason.clone().unwrap_or_default(),
                tombstoned_at: s.tombstoned_at.map(ts_to_proto),
            },
        )),
    };
    ProtoArticleSummary {
        id: s.id.to_string(),
        account_id: s.account_id.to_string(),
        state,
        created_at: Some(ts_to_proto(s.created_at)),
        state_data,
    }
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<A, R> ArticleService for ArticleServiceImpl<A, R>
where
    A: AccountRepo + 'static,
    R: ArticleRepo + 'static,
{
    async fn publish_article(
        &self,
        request: Request<PublishArticleRequest>,
    ) -> Result<Response<ProtoArticle>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        // Authorization: account self OR System with `articles.write`. The
        // proto-level gate already requires AccountOwnsResource (= Account
        // self for this RPC) or System; we recheck self-ness here so a
        // wrong-account caller receives a clean denial.
        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(account_id)),
            Subject::System { .. } => subject.has_scope("articles.write"),
            _ => false,
        };
        if !allowed {
            return Err(Status::permission_denied("not permitted on this account"));
        }

        let title = validate_title(&req.title).map_err(Status::from)?;
        let author_name = validate_author_name(&req.author_name).map_err(Status::from)?;
        let author_url = validate_author_url(&req.author_url).map_err(Status::from)?;
        let content_json = validate_and_encode_content(&req.content, self.content_max_bytes)
            .map_err(Status::from)?;

        // Account-state precondition: missing → ACCOUNT_NOT_FOUND, deleted →
        // ACCOUNT_DELETED. The repo's `get` already maps missing → NOT_FOUND.
        let acct = self.accounts.get(account_id).await.map_err(Status::from)?;
        if acct.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
        }

        let article = self
            .articles
            .publish(NewArticle {
                id: Uuid::now_v7(),
                account_id,
                title,
                author_name,
                author_url,
                content: content_json,
            })
            .await
            .map_err(Status::from)?;

        self.metrics
            .articles_published
            .add(1, &crate::metrics::no_attrs());
        Ok(Response::new(article_to_proto(article)))
    }

    async fn get_article(
        &self,
        request: Request<GetArticleRequest>,
    ) -> Result<Response<ProtoArticle>, Status> {
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;
        let article = self.articles.get(id).await.map_err(Status::from)?;
        Ok(Response::new(article_to_proto(article)))
    }

    async fn list_account_articles(
        &self,
        request: Request<ListAccountArticlesRequest>,
    ) -> Result<Response<ListAccountArticlesResponse>, Status> {
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        let page = self
            .articles
            .list_by_account(
                account_id,
                req.include_tombstoned,
                req.page_size,
                PageToken(req.page_token),
            )
            .await
            .map_err(Status::from)?;

        let items = page
            .items
            .into_iter()
            .map(article_summary_to_proto)
            .collect();
        Ok(Response::new(ListAccountArticlesResponse {
            items,
            next_page_token: page.next_page_token.0,
        }))
    }

    async fn edit_article(
        &self,
        request: Request<EditArticleRequest>,
    ) -> Result<Response<ProtoArticle>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;
        let edit_proto: ProtoArticleEdit = req.edit.unwrap_or_default();

        let mask = req
            .update_mask
            .ok_or_else(|| Status::from(HeadlinesError::EmptyUpdateMask))?;
        if mask.paths.is_empty() {
            return Err(HeadlinesError::EmptyUpdateMask.into());
        }
        let mask_set: HashSet<&str> = mask.paths.iter().map(String::as_str).collect();
        for p in &mask.paths {
            if !ALLOWED_MASK_PATHS.contains(&p.as_str()) {
                return Err(HeadlinesError::UnallowedMaskPath { path: p.to_owned() }.into());
            }
        }

        // Pre-fetch the article so we can authorize the caller against its
        // owning account_id. ARTICLE_NOT_FOUND on missing.
        let existing = self.articles.get(id).await.map_err(Status::from)?;
        if existing.summary.state == DomainArticleState::Tombstone {
            return Err(HeadlinesError::ArticleTombstoned { id }.into());
        }
        let owner = existing.summary.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("articles.write"),
            _ => false,
        };
        if !allowed {
            return Err(Status::permission_denied("not permitted on this article"));
        }

        // Build the repo-level edit DTO from the masked fields.
        let mut edit = DomainArticleEdit::default();
        if mask_set.contains("title") {
            edit.title = Some(validate_title(&edit_proto.title).map_err(Status::from)?);
        }
        if mask_set.contains("author_name") {
            edit.author_name =
                Some(validate_author_name(&edit_proto.author_name).map_err(Status::from)?);
        }
        if mask_set.contains("author_url") {
            edit.author_url =
                Some(validate_author_url(&edit_proto.author_url).map_err(Status::from)?);
        }
        if mask_set.contains("content") {
            let json = validate_and_encode_content(&edit_proto.content, self.content_max_bytes)
                .map_err(Status::from)?;
            edit.content = Some(json);
        }

        let updated = self.articles.edit(id, edit).await.map_err(Status::from)?;
        Ok(Response::new(article_to_proto(updated)))
    }

    async fn tombstone_article(
        &self,
        request: Request<TombstoneArticleRequest>,
    ) -> Result<Response<ProtoArticle>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;
        let reason = validate_tombstone_reason(&req.reason).map_err(Status::from)?;

        let existing = self.articles.get(id).await.map_err(Status::from)?;
        if existing.summary.state == DomainArticleState::Tombstone {
            return Err(HeadlinesError::ArticleTombstoned { id }.into());
        }
        let owner = existing.summary.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("articles.tombstone"),
            _ => false,
        };
        if !allowed {
            return Err(Status::permission_denied("not permitted on this article"));
        }

        let tombstoned = self
            .articles
            .tombstone(id, reason)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(article_to_proto(tombstoned)))
    }

    async fn redact_article_version(
        &self,
        request: Request<RedactArticleVersionRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let article_id = parse_uuid("article_id", &req.article_id).map_err(Status::from)?;
        let version = req.version;
        if version <= 0 {
            return Err(HeadlinesError::InvalidArgument {
                field: "version".into(),
                reason: "must be > 0".into(),
            }
            .into());
        }
        let reason = validate_redaction_reason(&req.redaction_reason).map_err(Status::from)?;

        // Authorization is already enforced by `AUTH_TABLE` (System +
        // articles.redact); no further account-scoped check needed.

        self.articles
            .redact_version(article_id, version, reason)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_title_rejects_empty_after_trim() {
        // Arrange / Act
        let res = validate_title("   ");

        // Assert
        assert!(matches!(
            res,
            Err(HeadlinesError::InvalidArgument { ref field, .. }) if field == "title"
        ));
    }

    #[test]
    fn validate_title_rejects_overlength() {
        // Arrange
        let s = "a".repeat(257);

        // Act
        let res = validate_title(&s);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidArgument { .. })));
    }

    #[test]
    fn validate_author_url_rejects_non_http_scheme() {
        // Arrange / Act
        let res = validate_author_url("ftp://example.com");

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidArgument { .. })));
    }

    #[test]
    fn validate_title_counts_chars_not_bytes() {
        // Arrange — 256 fox emoji = 256 chars but ~1024 bytes; must be allowed
        // because `title` is a human-display field measured in chars.
        let s: String = "🦊".repeat(256);

        // Act
        let res = validate_title(&s);

        // Assert
        assert_eq!(res.unwrap().chars().count(), 256);
    }

    #[test]
    fn validate_author_name_counts_chars_not_bytes() {
        // Arrange — 128 fox emoji = 128 chars but ~512 bytes; must be allowed
        // because `author_name` is a human-display field measured in chars.
        let s: String = "🦊".repeat(128);

        // Act
        let res = validate_author_name(&s);

        // Assert
        assert_eq!(res.unwrap().chars().count(), 128);
    }

    #[test]
    fn validate_node_rejects_unknown_tag() {
        // Arrange
        let n = ProtoNode {
            kind: Some(ProtoNodeKind::Element(ProtoNodeElement {
                tag: "marquee".into(),
                attrs: Default::default(),
                children: vec![],
            })),
        };

        // Act
        let res = validate_node(&n);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidNodeTag { .. })));
    }

    #[test]
    fn validate_node_rejects_unallowed_attr() {
        // Arrange — `<a onclick="...">`.
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("onclick".to_owned(), "x".to_owned());
        let n = ProtoNode {
            kind: Some(ProtoNodeKind::Element(ProtoNodeElement {
                tag: "a".into(),
                attrs,
                children: vec![],
            })),
        };

        // Act
        let res = validate_node(&n);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::InvalidNodeAttr { .. })));
    }

    #[test]
    fn nodes_round_trip_through_json() {
        // Arrange — `<p>hello <strong>world</strong></p>`.
        let strong = ProtoNode {
            kind: Some(ProtoNodeKind::Element(ProtoNodeElement {
                tag: "strong".into(),
                attrs: Default::default(),
                children: vec![ProtoNode {
                    kind: Some(ProtoNodeKind::Text("world".into())),
                }],
            })),
        };
        let p = ProtoNode {
            kind: Some(ProtoNodeKind::Element(ProtoNodeElement {
                tag: "p".into(),
                attrs: Default::default(),
                children: vec![
                    ProtoNode {
                        kind: Some(ProtoNodeKind::Text("hello ".into())),
                    },
                    strong,
                ],
            })),
        };
        let nodes = vec![p];

        // Act
        let json = nodes_to_json(&nodes);
        let back = json_to_nodes(&json);

        // Assert
        assert_eq!(back.len(), 1);
        let Some(ProtoNodeKind::Element(p_back)) = back[0].kind.as_ref() else {
            panic!("expected element");
        };
        assert_eq!(p_back.tag, "p");
        assert_eq!(p_back.children.len(), 2);
    }

    #[test]
    fn validate_and_encode_content_rejects_oversize() {
        // Arrange — one giant text node (~1 KiB cap, payload ~3 KiB).
        let big = ProtoNode {
            kind: Some(ProtoNodeKind::Text("x".repeat(3000))),
        };

        // Act
        let res = validate_and_encode_content(&[big], 1024);

        // Assert
        assert!(matches!(res, Err(HeadlinesError::ContentTooLarge { .. })));
    }
}
