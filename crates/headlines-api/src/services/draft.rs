//! `DraftServiceImpl` — gRPC handler for `headlines.v1.DraftService`.
//!
//! Authoritative spec: `docs/design/drafts.md`.
//!
//! Drafts are the publisher-side working space: mutable in place, hard
//! deleted, and converted to a live article via `PublishDraft` (preserving
//! the same UUID through the publish transition).
//!
//! Validation rules carry over from `articles.md` (this is the "strict on
//! every write" decision recorded in `drafts.md`); we reuse the article
//! validators directly via `crate::services::article` to keep the rules in
//! one place.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use headlines_core::HeadlinesError;
use headlines_core::Subject;
use headlines_core::repo::PageToken;
use headlines_core::repo::accounts::{AccountRepo, AccountStatus};
use headlines_core::repo::drafts::{
    Draft as DomainDraft, DraftRepo, DraftSummary as DomainDraftSummary, DraftUpdate, NewDraft,
};
use headlines_proto::v1::{
    CreateDraftRequest, DeleteDraftRequest, Draft as ProtoDraft, DraftSummary as ProtoDraftSummary,
    GetDraftRequest, ListAccountDraftsRequest, ListAccountDraftsResponse, PublishDraftRequest,
    UpdateDraftRequest, draft_service_server::DraftService,
};

use crate::services::article::{
    json_to_nodes, nodes_to_json, validate_and_encode_content, validate_author_name,
    validate_author_url, validate_title,
};

// ---------------------------------------------------------------------------
// Whitelisted update_mask paths for `UpdateDraft` — same set as the
// articles.md table for `EditArticle`.
// ---------------------------------------------------------------------------
const ALLOWED_MASK_PATHS: &[&str] = &["title", "author_name", "author_url", "content"];

// ---------------------------------------------------------------------------
// Concrete service
// ---------------------------------------------------------------------------

/// Concrete `DraftService` impl.
///
/// `content_max_bytes` is configurable so deployments (and tests) can lower
/// it without 20 MiB blobs.
pub struct DraftServiceImpl<A, D> {
    pub accounts: Arc<A>,
    pub drafts: Arc<D>,
    pub content_max_bytes: usize,
    pub metrics: Arc<crate::metrics::DomainMetrics>,
}

impl<A, D> DraftServiceImpl<A, D> {
    pub fn new(accounts: Arc<A>, drafts: Arc<D>, content_max_bytes: usize) -> Self {
        Self {
            accounts,
            drafts,
            content_max_bytes,
            metrics: crate::metrics::DomainMetrics::shared_no_op(),
        }
    }

    /// Override the default no-op `DomainMetrics`.
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::DomainMetrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_uuid(field: &str, raw: &str) -> Result<Uuid, HeadlinesError> {
    Uuid::parse_str(raw).map_err(|e| HeadlinesError::InvalidArgument {
        field: field.into(),
        reason: format!("invalid uuid: {e}"),
    })
}

fn ts_to_proto(t: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn current_subject<T>(req: &Request<T>) -> Subject {
    req.extensions()
        .get::<Subject>()
        .cloned()
        .unwrap_or(Subject::Anonymous)
}

fn draft_to_proto(d: DomainDraft) -> ProtoDraft {
    let content = json_to_nodes(&d.content);
    ProtoDraft {
        id: d.id.to_string(),
        account_id: d.account_id.to_string(),
        title: d.title,
        author_name: d.author_name,
        author_url: d.author_url,
        content,
        created_at: Some(ts_to_proto(d.created_at)),
        updated_at: Some(ts_to_proto(d.updated_at)),
    }
}

fn draft_summary_to_proto(s: DomainDraftSummary) -> ProtoDraftSummary {
    ProtoDraftSummary {
        id: s.id.to_string(),
        account_id: s.account_id.to_string(),
        title: s.title,
        created_at: Some(ts_to_proto(s.created_at)),
        updated_at: Some(ts_to_proto(s.updated_at)),
    }
}

/// Map a missing-account from `AccountRepo::get` into the domain error
/// variant the design doc wants. The repo already returns
/// `AccountNotFound` on miss, so this is a no-op pass-through.
fn account_lookup_err<E: Into<HeadlinesError>>(e: E) -> HeadlinesError {
    e.into()
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

#[async_trait]
impl<A, D> DraftService for DraftServiceImpl<A, D>
where
    A: AccountRepo + 'static,
    D: DraftRepo + 'static,
{
    async fn create_draft(
        &self,
        request: Request<CreateDraftRequest>,
    ) -> Result<Response<ProtoDraft>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        // Authorization: account self OR System with `drafts.write`. Same
        // shape as PublishArticle — the proto-level gate already requires
        // ACCOUNT_OWNS_RESOURCE or SYSTEM with the scope; we re-check here
        // so a wrong-account caller receives a clean denial.
        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(account_id)),
            Subject::System { .. } => subject.has_scope("drafts.write"),
            _ => false,
        };
        if !allowed {
            return Err(Status::permission_denied("not permitted on this account"));
        }

        // Strict validation per drafts.md (carries from articles.md).
        let title = validate_title(&req.title).map_err(Status::from)?;
        let author_name = validate_author_name(&req.author_name).map_err(Status::from)?;
        let author_url = validate_author_url(&req.author_url).map_err(Status::from)?;
        let content_json = validate_and_encode_content(&req.content, self.content_max_bytes)
            .map_err(Status::from)?;

        // Owning account precondition: ACCOUNT_NOT_FOUND on miss,
        // ACCOUNT_DELETED on tombstone.
        let acct = self
            .accounts
            .get(account_id)
            .await
            .map_err(account_lookup_err)
            .map_err(Status::from)?;
        if acct.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: account_id }.into());
        }

        let draft = self
            .drafts
            .create(NewDraft {
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
            .drafts_created
            .add(1, &crate::metrics::no_attrs());
        Ok(Response::new(draft_to_proto(draft)))
    }

    async fn get_draft(
        &self,
        request: Request<GetDraftRequest>,
    ) -> Result<Response<ProtoDraft>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        // Read the draft first so we can check ownership against the
        // owning account_id. Privacy: any failure to authorize as owner /
        // system surfaces as DRAFT_NOT_FOUND so we don't leak existence.
        let draft = self.drafts.get(id).await.map_err(Status::from)?;
        let owner = draft.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("drafts.read"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::DraftNotFound { id }.into());
        }

        Ok(Response::new(draft_to_proto(draft)))
    }

    async fn update_draft(
        &self,
        request: Request<UpdateDraftRequest>,
    ) -> Result<Response<ProtoDraft>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let draft_proto = req.draft.unwrap_or_default();
        let id = parse_uuid("draft.id", &draft_proto.id).map_err(Status::from)?;

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

        // Read the existing draft so we can authorize against its owner.
        let existing = self.drafts.get(id).await.map_err(Status::from)?;
        let owner = existing.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("drafts.write"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::DraftNotFound { id }.into());
        }

        // Build the repo-level update DTO. Validate every masked field
        // strictly per drafts.md (the resulting record must be a valid
        // article). Empty strings on author_* mask paths are valid (clear
        // the field).
        let mut update = DraftUpdate::default();
        if mask_set.contains("title") {
            update.title = Some(validate_title(&draft_proto.title).map_err(Status::from)?);
        }
        if mask_set.contains("author_name") {
            update.author_name =
                Some(validate_author_name(&draft_proto.author_name).map_err(Status::from)?);
        }
        if mask_set.contains("author_url") {
            update.author_url =
                Some(validate_author_url(&draft_proto.author_url).map_err(Status::from)?);
        }
        if mask_set.contains("content") {
            let json = validate_and_encode_content(&draft_proto.content, self.content_max_bytes)
                .map_err(Status::from)?;
            update.content = Some(json);
        }

        let updated = self.drafts.update(id, update).await.map_err(Status::from)?;
        Ok(Response::new(draft_to_proto(updated)))
    }

    async fn delete_draft(
        &self,
        request: Request<DeleteDraftRequest>,
    ) -> Result<Response<()>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        // Existence + ownership check first (so non-owner gets DRAFT_NOT_FOUND
        // even when the row exists).
        let existing = self.drafts.get(id).await.map_err(Status::from)?;
        let owner = existing.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("drafts.write"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::DraftNotFound { id }.into());
        }

        self.drafts.delete(id).await.map_err(Status::from)?;
        Ok(Response::new(()))
    }

    async fn list_account_drafts(
        &self,
        request: Request<ListAccountDraftsRequest>,
    ) -> Result<Response<ListAccountDraftsResponse>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let account_id = parse_uuid("account_id", &req.account_id).map_err(Status::from)?;

        // Authorization: account self OR System with `drafts.read`. No
        // anonymous reads — drafts are private working space.
        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(account_id)),
            Subject::System { .. } => subject.has_scope("drafts.read"),
            _ => false,
        };
        if !allowed {
            // Spec: unauthorized callers see the same NOT_FOUND-shaped
            // error to avoid existence leaks. Use an empty list response is
            // misleading (the caller could distinguish "no drafts" from
            // "denied"); we surface a clean PERMISSION_DENIED here, which
            // matches the AUTH_TABLE's existing PERMISSION_DENIED behavior
            // for ACCOUNT_OWNS_RESOURCE mismatches.
            return Err(Status::permission_denied("not permitted on this account"));
        }

        let page = self
            .drafts
            .list_by_account(account_id, req.page_size, PageToken(req.page_token))
            .await
            .map_err(Status::from)?;

        let items = page.items.into_iter().map(draft_summary_to_proto).collect();
        Ok(Response::new(ListAccountDraftsResponse {
            items,
            next_page_token: page.next_page_token.0,
        }))
    }

    async fn publish_draft(
        &self,
        request: Request<PublishDraftRequest>,
    ) -> Result<Response<headlines_proto::v1::Article>, Status> {
        let subject = current_subject(&request);
        let req = request.into_inner();
        let id = parse_uuid("id", &req.id).map_err(Status::from)?;

        // Read the draft so we can authorize and re-verify the account
        // status before the publish tx.
        let draft = self.drafts.get(id).await.map_err(Status::from)?;
        let owner = draft.account_id;

        let allowed = match &subject {
            Subject::Account { .. } => subject.is_self_for(None, Some(owner)),
            Subject::System { .. } => subject.has_scope("articles.write"),
            _ => false,
        };
        if !allowed {
            return Err(HeadlinesError::DraftNotFound { id }.into());
        }

        // Re-verify the owning account is active. The publish tx itself
        // takes the FOR UPDATE lock on the draft and serializes concurrent
        // publishes; the loser will see DraftNotFound.
        let acct = self
            .accounts
            .get(owner)
            .await
            .map_err(account_lookup_err)
            .map_err(Status::from)?;
        if acct.status == AccountStatus::Deleted {
            return Err(HeadlinesError::AccountDeleted { id: owner }.into());
        }

        // Re-validate the strict article rules cheaply. The draft was
        // already validated on every write, so this is mostly a guard rail
        // for content_max_bytes drift between create-time and publish-time.
        let _ = validate_title(&draft.title).map_err(Status::from)?;
        let _ = validate_author_name(&draft.author_name).map_err(Status::from)?;
        let _ = validate_author_url(&draft.author_url).map_err(Status::from)?;
        let nodes = json_to_nodes(&draft.content);
        let _ =
            validate_and_encode_content(&nodes, self.content_max_bytes).map_err(Status::from)?;
        // `nodes_to_json` round-trip is unused here; the field exists in
        // the import set so the explicit `use` doesn't go unused. Keep the
        // call site for future re-encode use.
        let _ = nodes_to_json;

        let article = self.drafts.publish(id).await.map_err(Status::from)?;

        // Publishing a draft is the same domain success as PublishArticle;
        // increment the same counter so dashboards can sum across both
        // entrypoints.
        self.metrics
            .articles_published
            .add(1, &crate::metrics::no_attrs());

        // Map domain Article back to proto Article. Reuse the converter
        // from the article service module via a small local helper that
        // mirrors `services::article::article_to_proto`.
        Ok(Response::new(article_to_proto(article)))
    }
}

// ---------------------------------------------------------------------------
// Domain Article → proto. Mirrors `services::article::article_to_proto`.
// We duplicate the small mapper here rather than make `article_to_proto`
// `pub(crate)` to keep the article module's public surface unchanged.
// ---------------------------------------------------------------------------

fn article_to_proto(a: headlines_core::repo::articles::Article) -> headlines_proto::v1::Article {
    use headlines_core::repo::articles::ArticleState as DomainState;
    use headlines_proto::v1::{
        Article as ProtoArticle, ArticleLive as ProtoArticleLive,
        ArticleState as ProtoArticleState, ArticleTombstone as ProtoArticleTombstone,
        article::StateData as ProtoArticleStateData,
    };

    let summary = a.summary;
    let state = match summary.state {
        DomainState::Live => ProtoArticleState::Live,
        DomainState::Tombstone => ProtoArticleState::Tombstone,
    } as i32;
    let state_data = match summary.state {
        DomainState::Live => Some(ProtoArticleStateData::Live(ProtoArticleLive {
            current_version: summary.current_version.unwrap_or(0),
            title: summary.title.clone().unwrap_or_default(),
            author_name: summary.author_name.clone().unwrap_or_default(),
            author_url: summary.author_url.clone().unwrap_or_default(),
            content: a.content.as_ref().map(json_to_nodes).unwrap_or_default(),
            redacted: summary.redacted,
            published_at: summary.published_at.map(ts_to_proto),
            updated_at: summary.updated_at.map(ts_to_proto),
        })),
        DomainState::Tombstone => Some(ProtoArticleStateData::Tombstone(ProtoArticleTombstone {
            reason: summary.tombstone_reason.clone().unwrap_or_default(),
            tombstoned_at: summary.tombstoned_at.map(ts_to_proto),
        })),
    };
    ProtoArticle {
        id: summary.id.to_string(),
        account_id: summary.account_id.to_string(),
        state,
        created_at: Some(ts_to_proto(summary.created_at)),
        state_data,
    }
}
