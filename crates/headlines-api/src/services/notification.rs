//! `NotificationServiceImpl` — gRPC handler for
//! `headlines.v1.NotificationService`.
//!
//! Authoritative spec: `docs/design/notifications.md`.
//!
//! Phase 7.9 reserves the proto + URLs + AUTH_TABLE entries; every RPC returns
//! `UNIMPLEMENTED` with `ErrorInfo.reason = "NOT_IMPLEMENTED_IN_V1"` per the
//! spec § "v1 behavior". A future "delivery" doc / phase will pick this up.
//!
//! The proto-driven `AUTH_TABLE` enforces the **subject class** + **system
//! scope** gate before this handler runs:
//!   - `SendNotification`:                 `[SYSTEM]` + `notifications.send`.
//!   - `SendNotificationBatch`:            `[SYSTEM]` + `notifications.send`.
//!   - `ListUserNotifications`:            `[USER_SELF, SYSTEM]` + `notifications.read`.
//!   - `MarkNotificationRead`:             `[USER_SELF]` (no scopes).
//!   - `MarkAllUserNotificationsRead`:     `[USER_SELF, SYSTEM]` + `notifications.admin`.
//!   - `GetUserNotificationPreferences`:   `[USER_SELF, SYSTEM]` + `notifications.read`.
//!   - `UpdateUserNotificationPreferences`:`[USER_SELF, SYSTEM]` + `notifications.admin`.
//!
//! Because the AUTH_TABLE gate runs first, a misconfigured caller (e.g.
//! anonymous) is rejected with `PERMISSION_DENIED` before the handler runs;
//! a correctly-authenticated caller falls through to the handler and sees
//! `UNIMPLEMENTED`.

use async_trait::async_trait;
use tonic::{Request, Response, Status};

use headlines_core::HeadlinesError;
use headlines_proto::v1::{
    GetUserNotificationPreferencesRequest, ListUserNotificationsRequest,
    ListUserNotificationsResponse, MarkAllUserNotificationsReadRequest,
    MarkAllUserNotificationsReadResponse, MarkNotificationReadRequest, Notification,
    NotificationPreferences, SendNotificationBatchRequest, SendNotificationBatchResponse,
    SendNotificationRequest, UpdateUserNotificationPreferencesRequest,
    notification_service_server::NotificationService,
};

/// Concrete `NotificationService` impl.
///
/// Holds nothing — every RPC returns `NOT_IMPLEMENTED_IN_V1`. No repo, no
/// time source, no idempotency cache. When implementation begins, this struct
/// will gain `Arc<dyn NotificationRepo>`, `Arc<dyn IdempotencyStore>`, and
/// (likely) channel adapters per `notifications.md` § Storage / delivery.
#[derive(Default)]
pub struct NotificationServiceImpl;

impl NotificationServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

fn unimpl(rpc: &'static str) -> Status {
    HeadlinesError::NotImplementedInV1 {
        rpc: rpc.to_owned(),
    }
    .into()
}

#[async_trait]
impl NotificationService for NotificationServiceImpl {
    async fn send_notification(
        &self,
        _request: Request<SendNotificationRequest>,
    ) -> Result<Response<Notification>, Status> {
        Err(unimpl("NotificationService/SendNotification"))
    }

    async fn send_notification_batch(
        &self,
        _request: Request<SendNotificationBatchRequest>,
    ) -> Result<Response<SendNotificationBatchResponse>, Status> {
        Err(unimpl("NotificationService/SendNotificationBatch"))
    }

    async fn list_user_notifications(
        &self,
        _request: Request<ListUserNotificationsRequest>,
    ) -> Result<Response<ListUserNotificationsResponse>, Status> {
        Err(unimpl("NotificationService/ListUserNotifications"))
    }

    async fn mark_notification_read(
        &self,
        _request: Request<MarkNotificationReadRequest>,
    ) -> Result<Response<Notification>, Status> {
        Err(unimpl("NotificationService/MarkNotificationRead"))
    }

    async fn mark_all_user_notifications_read(
        &self,
        _request: Request<MarkAllUserNotificationsReadRequest>,
    ) -> Result<Response<MarkAllUserNotificationsReadResponse>, Status> {
        Err(unimpl("NotificationService/MarkAllUserNotificationsRead"))
    }

    async fn get_user_notification_preferences(
        &self,
        _request: Request<GetUserNotificationPreferencesRequest>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(unimpl("NotificationService/GetUserNotificationPreferences"))
    }

    async fn update_user_notification_preferences(
        &self,
        _request: Request<UpdateUserNotificationPreferencesRequest>,
    ) -> Result<Response<NotificationPreferences>, Status> {
        Err(unimpl(
            "NotificationService/UpdateUserNotificationPreferences",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — extract the `(code, reason)` from the `Status` produced by
    /// `unimpl(rpc)` to keep each per-method test small.
    fn unwrap_unimpl_status(s: Status) -> (tonic::Code, String) {
        // Decoding `ErrorInfo.reason` lives in `HeadlinesError`'s tests; here
        // we only assert `Status.code()` and that the message names the rpc.
        (s.code(), s.message().to_owned())
    }

    #[test]
    fn unimpl_helper_emits_unimplemented_with_rpc_in_message() {
        // Arrange / Act
        let s = unimpl("NotificationService/SendNotification");

        // Assert
        let (code, msg) = unwrap_unimpl_status(s);
        assert_eq!(code, tonic::Code::Unimplemented);
        assert!(msg.contains("NotificationService/SendNotification"));
    }

    #[tokio::test]
    async fn send_notification_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(SendNotificationRequest::default());

        // Act
        let res = svc.send_notification(req).await;

        // Assert
        let err = res.expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn send_notification_batch_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(SendNotificationBatchRequest::default());

        // Act
        let res = svc.send_notification_batch(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn list_user_notifications_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(ListUserNotificationsRequest::default());

        // Act
        let res = svc.list_user_notifications(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn mark_notification_read_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(MarkNotificationReadRequest::default());

        // Act
        let res = svc.mark_notification_read(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn mark_all_user_notifications_read_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(MarkAllUserNotificationsReadRequest::default());

        // Act
        let res = svc.mark_all_user_notifications_read(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn get_user_notification_preferences_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(GetUserNotificationPreferencesRequest::default());

        // Act
        let res = svc.get_user_notification_preferences(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn update_user_notification_preferences_returns_unimplemented() {
        // Arrange
        let svc = NotificationServiceImpl::new();
        let req = Request::new(UpdateUserNotificationPreferencesRequest::default());

        // Act
        let res = svc.update_user_notification_preferences(req).await;

        // Assert
        assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    }
}
