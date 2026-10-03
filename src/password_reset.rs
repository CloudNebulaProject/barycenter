//! Operator-issued recovery for an existing, enabled account, proving its stored email by token possession.
use crate::{
    entities::{access_token, auth_code, password_reset as reset, refresh_token, session, user},
    onboarding::{authorize, AcceptRequest, AdminState},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{delete, get, post},
    Json, Router,
};
use sea_orm::{
    sea_query::{Expr, OnConflict},
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
type ApiError = (StatusCode, &'static str);
fn internal(_: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed")
}
fn invalid() -> ApiError {
    (StatusCode::BAD_REQUEST, "Invalid or expired reset")
}
fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[derive(Deserialize)]
pub struct IssueRequest {
    pub username: String,
    pub expires_in: Option<i64>,
}
#[derive(Serialize, Deserialize)]
pub struct IssuedReset {
    pub username: String,
    pub email: String,
    pub expires_at: i64,
    pub reset_url: String,
}
pub async fn issue(
    db: &DatabaseConnection,
    base: &str,
    req: IssueRequest,
) -> Result<IssuedReset, ApiError> {
    let ttl = req.expires_in.unwrap_or(3600);
    if !(300..=86400).contains(&ttl) {
        return Err((StatusCode::BAD_REQUEST, "Invalid lifetime"));
    }
    let u = user::Entity::find()
        .filter(user::Column::Username.eq(&req.username))
        .filter(user::Column::Enabled.eq(1))
        .one(db)
        .await
        .map_err(internal)?
        .ok_or((
            StatusCode::CONFLICT,
            "Account is not eligible for email recovery",
        ))?;
    let email = u
        .email
        .filter(|e| {
            !e.chars().any(char::is_whitespace)
                && e.matches('@').count() == 1
                && !e.starts_with('@')
                && !e.ends_with('@')
        })
        .ok_or((
            StatusCode::CONFLICT,
            "Account is not eligible for email recovery",
        ))?;
    use rand::RngCore;
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let expires_at = chrono::Utc::now().timestamp() + ttl;
    reset::Entity::insert(reset::ActiveModel {
        subject: Set(u.subject),
        email: Set(email.clone()),
        password_hash_at_issue: Set(u.password_hash),
        token_hash: Set(digest(&token)),
        expires_at: Set(expires_at),
        consumed: Set(0),
    })
    .on_conflict(
        OnConflict::column(reset::Column::Subject)
            .update_columns([
                reset::Column::Email,
                reset::Column::PasswordHashAtIssue,
                reset::Column::TokenHash,
                reset::Column::ExpiresAt,
                reset::Column::Consumed,
            ])
            .to_owned(),
    )
    .exec(db)
    .await
    .map_err(internal)?;
    Ok(IssuedReset {
        username: req.username,
        email,
        expires_at,
        reset_url: format!("{base}/password-reset#token={token}"),
    })
}
pub async fn accept(db: &DatabaseConnection, req: AcceptRequest) -> Result<(), ApiError> {
    if req.token.len() != 64
        || !req.token.bytes().all(|b| b.is_ascii_hexdigit())
        || !(12..=128).contains(&req.password.len())
    {
        return Err(invalid());
    }
    let hash = digest(&req.token);
    let row = reset::Entity::find()
        .filter(reset::Column::TokenHash.eq(&hash))
        .filter(reset::Column::Consumed.eq(0))
        .filter(reset::Column::ExpiresAt.gt(chrono::Utc::now().timestamp()))
        .one(db)
        .await
        .map_err(internal)?
        .ok_or_else(invalid)?;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    let password = req.password;
    let password_hash = tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|h| h.to_string())
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    let tx = db.begin().await.map_err(internal)?;
    let claimed = reset::Entity::update_many()
        .col_expr(reset::Column::Consumed, Expr::value(1))
        .filter(reset::Column::TokenHash.eq(hash))
        .filter(reset::Column::Consumed.eq(0))
        .filter(reset::Column::ExpiresAt.gt(chrono::Utc::now().timestamp()))
        .exec(&tx)
        .await
        .map_err(internal)?;
    if claimed.rows_affected != 1 {
        return Err(invalid());
    }
    // A link cannot reactivate a disabled account, change its email, bypass MFA,
    // or survive an intervening credential change. Failed updates roll back claim.
    let changed = user::Entity::update_many()
        .col_expr(user::Column::PasswordHash, Expr::value(password_hash))
        .col_expr(user::Column::EmailVerified, Expr::value(1))
        .filter(user::Column::Subject.eq(&row.subject))
        .filter(user::Column::Enabled.eq(1))
        .filter(user::Column::Email.eq(&row.email))
        .filter(user::Column::PasswordHash.eq(&row.password_hash_at_issue))
        .exec(&tx)
        .await
        .map_err(internal)?;
    if changed.rows_affected != 1 {
        return Err(invalid());
    }
    session::Entity::delete_many()
        .filter(session::Column::Subject.eq(&row.subject))
        .exec(&tx)
        .await
        .map_err(internal)?;
    auth_code::Entity::delete_many()
        .filter(auth_code::Column::Subject.eq(&row.subject))
        .exec(&tx)
        .await
        .map_err(internal)?;
    access_token::Entity::update_many()
        .col_expr(access_token::Column::Revoked, Expr::value(1))
        .filter(access_token::Column::Subject.eq(&row.subject))
        .exec(&tx)
        .await
        .map_err(internal)?;
    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(1))
        .filter(refresh_token::Column::Subject.eq(&row.subject))
        .exec(&tx)
        .await
        .map_err(internal)?;
    crate::entities::device_code::Entity::delete_many()
        .filter(crate::entities::device_code::Column::Subject.eq(&row.subject))
        .exec(&tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(())
}
async fn issue_handler(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    authorize(&headers, &s)?;
    Ok((
        [("cache-control", "no-store")],
        Json(issue(&s.db, &s.base, req).await?),
    ))
}
async fn revoke_handler(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &s)?;
    if let Some(u) = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(&s.db)
        .await
        .map_err(internal)?
    {
        reset::Entity::update_many()
            .col_expr(reset::Column::Consumed, Expr::value(1))
            .filter(reset::Column::Subject.eq(u.subject))
            .exec(&s.db)
            .await
            .map_err(internal)?;
    }
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) fn admin_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/password-resets", post(issue_handler))
        .route("/admin/password-resets/{username}", delete(revoke_handler))
}
async fn accept_handler(
    State(db): State<DatabaseConnection>,
    Json(req): Json<AcceptRequest>,
) -> Result<StatusCode, ApiError> {
    accept(&db, req).await?;
    Ok(StatusCode::NO_CONTENT)
}
pub fn public_router<S: Clone + Send + Sync + 'static>(db: DatabaseConnection) -> Router<S> {
    Router::new()
        .route(
            "/password-reset",
            get(|| async {
                (
                    [("cache-control", "no-store")],
                    Html(include_str!("../static/password-reset.html")),
                )
            }),
        )
        .route(
            "/password-reset.js",
            get(|| async {
                (
                    [
                        ("content-type", "text/javascript"),
                        ("cache-control", "no-store"),
                    ],
                    include_str!("../static/password-reset.js"),
                )
            }),
        )
        .route("/password-reset/accept", post(accept_handler))
        .with_state(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, IntoActiveModel};
    const OLD: &str = "original long password";
    const NEW: &str = "replacement long password";
    async fn database() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let u = crate::storage::create_user(&db, "alice", OLD, Some("alice@example.test".into()))
            .await
            .unwrap();
        user::Entity::update_many()
            .col_expr(user::Column::EmailVerified, Expr::value(1))
            .filter(user::Column::Subject.eq(u.subject))
            .exec(&db)
            .await
            .unwrap();
        db
    }
    async fn issued(db: &DatabaseConnection) -> IssuedReset {
        issue(
            db,
            "https://auth.example.test",
            IssueRequest {
                username: "alice".into(),
                expires_in: Some(600),
            },
        )
        .await
        .unwrap()
    }
    fn token(r: &IssuedReset) -> String {
        r.reset_url.split("#token=").nth(1).unwrap().into()
    }
    async fn redeem(
        db: &DatabaseConnection,
        r: &IssuedReset,
        password: &str,
    ) -> Result<(), ApiError> {
        accept(
            db,
            AcceptRequest {
                token: token(r),
                password: password.into(),
            },
        )
        .await
    }
    #[tokio::test]
    async fn preserves_identity_and_mfa_and_revokes_only_this_users_credentials() {
        let db = database().await;
        let u = user::Entity::find().one(&db).await.unwrap().unwrap();
        user::Entity::update_many()
            .col_expr(user::Column::Requires2fa, Expr::value(1))
            .exec(&db)
            .await
            .unwrap();
        let other = crate::storage::create_user(&db, "bob", OLD, Some("bob@example.test".into()))
            .await
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        for subject in [&u.subject, &other.subject] {
            crate::storage::create_session(&db, subject, now, 3600, None, None)
                .await
                .unwrap();
            crate::storage::issue_access_token(&db, "client", subject, "openid", 3600)
                .await
                .unwrap();
            crate::storage::issue_refresh_token(&db, "client", subject, "openid", 3600, None)
                .await
                .unwrap();
        }
        for subject in [&u.subject, &other.subject] {
            crate::storage::issue_auth_code(
                &db,
                "client",
                "https://rp.example.test/cb",
                "openid",
                subject,
                None,
                "challenge",
                "S256",
                600,
                Some(now),
            )
            .await
            .unwrap();
            crate::entities::device_code::ActiveModel {
                device_code: Set(subject.clone()),
                user_code: Set(subject.clone()),
                client_id: Set("client".into()),
                client_name: Set(None),
                scope: Set("openid".into()),
                device_info: Set(None),
                created_at: Set(now),
                expires_at: Set(now + 600),
                last_poll_at: Set(None),
                interval: Set(5),
                status: Set("approved".into()),
                subject: Set(Some(subject.clone())),
                auth_time: Set(Some(now)),
                amr: Set(None),
                acr: Set(None),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        let r = issued(&db).await;
        let stored = reset::Entity::find_by_id(&u.subject)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.token_hash, digest(&token(&r)));
        assert_ne!(stored.token_hash, token(&r));
        // Merely issuing a link does not change the password or revoke sessions.
        assert!(crate::storage::verify_user_password(&db, "alice", OLD)
            .await
            .unwrap()
            .is_some());
        redeem(&db, &r, NEW).await.unwrap();
        let after = user::Entity::find_by_id(&u.subject)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.subject, u.subject);
        assert_eq!(after.email, u.email);
        assert_eq!(after.requires_2fa, 1);
        assert_eq!(after.enabled, 1);
        assert!(crate::storage::verify_user_password(&db, "alice", OLD)
            .await
            .unwrap()
            .is_none());
        assert!(crate::storage::verify_user_password(&db, "alice", NEW)
            .await
            .unwrap()
            .is_some());
        assert!(session::Entity::find()
            .filter(session::Column::Subject.eq(&u.subject))
            .all(&db)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            session::Entity::find()
                .filter(session::Column::Subject.eq(&other.subject))
                .all(&db)
                .await
                .unwrap()
                .len(),
            1
        );
        for t in access_token::Entity::find().all(&db).await.unwrap() {
            assert_eq!(t.revoked, i64::from(t.subject == u.subject));
        }
        for t in refresh_token::Entity::find().all(&db).await.unwrap() {
            assert_eq!(t.revoked, i64::from(t.subject == u.subject));
        }
        let codes = auth_code::Entity::find().all(&db).await.unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].subject, other.subject);
        let devices = crate::entities::device_code::Entity::find()
            .all(&db)
            .await
            .unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].subject.as_deref(), Some(other.subject.as_str()));
        assert!(redeem(&db, &r, OLD).await.is_err());
    }
    #[tokio::test]
    async fn reissue_expiry_revocation_and_weak_password() {
        let db = database().await;
        let old = issued(&db).await;
        let new = issued(&db).await;
        assert!(redeem(&db, &old, NEW).await.is_err());
        assert!(redeem(&db, &new, "short").await.is_err());
        reset::Entity::update_many()
            .col_expr(reset::Column::ExpiresAt, Expr::value(0))
            .exec(&db)
            .await
            .unwrap();
        assert!(redeem(&db, &new, NEW).await.is_err());
        let r = issued(&db).await;
        reset::Entity::update_many()
            .col_expr(reset::Column::Consumed, Expr::value(1))
            .exec(&db)
            .await
            .unwrap();
        assert!(redeem(&db, &r, NEW).await.is_err());
        let r = issued(&db).await;
        assert!(redeem(&db, &r, "é".repeat(65).as_str()).await.is_err());
        redeem(&db, &r, NEW).await.unwrap();
    }
    #[tokio::test]
    async fn account_changes_cannot_be_overridden_by_old_link() {
        let db = database().await;
        let r = issued(&db).await;
        let u = user::Entity::find().one(&db).await.unwrap().unwrap();
        let mut active = u.clone().into_active_model();
        active.email = Set(Some("changed@example.test".into()));
        active.update(&db).await.unwrap();
        assert!(redeem(&db, &r, NEW).await.is_err());
        let mut active = u.into_active_model();
        active.enabled = Set(0);
        active.update(&db).await.unwrap();
        assert!(redeem(&db, &r, NEW).await.is_err());
        assert!(issue(
            &db,
            "https://auth.example.test",
            IssueRequest {
                username: "alice".into(),
                expires_in: None
            }
        )
        .await
        .is_err());
        user::Entity::update_many()
            .col_expr(user::Column::Enabled, Expr::value(1))
            .col_expr(user::Column::EmailVerified, Expr::value(0))
            .exec(&db)
            .await
            .unwrap();
        let verified_by_mail = issued(&db).await;
        redeem(&db, &verified_by_mail, NEW).await.unwrap();
        assert_eq!(
            user::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .email_verified,
            1
        );
    }
    #[tokio::test]
    async fn intervening_password_change_invalidates_old_reset_without_consuming_it() {
        let db = database().await;
        let r = issued(&db).await;
        user::Entity::update_many()
            .col_expr(user::Column::PasswordHash, Expr::value("changed-hash"))
            .exec(&db)
            .await
            .unwrap();
        assert!(redeem(&db, &r, NEW).await.is_err());
        assert_eq!(
            reset::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .consumed,
            0
        );
        assert_eq!(
            user::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .password_hash,
            "changed-hash"
        );
    }
    #[tokio::test]
    async fn concurrent_redemption_has_one_winner() {
        let db = database().await;
        let r = issued(&db).await;
        let (a, b) = tokio::join!(
            redeem(&db, &r, NEW),
            redeem(&db, &r, "another long replacement")
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    }
}
