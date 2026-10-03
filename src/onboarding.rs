//! Explicitly issued, expiring invitations. Possession verifies the invited email.
use crate::entities::{onboarding_invitation as invitation, user};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use sea_orm::{
    sea_query::OnConflict, ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

type ApiError = (StatusCode, &'static str);
fn internal(_: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed")
}
fn invalid() -> ApiError {
    (StatusCode::BAD_REQUEST, "Invalid or expired invitation")
}
fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[derive(Clone)]
struct AdminState {
    db: DatabaseConnection,
    base: String,
    token_hash: [u8; 32],
}
fn authorize(headers: &HeaderMap, state: &AdminState) -> Result<(), ApiError> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let hash: [u8; 32] = Sha256::digest(provided.as_bytes()).into();
    if bool::from(hash.ct_eq(&state.token_hash)) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}
/// Disabled by default. This dedicated credential does not expose the GraphQL API.
pub fn admin_router(db: DatabaseConnection, base: Option<String>) -> Result<Router, String> {
    let path = match std::env::var("BARYCENTER_ONBOARDING_ADMIN_TOKEN_FILE") {
        Ok(path) => path,
        Err(std::env::VarError::NotPresent) => return Ok(Router::new()),
        Err(_) => return Err("invalid token file setting".into()),
    };
    let token = std::fs::read_to_string(path).map_err(|_| "cannot read token file")?;
    let token = token.trim();
    if token.len() < 32 {
        return Err("admin token must have at least 32 characters".into());
    }
    let base = base.ok_or("public_base_url must be configured")?;
    let url = url::Url::parse(&base).map_err(|_| "invalid public_base_url")?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
    {
        return Err("public_base_url requires HTTPS except loopback".into());
    }
    let state = Arc::new(AdminState {
        db,
        base: base.trim_end_matches('/').into(),
        token_hash: Sha256::digest(token.as_bytes()).into(),
    });
    Ok(Router::new()
        .route("/admin/onboarding/invitations", post(issue_handler))
        .route(
            "/admin/onboarding/invitations/{username}",
            delete(revoke_handler),
        )
        .with_state(state))
}
#[derive(Deserialize, Serialize)]
pub struct IssueRequest {
    pub username: String,
    pub email: String,
    pub expires_in: Option<i64>,
}
#[derive(Serialize, Deserialize)]
pub struct IssuedInvitation {
    pub username: String,
    pub email: String,
    pub expires_at: i64,
    pub onboarding_url: String,
}
pub async fn issue(
    db: &DatabaseConnection,
    base: &str,
    req: IssueRequest,
) -> Result<IssuedInvitation, ApiError> {
    let ttl = req.expires_in.unwrap_or(86400);
    if !(300..=604800).contains(&ttl)
        || req.username.is_empty()
        || req.username.len() > 128
        || req.username.chars().any(char::is_control)
        || req.email.len() > 254
        || req.email.chars().any(char::is_whitespace)
        || req.email.matches('@').count() != 1
        || req.email.starts_with('@')
        || req.email.ends_with('@')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid username, email or lifetime",
        ));
    }
    if user::Entity::find()
        .filter(user::Column::Username.eq(&req.username))
        .one(db)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            "User already exists; invitations cannot reset accounts",
        ));
    }
    use rand::RngCore;
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let expires_at = chrono::Utc::now().timestamp() + ttl;
    invitation::Entity::insert(invitation::ActiveModel {
        username: Set(req.username.clone()),
        email: Set(req.email.clone()),
        token_hash: Set(digest(&token)),
        expires_at: Set(expires_at),
        consumed: Set(0),
    })
    .on_conflict(
        OnConflict::column(invitation::Column::Username)
            .update_columns([
                invitation::Column::Email,
                invitation::Column::TokenHash,
                invitation::Column::ExpiresAt,
                invitation::Column::Consumed,
            ])
            .to_owned(),
    )
    .exec(db)
    .await
    .map_err(internal)?;
    Ok(IssuedInvitation {
        username: req.username,
        email: req.email,
        expires_at,
        onboarding_url: format!("{base}/onboarding#token={token}"),
    })
}
async fn issue_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&headers, &state)?;
    Ok((
        [("cache-control", "no-store")],
        Json(issue(&state.db, &state.base, req).await?),
    ))
}
async fn revoke_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state)?;
    invitation::Entity::update_many()
        .col_expr(
            invitation::Column::Consumed,
            sea_orm::sea_query::Expr::value(1),
        )
        .filter(invitation::Column::Username.eq(username))
        .exec(&state.db)
        .await
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct AcceptRequest {
    pub token: String,
    pub password: String,
}
pub async fn accept(db: &DatabaseConnection, req: AcceptRequest) -> Result<(), ApiError> {
    if req.token.len() != 64
        || !req.token.bytes().all(|b| b.is_ascii_hexdigit())
        || !(12..=128).contains(&req.password.len())
    {
        return Err(invalid());
    }
    let hash = digest(&req.token);
    let now = chrono::Utc::now().timestamp();
    let row = invitation::Entity::find()
        .filter(invitation::Column::TokenHash.eq(&hash))
        .filter(invitation::Column::Consumed.eq(0))
        .filter(invitation::Column::ExpiresAt.gt(now))
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
    let claimed = invitation::Entity::update_many()
        .col_expr(
            invitation::Column::Consumed,
            sea_orm::sea_query::Expr::value(1),
        )
        .filter(invitation::Column::TokenHash.eq(hash))
        .filter(invitation::Column::Consumed.eq(0))
        .filter(invitation::Column::ExpiresAt.gt(chrono::Utc::now().timestamp()))
        .exec(&tx)
        .await
        .map_err(internal)?;
    if claimed.rows_affected != 1 {
        return Err(invalid());
    }
    user::ActiveModel {
        subject: Set(uuid::Uuid::new_v4().to_string()),
        username: Set(row.username),
        email: Set(Some(row.email)),
        email_verified: Set(1),
        password_hash: Set(password_hash),
        created_at: Set(now),
        enabled: Set(1),
        requires_2fa: Set(0),
        passkey_enrolled_at: Set(None),
    }
    .insert(&tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(())
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
            "/onboarding",
            get(|| async {
                (
                    [("cache-control", "no-store")],
                    Html(include_str!("../static/onboarding.html")),
                )
            }),
        )
        .route(
            "/onboarding.js",
            get(|| async {
                (
                    [
                        ("content-type", "text/javascript"),
                        ("cache-control", "no-store"),
                    ],
                    include_str!("../static/onboarding.js"),
                )
            }),
        )
        .route("/onboarding/accept", post(accept_handler))
        .with_state(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    async fn database() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db
    }
    async fn invited(db: &DatabaseConnection) -> IssuedInvitation {
        issue(
            db,
            "https://auth.example.test",
            IssueRequest {
                username: "alice".into(),
                email: "alice@example.test".into(),
                expires_in: Some(600),
            },
        )
        .await
        .unwrap()
    }
    fn token(i: &IssuedInvitation) -> String {
        i.onboarding_url.split("#token=").nth(1).unwrap().into()
    }
    #[tokio::test]
    async fn activates_once_with_verified_email_and_hashed_password() {
        let db = database().await;
        let i = invited(&db).await;
        let raw = token(&i);
        let stored = invitation::Entity::find_by_id("alice")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.token_hash, raw);
        assert_eq!(stored.token_hash, digest(&raw));
        accept(
            &db,
            AcceptRequest {
                token: raw.clone(),
                password: "a sufficiently long password".into(),
            },
        )
        .await
        .unwrap();
        let u = user::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(u.email_verified, 1);
        assert!(u.password_hash.starts_with("$argon2"));
        assert!(
            crate::storage::verify_user_password(&db, "alice", "a sufficiently long password")
                .await
                .unwrap()
                .is_some()
        );
        assert!(accept(
            &db,
            AcceptRequest {
                token: raw,
                password: "another long password".into()
            }
        )
        .await
        .is_err());
        assert_eq!(
            invited_existing(&db).await.err().unwrap().0,
            StatusCode::CONFLICT
        );
    }
    async fn invited_existing(db: &DatabaseConnection) -> Result<IssuedInvitation, ApiError> {
        issue(
            db,
            "https://auth.example.test",
            IssueRequest {
                username: "alice".into(),
                email: "other@example.test".into(),
                expires_in: None,
            },
        )
        .await
    }
    #[tokio::test]
    async fn reissue_expiry_and_revocation_reject_old_tokens() {
        let db = database().await;
        let old = invited(&db).await;
        let new = invited(&db).await;
        assert!(accept(
            &db,
            AcceptRequest {
                token: token(&old),
                password: "a sufficiently long password".into()
            }
        )
        .await
        .is_err());
        invitation::Entity::update_many()
            .col_expr(
                invitation::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(0),
            )
            .exec(&db)
            .await
            .unwrap();
        assert!(accept(
            &db,
            AcceptRequest {
                token: token(&new),
                password: "a sufficiently long password".into()
            }
        )
        .await
        .is_err());
        let new = invited(&db).await;
        invitation::Entity::update_many()
            .col_expr(
                invitation::Column::Consumed,
                sea_orm::sea_query::Expr::value(1),
            )
            .exec(&db)
            .await
            .unwrap();
        assert!(accept(
            &db,
            AcceptRequest {
                token: token(&new),
                password: "a sufficiently long password".into()
            }
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn weak_password_does_not_consume_invitation() {
        let db = database().await;
        let i = invited(&db).await;
        assert!(accept(
            &db,
            AcceptRequest {
                token: token(&i),
                password: "short".into()
            }
        )
        .await
        .is_err());
        accept(
            &db,
            AcceptRequest {
                token: token(&i),
                password: "a sufficiently long password".into(),
            },
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn concurrent_redemption_creates_exactly_one_user() {
        let db = database().await;
        let i = invited(&db).await;
        let (first, second) = tokio::join!(
            accept(
                &db,
                AcceptRequest {
                    token: token(&i),
                    password: "a sufficiently long password".into()
                }
            ),
            accept(
                &db,
                AcceptRequest {
                    token: token(&i),
                    password: "another sufficiently long password".into()
                }
            )
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(user::Entity::find().all(&db).await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn unauthenticated_admin_request_is_denied() {
        let db = database().await;
        let s = AdminState {
            db,
            base: "https://auth.example.test".into(),
            token_hash: Sha256::digest(b"correct-secret").into(),
        };
        assert_eq!(
            authorize(&HeaderMap::new(), &s).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer correct-secret".parse().unwrap());
        authorize(&headers, &s).unwrap();
    }
}
