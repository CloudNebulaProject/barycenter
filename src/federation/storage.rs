use crate::entities;
use crate::errors::CrabError;
use crate::storage::random_id;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Struct types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub id: String,
    pub domain: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub pinned_jwks: Option<String>,
    pub jwks_pin_mode: String,
    pub scopes: String,
    pub mapping_policy: String,
    pub trust_peer_acr: bool,
    pub sync_profile: bool,
    pub status: String,
    pub verification_level: Option<String>,
    pub verified_at: Option<String>,
    pub webfinger_issuer_match: Option<bool>,
    pub last_discovery_refresh: Option<String>,
    pub last_discovery_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentity {
    pub id: String,
    pub local_user_id: String,
    pub peer_id: String,
    pub external_subject: String,
    pub external_issuer: String,
    pub external_email: Option<String>,
    pub linked_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationAuthRequest {
    pub id: String,
    pub peer_id: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub original_authorize_params: String,
    pub original_session_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRequest {
    pub id: String,
    pub requesting_issuer: String,
    pub requesting_domain: String,
    pub client_id_at_us: String,
    pub callback_endpoint: String,
    pub request_jws: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

// ---------------------------------------------------------------------------
// Conversions from entity models
// ---------------------------------------------------------------------------

impl From<entities::trusted_peer::Model> for TrustedPeer {
    fn from(m: entities::trusted_peer::Model) -> Self {
        Self {
            id: m.id,
            domain: m.domain,
            issuer_url: m.issuer_url,
            client_id: m.client_id,
            client_secret: m.client_secret,
            token_endpoint: m.token_endpoint,
            authorization_endpoint: m.authorization_endpoint,
            userinfo_endpoint: m.userinfo_endpoint,
            jwks_uri: m.jwks_uri,
            pinned_jwks: m.pinned_jwks,
            jwks_pin_mode: m.jwks_pin_mode,
            scopes: m.scopes,
            mapping_policy: m.mapping_policy,
            trust_peer_acr: m.trust_peer_acr,
            sync_profile: m.sync_profile,
            status: m.status,
            verification_level: m.verification_level,
            verified_at: m.verified_at,
            webfinger_issuer_match: m.webfinger_issuer_match,
            last_discovery_refresh: m.last_discovery_refresh,
            last_discovery_error: m.last_discovery_error,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

impl From<entities::federated_identity::Model> for FederatedIdentity {
    fn from(m: entities::federated_identity::Model) -> Self {
        Self {
            id: m.id,
            local_user_id: m.local_user_id,
            peer_id: m.peer_id,
            external_subject: m.external_subject,
            external_issuer: m.external_issuer,
            external_email: m.external_email,
            linked_at: m.linked_at,
            last_login_at: m.last_login_at,
        }
    }
}

impl From<entities::federation_auth_request::Model> for FederationAuthRequest {
    fn from(m: entities::federation_auth_request::Model) -> Self {
        Self {
            id: m.id,
            peer_id: m.peer_id,
            state: m.state,
            nonce: m.nonce,
            pkce_verifier: m.pkce_verifier,
            original_authorize_params: m.original_authorize_params,
            original_session_id: m.original_session_id,
            created_at: m.created_at,
            expires_at: m.expires_at,
        }
    }
}

impl From<entities::peer_request::Model> for PeerRequest {
    fn from(m: entities::peer_request::Model) -> Self {
        Self {
            id: m.id,
            requesting_issuer: m.requesting_issuer,
            requesting_domain: m.requesting_domain,
            client_id_at_us: m.client_id_at_us,
            callback_endpoint: m.callback_endpoint,
            request_jws: m.request_jws,
            status: m.status,
            created_at: m.created_at,
            expires_at: m.expires_at,
        }
    }
}

// ---------------------------------------------------------------------------
// trusted_peers CRUD
// ---------------------------------------------------------------------------

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub async fn create_trusted_peer(
    db: &DatabaseConnection,
    domain: &str,
    issuer_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    mapping_policy: &str,
    jwks_pin_mode: &str,
) -> Result<String, CrabError> {
    let id = random_id();
    let now = now_iso();

    let model = entities::trusted_peer::ActiveModel {
        id: Set(id.clone()),
        domain: Set(domain.to_string()),
        issuer_url: Set(issuer_url.to_string()),
        client_id: Set(client_id.to_string()),
        client_secret: Set(client_secret.map(|s| s.to_string())),
        token_endpoint: Set(None),
        authorization_endpoint: Set(None),
        userinfo_endpoint: Set(None),
        jwks_uri: Set(None),
        pinned_jwks: Set(None),
        jwks_pin_mode: Set(jwks_pin_mode.to_string()),
        scopes: Set("openid email profile".to_string()),
        mapping_policy: Set(mapping_policy.to_string()),
        trust_peer_acr: Set(false),
        sync_profile: Set(false),
        status: Set("pending_verification".to_string()),
        verification_level: Set(None),
        verified_at: Set(None),
        webfinger_issuer_match: Set(None),
        last_discovery_refresh: Set(None),
        last_discovery_error: Set(None),
        created_at: Set(now.clone()),
        updated_at: Set(now),
    };

    model.insert(db).await?;
    Ok(id)
}

pub async fn get_trusted_peer_by_domain(
    db: &DatabaseConnection,
    domain: &str,
) -> Result<Option<TrustedPeer>, CrabError> {
    use entities::trusted_peer::{Column, Entity};

    let peer = Entity::find()
        .filter(Column::Domain.eq(domain))
        .one(db)
        .await?;

    Ok(peer.map(TrustedPeer::from))
}

pub async fn get_active_trusted_peer_by_domain(
    db: &DatabaseConnection,
    domain: &str,
) -> Result<Option<TrustedPeer>, CrabError> {
    use entities::trusted_peer::{Column, Entity};

    let peer = Entity::find()
        .filter(Column::Domain.eq(domain))
        .filter(Column::Status.eq("active"))
        .one(db)
        .await?;

    Ok(peer.map(TrustedPeer::from))
}

pub async fn list_trusted_peers(
    db: &DatabaseConnection,
) -> Result<Vec<TrustedPeer>, CrabError> {
    use entities::trusted_peer::Entity;

    let peers = Entity::find().all(db).await?;
    Ok(peers.into_iter().map(TrustedPeer::from).collect())
}

pub async fn update_trusted_peer_status(
    db: &DatabaseConnection,
    id: &str,
    status: &str,
) -> Result<(), CrabError> {
    use entities::trusted_peer::{Column, Entity};

    if let Some(peer) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::trusted_peer::ActiveModel = peer.into();
        active.status = Set(status.to_string());
        active.updated_at = Set(now_iso());
        active.update(db).await?;
    }

    Ok(())
}

pub async fn update_trusted_peer_discovery(
    db: &DatabaseConnection,
    id: &str,
    token_endpoint: Option<&str>,
    authorization_endpoint: Option<&str>,
    userinfo_endpoint: Option<&str>,
    jwks_uri: Option<&str>,
    pinned_jwks: Option<&str>,
) -> Result<(), CrabError> {
    use entities::trusted_peer::{Column, Entity};

    if let Some(peer) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::trusted_peer::ActiveModel = peer.into();
        active.token_endpoint = Set(token_endpoint.map(|s| s.to_string()));
        active.authorization_endpoint = Set(authorization_endpoint.map(|s| s.to_string()));
        active.userinfo_endpoint = Set(userinfo_endpoint.map(|s| s.to_string()));
        active.jwks_uri = Set(jwks_uri.map(|s| s.to_string()));
        active.pinned_jwks = Set(pinned_jwks.map(|s| s.to_string()));
        active.last_discovery_refresh = Set(Some(now_iso()));
        active.last_discovery_error = Set(None);
        active.updated_at = Set(now_iso());
        active.update(db).await?;
    }

    Ok(())
}

pub async fn update_trusted_peer_verification(
    db: &DatabaseConnection,
    id: &str,
    verification_level: Option<&str>,
    webfinger_issuer_match: Option<bool>,
) -> Result<(), CrabError> {
    use entities::trusted_peer::{Column, Entity};

    if let Some(peer) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::trusted_peer::ActiveModel = peer.into();
        active.verification_level = Set(verification_level.map(|s| s.to_string()));
        active.webfinger_issuer_match = Set(webfinger_issuer_match);
        active.verified_at = Set(Some(now_iso()));
        active.updated_at = Set(now_iso());
        active.update(db).await?;
    }

    Ok(())
}

pub async fn update_trusted_peer_discovery_error(
    db: &DatabaseConnection,
    id: &str,
    error_message: &str,
) -> Result<(), CrabError> {
    use entities::trusted_peer::{Column, Entity};

    if let Some(peer) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::trusted_peer::ActiveModel = peer.into();
        active.last_discovery_error = Set(Some(error_message.to_string()));
        active.updated_at = Set(now_iso());
        active.update(db).await?;
    }

    Ok(())
}

pub async fn get_trusted_peer_by_id(
    db: &DatabaseConnection,
    id: &str,
) -> Result<Option<TrustedPeer>, CrabError> {
    use entities::trusted_peer::{Column, Entity};

    let model = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?;

    Ok(model.map(TrustedPeer::from))
}

pub async fn delete_trusted_peer(
    db: &DatabaseConnection,
    id: &str,
) -> Result<(), CrabError> {
    use entities::trusted_peer::{Column, Entity};

    Entity::delete_many()
        .filter(Column::Id.eq(id))
        .exec(db)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// federated_identities CRUD
// ---------------------------------------------------------------------------

pub async fn link_federated_identity(
    db: &DatabaseConnection,
    local_user_id: &str,
    peer_id: &str,
    external_subject: &str,
    external_issuer: &str,
    external_email: Option<&str>,
) -> Result<String, CrabError> {
    let id = random_id();
    let now = now_iso();

    let model = entities::federated_identity::ActiveModel {
        id: Set(id.clone()),
        local_user_id: Set(local_user_id.to_string()),
        peer_id: Set(peer_id.to_string()),
        external_subject: Set(external_subject.to_string()),
        external_issuer: Set(external_issuer.to_string()),
        external_email: Set(external_email.map(|s| s.to_string())),
        linked_at: Set(now),
        last_login_at: Set(None),
    };

    model.insert(db).await?;
    Ok(id)
}

pub async fn find_local_user_by_federated_id(
    db: &DatabaseConnection,
    peer_id: &str,
    external_subject: &str,
) -> Result<Option<FederatedIdentity>, CrabError> {
    use entities::federated_identity::{Column, Entity};

    let identity = Entity::find()
        .filter(Column::PeerId.eq(peer_id))
        .filter(Column::ExternalSubject.eq(external_subject))
        .one(db)
        .await?;

    Ok(identity.map(FederatedIdentity::from))
}

pub async fn list_federated_identities_for_user(
    db: &DatabaseConnection,
    local_user_id: &str,
) -> Result<Vec<FederatedIdentity>, CrabError> {
    use entities::federated_identity::{Column, Entity};

    let identities = Entity::find()
        .filter(Column::LocalUserId.eq(local_user_id))
        .all(db)
        .await?;

    Ok(identities.into_iter().map(FederatedIdentity::from).collect())
}

pub async fn update_federated_identity_last_login(
    db: &DatabaseConnection,
    id: &str,
) -> Result<(), CrabError> {
    use entities::federated_identity::{Column, Entity};

    if let Some(identity) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::federated_identity::ActiveModel = identity.into();
        active.last_login_at = Set(Some(now_iso()));
        active.update(db).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// federation_auth_requests CRUD
// ---------------------------------------------------------------------------

pub async fn create_federation_auth_request(
    db: &DatabaseConnection,
    peer_id: &str,
    state: &str,
    nonce: &str,
    pkce_verifier: &str,
    original_authorize_params: &str,
    original_session_id: Option<&str>,
    expires_at: &str,
) -> Result<String, CrabError> {
    let id = random_id();
    let now = now_iso();

    let model = entities::federation_auth_request::ActiveModel {
        id: Set(id.clone()),
        peer_id: Set(peer_id.to_string()),
        state: Set(state.to_string()),
        nonce: Set(nonce.to_string()),
        pkce_verifier: Set(pkce_verifier.to_string()),
        original_authorize_params: Set(original_authorize_params.to_string()),
        original_session_id: Set(original_session_id.map(|s| s.to_string())),
        created_at: Set(now),
        expires_at: Set(expires_at.to_string()),
    };

    model.insert(db).await?;
    Ok(id)
}

pub async fn get_federation_auth_request_by_state(
    db: &DatabaseConnection,
    state: &str,
) -> Result<Option<FederationAuthRequest>, CrabError> {
    use entities::federation_auth_request::{Column, Entity};

    let request = Entity::find()
        .filter(Column::State.eq(state))
        .one(db)
        .await?;

    Ok(request.map(FederationAuthRequest::from))
}

pub async fn delete_federation_auth_request(
    db: &DatabaseConnection,
    id: &str,
) -> Result<(), CrabError> {
    use entities::federation_auth_request::{Column, Entity};

    Entity::delete_many()
        .filter(Column::Id.eq(id))
        .exec(db)
        .await?;

    Ok(())
}

pub async fn cleanup_expired_federation_requests(
    db: &DatabaseConnection,
) -> Result<u64, CrabError> {
    use entities::federation_auth_request::{Column, Entity};

    let now = now_iso();
    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

// ---------------------------------------------------------------------------
// trusted_peers: lookup by issuer_url
// ---------------------------------------------------------------------------

pub async fn get_trusted_peer_by_issuer_url(
    db: &DatabaseConnection,
    issuer_url: &str,
) -> Result<Option<TrustedPeer>, CrabError> {
    use entities::trusted_peer::{Column, Entity};

    let peer = Entity::find()
        .filter(Column::IssuerUrl.eq(issuer_url))
        .one(db)
        .await?;

    Ok(peer.map(TrustedPeer::from))
}

// ---------------------------------------------------------------------------
// peer_requests CRUD
// ---------------------------------------------------------------------------

pub async fn create_peer_request(
    db: &DatabaseConnection,
    requesting_issuer: &str,
    requesting_domain: &str,
    client_id_at_us: &str,
    callback_endpoint: &str,
    request_jws: &str,
    expires_at: &str,
) -> Result<String, CrabError> {
    let id = random_id();
    let now = now_iso();

    let model = entities::peer_request::ActiveModel {
        id: Set(id.clone()),
        requesting_issuer: Set(requesting_issuer.to_string()),
        requesting_domain: Set(requesting_domain.to_string()),
        client_id_at_us: Set(client_id_at_us.to_string()),
        callback_endpoint: Set(callback_endpoint.to_string()),
        request_jws: Set(request_jws.to_string()),
        status: Set("pending_approval".to_string()),
        created_at: Set(now),
        expires_at: Set(expires_at.to_string()),
    };

    model.insert(db).await?;
    Ok(id)
}

pub async fn get_peer_request(
    db: &DatabaseConnection,
    id: &str,
) -> Result<Option<PeerRequest>, CrabError> {
    use entities::peer_request::{Column, Entity};

    let model = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?;

    Ok(model.map(PeerRequest::from))
}

pub async fn list_pending_peer_requests(
    db: &DatabaseConnection,
) -> Result<Vec<PeerRequest>, CrabError> {
    use entities::peer_request::{Column, Entity};

    let models = Entity::find()
        .filter(Column::Status.eq("pending_approval"))
        .all(db)
        .await?;

    Ok(models.into_iter().map(PeerRequest::from).collect())
}

pub async fn update_peer_request_status(
    db: &DatabaseConnection,
    id: &str,
    status: &str,
) -> Result<(), CrabError> {
    use entities::peer_request::{Column, Entity};

    if let Some(req) = Entity::find()
        .filter(Column::Id.eq(id))
        .one(db)
        .await?
    {
        let mut active: entities::peer_request::ActiveModel = req.into();
        active.status = Set(status.to_string());
        active.update(db).await?;
    }

    Ok(())
}

pub async fn cleanup_expired_peer_requests(
    db: &DatabaseConnection,
) -> Result<u64, CrabError> {
    use entities::peer_request::{Column, Entity};

    let now = now_iso();
    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .filter(Column::Status.eq("pending_approval"))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    /// Create a temporary SQLite database with all migrations applied.
    async fn setup_db() -> (DatabaseConnection, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let db_url = format!("sqlite://{}?mode=rwc", temp.path().to_str().unwrap());
        let db = Database::connect(&db_url).await.unwrap();
        migration::Migrator::up(&db, None).await.unwrap();
        (db, temp)
    }

    // -----------------------------------------------------------------------
    // TrustedPeer CRUD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_trusted_peer_create_and_get_by_id() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db,
            "peer.example.com",
            "https://auth.peer.example.com",
            "client123",
            Some("secret456"),
            "existing_only",
            "trust_discovery",
        )
        .await
        .unwrap();

        assert!(!id.is_empty());

        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.domain, "peer.example.com");
        assert_eq!(peer.issuer_url, "https://auth.peer.example.com");
        assert_eq!(peer.client_id, "client123");
        assert_eq!(peer.client_secret.as_deref(), Some("secret456"));
        assert_eq!(peer.mapping_policy, "existing_only");
        assert_eq!(peer.jwks_pin_mode, "trust_discovery");
        assert_eq!(peer.status, "pending_verification");
        assert_eq!(peer.scopes, "openid email profile");
        assert!(!peer.trust_peer_acr);
        assert!(!peer.sync_profile);
    }

    #[tokio::test]
    async fn test_trusted_peer_get_by_domain() {
        let (db, _tmp) = setup_db().await;

        create_trusted_peer(
            &db,
            "peer.example.com",
            "https://auth.peer.example.com",
            "client123",
            None,
            "auto_provision",
            "tofu",
        )
        .await
        .unwrap();

        let peer = get_trusted_peer_by_domain(&db, "peer.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.domain, "peer.example.com");

        // Non-existent domain
        let none = get_trusted_peer_by_domain(&db, "nonexistent.com")
            .await
            .unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn test_trusted_peer_get_active_by_domain() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db,
            "peer.example.com",
            "https://auth.peer.example.com",
            "client123",
            None,
            "existing_only",
            "trust_discovery",
        )
        .await
        .unwrap();

        // Initially pending_verification - should not be found as active.
        let none = get_active_trusted_peer_by_domain(&db, "peer.example.com")
            .await
            .unwrap();
        assert!(none.is_none());

        // Activate and try again.
        update_trusted_peer_status(&db, &id, "active").await.unwrap();
        let peer = get_active_trusted_peer_by_domain(&db, "peer.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.status, "active");
    }

    #[tokio::test]
    async fn test_trusted_peer_list() {
        let (db, _tmp) = setup_db().await;

        let peers = list_trusted_peers(&db).await.unwrap();
        assert_eq!(peers.len(), 0);

        create_trusted_peer(&db, "a.com", "https://a.com", "c1", None, "existing_only", "tofu")
            .await
            .unwrap();
        create_trusted_peer(&db, "b.com", "https://b.com", "c2", None, "auto_provision", "tofu")
            .await
            .unwrap();

        let peers = list_trusted_peers(&db).await.unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[tokio::test]
    async fn test_trusted_peer_update_status() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.status, "pending_verification");

        update_trusted_peer_status(&db, &id, "active").await.unwrap();
        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.status, "active");

        update_trusted_peer_status(&db, &id, "suspended").await.unwrap();
        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.status, "suspended");
    }

    #[tokio::test]
    async fn test_trusted_peer_update_discovery() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        // Initially no endpoints are set.
        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert!(peer.token_endpoint.is_none());
        assert!(peer.authorization_endpoint.is_none());

        update_trusted_peer_discovery(
            &db,
            &id,
            Some("https://peer.example.com/token"),
            Some("https://peer.example.com/authorize"),
            Some("https://peer.example.com/userinfo"),
            Some("https://peer.example.com/.well-known/jwks.json"),
            Some(r#"{"keys":[]}"#),
        )
        .await
        .unwrap();

        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.token_endpoint.as_deref(), Some("https://peer.example.com/token"));
        assert_eq!(peer.authorization_endpoint.as_deref(), Some("https://peer.example.com/authorize"));
        assert_eq!(peer.userinfo_endpoint.as_deref(), Some("https://peer.example.com/userinfo"));
        assert_eq!(peer.jwks_uri.as_deref(), Some("https://peer.example.com/.well-known/jwks.json"));
        assert_eq!(peer.pinned_jwks.as_deref(), Some(r#"{"keys":[]}"#));
        assert!(peer.last_discovery_refresh.is_some());
        assert!(peer.last_discovery_error.is_none());
    }

    #[tokio::test]
    async fn test_trusted_peer_update_verification() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        update_trusted_peer_verification(&db, &id, Some("entity_proof"), Some(true))
            .await
            .unwrap();

        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.verification_level.as_deref(), Some("entity_proof"));
        assert_eq!(peer.webfinger_issuer_match, Some(true));
        assert!(peer.verified_at.is_some());
    }

    #[tokio::test]
    async fn test_trusted_peer_update_discovery_error() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        update_trusted_peer_discovery_error(&db, &id, "connection refused")
            .await
            .unwrap();

        let peer = get_trusted_peer_by_id(&db, &id).await.unwrap().unwrap();
        assert_eq!(peer.last_discovery_error.as_deref(), Some("connection refused"));
    }

    #[tokio::test]
    async fn test_trusted_peer_delete() {
        let (db, _tmp) = setup_db().await;

        let id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        assert!(get_trusted_peer_by_id(&db, &id).await.unwrap().is_some());

        delete_trusted_peer(&db, &id).await.unwrap();

        assert!(get_trusted_peer_by_id(&db, &id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_trusted_peer_get_by_issuer_url() {
        let (db, _tmp) = setup_db().await;

        create_trusted_peer(
            &db, "peer.example.com", "https://auth.peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let peer = get_trusted_peer_by_issuer_url(&db, "https://auth.peer.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.domain, "peer.example.com");

        let none = get_trusted_peer_by_issuer_url(&db, "https://nonexistent.com")
            .await
            .unwrap();
        assert!(none.is_none());
    }

    // -----------------------------------------------------------------------
    // FederatedIdentity CRUD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_federated_identity_link_and_find() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let link_id = link_federated_identity(
            &db,
            "local_user_1",
            &peer_id,
            "ext_sub_123",
            "https://peer.example.com",
            Some("user@peer.example.com"),
        )
        .await
        .unwrap();

        assert!(!link_id.is_empty());

        // Find by peer + external subject
        let found = find_local_user_by_federated_id(&db, &peer_id, "ext_sub_123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.local_user_id, "local_user_1");
        assert_eq!(found.external_subject, "ext_sub_123");
        assert_eq!(found.external_issuer, "https://peer.example.com");
        assert_eq!(found.external_email.as_deref(), Some("user@peer.example.com"));
        assert!(found.last_login_at.is_none());

        // Non-existent
        let none = find_local_user_by_federated_id(&db, &peer_id, "nonexistent")
            .await
            .unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn test_federated_identity_list_for_user() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        // No identities yet.
        let identities = list_federated_identities_for_user(&db, "local_user_1")
            .await
            .unwrap();
        assert!(identities.is_empty());

        // Link two identities from different peers to the same local user.
        link_federated_identity(
            &db, "local_user_1", &peer_id, "ext1", "https://peer.example.com", None,
        ).await.unwrap();

        let peer_id2 = create_trusted_peer(
            &db, "other.example.com", "https://other.example.com",
            "c2", None, "existing_only", "tofu",
        ).await.unwrap();

        link_federated_identity(
            &db, "local_user_1", &peer_id2, "ext2", "https://other.example.com", None,
        ).await.unwrap();

        let identities = list_federated_identities_for_user(&db, "local_user_1")
            .await
            .unwrap();
        assert_eq!(identities.len(), 2);
    }

    #[tokio::test]
    async fn test_federated_identity_update_last_login() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let link_id = link_federated_identity(
            &db, "local_user_1", &peer_id, "ext_sub", "https://peer.example.com", None,
        ).await.unwrap();

        // Initially no last_login_at.
        let identity = find_local_user_by_federated_id(&db, &peer_id, "ext_sub")
            .await
            .unwrap()
            .unwrap();
        assert!(identity.last_login_at.is_none());

        // Update last_login_at.
        update_federated_identity_last_login(&db, &link_id).await.unwrap();

        let identity = find_local_user_by_federated_id(&db, &peer_id, "ext_sub")
            .await
            .unwrap()
            .unwrap();
        assert!(identity.last_login_at.is_some());
    }

    // -----------------------------------------------------------------------
    // FederationAuthRequest CRUD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_federation_auth_request_create_and_get() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let id = create_federation_auth_request(
            &db,
            &peer_id,
            "state_abc",
            "nonce_xyz",
            "verifier_123",
            "client_id=foo&scope=openid",
            Some("session_456"),
            "2099-01-01T00:00:00Z",
        )
        .await
        .unwrap();

        assert!(!id.is_empty());

        let req = get_federation_auth_request_by_state(&db, "state_abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(req.peer_id, peer_id);
        assert_eq!(req.state, "state_abc");
        assert_eq!(req.nonce, "nonce_xyz");
        assert_eq!(req.pkce_verifier, "verifier_123");
        assert_eq!(req.original_authorize_params, "client_id=foo&scope=openid");
        assert_eq!(req.original_session_id.as_deref(), Some("session_456"));
        assert_eq!(req.expires_at, "2099-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn test_federation_auth_request_get_nonexistent() {
        let (db, _tmp) = setup_db().await;

        let none = get_federation_auth_request_by_state(&db, "nonexistent_state")
            .await
            .unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn test_federation_auth_request_delete() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        let id = create_federation_auth_request(
            &db, &peer_id, "state_del", "nonce", "verifier",
            "params", None, "2099-01-01T00:00:00Z",
        ).await.unwrap();

        assert!(get_federation_auth_request_by_state(&db, "state_del").await.unwrap().is_some());

        delete_federation_auth_request(&db, &id).await.unwrap();

        assert!(get_federation_auth_request_by_state(&db, "state_del").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_federation_auth_request_cleanup_expired() {
        let (db, _tmp) = setup_db().await;

        let peer_id = create_trusted_peer(
            &db, "peer.example.com", "https://peer.example.com",
            "c1", None, "existing_only", "tofu",
        ).await.unwrap();

        // Create an already-expired request.
        create_federation_auth_request(
            &db, &peer_id, "state_expired", "nonce", "verifier",
            "params", None, "2000-01-01T00:00:00Z", // well in the past
        ).await.unwrap();

        // Create a valid (future) request.
        create_federation_auth_request(
            &db, &peer_id, "state_valid", "nonce", "verifier",
            "params", None, "2099-01-01T00:00:00Z",
        ).await.unwrap();

        let cleaned = cleanup_expired_federation_requests(&db).await.unwrap();
        assert_eq!(cleaned, 1);

        // The expired one is gone.
        assert!(get_federation_auth_request_by_state(&db, "state_expired").await.unwrap().is_none());
        // The valid one remains.
        assert!(get_federation_auth_request_by_state(&db, "state_valid").await.unwrap().is_some());
    }

    // -----------------------------------------------------------------------
    // PeerRequest CRUD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_peer_request_create_and_get() {
        let (db, _tmp) = setup_db().await;

        let id = create_peer_request(
            &db,
            "https://remote.example.com",
            "remote.example.com",
            "client_at_us_123",
            "https://remote.example.com/federation/callback",
            "eyJ...",
            "2099-01-01T00:00:00Z",
        )
        .await
        .unwrap();

        assert!(!id.is_empty());

        let req = get_peer_request(&db, &id).await.unwrap().unwrap();
        assert_eq!(req.requesting_issuer, "https://remote.example.com");
        assert_eq!(req.requesting_domain, "remote.example.com");
        assert_eq!(req.client_id_at_us, "client_at_us_123");
        assert_eq!(req.callback_endpoint, "https://remote.example.com/federation/callback");
        assert_eq!(req.request_jws, "eyJ...");
        assert_eq!(req.status, "pending_approval");
    }

    #[tokio::test]
    async fn test_peer_request_list_pending() {
        let (db, _tmp) = setup_db().await;

        // No requests yet.
        let pending = list_pending_peer_requests(&db).await.unwrap();
        assert!(pending.is_empty());

        // Create two pending requests.
        create_peer_request(
            &db, "https://a.com", "a.com", "c1", "https://a.com/cb", "jws1", "2099-01-01T00:00:00Z",
        ).await.unwrap();
        let id2 = create_peer_request(
            &db, "https://b.com", "b.com", "c2", "https://b.com/cb", "jws2", "2099-01-01T00:00:00Z",
        ).await.unwrap();

        let pending = list_pending_peer_requests(&db).await.unwrap();
        assert_eq!(pending.len(), 2);

        // Approve one — it should no longer appear in pending.
        update_peer_request_status(&db, &id2, "approved").await.unwrap();
        let pending = list_pending_peer_requests(&db).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requesting_domain, "a.com");
    }

    #[tokio::test]
    async fn test_peer_request_update_status() {
        let (db, _tmp) = setup_db().await;

        let id = create_peer_request(
            &db, "https://remote.com", "remote.com", "c1", "https://remote.com/cb",
            "jws", "2099-01-01T00:00:00Z",
        ).await.unwrap();

        let req = get_peer_request(&db, &id).await.unwrap().unwrap();
        assert_eq!(req.status, "pending_approval");

        update_peer_request_status(&db, &id, "approved").await.unwrap();
        let req = get_peer_request(&db, &id).await.unwrap().unwrap();
        assert_eq!(req.status, "approved");

        update_peer_request_status(&db, &id, "rejected").await.unwrap();
        let req = get_peer_request(&db, &id).await.unwrap().unwrap();
        assert_eq!(req.status, "rejected");
    }

    #[tokio::test]
    async fn test_peer_request_cleanup_expired() {
        let (db, _tmp) = setup_db().await;

        // Create an expired pending request.
        create_peer_request(
            &db, "https://expired.com", "expired.com", "c1", "https://expired.com/cb",
            "jws", "2000-01-01T00:00:00Z",
        ).await.unwrap();

        // Create a valid pending request.
        create_peer_request(
            &db, "https://valid.com", "valid.com", "c2", "https://valid.com/cb",
            "jws", "2099-01-01T00:00:00Z",
        ).await.unwrap();

        // Create an expired but already approved request (should NOT be cleaned up).
        let approved_id = create_peer_request(
            &db, "https://approved.com", "approved.com", "c3", "https://approved.com/cb",
            "jws", "2000-01-01T00:00:00Z",
        ).await.unwrap();
        update_peer_request_status(&db, &approved_id, "approved").await.unwrap();

        let cleaned = cleanup_expired_peer_requests(&db).await.unwrap();
        assert_eq!(cleaned, 1); // only the expired pending one

        // Valid request remains.
        let pending = list_pending_peer_requests(&db).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requesting_domain, "valid.com");

        // Approved request still exists.
        let approved = get_peer_request(&db, &approved_id).await.unwrap();
        assert!(approved.is_some());
    }
}
