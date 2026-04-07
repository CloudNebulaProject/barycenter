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
