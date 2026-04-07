//! Federated identity resolution for Barycenter's P2P federation protocol.
//!
//! Maps external identities (from trusted peers) to local user accounts
//! according to the peer's configured mapping policy.

use sea_orm::DatabaseConnection;

use crate::federation::storage::{self as fed_storage, TrustedPeer};
use crate::storage;

// ---------------------------------------------------------------------------
// Mapping policy
// ---------------------------------------------------------------------------

/// Controls how external identities are mapped to local accounts.
#[derive(Debug, Clone, PartialEq)]
pub enum MappingPolicy {
    /// Only allow login if a federated identity link already exists.
    ExistingOnly,
    /// Automatically link to a local user whose email matches the external email.
    AutoLinkByEmail,
    /// Automatically create a new local user if no link or email match exists.
    AutoProvision,
}

impl MappingPolicy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "auto_link_by_email" => Self::AutoLinkByEmail,
            "auto_provision" => Self::AutoProvision,
            _ => Self::ExistingOnly,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during federated identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityResolutionError {
    #[error("no existing link for {external_subject} from peer {peer_domain}")]
    NoExistingLink {
        peer_domain: String,
        external_subject: String,
    },

    #[error("no local user with email {email}")]
    NoMatchingLocalUser { email: String },

    #[error("peer did not send email_verified=true")]
    EmailNotVerified,

    #[error("failed to create user: {0}")]
    UserCreationFailed(String),

    #[error("database error: {0}")]
    DatabaseError(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve a federated identity to a local user subject.
///
/// Checks for an existing link first, then applies the peer's mapping policy
/// to auto-link or auto-provision a local account as needed.
///
/// Returns the local user's subject (user ID).
pub async fn resolve_federated_identity(
    db: &DatabaseConnection,
    peer: &TrustedPeer,
    external_subject: &str,
    external_issuer: &str,
    external_email: Option<&str>,
    email_verified: bool,
    _external_name: Option<&str>,
) -> Result<String, IdentityResolutionError> {
    // 1. Check for an existing federated identity link.
    let existing = fed_storage::find_local_user_by_federated_id(db, &peer.id, external_subject)
        .await
        .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?;

    if let Some(identity) = existing {
        // Update last_login_at timestamp.
        let _ = fed_storage::update_federated_identity_last_login(db, &identity.id).await;
        return Ok(identity.local_user_id);
    }

    // 2. Determine mapping policy.
    let policy = MappingPolicy::from_str(&peer.mapping_policy);

    match policy {
        // 3. ExistingOnly — no auto-linking allowed.
        MappingPolicy::ExistingOnly => Err(IdentityResolutionError::NoExistingLink {
            peer_domain: peer.domain.clone(),
            external_subject: external_subject.to_string(),
        }),

        // 4. AutoLinkByEmail — find a local user with matching email.
        MappingPolicy::AutoLinkByEmail => {
            let email = external_email.ok_or(IdentityResolutionError::EmailNotVerified)?;
            if !email_verified {
                return Err(IdentityResolutionError::EmailNotVerified);
            }

            let local_user = get_user_by_email(db, email)
                .await
                .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?
                .ok_or_else(|| IdentityResolutionError::NoMatchingLocalUser {
                    email: email.to_string(),
                })?;

            // Create federated identity link.
            fed_storage::link_federated_identity(
                db,
                &local_user.subject,
                &peer.id,
                external_subject,
                external_issuer,
                external_email,
            )
            .await
            .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?;

            Ok(local_user.subject)
        }

        // 5. AutoProvision — create a new local user.
        MappingPolicy::AutoProvision => {
            // Generate a username from email or external subject.
            let base_username = if let Some(email) = external_email {
                let local_part = email.split('@').next().unwrap_or(email);
                format!("{}@{}", local_part, peer.domain)
            } else {
                let prefix = if external_subject.len() >= 8 {
                    &external_subject[..8]
                } else {
                    external_subject
                };
                format!("fed_{}@{}", prefix, peer.domain)
            };

            // Ensure username uniqueness.
            let username = find_unique_username(db, &base_username).await?;

            // Generate a random password (user will authenticate via federation).
            let random_password = storage::random_id();

            let user = storage::create_user(
                db,
                &username,
                &random_password,
                external_email.map(|s| s.to_string()),
            )
            .await
            .map_err(|e| IdentityResolutionError::UserCreationFailed(e.to_string()))?;

            // Create federated identity link.
            fed_storage::link_federated_identity(
                db,
                &user.subject,
                &peer.id,
                external_subject,
                external_issuer,
                external_email,
            )
            .await
            .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?;

            // TODO: If peer.sync_profile is true, update local user's
            // name/email from external claims once a profile update storage
            // function is available.

            Ok(user.subject)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Look up a local user by email address.
async fn get_user_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<Option<storage::User>, crate::errors::CrabError> {
    use crate::entities::user::{Column, Entity};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let model = Entity::find()
        .filter(Column::Email.eq(Some(email.to_string())))
        .one(db)
        .await?;

    Ok(model.map(|m| storage::User {
        subject: m.subject,
        username: m.username,
        password_hash: m.password_hash,
        email: m.email,
        email_verified: m.email_verified,
        created_at: m.created_at,
        enabled: m.enabled,
        requires_2fa: m.requires_2fa,
        passkey_enrolled_at: m.passkey_enrolled_at,
    }))
}

/// Find a unique username by appending a random suffix if necessary.
async fn find_unique_username(
    db: &DatabaseConnection,
    base: &str,
) -> Result<String, IdentityResolutionError> {
    use rand::Rng;

    // Try the base username first.
    let existing = storage::get_user_by_username(db, base)
        .await
        .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?;

    if existing.is_none() {
        return Ok(base.to_string());
    }

    // Append a random 4-digit suffix.
    for _ in 0..10 {
        let suffix: u16 = rand::thread_rng().gen_range(1000..9999);
        let candidate = format!("{}_{}", base, suffix);
        let exists = storage::get_user_by_username(db, &candidate)
            .await
            .map_err(|e| IdentityResolutionError::DatabaseError(e.to_string()))?;
        if exists.is_none() {
            return Ok(candidate);
        }
    }

    Err(IdentityResolutionError::UserCreationFailed(
        "could not generate a unique username after 10 attempts".to_string(),
    ))
}
