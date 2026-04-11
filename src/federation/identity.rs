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
    pub fn parse(s: &str) -> Self {
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
    let policy = MappingPolicy::parse(&peer.mapping_policy);

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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    /// Create a temporary in-memory-like SQLite database with all migrations applied.
    async fn setup_db() -> (DatabaseConnection, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let db_url = format!("sqlite://{}?mode=rwc", temp.path().to_str().unwrap());
        let db = Database::connect(&db_url).await.unwrap();
        migration::Migrator::up(&db, None).await.unwrap();
        (db, temp)
    }

    /// Create a trusted peer in the DB and return its ID.
    async fn create_peer(db: &DatabaseConnection, mapping_policy: &str) -> String {
        let peer_id = crate::federation::storage::create_trusted_peer(
            db,
            "peer.example.com",
            "https://auth.peer.example.com",
            "client123",
            Some("secret"),
            mapping_policy,
            "trust_discovery",
        )
        .await
        .unwrap();

        // Activate it so it can be used.
        crate::federation::storage::update_trusted_peer_status(db, &peer_id, "active")
            .await
            .unwrap();

        peer_id
    }

    // -----------------------------------------------------------------------
    // MappingPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn test_mapping_policy_from_str() {
        assert_eq!(
            MappingPolicy::parse("existing_only"),
            MappingPolicy::ExistingOnly
        );
        assert_eq!(
            MappingPolicy::parse("auto_link_by_email"),
            MappingPolicy::AutoLinkByEmail
        );
        assert_eq!(
            MappingPolicy::parse("auto_provision"),
            MappingPolicy::AutoProvision
        );
        // Unknown strings default to ExistingOnly
        assert_eq!(MappingPolicy::parse("unknown"), MappingPolicy::ExistingOnly);
        assert_eq!(MappingPolicy::parse(""), MappingPolicy::ExistingOnly);
    }

    // -----------------------------------------------------------------------
    // resolve_federated_identity — existing_only
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_existing_only_no_link() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "existing_only").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        let result = resolve_federated_identity(
            &db,
            &peer,
            "external_sub_123",
            "https://auth.peer.example.com",
            Some("user@peer.example.com"),
            true,
            Some("Test User"),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolutionError::NoExistingLink {
                peer_domain,
                external_subject,
            } => {
                assert_eq!(peer_domain, "peer.example.com");
                assert_eq!(external_subject, "external_sub_123");
            }
            e => panic!("Expected NoExistingLink, got: {:?}", e),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_federated_identity — existing link reused
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_existing_link_reused() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "existing_only").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Create a local user first.
        let user = crate::storage::create_user(&db, "localuser", "password123", None)
            .await
            .unwrap();

        // Manually create a federated identity link.
        crate::federation::storage::link_federated_identity(
            &db,
            &user.subject,
            &peer_id,
            "external_sub_123",
            "https://auth.peer.example.com",
            Some("user@peer.example.com"),
        )
        .await
        .unwrap();

        // Resolve should find the existing link and return the local subject.
        let result = resolve_federated_identity(
            &db,
            &peer,
            "external_sub_123",
            "https://auth.peer.example.com",
            Some("user@peer.example.com"),
            true,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result, user.subject);

        // Verify last_login_at was updated.
        let identity = crate::federation::storage::find_local_user_by_federated_id(
            &db,
            &peer_id,
            "external_sub_123",
        )
        .await
        .unwrap()
        .unwrap();
        assert!(identity.last_login_at.is_some());
    }

    // -----------------------------------------------------------------------
    // resolve_federated_identity — auto_link_by_email
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_auto_link_by_email() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_link_by_email").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Create a local user with a matching email.
        let user = crate::storage::create_user(
            &db,
            "localuser",
            "password123",
            Some("user@example.com".to_string()),
        )
        .await
        .unwrap();

        // Resolve should auto-link by matching email.
        let result = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_456",
            "https://auth.peer.example.com",
            Some("user@example.com"),
            true,
            Some("Test User"),
        )
        .await
        .unwrap();

        assert_eq!(result, user.subject);

        // Verify that a federated identity link was created.
        let identities =
            crate::federation::storage::list_federated_identities_for_user(&db, &user.subject)
                .await
                .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].external_subject, "ext_sub_456");
    }

    #[tokio::test]
    async fn test_resolve_auto_link_email_not_verified() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_link_by_email").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Create a local user with email.
        let _user = crate::storage::create_user(
            &db,
            "localuser",
            "password123",
            Some("user@example.com".to_string()),
        )
        .await
        .unwrap();

        // Should fail because email_verified is false.
        let result = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_456",
            "https://auth.peer.example.com",
            Some("user@example.com"),
            false, // not verified
            None,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolutionError::EmailNotVerified => {} // expected
            e => panic!("Expected EmailNotVerified, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_resolve_auto_link_no_email_provided() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_link_by_email").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Should fail because no email was provided.
        let result = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_456",
            "https://auth.peer.example.com",
            None, // no email
            true,
            None,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolutionError::EmailNotVerified => {} // expected (no email treated as unverified)
            e => panic!("Expected EmailNotVerified, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_resolve_auto_link_no_matching_local_user() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_link_by_email").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // No local user with this email exists.
        let result = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_456",
            "https://auth.peer.example.com",
            Some("nonexistent@example.com"),
            true,
            None,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolutionError::NoMatchingLocalUser { email } => {
                assert_eq!(email, "nonexistent@example.com");
            }
            e => panic!("Expected NoMatchingLocalUser, got: {:?}", e),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_federated_identity — auto_provision
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_auto_provision() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_provision").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Should auto-create a new user.
        let local_subject = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_789",
            "https://auth.peer.example.com",
            Some("newuser@peer.example.com"),
            true,
            Some("New User"),
        )
        .await
        .unwrap();

        // Verify a local user was created.
        assert!(!local_subject.is_empty());

        // Verify federated identity link was created.
        let identity = crate::federation::storage::find_local_user_by_federated_id(
            &db,
            &peer_id,
            "ext_sub_789",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(identity.local_user_id, local_subject);
        assert_eq!(
            identity.external_email.as_deref(),
            Some("newuser@peer.example.com")
        );
    }

    #[tokio::test]
    async fn test_resolve_auto_provision_no_email() {
        let (db, _tmp) = setup_db().await;
        let peer_id = create_peer(&db, "auto_provision").await;
        let peer = crate::federation::storage::get_trusted_peer_by_id(&db, &peer_id)
            .await
            .unwrap()
            .unwrap();

        // Should still create a user with a generated username.
        let local_subject = resolve_federated_identity(
            &db,
            &peer,
            "ext_sub_abc",
            "https://auth.peer.example.com",
            None,
            false,
            None,
        )
        .await
        .unwrap();

        assert!(!local_subject.is_empty());
    }

    // -----------------------------------------------------------------------
    // IdentityResolutionError Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_identity_resolution_error_display() {
        let err = IdentityResolutionError::NoExistingLink {
            peer_domain: "example.com".into(),
            external_subject: "sub123".into(),
        };
        assert!(err.to_string().contains("sub123"));
        assert!(err.to_string().contains("example.com"));

        let err = IdentityResolutionError::EmailNotVerified;
        assert!(err.to_string().contains("email_verified"));

        let err = IdentityResolutionError::NoMatchingLocalUser {
            email: "test@test.com".into(),
        };
        assert!(err.to_string().contains("test@test.com"));
    }
}
