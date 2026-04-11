//! Integration tests for Barycenter's P2P federation flow.
//!
//! These tests validate federation components using real SQLite databases
//! but without starting HTTP servers, avoiding port conflict issues.

use sea_orm::DatabaseConnection;
use sea_orm_migration::MigratorTrait;
use tempfile::NamedTempFile;

use barycenter::federation::storage::{self as fed_storage};
use barycenter::storage;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_db() -> (DatabaseConnection, NamedTempFile) {
    let temp = NamedTempFile::new().unwrap();
    let db_url = format!("sqlite://{}?mode=rwc", temp.path().to_str().unwrap());
    let db = sea_orm::Database::connect(&db_url).await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    (db, temp)
}

/// Create a trusted peer in the database and return its ID.
async fn create_test_peer(db: &DatabaseConnection, domain: &str, mapping_policy: &str) -> String {
    fed_storage::create_trusted_peer(
        db,
        domain,
        &format!("https://{}", domain),
        "test-client-id",
        Some("test-client-secret"),
        mapping_policy,
        "pin_on_first_use",
    )
    .await
    .expect("failed to create trusted peer")
}

// ---------------------------------------------------------------------------
// Test 1: Trusted peer CRUD lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_peer_lifecycle() {
    let (db, _tmp) = setup_test_db().await;

    // 1. Create a trusted peer.
    let peer_id = create_test_peer(&db, "peer.example.com", "existing_only").await;

    // 2. Verify it starts as pending_verification.
    let peer = fed_storage::get_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap()
        .expect("peer should exist");
    assert_eq!(peer.status, "pending_verification");
    assert_eq!(peer.domain, "peer.example.com");
    assert_eq!(peer.issuer_url, "https://peer.example.com");
    assert_eq!(peer.mapping_policy, "existing_only");

    // 3. Activate the peer.
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();

    // 4. Verify get_active_trusted_peer_by_domain returns it.
    let active = fed_storage::get_active_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap();
    assert!(active.is_some(), "active peer should be found");
    assert_eq!(active.unwrap().status, "active");

    // 5. Suspend it.
    fed_storage::update_trusted_peer_status(&db, &peer_id, "suspended")
        .await
        .unwrap();

    // 6. Verify get_active_trusted_peer_by_domain returns None.
    let suspended = fed_storage::get_active_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap();
    assert!(
        suspended.is_none(),
        "suspended peer should not be found via active query"
    );

    // 7. Reactivate and verify.
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();
    let reactivated = fed_storage::get_active_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap();
    assert!(reactivated.is_some(), "reactivated peer should be found");

    // 8. Delete and verify gone.
    fed_storage::delete_trusted_peer(&db, &peer_id)
        .await
        .unwrap();
    let deleted = fed_storage::get_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap();
    assert!(deleted.is_none(), "deleted peer should not be found");
}

// ---------------------------------------------------------------------------
// Test 2: Federation auth request flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_auth_request_flow() {
    let (db, _tmp) = setup_test_db().await;

    // Setup: create an active peer.
    let peer_id = create_test_peer(&db, "peer.example.com", "existing_only").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();

    let state = "random-state-value-12345";
    let nonce = "random-nonce-value-67890";
    let pkce_verifier = "pkce-verifier-abcdef";
    let original_params = r#"{"client_id":"c1","redirect_uri":"http://localhost/cb"}"#;
    let expires_at = "2099-12-31T23:59:59Z";

    // 1. Create a federation auth request.
    let req_id = fed_storage::create_federation_auth_request(
        &db,
        &peer_id,
        state,
        nonce,
        pkce_verifier,
        original_params,
        None,
        expires_at,
    )
    .await
    .expect("failed to create auth request");
    assert!(!req_id.is_empty());

    // 2. Look it up by state.
    let found = fed_storage::get_federation_auth_request_by_state(&db, state)
        .await
        .unwrap()
        .expect("auth request should be found by state");

    // 3. Verify all fields match.
    assert_eq!(found.id, req_id);
    assert_eq!(found.peer_id, peer_id);
    assert_eq!(found.state, state);
    assert_eq!(found.nonce, nonce);
    assert_eq!(found.pkce_verifier, pkce_verifier);
    assert_eq!(found.original_authorize_params, original_params);
    assert!(found.original_session_id.is_none());
    assert_eq!(found.expires_at, expires_at);

    // 4. Delete it (single-use).
    fed_storage::delete_federation_auth_request(&db, &req_id)
        .await
        .unwrap();

    // 5. Look it up again — should be None.
    let gone = fed_storage::get_federation_auth_request_by_state(&db, state)
        .await
        .unwrap();
    assert!(gone.is_none(), "deleted auth request should not be found");
}

// ---------------------------------------------------------------------------
// Test 3: Federation auth request expiry cleanup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_auth_request_expiry() {
    let (db, _tmp) = setup_test_db().await;

    let peer_id = create_test_peer(&db, "peer.example.com", "existing_only").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();

    // 1. Create a request with expires_at in the past.
    fed_storage::create_federation_auth_request(
        &db,
        &peer_id,
        "expired-state",
        "nonce1",
        "verifier1",
        "{}",
        None,
        "2020-01-01T00:00:00Z", // in the past
    )
    .await
    .unwrap();

    // 2. Call cleanup — should delete the expired request.
    let cleaned = fed_storage::cleanup_expired_federation_requests(&db)
        .await
        .unwrap();
    assert_eq!(cleaned, 1, "should have cleaned up 1 expired request");

    // 3. Verify it was deleted.
    let gone = fed_storage::get_federation_auth_request_by_state(&db, "expired-state")
        .await
        .unwrap();
    assert!(gone.is_none());

    // 4. Create a request with expires_at in the future.
    fed_storage::create_federation_auth_request(
        &db,
        &peer_id,
        "future-state",
        "nonce2",
        "verifier2",
        "{}",
        None,
        "2099-12-31T23:59:59Z",
    )
    .await
    .unwrap();

    // 5. Cleanup again — should return 0.
    let cleaned2 = fed_storage::cleanup_expired_federation_requests(&db)
        .await
        .unwrap();
    assert_eq!(cleaned2, 0, "future request should not be cleaned up");

    // Verify it still exists.
    let still_there = fed_storage::get_federation_auth_request_by_state(&db, "future-state")
        .await
        .unwrap();
    assert!(still_there.is_some());
}

// ---------------------------------------------------------------------------
// Test 4: Federated identity linking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_identity_linking() {
    let (db, _tmp) = setup_test_db().await;

    // Setup: create peer and local user.
    let peer_id = create_test_peer(&db, "peer.example.com", "existing_only").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();

    let user = storage::create_user(
        &db,
        "localuser",
        "password123",
        Some("local@example.com".to_string()),
    )
    .await
    .unwrap();

    // 1. Link a federated identity.
    let link_id = fed_storage::link_federated_identity(
        &db,
        &user.subject,
        &peer_id,
        "external-sub-123",
        "https://peer.example.com",
        Some("external@peer.example.com"),
    )
    .await
    .expect("failed to link federated identity");
    assert!(!link_id.is_empty());

    // 2. Find it by (peer_id, external_sub).
    let found = fed_storage::find_local_user_by_federated_id(&db, &peer_id, "external-sub-123")
        .await
        .unwrap()
        .expect("linked identity should be found");

    // 3. Verify local_user_id matches.
    assert_eq!(found.local_user_id, user.subject);
    assert_eq!(found.external_subject, "external-sub-123");
    assert_eq!(found.external_issuer, "https://peer.example.com");
    assert_eq!(
        found.external_email.as_deref(),
        Some("external@peer.example.com")
    );
    assert!(found.last_login_at.is_none());

    // 4. List federated identities for the local user.
    let identities = fed_storage::list_federated_identities_for_user(&db, &user.subject)
        .await
        .unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].id, link_id);

    // 5. Update last_login_at.
    fed_storage::update_federated_identity_last_login(&db, &link_id)
        .await
        .unwrap();

    // 6. Verify last_login_at was updated.
    let updated = fed_storage::find_local_user_by_federated_id(&db, &peer_id, "external-sub-123")
        .await
        .unwrap()
        .expect("identity should still exist");
    assert!(
        updated.last_login_at.is_some(),
        "last_login_at should be set after update"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Identity resolution policies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_identity_resolution_policies() {
    use barycenter::federation::identity::{resolve_federated_identity, IdentityResolutionError};

    let (db, _tmp) = setup_test_db().await;

    // Create a peer with mapping_policy="existing_only".
    let peer_id = create_test_peer(&db, "peer.example.com", "existing_only").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id, "active")
        .await
        .unwrap();

    let peer = fed_storage::get_trusted_peer_by_domain(&db, "peer.example.com")
        .await
        .unwrap()
        .unwrap();

    // Create a local user with an email.
    let user = storage::create_user(
        &db,
        "localuser",
        "password123",
        Some("toasty@example.com".to_string()),
    )
    .await
    .unwrap();

    // -- Test 1: existing_only with no link -- should fail.
    let result = resolve_federated_identity(
        &db,
        &peer,
        "ext-sub-1",
        "https://peer.example.com",
        Some("toasty@example.com"),
        true,
        None,
    )
    .await;
    assert!(result.is_err(), "existing_only should fail with no link");
    assert!(
        matches!(
            result.unwrap_err(),
            IdentityResolutionError::NoExistingLink { .. }
        ),
        "should be NoExistingLink error"
    );

    // -- Test 2: manually create a link, then resolve -- should succeed.
    fed_storage::link_federated_identity(
        &db,
        &user.subject,
        &peer_id,
        "ext-sub-1",
        "https://peer.example.com",
        Some("toasty@example.com"),
    )
    .await
    .unwrap();

    let resolved = resolve_federated_identity(
        &db,
        &peer,
        "ext-sub-1",
        "https://peer.example.com",
        Some("toasty@example.com"),
        true,
        None,
    )
    .await
    .expect("should resolve with existing link");
    assert_eq!(resolved, user.subject);

    // -- Change peer to auto_link_by_email --
    // Need a new peer for this policy (different domain to avoid duplicate).
    let peer_id2 = create_test_peer(&db, "peer2.example.com", "auto_link_by_email").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id2, "active")
        .await
        .unwrap();
    let peer2 = fed_storage::get_trusted_peer_by_domain(&db, "peer2.example.com")
        .await
        .unwrap()
        .unwrap();

    // -- Test 3: resolve with matching email + email_verified=true -- should auto-link.
    let resolved2 = resolve_federated_identity(
        &db,
        &peer2,
        "ext-sub-2",
        "https://peer2.example.com",
        Some("toasty@example.com"),
        true,
        None,
    )
    .await
    .expect("auto_link_by_email should succeed with matching email");
    assert_eq!(resolved2, user.subject);

    // -- Test 4: resolve with email_verified=false -- should fail.
    let result4 = resolve_federated_identity(
        &db,
        &peer2,
        "ext-sub-3",
        "https://peer2.example.com",
        Some("toasty@example.com"),
        false, // not verified
        None,
    )
    .await;
    assert!(result4.is_err(), "should fail with unverified email");
    assert!(
        matches!(
            result4.unwrap_err(),
            IdentityResolutionError::EmailNotVerified
        ),
        "should be EmailNotVerified error"
    );

    // -- Change peer to auto_provision --
    let peer_id3 = create_test_peer(&db, "peer3.example.com", "auto_provision").await;
    fed_storage::update_trusted_peer_status(&db, &peer_id3, "active")
        .await
        .unwrap();
    let peer3 = fed_storage::get_trusted_peer_by_domain(&db, "peer3.example.com")
        .await
        .unwrap()
        .unwrap();

    // -- Test 5: resolve with new external identity -- should create local user + link.
    let resolved5 = resolve_federated_identity(
        &db,
        &peer3,
        "ext-sub-new",
        "https://peer3.example.com",
        Some("newuser@peer3.example.com"),
        true,
        None,
    )
    .await
    .expect("auto_provision should create a new user");
    assert!(!resolved5.is_empty(), "should return a non-empty subject");

    // Verify a federated identity link was created.
    let link = fed_storage::find_local_user_by_federated_id(&db, &peer_id3, "ext-sub-new")
        .await
        .unwrap();
    assert!(link.is_some(), "federated identity link should exist");
    assert_eq!(link.unwrap().local_user_id, resolved5);

    // -- Test 6: resolve same identity again -- should reuse existing link.
    let resolved6 = resolve_federated_identity(
        &db,
        &peer3,
        "ext-sub-new",
        "https://peer3.example.com",
        Some("newuser@peer3.example.com"),
        true,
        None,
    )
    .await
    .expect("should reuse existing link");
    assert_eq!(resolved6, resolved5, "should return the same local subject");
}

// ---------------------------------------------------------------------------
// Test 6: PKCE generation
// ---------------------------------------------------------------------------

#[test]
fn test_federation_pkce_generation() {
    use barycenter::federation::rp_client::OidcRpClient;
    use base64ct::Encoding;
    use sha2::{Digest, Sha256};

    let (verifier, challenge) = OidcRpClient::generate_pkce();

    // Verify S256: challenge should be SHA256(verifier) base64url-encoded.
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let expected = base64ct::Base64UrlUnpadded::encode_string(&hash);
    assert_eq!(challenge, expected, "PKCE S256 challenge mismatch");

    // Verify verifier length (32 bytes -> 43 chars base64url-unpadded).
    assert_eq!(verifier.len(), 43);
}

// ---------------------------------------------------------------------------
// Test 7: WebFinger domain extraction
// ---------------------------------------------------------------------------

#[test]
fn test_federation_webfinger_extract_domain() {
    use barycenter::federation::webfinger::WebFingerClient;

    assert_eq!(
        WebFingerClient::extract_domain("toasty@wegmueller.it").unwrap(),
        "wegmueller.it"
    );
    assert_eq!(
        WebFingerClient::extract_domain("user@auth.example.com").unwrap(),
        "auth.example.com"
    );
    assert!(WebFingerClient::extract_domain("noatsign").is_err());
    assert!(WebFingerClient::extract_domain("").is_err());
    assert!(WebFingerClient::extract_domain("user@").is_err());
    // Note: "@domain" has an empty local part but the current implementation
    // only validates the domain part is non-empty, so it returns Ok.
    // We test the actual behavior.
    assert_eq!(
        WebFingerClient::extract_domain("@domain.com").unwrap(),
        "domain.com"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Peer request lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_peer_request_lifecycle() {
    let (db, _tmp) = setup_test_db().await;

    let expires_at = "2099-12-31T23:59:59Z";

    // 1. Create a peer request (simulating an incoming peering request).
    let req_id = fed_storage::create_peer_request(
        &db,
        "https://requester.example.com",
        "requester.example.com",
        "client-at-us-123",
        "https://requester.example.com/federation/callback",
        "eyJhbGciOi...", // mock JWS
        expires_at,
    )
    .await
    .expect("failed to create peer request");

    // 2. List pending requests — should have 1.
    let pending = fed_storage::list_pending_peer_requests(&db).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, req_id);
    assert_eq!(pending[0].status, "pending_approval");
    assert_eq!(pending[0].requesting_domain, "requester.example.com");

    // 3. Approve it.
    fed_storage::update_peer_request_status(&db, &req_id, "approved")
        .await
        .unwrap();

    // 4. List pending — should have 0.
    let pending_after = fed_storage::list_pending_peer_requests(&db).await.unwrap();
    assert_eq!(
        pending_after.len(),
        0,
        "approved request should not appear in pending list"
    );

    // Verify the request still exists with updated status.
    let approved = fed_storage::get_peer_request(&db, &req_id)
        .await
        .unwrap()
        .expect("approved request should still exist");
    assert_eq!(approved.status, "approved");

    // 5. Create another, reject it.
    let req_id2 = fed_storage::create_peer_request(
        &db,
        "https://other.example.com",
        "other.example.com",
        "client-at-us-456",
        "https://other.example.com/federation/callback",
        "eyJhbGciOi...",
        expires_at,
    )
    .await
    .unwrap();

    fed_storage::update_peer_request_status(&db, &req_id2, "rejected")
        .await
        .unwrap();

    // 6. Verify rejected requests don't show in pending list.
    let pending_final = fed_storage::list_pending_peer_requests(&db).await.unwrap();
    assert_eq!(
        pending_final.len(),
        0,
        "rejected request should not appear in pending list"
    );

    let rejected = fed_storage::get_peer_request(&db, &req_id2)
        .await
        .unwrap()
        .expect("rejected request should still exist");
    assert_eq!(rejected.status, "rejected");
}

// ---------------------------------------------------------------------------
// Test 9: AMR/ACR propagation in sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_federation_amr_acr_propagation() {
    let (db, _tmp) = setup_test_db().await;

    // Create a user.
    let user = storage::create_user(&db, "feduser", "password123", None)
        .await
        .unwrap();

    // Create a session.
    let now = chrono::Utc::now().timestamp();
    let session = storage::create_session(
        &db,
        &user.subject,
        now,
        3600,
        Some("TestAgent/1.0".to_string()),
        Some("127.0.0.1".to_string()),
    )
    .await
    .unwrap();

    // Initially AMR and ACR should be default/empty.
    assert!(session.amr.is_none() || session.amr.as_deref() == Some(""));

    // Update session with federation AMR/ACR.
    storage::update_session_auth_context(
        &db,
        &session.session_id,
        Some("fed"),  // federated authentication
        Some("aal1"), // single factor via federation
        Some(false),  // not MFA verified yet
    )
    .await
    .unwrap();

    // Verify the session has the updated auth context.
    let updated = storage::get_session(&db, &session.session_id)
        .await
        .unwrap()
        .expect("session should exist");
    assert_eq!(updated.amr.as_deref(), Some("fed"));
    assert_eq!(updated.acr.as_deref(), Some("aal1"));

    // Simulate upgrading to AAL2 with federation + passkey.
    storage::update_session_auth_context(
        &db,
        &session.session_id,
        Some("fed,hwk"), // federated + hardware key
        Some("aal2"),    // two-factor
        Some(true),      // MFA verified
    )
    .await
    .unwrap();

    let upgraded = storage::get_session(&db, &session.session_id)
        .await
        .unwrap()
        .expect("session should exist");
    assert_eq!(upgraded.amr.as_deref(), Some("fed,hwk"));
    assert_eq!(upgraded.acr.as_deref(), Some("aal2"));
    assert_eq!(upgraded.mfa_verified, 1);
}
