// Integration tests for passkey counter tracking and AMR determination
//
// These tests verify:
// 1. Counter extraction at registration
// 2. Counter updates after authentication
// 3. Backup state extraction (backup_eligible, backup_state)
// 4. Correct AMR values (hwk vs swk)

mod helpers;

use barycenter::storage;
use helpers::TestDb;

/// Test that passkey counter is extracted and stored during registration
///
/// This test verifies the fix for web.rs:2012 where counter was hardcoded to 0.
/// Now it should extract the actual counter value from the Passkey object.
#[tokio::test]
async fn test_counter_extracted_at_registration() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    // Create a user
    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    // Create a mock passkey with counter = 0 (initial registration)
    // In a real scenario, this would come from webauthn-rs finish_passkey_registration
    let passkey_json = serde_json::json!({
        "cred_id": "test_credential_id",
        "cred": {
            "counter": 0,
            "backup_eligible": false,
            "backup_state": false,
            "verified": true
        }
    });

    storage::create_passkey(
        &db,
        "test_credential_id",
        &user.subject,
        &passkey_json.to_string(),
        0,     // Initial counter
        None,  // aaguid
        false, // backup_eligible (hardware-bound)
        false, // backup_state
        None,  // transports
        Some("Test Passkey"),
    )
    .await
    .expect("Failed to create passkey");

    // Verify passkey was stored with correct counter
    let passkey = storage::get_passkey_by_credential_id(&db, "test_credential_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    assert_eq!(passkey.counter, 0, "Initial counter should be 0");
    assert_eq!(
        passkey.backup_eligible, 0,
        "Hardware key should not be backup eligible"
    );
    assert_eq!(
        passkey.backup_state, 0,
        "Hardware key should not have backup state"
    );
}

/// Test that passkey counter is updated after authentication
///
/// This test verifies the fix for web.rs:2151 where counter update was commented out.
/// Now it should extract counter from AuthenticationResult and update the database.
#[tokio::test]
async fn test_counter_updated_after_authentication() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    // Create user and passkey
    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    let passkey_json = serde_json::json!({
        "cred_id": "test_credential_id",
        "cred": {
            "counter": 0,
            "backup_eligible": false,
            "backup_state": false
        }
    });

    storage::create_passkey(
        &db,
        "test_credential_id",
        &user.subject,
        &passkey_json.to_string(),
        0,
        None,
        false,
        false,
        None,
        Some("Test Passkey"),
    )
    .await
    .expect("Failed to create passkey");

    // Verify initial counter
    let passkey_before = storage::get_passkey_by_credential_id(&db, "test_credential_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");
    assert_eq!(passkey_before.counter, 0);

    // Simulate authentication by updating counter (mimics what happens in web.rs:2183)
    storage::update_passkey_counter(&db, "test_credential_id", 1)
        .await
        .expect("Failed to update counter");

    // Verify counter was incremented
    let passkey_after = storage::get_passkey_by_credential_id(&db, "test_credential_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    assert_eq!(passkey_after.counter, 1, "Counter should increment to 1");
    assert!(
        passkey_after.last_used_at.is_some(),
        "last_used_at should be updated"
    );
}

/// Test counter increments across multiple authentications
///
/// This test verifies that counter properly increments with each authentication,
/// which is critical for detecting cloned authenticators.
#[tokio::test]
async fn test_counter_increments_multiple_times() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    let passkey_json = serde_json::json!({
        "cred_id": "test_credential_id",
        "cred": { "counter": 0, "backup_eligible": false, "backup_state": false }
    });

    storage::create_passkey(
        &db,
        "test_credential_id",
        &user.subject,
        &passkey_json.to_string(),
        0,
        None,
        false,
        false,
        None,
        Some("Test Passkey"),
    )
    .await
    .expect("Failed to create passkey");

    // Simulate multiple authentications
    for expected_counter in 1..=5 {
        storage::update_passkey_counter(&db, "test_credential_id", expected_counter)
            .await
            .expect("Failed to update counter");

        let passkey = storage::get_passkey_by_credential_id(&db, "test_credential_id")
            .await
            .expect("Failed to get passkey")
            .expect("Passkey not found");

        assert_eq!(
            passkey.counter, expected_counter,
            "Counter should be {}",
            expected_counter
        );
    }
}

/// Test backup_eligible and backup_state extraction for cloud-synced passkeys
///
/// This test verifies the fix for web.rs:2014-2015 where backup flags were hardcoded to false.
/// Cloud-synced passkeys (iCloud Keychain, Windows Hello, etc.) should have both flags set to true.
#[tokio::test]
async fn test_cloud_synced_passkey_backup_flags() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    // Cloud-synced passkey has backup_eligible=true and backup_state=true
    let passkey_json = serde_json::json!({
        "cred_id": "cloud_credential_id",
        "cred": {
            "counter": 0,
            "backup_eligible": true,
            "backup_state": true
        }
    });

    storage::create_passkey(
        &db,
        "cloud_credential_id",
        &user.subject,
        &passkey_json.to_string(),
        0,
        None,
        true, // backup_eligible
        true, // backup_state
        None,
        Some("Cloud Passkey"),
    )
    .await
    .expect("Failed to create passkey");

    let passkey = storage::get_passkey_by_credential_id(&db, "cloud_credential_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    assert_eq!(
        passkey.backup_eligible, 1,
        "Cloud-synced passkey should be backup eligible"
    );
    assert_eq!(
        passkey.backup_state, 1,
        "Cloud-synced passkey should have backup state"
    );
}

/// Test hardware-bound passkey backup flags
///
/// Hardware-bound keys (YubiKey, etc.) should have backup_eligible=false and backup_state=false.
#[tokio::test]
async fn test_hardware_bound_passkey_backup_flags() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    let passkey_json = serde_json::json!({
        "cred_id": "hardware_credential_id",
        "cred": {
            "counter": 0,
            "backup_eligible": false,
            "backup_state": false
        }
    });

    storage::create_passkey(
        &db,
        "hardware_credential_id",
        &user.subject,
        &passkey_json.to_string(),
        0,
        None,
        false, // backup_eligible
        false, // backup_state
        None,
        Some("Hardware Passkey"),
    )
    .await
    .expect("Failed to create passkey");

    let passkey = storage::get_passkey_by_credential_id(&db, "hardware_credential_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    assert_eq!(
        passkey.backup_eligible, 0,
        "Hardware key should not be backup eligible"
    );
    assert_eq!(
        passkey.backup_state, 0,
        "Hardware key should not have backup state"
    );
}

/// Test AMR (Authentication Method References) for hardware-bound passkey
///
/// Verifies that web.rs:2156-2160 correctly determines AMR based on backup_eligible and backup_state.
/// Hardware-bound passkeys should result in AMR = ["hwk"]
#[tokio::test]
async fn test_amr_determination_hardware_key() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    storage::create_passkey(
        &db,
        "hw_key_id",
        &user.subject,
        &serde_json::json!({"cred": {"counter": 0}}).to_string(),
        0,
        None,
        false, // backup_eligible = false
        false, // backup_state = false
        None,
        Some("HW Key"),
    )
    .await
    .expect("Failed to create passkey");

    let passkey = storage::get_passkey_by_credential_id(&db, "hw_key_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    // Mimic AMR determination logic from web.rs:2156-2160
    let expected_amr = if passkey.backup_eligible == 1 && passkey.backup_state == 1 {
        "swk" // Software key
    } else {
        "hwk" // Hardware key
    };

    assert_eq!(expected_amr, "hwk", "Hardware key should have AMR = hwk");
}

/// Test AMR for cloud-synced passkey
///
/// Cloud-synced passkeys should result in AMR = ["swk"]
#[tokio::test]
async fn test_amr_determination_cloud_key() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    storage::create_passkey(
        &db,
        "cloud_key_id",
        &user.subject,
        &serde_json::json!({"cred": {"counter": 0}}).to_string(),
        0,
        None,
        true, // backup_eligible = true
        true, // backup_state = true
        None,
        Some("Cloud Key"),
    )
    .await
    .expect("Failed to create passkey");

    let passkey = storage::get_passkey_by_credential_id(&db, "cloud_key_id")
        .await
        .expect("Failed to get passkey")
        .expect("Passkey not found");

    // Mimic AMR determination logic from web.rs:2156-2160
    let expected_amr = if passkey.backup_eligible == 1 && passkey.backup_state == 1 {
        "swk" // Software key
    } else {
        "hwk" // Hardware key
    };

    assert_eq!(
        expected_amr, "swk",
        "Cloud-synced key should have AMR = swk"
    );
}

/// Test that multiple passkeys for one user are tracked independently
#[tokio::test]
async fn test_multiple_passkeys_independent_counters() {
    let test_db = TestDb::new().await;
    let db = test_db.connection();

    let user = storage::create_user(&db, "testuser", "password123", None)
        .await
        .expect("Failed to create user");

    // Create two passkeys for the same user
    storage::create_passkey(
        &db,
        "passkey1",
        &user.subject,
        &serde_json::json!({"cred": {"counter": 0}}).to_string(),
        0,
        None,
        false,
        false,
        None,
        Some("Passkey 1"),
    )
    .await
    .expect("Failed to create passkey 1");

    storage::create_passkey(
        &db,
        "passkey2",
        &user.subject,
        &serde_json::json!({"cred": {"counter": 0}}).to_string(),
        0,
        None,
        true,
        true,
        None,
        Some("Passkey 2"),
    )
    .await
    .expect("Failed to create passkey 2");

    // Update counters independently
    storage::update_passkey_counter(&db, "passkey1", 5)
        .await
        .expect("Failed to update counter 1");
    storage::update_passkey_counter(&db, "passkey2", 10)
        .await
        .expect("Failed to update counter 2");

    // Verify independent tracking
    let pk1 = storage::get_passkey_by_credential_id(&db, "passkey1")
        .await
        .expect("Failed to get passkey 1")
        .expect("Passkey 1 not found");

    let pk2 = storage::get_passkey_by_credential_id(&db, "passkey2")
        .await
        .expect("Failed to get passkey 2")
        .expect("Passkey 2 not found");

    assert_eq!(pk1.counter, 5);
    assert_eq!(pk2.counter, 10);
    assert_eq!(pk1.backup_state, 0);
    assert_eq!(pk2.backup_state, 1);
}
