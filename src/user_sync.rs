use crate::errors::CrabError;
use crate::storage;
use miette::{IntoDiagnostic, Result};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

/// User definition from JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDefinition {
    /// Username (unique identifier)
    pub username: String,
    /// User email
    #[serde(default)]
    pub email: Option<String>,
    /// Plain text password (will be hashed)
    pub password: String,
    /// Whether the user account is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether the email is verified
    #[serde(default)]
    pub email_verified: bool,
    /// Custom properties to attach to the user
    #[serde(default)]
    pub properties: HashMap<String, Value>,
}

fn default_true() -> bool {
    true
}

/// Root structure of the users JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersFile {
    pub users: Vec<UserDefinition>,
}

/// Sync users from a JSON file to the database (idempotent)
pub async fn sync_users_from_file(db: &DatabaseConnection, file_path: &str) -> Result<()> {
    tracing::info!("Loading users from {}", file_path);

    // Read and parse JSON file
    let content = fs::read_to_string(file_path)
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                "Failed to read users file at '{}': {}",
                file_path,
                e
            )
        })?;

    let users_file: UsersFile = serde_json::from_str(&content)
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                "Failed to parse users JSON file: {}\n\nExpected format:\n{{\n  \"users\": [\n    {{\n      \"username\": \"alice\",\n      \"email\": \"alice@example.com\",\n      \"password\": \"secure-password\",\n      \"enabled\": true,\n      \"email_verified\": false,\n      \"properties\": {{\n        \"department\": \"Engineering\"\n      }}\n    }}\n  ]\n}}",
                e
            )
        })?;

    tracing::info!("Found {} user(s) in file", users_file.users.len());

    let mut created = 0;
    let mut updated = 0;
    let mut unchanged = 0;

    for user_def in users_file.users {
        match sync_user(db, &user_def).await? {
            SyncResult::Created => created += 1,
            SyncResult::Updated => updated += 1,
            SyncResult::Unchanged => unchanged += 1,
        }
    }

    tracing::info!(
        "User sync complete: {} created, {} updated, {} unchanged",
        created,
        updated,
        unchanged
    );

    Ok(())
}

#[derive(Debug)]
enum SyncResult {
    Created,
    Updated,
    Unchanged,
}

/// Sync a single user (idempotent)
async fn sync_user(db: &DatabaseConnection, user_def: &UserDefinition) -> Result<SyncResult> {
    // Check if user exists
    let existing = storage::get_user_by_username(db, &user_def.username)
        .await
        .into_diagnostic()?;

    let result = match existing {
        None => {
            // Create new user
            tracing::info!("Creating user: {}", user_def.username);
            storage::create_user(
                db,
                &user_def.username,
                &user_def.password,
                user_def.email.clone(),
            )
            .await
            .into_diagnostic()?;

            // Update enabled and email_verified flags if needed
            if !user_def.enabled || user_def.email_verified {
                storage::update_user(
                    db,
                    &user_def.username,
                    user_def.enabled,
                    user_def.email_verified,
                )
                .await
                .into_diagnostic()?;
            }

            SyncResult::Created
        }
        Some(existing_user) => {
            // User exists - check if update is needed
            let enabled_matches = (existing_user.enabled == 1) == user_def.enabled;
            let email_verified_matches =
                (existing_user.email_verified == 1) == user_def.email_verified;
            let email_matches = existing_user.email == user_def.email;

            if !enabled_matches || !email_verified_matches || !email_matches {
                tracing::info!("Updating user: {}", user_def.username);
                storage::update_user(
                    db,
                    &user_def.username,
                    user_def.enabled,
                    user_def.email_verified,
                )
                .await
                .into_diagnostic()?;

                // Update email if it changed
                if !email_matches {
                    storage::update_user_email(db, &user_def.username, user_def.email.clone())
                        .await
                        .into_diagnostic()?;
                }

                SyncResult::Updated
            } else {
                SyncResult::Unchanged
            }
        }
    };

    // Sync properties
    for (key, value) in &user_def.properties {
        // Get the user's subject to use as owner for properties
        let user = storage::get_user_by_username(db, &user_def.username)
            .await
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("User not found after creation: {}", user_def.username))?;

        storage::set_property(db, &user.subject, key, value)
            .await
            .into_diagnostic()?;
    }

    if !user_def.properties.is_empty() {
        tracing::debug!(
            "Synced {} properties for user {}",
            user_def.properties.len(),
            user_def.username
        );
    }

    Ok(result)
}
