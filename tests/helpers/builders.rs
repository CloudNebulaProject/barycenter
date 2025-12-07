use barycenter::entities;
use barycenter::storage;
use sea_orm::DatabaseConnection;

/// Builder for creating test users
pub struct UserBuilder {
    username: String,
    password: String,
    email: Option<String>,
    enabled: bool,
    requires_2fa: bool,
}

impl UserBuilder {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            password: "password123".to_string(),
            email: None,
            enabled: true,
            requires_2fa: false,
        }
    }

    pub fn with_password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    pub fn requires_2fa(mut self) -> Self {
        self.requires_2fa = true;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub async fn create(self, db: &DatabaseConnection) -> entities::user::Model {
        let user = storage::create_user(db, &self.username, &self.password, self.email)
            .await
            .expect("Failed to create test user");

        // Update 2FA and enabled flags if needed
        if !self.enabled || self.requires_2fa {
            storage::update_user(
                db,
                &user.subject,
                self.enabled,
                None,
                if self.requires_2fa { Some(true) } else { None },
            )
            .await
            .expect("Failed to update user flags");

            // Retrieve updated user
            storage::get_user_by_subject(db, &user.subject)
                .await
                .expect("Failed to get updated user")
                .expect("User not found")
        } else {
            user
        }
    }
}

/// Builder for creating test OAuth clients
pub struct ClientBuilder {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        }
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.client_name = Some(name.to_string());
        self
    }

    pub fn with_redirect_uri(mut self, uri: &str) -> Self {
        self.redirect_uris = vec![uri.to_string()];
        self
    }

    pub fn with_redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.redirect_uris = uris;
        self
    }

    pub async fn create(self, db: &DatabaseConnection) -> entities::client::Model {
        storage::create_client(
            db,
            storage::NewClient {
                client_name: self.client_name,
                redirect_uris: self.redirect_uris,
            },
        )
        .await
        .expect("Failed to create test client")
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating test sessions
pub struct SessionBuilder {
    subject: String,
    auth_time: i64,
    ttl: i64,
    amr: Option<Vec<String>>,
    acr: Option<String>,
    mfa_verified: bool,
}

impl SessionBuilder {
    pub fn new(subject: &str) -> Self {
        Self {
            subject: subject.to_string(),
            auth_time: chrono::Utc::now().timestamp(),
            ttl: 3600, // 1 hour
            amr: None,
            acr: None,
            mfa_verified: false,
        }
    }

    pub fn with_auth_time(mut self, auth_time: i64) -> Self {
        self.auth_time = auth_time;
        self
    }

    pub fn with_ttl(mut self, ttl: i64) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_amr(mut self, amr: Vec<String>) -> Self {
        self.amr = Some(amr);
        self
    }

    pub fn with_acr(mut self, acr: &str) -> Self {
        self.acr = Some(acr.to_string());
        self
    }

    pub fn with_mfa_verified(mut self) -> Self {
        self.mfa_verified = true;
        self
    }

    pub async fn create(self, db: &DatabaseConnection) -> entities::session::Model {
        let session = storage::create_session(db, &self.subject, self.auth_time, self.ttl, None, None)
            .await
            .expect("Failed to create test session");

        // Update AMR/ACR/MFA if needed
        if self.amr.is_some() || self.acr.is_some() || self.mfa_verified {
            let amr_json = self.amr.map(|a| serde_json::to_string(&a).unwrap());
            storage::update_session_auth_context(
                db,
                &session.session_id,
                amr_json.as_deref(),
                self.acr.as_deref(),
                if self.mfa_verified { Some(true) } else { None },
            )
            .await
            .expect("Failed to update session auth context");

            // Retrieve updated session
            storage::get_session(db, &session.session_id)
                .await
                .expect("Failed to get updated session")
                .expect("Session not found")
        } else {
            session
        }
    }
}

/// Builder for creating test passkeys
pub struct PasskeyBuilder {
    subject: String,
    name: Option<String>,
    backup_state: bool,
    backup_eligible: bool,
}

impl PasskeyBuilder {
    pub fn new(subject: &str) -> Self {
        Self {
            subject: subject.to_string(),
            name: None,
            backup_state: false,
            backup_eligible: false,
        }
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn cloud_synced(mut self) -> Self {
        self.backup_state = true;
        self.backup_eligible = true;
        self
    }

    pub fn hardware_bound(mut self) -> Self {
        self.backup_state = false;
        self.backup_eligible = false;
        self
    }

    pub async fn create(self, db: &DatabaseConnection) -> entities::passkey::Model {
        // Create a minimal test passkey
        // In real tests, you'd use MockWebAuthnCredential to generate this
        use webauthn_rs::prelude::*;

        // Create a test passkey with minimal data
        let credential_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        let passkey_json = serde_json::json!({
            "cred_id": base64::encode(&credential_id),
            "cred": {
                "counter": 0,
                "backup_state": self.backup_state,
                "backup_eligible": self.backup_eligible
            }
        });

        storage::create_passkey(
            db,
            &base64ct::Base64UrlUnpadded::encode_string(&credential_id),
            &self.subject,
            &serde_json::to_string(&passkey_json).unwrap(),
            0,
            None,
            self.backup_eligible,
            self.backup_state,
            None,
            self.name.as_deref(),
        )
        .await
        .expect("Failed to create test passkey")
    }
}
