use crate::entities;
use crate::errors::CrabError;
use crate::settings::Database as DbCfg;
use base64ct::Encoding;
use chrono::Utc;
use rand::{Rng, RngCore};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewClient {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub subject: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub consumed: i64,
    pub auth_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub subject: String,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub subject: String,
    pub username: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub email_verified: i64,
    pub created_at: i64,
    pub enabled: i64,
    pub requires_2fa: i64,
    pub passkey_enrolled_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub subject: String,
    pub auth_time: i64,
    pub created_at: i64,
    pub expires_at: i64,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub amr: Option<String>,
    pub acr: Option<String>,
    pub mfa_verified: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub subject: String,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: i64,
    pub parent_token: Option<String>, // For token rotation tracking
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub scope: String,
    pub device_info: Option<String>, // JSON: {ip_address, user_agent}
    pub created_at: i64,
    pub expires_at: i64,
    pub last_poll_at: Option<i64>,
    pub interval: i64,
    pub status: String, // "pending" | "approved" | "denied" | "consumed"
    pub subject: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Option<String>, // JSON array: ["pwd", "hwk"]
    pub acr: Option<String>, // "aal1" or "aal2"
}

pub async fn init(cfg: &DbCfg) -> Result<DatabaseConnection, CrabError> {
    let db = Database::connect(&cfg.url).await?;
    Ok(db)
}

pub async fn create_client(db: &DatabaseConnection, input: NewClient) -> Result<Client, CrabError> {
    let client_id = random_id();
    let client_secret = random_id();
    let created_at = Utc::now().timestamp();
    let redirect_uris_json = serde_json::to_string(&input.redirect_uris)?;

    let client = entities::client::ActiveModel {
        client_id: Set(client_id.clone()),
        client_secret: Set(client_secret.clone()),
        client_name: Set(input.client_name.clone()),
        redirect_uris: Set(redirect_uris_json),
        created_at: Set(created_at),
    };

    client.insert(db).await?;

    Ok(Client {
        client_id,
        client_secret,
        client_name: input.client_name,
        redirect_uris: input.redirect_uris,
        created_at,
    })
}

pub async fn get_property(
    db: &DatabaseConnection,
    owner: &str,
    key: &str,
) -> Result<Option<Value>, CrabError> {
    use entities::property::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::Owner.eq(owner))
        .filter(Column::Key.eq(key))
        .one(db)
        .await?
    {
        let json: Value = serde_json::from_str(&model.value)?;
        Ok(Some(json))
    } else {
        Ok(None)
    }
}

pub async fn set_property(
    db: &DatabaseConnection,
    owner: &str,
    key: &str,
    value: &Value,
) -> Result<(), CrabError> {
    use entities::property::{Column, Entity};
    use sea_orm::sea_query::OnConflict;

    let now = Utc::now().timestamp();
    let json = serde_json::to_string(value)?;

    let property = entities::property::ActiveModel {
        owner: Set(owner.to_string()),
        key: Set(key.to_string()),
        value: Set(json.clone()),
        updated_at: Set(now),
    };

    Entity::insert(property)
        .on_conflict(
            OnConflict::columns([Column::Owner, Column::Key])
                .update_columns([Column::Value, Column::UpdatedAt])
                .to_owned(),
        )
        .exec(db)
        .await?;

    Ok(())
}

pub async fn get_client(
    db: &DatabaseConnection,
    client_id: &str,
) -> Result<Option<Client>, CrabError> {
    use entities::client::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::ClientId.eq(client_id))
        .one(db)
        .await?
    {
        let redirect_uris: Vec<String> = serde_json::from_str(&model.redirect_uris)?;
        Ok(Some(Client {
            client_id: model.client_id,
            client_secret: model.client_secret,
            client_name: model.client_name,
            redirect_uris,
            created_at: model.created_at,
        }))
    } else {
        Ok(None)
    }
}

pub async fn issue_auth_code(
    db: &DatabaseConnection,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    subject: &str,
    nonce: Option<String>,
    code_challenge: &str,
    code_challenge_method: &str,
    ttl_secs: i64,
    auth_time: Option<i64>,
) -> Result<AuthCode, CrabError> {
    let code = random_id();
    let now = Utc::now().timestamp();
    let expires_at = now + ttl_secs;

    let auth_code = entities::auth_code::ActiveModel {
        code: Set(code.clone()),
        client_id: Set(client_id.to_string()),
        redirect_uri: Set(redirect_uri.to_string()),
        scope: Set(scope.to_string()),
        subject: Set(subject.to_string()),
        nonce: Set(nonce.clone()),
        code_challenge: Set(code_challenge.to_string()),
        code_challenge_method: Set(code_challenge_method.to_string()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        consumed: Set(0),
        auth_time: Set(auth_time),
    };

    auth_code.insert(db).await?;

    Ok(AuthCode {
        code,
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope: scope.to_string(),
        subject: subject.to_string(),
        nonce,
        code_challenge: code_challenge.to_string(),
        code_challenge_method: code_challenge_method.to_string(),
        created_at: now,
        expires_at,
        consumed: 0,
        auth_time,
    })
}

pub async fn consume_auth_code(
    db: &DatabaseConnection,
    code: &str,
) -> Result<Option<AuthCode>, CrabError> {
    use entities::auth_code::{Column, Entity};

    if let Some(model) = Entity::find().filter(Column::Code.eq(code)).one(db).await? {
        let now = Utc::now().timestamp();
        if model.consumed != 0 || now > model.expires_at {
            return Ok(None);
        }

        // Mark as consumed
        let mut active_model: entities::auth_code::ActiveModel = model.clone().into();
        active_model.consumed = Set(1);
        active_model.update(db).await?;

        Ok(Some(AuthCode {
            code: model.code,
            client_id: model.client_id,
            redirect_uri: model.redirect_uri,
            scope: model.scope,
            subject: model.subject,
            nonce: model.nonce,
            code_challenge: model.code_challenge,
            code_challenge_method: model.code_challenge_method,
            created_at: model.created_at,
            expires_at: model.expires_at,
            consumed: 1,
            auth_time: model.auth_time,
        }))
    } else {
        Ok(None)
    }
}

pub async fn issue_access_token(
    db: &DatabaseConnection,
    client_id: &str,
    subject: &str,
    scope: &str,
    ttl_secs: i64,
) -> Result<AccessToken, CrabError> {
    let token = random_id();
    let now = Utc::now().timestamp();
    let expires_at = now + ttl_secs;

    let access_token = entities::access_token::ActiveModel {
        token: Set(token.clone()),
        client_id: Set(client_id.to_string()),
        subject: Set(subject.to_string()),
        scope: Set(scope.to_string()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        revoked: Set(0),
    };

    access_token.insert(db).await?;

    Ok(AccessToken {
        token,
        client_id: client_id.to_string(),
        subject: subject.to_string(),
        scope: scope.to_string(),
        created_at: now,
        expires_at,
        revoked: 0,
    })
}

pub async fn get_access_token(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<AccessToken>, CrabError> {
    use entities::access_token::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::Token.eq(token))
        .one(db)
        .await?
    {
        let now = Utc::now().timestamp();
        if model.revoked != 0 || now > model.expires_at {
            return Ok(None);
        }

        Ok(Some(AccessToken {
            token: model.token,
            client_id: model.client_id,
            subject: model.subject,
            scope: model.scope,
            created_at: model.created_at,
            expires_at: model.expires_at,
            revoked: model.revoked,
        }))
    } else {
        Ok(None)
    }
}

fn random_id() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64ct::Base64UrlUnpadded::encode_string(&bytes)
}

/// Generate 8-character base-20 user code in format XXXX-XXXX
/// Alphabet: BCDFGHJKLMNPQRSTVWXZ (consonants only, no ambiguous chars)
/// Entropy: 20^8 = ~43 bits
fn generate_user_code() -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut rng = rand::thread_rng();
    let mut code = String::with_capacity(9);

    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        let idx = rng.gen_range(0..ALPHABET.len());
        code.push(ALPHABET[idx] as char);
    }

    code
}

// User management functions

pub async fn create_user(
    db: &DatabaseConnection,
    username: &str,
    password: &str,
    email: Option<String>,
) -> Result<User, CrabError> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};

    let subject = random_id();
    let created_at = Utc::now().timestamp();

    // Hash password with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CrabError::Other(format!("Password hashing failed: {}", e)))?
        .to_string();

    let user = entities::user::ActiveModel {
        subject: Set(subject.clone()),
        username: Set(username.to_string()),
        password_hash: Set(password_hash.clone()),
        email: Set(email.clone()),
        email_verified: Set(0),
        created_at: Set(created_at),
        enabled: Set(1),
        requires_2fa: Set(0),
        passkey_enrolled_at: Set(None),
    };

    user.insert(db).await?;

    Ok(User {
        subject,
        username: username.to_string(),
        password_hash,
        email,
        email_verified: 0,
        created_at,
        enabled: 1,
        requires_2fa: 0,
        passkey_enrolled_at: None,
    })
}

pub async fn get_user_by_username(
    db: &DatabaseConnection,
    username: &str,
) -> Result<Option<User>, CrabError> {
    use entities::user::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::Username.eq(username))
        .one(db)
        .await?
    {
        Ok(Some(User {
            subject: model.subject,
            username: model.username,
            password_hash: model.password_hash,
            email: model.email,
            email_verified: model.email_verified,
            created_at: model.created_at,
            enabled: model.enabled,
            requires_2fa: model.requires_2fa,
            passkey_enrolled_at: model.passkey_enrolled_at,
        }))
    } else {
        Ok(None)
    }
}

pub async fn verify_user_password(
    db: &DatabaseConnection,
    username: &str,
    password: &str,
) -> Result<Option<String>, CrabError> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let user = match get_user_by_username(db, username).await? {
        Some(u) if u.enabled == 1 => u,
        _ => return Ok(None),
    };

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|e| CrabError::Other(format!("Invalid password hash: {}", e)))?;

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        Ok(Some(user.subject))
    } else {
        Ok(None)
    }
}

/// Update user fields (enabled, email, requires_2fa)
pub async fn update_user(
    db: &DatabaseConnection,
    subject: &str,
    enabled: bool,
    email: Option<String>,
    requires_2fa: Option<bool>,
) -> Result<(), CrabError> {
    use entities::user::{Column, Entity};

    // Find the user by subject
    let user = Entity::find()
        .filter(Column::Subject.eq(subject))
        .one(db)
        .await?
        .ok_or_else(|| CrabError::Other(format!("User not found: {}", subject)))?;

    // Update the user
    let mut active: entities::user::ActiveModel = user.into();
    active.enabled = Set(if enabled { 1 } else { 0 });

    if let Some(email_val) = email {
        active.email = Set(Some(email_val));
    }

    if let Some(requires_2fa_val) = requires_2fa {
        active.requires_2fa = Set(if requires_2fa_val { 1 } else { 0 });
    }

    active.update(db).await?;

    Ok(())
}

/// Update user email
pub async fn update_user_email(
    db: &DatabaseConnection,
    username: &str,
    email: Option<String>,
) -> Result<(), CrabError> {
    use entities::user::{Column, Entity};

    // Find the user
    let user = Entity::find()
        .filter(Column::Username.eq(username))
        .one(db)
        .await?
        .ok_or_else(|| CrabError::Other(format!("User not found: {}", username)))?;

    // Update the user
    let mut active: entities::user::ActiveModel = user.into();
    active.email = Set(email);
    active.update(db).await?;

    Ok(())
}

// Session management functions

pub async fn create_session(
    db: &DatabaseConnection,
    subject: &str,
    auth_time: i64,
    ttl_secs: i64,
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> Result<Session, CrabError> {
    let session_id = random_id();
    let now = Utc::now().timestamp();
    let expires_at = auth_time + ttl_secs;

    let session = entities::session::ActiveModel {
        session_id: Set(session_id.clone()),
        subject: Set(subject.to_string()),
        auth_time: Set(auth_time),
        created_at: Set(now),
        expires_at: Set(expires_at),
        user_agent: Set(user_agent.clone()),
        ip_address: Set(ip_address.clone()),
        amr: Set(None),
        acr: Set(None),
        mfa_verified: Set(0),
    };

    session.insert(db).await?;

    Ok(Session {
        session_id,
        subject: subject.to_string(),
        auth_time,
        created_at: now,
        expires_at,
        user_agent,
        ip_address,
        amr: None,
        acr: None,
        mfa_verified: 0,
    })
}

pub async fn get_session(
    db: &DatabaseConnection,
    session_id: &str,
) -> Result<Option<Session>, CrabError> {
    use entities::session::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::SessionId.eq(session_id))
        .one(db)
        .await?
    {
        // Check if session is expired
        let now = Utc::now().timestamp();
        if now > model.expires_at {
            return Ok(None);
        }

        Ok(Some(Session {
            session_id: model.session_id,
            subject: model.subject,
            auth_time: model.auth_time,
            created_at: model.created_at,
            expires_at: model.expires_at,
            user_agent: model.user_agent,
            ip_address: model.ip_address,
            amr: model.amr,
            acr: model.acr,
            mfa_verified: model.mfa_verified,
        }))
    } else {
        Ok(None)
    }
}

pub async fn delete_session(db: &DatabaseConnection, session_id: &str) -> Result<(), CrabError> {
    use entities::session::{Column, Entity};

    Entity::delete_many()
        .filter(Column::SessionId.eq(session_id))
        .exec(db)
        .await?;

    Ok(())
}

pub async fn cleanup_expired_sessions(db: &DatabaseConnection) -> Result<u64, CrabError> {
    use entities::session::{Column, Entity};

    let now = Utc::now().timestamp();
    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

// Refresh Token Functions

pub async fn issue_refresh_token(
    db: &DatabaseConnection,
    client_id: &str,
    subject: &str,
    scope: &str,
    ttl_secs: i64,
    parent_token: Option<String>,
) -> Result<RefreshToken, CrabError> {
    let token = random_id();
    let now = Utc::now().timestamp();
    let expires_at = now + ttl_secs;

    let refresh_token = entities::refresh_token::ActiveModel {
        token: Set(token.clone()),
        client_id: Set(client_id.to_string()),
        subject: Set(subject.to_string()),
        scope: Set(scope.to_string()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        revoked: Set(0),
        parent_token: Set(parent_token.clone()),
    };

    refresh_token.insert(db).await?;

    Ok(RefreshToken {
        token,
        client_id: client_id.to_string(),
        subject: subject.to_string(),
        scope: scope.to_string(),
        created_at: now,
        expires_at,
        revoked: 0,
        parent_token,
    })
}

pub async fn get_refresh_token(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<RefreshToken>, CrabError> {
    use entities::refresh_token::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::Token.eq(token))
        .one(db)
        .await?
    {
        // Check if token is expired or revoked
        let now = Utc::now().timestamp();
        if model.revoked != 0 || now > model.expires_at {
            return Ok(None);
        }

        Ok(Some(RefreshToken {
            token: model.token,
            client_id: model.client_id,
            subject: model.subject,
            scope: model.scope,
            created_at: model.created_at,
            expires_at: model.expires_at,
            revoked: model.revoked,
            parent_token: model.parent_token,
        }))
    } else {
        Ok(None)
    }
}

pub async fn revoke_refresh_token(db: &DatabaseConnection, token: &str) -> Result<(), CrabError> {
    use entities::refresh_token::{Column, Entity};

    // Find the token and update it
    if let Some(model) = Entity::find()
        .filter(Column::Token.eq(token))
        .one(db)
        .await?
    {
        let mut active_model: entities::refresh_token::ActiveModel = model.into();
        active_model.revoked = Set(1);
        active_model.update(db).await?;
    }

    Ok(())
}

pub async fn rotate_refresh_token(
    db: &DatabaseConnection,
    old_token: &str,
    client_id: &str,
    subject: &str,
    scope: &str,
    ttl_secs: i64,
) -> Result<RefreshToken, CrabError> {
    // Revoke the old token
    revoke_refresh_token(db, old_token).await?;

    // Issue a new token with the old token as parent
    issue_refresh_token(
        db,
        client_id,
        subject,
        scope,
        ttl_secs,
        Some(old_token.to_string()),
    )
    .await
}

pub async fn cleanup_expired_refresh_tokens(db: &DatabaseConnection) -> Result<u64, CrabError> {
    use entities::refresh_token::{Column, Entity};

    let now = Utc::now().timestamp();
    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

// User helper functions

pub async fn get_user_by_subject(
    db: &DatabaseConnection,
    subject: &str,
) -> Result<Option<User>, CrabError> {
    use entities::user::{Column, Entity};

    if let Some(model) = Entity::find()
        .filter(Column::Subject.eq(subject))
        .one(db)
        .await?
    {
        Ok(Some(User {
            subject: model.subject,
            username: model.username,
            password_hash: model.password_hash,
            email: model.email,
            email_verified: model.email_verified,
            created_at: model.created_at,
            enabled: model.enabled,
            requires_2fa: model.requires_2fa,
            passkey_enrolled_at: model.passkey_enrolled_at,
        }))
    } else {
        Ok(None)
    }
}

// Passkey management functions

pub async fn create_passkey(
    db: &DatabaseConnection,
    credential_id: &str,
    subject: &str,
    passkey_json: &str,
    counter: i64,
    aaguid: Option<String>,
    backup_eligible: bool,
    backup_state: bool,
    transports: Option<String>,
    name: Option<&str>,
) -> Result<entities::passkey::Model, CrabError> {
    use entities::passkey;

    let now = Utc::now().timestamp();

    let passkey = passkey::ActiveModel {
        credential_id: Set(credential_id.to_string()),
        subject: Set(subject.to_string()),
        public_key_cose: Set(passkey_json.to_string()),
        counter: Set(counter),
        aaguid: Set(aaguid),
        backup_eligible: Set(if backup_eligible { 1 } else { 0 }),
        backup_state: Set(if backup_state { 1 } else { 0 }),
        transports: Set(transports),
        name: Set(name.map(|n| n.to_string())),
        created_at: Set(now),
        last_used_at: Set(None),
    };

    let result = passkey.insert(db).await?;

    // Update user's passkey_enrolled_at if this is their first passkey
    use entities::user::{Column as UserColumn, Entity as UserEntity};

    if let Some(user) = UserEntity::find()
        .filter(UserColumn::Subject.eq(subject))
        .one(db)
        .await?
    {
        if user.passkey_enrolled_at.is_none() {
            let mut user_active: entities::user::ActiveModel = user.into();
            user_active.passkey_enrolled_at = Set(Some(now));
            user_active.update(db).await?;
        }
    }

    Ok(result)
}

pub async fn get_passkey_by_credential_id(
    db: &DatabaseConnection,
    credential_id: &str,
) -> Result<Option<entities::passkey::Model>, CrabError> {
    use entities::passkey::{Column, Entity};

    let passkey = Entity::find()
        .filter(Column::CredentialId.eq(credential_id))
        .one(db)
        .await?;

    Ok(passkey)
}

pub async fn get_passkeys_by_subject(
    db: &DatabaseConnection,
    subject: &str,
) -> Result<Vec<entities::passkey::Model>, CrabError> {
    use entities::passkey::{Column, Entity};

    let passkeys = Entity::find()
        .filter(Column::Subject.eq(subject))
        .all(db)
        .await?;

    Ok(passkeys)
}

pub async fn update_passkey_counter(
    db: &DatabaseConnection,
    credential_id: &str,
    new_counter: i64,
) -> Result<(), CrabError> {
    use entities::passkey::{Column, Entity};

    let now = Utc::now().timestamp();

    if let Some(passkey) = Entity::find()
        .filter(Column::CredentialId.eq(credential_id))
        .one(db)
        .await?
    {
        let mut active: entities::passkey::ActiveModel = passkey.into();
        active.counter = Set(new_counter);
        active.last_used_at = Set(Some(now));
        active.update(db).await?;
    }

    Ok(())
}

pub async fn update_passkey_name(
    db: &DatabaseConnection,
    credential_id: &str,
    name: Option<String>,
) -> Result<(), CrabError> {
    use entities::passkey::{Column, Entity};

    if let Some(passkey) = Entity::find()
        .filter(Column::CredentialId.eq(credential_id))
        .one(db)
        .await?
    {
        let mut active: entities::passkey::ActiveModel = passkey.into();
        active.name = Set(name);
        active.update(db).await?;
    }

    Ok(())
}

pub async fn delete_passkey(db: &DatabaseConnection, credential_id: &str) -> Result<(), CrabError> {
    use entities::passkey::{Column, Entity};

    Entity::delete_many()
        .filter(Column::CredentialId.eq(credential_id))
        .exec(db)
        .await?;

    Ok(())
}

// WebAuthn challenge management

pub async fn create_webauthn_challenge(
    db: &DatabaseConnection,
    challenge: &str,
    subject: Option<&str>,
    session_id: Option<&str>,
    challenge_type: &str,
    options_json: &str,
) -> Result<entities::webauthn_challenge::Model, CrabError> {
    use entities::webauthn_challenge;

    let now = Utc::now().timestamp();
    let expires_at = now + 300; // 5 minutes

    let challenge_model = webauthn_challenge::ActiveModel {
        challenge: Set(challenge.to_string()),
        subject: Set(subject.map(|s| s.to_string())),
        session_id: Set(session_id.map(|s| s.to_string())),
        challenge_type: Set(challenge_type.to_string()),
        options_json: Set(options_json.to_string()),
        created_at: Set(now),
        expires_at: Set(expires_at),
    };

    let result = challenge_model.insert(db).await?;
    Ok(result)
}

pub async fn get_latest_webauthn_challenge_by_subject(
    db: &DatabaseConnection,
    subject: &str,
    challenge_type: &str,
) -> Result<Option<entities::webauthn_challenge::Model>, CrabError> {
    use entities::webauthn_challenge::{Column, Entity};

    let now = Utc::now().timestamp();

    let challenge = Entity::find()
        .filter(Column::Subject.eq(subject))
        .filter(Column::ChallengeType.eq(challenge_type))
        .filter(Column::ExpiresAt.gt(now))
        .order_by_desc(Column::CreatedAt)
        .one(db)
        .await?;

    Ok(challenge)
}

pub async fn delete_webauthn_challenge(
    db: &DatabaseConnection,
    challenge: &str,
) -> Result<(), CrabError> {
    use entities::webauthn_challenge::{Column, Entity};

    Entity::delete_many()
        .filter(Column::Challenge.eq(challenge))
        .exec(db)
        .await?;

    Ok(())
}

pub async fn cleanup_expired_challenges(db: &DatabaseConnection) -> Result<u64, CrabError> {
    use entities::webauthn_challenge::{Column, Entity};

    let now = Utc::now().timestamp();
    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

// Session authentication context management

pub async fn update_session_auth_context(
    db: &DatabaseConnection,
    session_id: &str,
    amr: Option<&str>,
    acr: Option<&str>,
    mfa_verified: Option<bool>,
) -> Result<(), CrabError> {
    use entities::session::{Column, Entity};

    if let Some(session) = Entity::find()
        .filter(Column::SessionId.eq(session_id))
        .one(db)
        .await?
    {
        let mut active: entities::session::ActiveModel = session.into();

        if let Some(amr_val) = amr {
            active.amr = Set(Some(amr_val.to_string()));
        }

        if let Some(acr_val) = acr {
            active.acr = Set(Some(acr_val.to_string()));
        }

        if let Some(mfa_val) = mfa_verified {
            active.mfa_verified = Set(if mfa_val { 1 } else { 0 });
        }

        active.update(db).await?;
    }

    Ok(())
}

pub async fn append_session_amr(
    db: &DatabaseConnection,
    session_id: &str,
    new_amr: &str,
) -> Result<(), CrabError> {
    use entities::session::{Column, Entity};

    if let Some(session) = Entity::find()
        .filter(Column::SessionId.eq(session_id))
        .one(db)
        .await?
    {
        let mut amr_array: Vec<String> = if let Some(existing_amr) = &session.amr {
            serde_json::from_str(existing_amr).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };

        // Only append if not already present
        if !amr_array.contains(&new_amr.to_string()) {
            amr_array.push(new_amr.to_string());
        }

        let amr_json = serde_json::to_string(&amr_array)?;

        let mut active: entities::session::ActiveModel = session.into();
        active.amr = Set(Some(amr_json));
        active.update(db).await?;
    }

    Ok(())
}

/// Revoke an access token by marking it as revoked (RFC 7009)
pub async fn revoke_access_token(db: &DatabaseConnection, token: &str) -> Result<(), CrabError> {
    use entities::access_token::{Column, Entity};

    if let Some(at) = Entity::find()
        .filter(Column::Token.eq(token))
        .one(db)
        .await?
    {
        let mut active: entities::access_token::ActiveModel = at.into();
        active.revoked = Set(1);
        active.update(db).await?;
    }
    Ok(())
}

// ============================================================================
// Consent Operations
// ============================================================================

/// Grant consent for a client to access a user's resources with specific scopes
pub async fn grant_consent(
    db: &DatabaseConnection,
    client_id: &str,
    subject: &str,
    scope: &str,
    ttl_secs: Option<i64>,
) -> Result<entities::consent::Model, CrabError> {
    use entities::consent;

    let now = Utc::now().timestamp();
    let expires_at = ttl_secs.map(|ttl| now + ttl);

    let consent = consent::ActiveModel {
        id: Default::default(),
        client_id: Set(client_id.to_string()),
        subject: Set(subject.to_string()),
        scope: Set(scope.to_string()),
        granted_at: Set(now),
        expires_at: Set(expires_at),
        revoked: Set(0),
    };

    Ok(consent.insert(db).await?)
}

/// Check if consent exists for a client and subject with the requested scopes
///
/// Returns true if:
/// - A non-revoked consent exists
/// - The consent covers all requested scopes
/// - The consent hasn't expired
pub async fn has_consent(
    db: &DatabaseConnection,
    client_id: &str,
    subject: &str,
    requested_scopes: &str,
) -> Result<bool, CrabError> {
    use entities::consent::{Column, Entity};

    let now = Utc::now().timestamp();

    // Get all active consents for this client and subject
    let consents = Entity::find()
        .filter(Column::ClientId.eq(client_id))
        .filter(Column::Subject.eq(subject))
        .filter(Column::Revoked.eq(0))
        .all(db)
        .await?;

    let requested: std::collections::HashSet<_> = requested_scopes.split_whitespace().collect();

    for consent in consents {
        // Check if expired
        if let Some(expires_at) = consent.expires_at {
            if expires_at < now {
                continue;
            }
        }

        // Check if this consent covers all requested scopes
        let granted: std::collections::HashSet<_> = consent.scope.split_whitespace().collect();

        if requested.is_subset(&granted) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Get all consents for a subject
pub async fn get_consents_by_subject(
    db: &DatabaseConnection,
    subject: &str,
) -> Result<Vec<entities::consent::Model>, CrabError> {
    use entities::consent::{Column, Entity};

    Ok(Entity::find()
        .filter(Column::Subject.eq(subject))
        .filter(Column::Revoked.eq(0))
        .all(db)
        .await?)
}

/// Revoke a specific consent
pub async fn revoke_consent(db: &DatabaseConnection, consent_id: i32) -> Result<(), CrabError> {
    use entities::consent::{Column, Entity};

    if let Some(consent) = Entity::find()
        .filter(Column::Id.eq(consent_id))
        .one(db)
        .await?
    {
        let mut active: entities::consent::ActiveModel = consent.into();
        active.revoked = Set(1);
        active.update(db).await?;
    }

    Ok(())
}

/// Revoke all consents for a client and subject
pub async fn revoke_consents_for_client(
    db: &DatabaseConnection,
    client_id: &str,
    subject: &str,
) -> Result<(), CrabError> {
    use entities::consent::{Column, Entity};

    let consents = Entity::find()
        .filter(Column::ClientId.eq(client_id))
        .filter(Column::Subject.eq(subject))
        .filter(Column::Revoked.eq(0))
        .all(db)
        .await?;

    for consent in consents {
        let mut active: entities::consent::ActiveModel = consent.into();
        active.revoked = Set(1);
        active.update(db).await?;
    }

    Ok(())
}

// Device Authorization Grant (RFC 8628) functions

/// Create a new device authorization code
pub async fn create_device_code(
    db: &DatabaseConnection,
    client_id: &str,
    client_name: Option<String>,
    scope: &str,
    device_info: Option<String>,
) -> Result<DeviceCode, CrabError> {
    let device_code = random_id();
    let user_code = generate_user_code();
    let now = Utc::now().timestamp();
    let expires_at = now + 1800; // 30 minutes

    let device_code_model = entities::device_code::ActiveModel {
        device_code: Set(device_code.clone()),
        user_code: Set(user_code.clone()),
        client_id: Set(client_id.to_string()),
        client_name: Set(client_name.clone()),
        scope: Set(scope.to_string()),
        device_info: Set(device_info.clone()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        last_poll_at: Set(None),
        interval: Set(5),
        status: Set("pending".to_string()),
        subject: Set(None),
        auth_time: Set(None),
        amr: Set(None),
        acr: Set(None),
    };

    device_code_model.insert(db).await?;

    Ok(DeviceCode {
        device_code,
        user_code,
        client_id: client_id.to_string(),
        client_name,
        scope: scope.to_string(),
        device_info,
        created_at: now,
        expires_at,
        last_poll_at: None,
        interval: 5,
        status: "pending".to_string(),
        subject: None,
        auth_time: None,
        amr: None,
        acr: None,
    })
}

/// Get device code by device_code
pub async fn get_device_code(
    db: &DatabaseConnection,
    device_code: &str,
) -> Result<Option<DeviceCode>, CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    let result = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?;

    match result {
        Some(dc) => {
            // Check if expired
            if dc.expires_at < now {
                return Ok(None);
            }

            Ok(Some(DeviceCode {
                device_code: dc.device_code,
                user_code: dc.user_code,
                client_id: dc.client_id,
                client_name: dc.client_name,
                scope: dc.scope,
                device_info: dc.device_info,
                created_at: dc.created_at,
                expires_at: dc.expires_at,
                last_poll_at: dc.last_poll_at,
                interval: dc.interval,
                status: dc.status,
                subject: dc.subject,
                auth_time: dc.auth_time,
                amr: dc.amr,
                acr: dc.acr,
            }))
        }
        None => Ok(None),
    }
}

/// Get device code by user_code
pub async fn get_device_code_by_user_code(
    db: &DatabaseConnection,
    user_code: &str,
) -> Result<Option<DeviceCode>, CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    let result = Entity::find()
        .filter(Column::UserCode.eq(user_code))
        .one(db)
        .await?;

    match result {
        Some(dc) => {
            // Check if expired
            if dc.expires_at < now {
                return Ok(None);
            }

            Ok(Some(DeviceCode {
                device_code: dc.device_code,
                user_code: dc.user_code,
                client_id: dc.client_id,
                client_name: dc.client_name,
                scope: dc.scope,
                device_info: dc.device_info,
                created_at: dc.created_at,
                expires_at: dc.expires_at,
                last_poll_at: dc.last_poll_at,
                interval: dc.interval,
                status: dc.status,
                subject: dc.subject,
                auth_time: dc.auth_time,
                amr: dc.amr,
                acr: dc.acr,
            }))
        }
        None => Ok(None),
    }
}

/// Update device code polling metadata
pub async fn update_device_code_poll(
    db: &DatabaseConnection,
    device_code: &str,
) -> Result<(), CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    if let Some(dc) = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?
    {
        let mut active: entities::device_code::ActiveModel = dc.into();
        active.last_poll_at = Set(Some(now));
        active.update(db).await?;
    }

    Ok(())
}

/// Approve device code with user authentication context
pub async fn approve_device_code(
    db: &DatabaseConnection,
    device_code: &str,
    subject: &str,
    auth_time: i64,
    amr: Option<String>,
    acr: Option<String>,
) -> Result<(), CrabError> {
    use entities::device_code::{Column, Entity};

    if let Some(dc) = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?
    {
        let mut active: entities::device_code::ActiveModel = dc.into();
        active.status = Set("approved".to_string());
        active.subject = Set(Some(subject.to_string()));
        active.auth_time = Set(Some(auth_time));
        active.amr = Set(amr);
        active.acr = Set(acr);
        active.update(db).await?;
    }

    Ok(())
}

/// Deny device code
pub async fn deny_device_code(
    db: &DatabaseConnection,
    device_code: &str,
) -> Result<(), CrabError> {
    use entities::device_code::{Column, Entity};

    if let Some(dc) = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?
    {
        let mut active: entities::device_code::ActiveModel = dc.into();
        active.status = Set("denied".to_string());
        active.update(db).await?;
    }

    Ok(())
}

/// Consume device code (mark as used) and return its data
pub async fn consume_device_code(
    db: &DatabaseConnection,
    device_code: &str,
) -> Result<Option<DeviceCode>, CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    if let Some(dc) = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?
    {
        // Check if expired
        if dc.expires_at < now {
            return Ok(None);
        }

        // Check if status is approved
        if dc.status != "approved" {
            return Ok(None);
        }

        // Mark as consumed
        let mut active: entities::device_code::ActiveModel = dc.clone().into();
        active.status = Set("consumed".to_string());
        active.update(db).await?;

        // Return the device code data
        Ok(Some(DeviceCode {
            device_code: dc.device_code,
            user_code: dc.user_code,
            client_id: dc.client_id,
            client_name: dc.client_name,
            scope: dc.scope,
            device_info: dc.device_info,
            created_at: dc.created_at,
            expires_at: dc.expires_at,
            last_poll_at: dc.last_poll_at,
            interval: dc.interval,
            status: "consumed".to_string(),
            subject: dc.subject,
            auth_time: dc.auth_time,
            amr: dc.amr,
            acr: dc.acr,
        }))
    } else {
        Ok(None)
    }
}

/// Increment device code polling interval by 5 seconds (for slow_down)
pub async fn increment_device_code_interval(
    db: &DatabaseConnection,
    device_code: &str,
) -> Result<(), CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    if let Some(dc) = Entity::find()
        .filter(Column::DeviceCode.eq(device_code))
        .one(db)
        .await?
    {
        let mut active: entities::device_code::ActiveModel = dc.into();
        active.interval = Set(active.interval.clone().unwrap() + 5);
        active.last_poll_at = Set(Some(now));
        active.update(db).await?;
    }

    Ok(())
}

/// Cleanup expired device codes
pub async fn cleanup_expired_device_codes(db: &DatabaseConnection) -> Result<u64, CrabError> {
    use entities::device_code::{Column, Entity};

    let now = Utc::now().timestamp();

    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use tempfile::NamedTempFile;

    /// Test database helper that keeps temp file alive
    struct TestDb {
        connection: DatabaseConnection,
        _temp_file: NamedTempFile,
    }

    impl TestDb {
        async fn new() -> Self {
            let temp_file = NamedTempFile::new().expect("Failed to create temp file");
            let db_path = temp_file.path().to_str().expect("Invalid temp file path");
            let db_url = format!("sqlite://{}?mode=rwc", db_path);

            let connection = Database::connect(&db_url)
                .await
                .expect("Failed to connect to test database");

            migration::Migrator::up(&connection, None)
                .await
                .expect("Failed to run migrations");

            Self {
                connection,
                _temp_file: temp_file,
            }
        }

        fn connection(&self) -> &DatabaseConnection {
            &self.connection
        }
    }

    // ============================================================================
    // Client Operations Tests
    // ============================================================================

    #[tokio::test]
    async fn test_create_client() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let client = create_client(
            &db,
            NewClient {
                client_name: Some("Test Client".to_string()),
                redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            },
        )
        .await
        .expect("Failed to create client");

        assert!(!client.client_id.is_empty());
        assert!(!client.client_secret.is_empty());
        assert_eq!(client.client_name, Some("Test Client".to_string()));
    }

    #[tokio::test]
    async fn test_get_client() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let created = create_client(
            &db,
            NewClient {
                client_name: Some("Test Client".to_string()),
                redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            },
        )
        .await
        .expect("Failed to create client");

        let retrieved = get_client(&db, &created.client_id)
            .await
            .expect("Failed to get client")
            .expect("Client not found");

        assert_eq!(retrieved.client_id, created.client_id);
        assert_eq!(retrieved.client_secret, created.client_secret);
    }

    #[tokio::test]
    async fn test_get_client_not_found() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let result = get_client(&db, "nonexistent_client_id")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_client_redirect_uris_parsing() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let uris = vec![
            "http://localhost:3000/callback".to_string(),
            "http://localhost:3000/callback2".to_string(),
        ];

        let client = create_client(
            &db,
            NewClient {
                client_name: Some("Multi-URI Client".to_string()),
                redirect_uris: uris.clone(),
            },
        )
        .await
        .expect("Failed to create client");

        let retrieved = get_client(&db, &client.client_id)
            .await
            .expect("Failed to get client")
            .expect("Client not found");

        let parsed_uris = retrieved.redirect_uris.clone();

        assert_eq!(parsed_uris, uris);
    }

    // ============================================================================
    // Auth Code Operations Tests
    // ============================================================================

    #[tokio::test]
    async fn test_issue_auth_code() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let code = issue_auth_code(
            &db,
            "test_client_id",
            "http://localhost:3000/callback",
            "openid profile",
            "test_subject",
            Some("test_nonce".to_string()),
            "challenge_string",
            "S256",
            300,  // 5 minutes TTL
            None, // auth_time
        )
        .await
        .expect("Failed to issue auth code");

        assert!(!code.code.is_empty());
        assert_eq!(code.subject, "test_subject");
    }

    #[tokio::test]
    async fn test_consume_auth_code_success() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let code = issue_auth_code(
            &db,
            "test_client_id",
            "http://localhost:3000/callback",
            "openid profile",
            "test_subject",
            Some("test_nonce".to_string()),
            "challenge_string",
            "S256",
            300,
            None,
        )
        .await
        .expect("Failed to issue auth code");

        let auth_code = consume_auth_code(&db, &code.code)
            .await
            .expect("Failed to consume auth code")
            .expect("Auth code not found");

        assert_eq!(auth_code.subject, "test_subject");
        assert_eq!(auth_code.client_id, "test_client_id");
        assert_eq!(auth_code.scope, "openid profile");
    }

    #[tokio::test]
    async fn test_consume_auth_code_already_consumed() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let code = issue_auth_code(
            &db,
            "test_client_id",
            "http://localhost:3000/callback",
            "openid profile",
            "test_subject",
            None,
            "",
            "",
            300,  // TTL
            None, // auth_time
        )
        .await
        .expect("Failed to issue auth code");

        // First consumption succeeds
        consume_auth_code(&db, &code.code)
            .await
            .expect("Failed to consume auth code")
            .expect("Auth code not found");

        // Second consumption returns None
        let result = consume_auth_code(&db, &code.code)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_consume_auth_code_expired() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let code = issue_auth_code(
            &db,
            "test_client_id",
            "http://localhost:3000/callback",
            "openid profile",
            "test_subject",
            None,
            "",
            "",
            300,  // TTL
            None, // auth_time
        )
        .await
        .expect("Failed to issue auth code");

        // Manually expire the code by setting expires_at to past
        use entities::auth_code::{ActiveModel, Column, Entity};
        use sea_orm::ActiveValue::Set;
        use sea_orm::EntityTrait;

        let past_timestamp = chrono::Utc::now().timestamp() - 600; // 10 minutes ago

        Entity::update_many()
            .col_expr(
                Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(past_timestamp),
            )
            .filter(Column::Code.eq(&code.code))
            .exec(db)
            .await
            .expect("Failed to update expiry");

        // Consumption should return None for expired code
        let result = consume_auth_code(&db, &code.code)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_auth_code_pkce_storage() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let code = issue_auth_code(
            &db,
            "test_client_id",
            "http://localhost:3000/callback",
            "openid profile",
            "test_subject",
            None,
            "challenge_string",
            "S256",
            300,
            None,
        )
        .await
        .expect("Failed to issue auth code");

        let auth_code = consume_auth_code(&db, &code.code)
            .await
            .expect("Failed to consume auth code")
            .expect("Auth code not found");

        assert_eq!(auth_code.code_challenge, "challenge_string");
        assert_eq!(auth_code.code_challenge_method, "S256");
    }

    // ============================================================================
    // Token Operations Tests
    // ============================================================================

    #[tokio::test]
    async fn test_issue_access_token() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let token = issue_access_token(
            &db,
            "test_client_id",
            "test_subject",
            "openid profile",
            3600, // TTL
        )
        .await
        .expect("Failed to issue access token");

        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_get_access_token_valid() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let token = issue_access_token(
            &db,
            "test_client_id",
            "test_subject",
            "openid profile",
            3600, // TTL
        )
        .await
        .expect("Failed to issue access token");

        let access_token = get_access_token(&db, &token.token)
            .await
            .expect("Failed to get access token")
            .expect("Access token not found");

        assert_eq!(access_token.subject, "test_subject");
        assert_eq!(access_token.scope, "openid profile");
        assert_eq!(access_token.revoked, 0);
    }

    #[tokio::test]
    async fn test_get_access_token_expired() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let token = issue_access_token(
            &db,
            "test_client_id",
            "test_subject",
            "openid profile",
            3600, // TTL
        )
        .await
        .expect("Failed to issue access token");

        // Manually expire the token
        use entities::access_token::{Column, Entity};
        use sea_orm::EntityTrait;

        let past_timestamp = chrono::Utc::now().timestamp() - 7200; // 2 hours ago

        Entity::update_many()
            .col_expr(
                Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(past_timestamp),
            )
            .filter(Column::Token.eq(&token.token))
            .exec(db)
            .await
            .expect("Failed to update expiry");

        // Should return None for expired token
        let result = get_access_token(&db, &token.token)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_access_token_revoked() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let token = issue_access_token(
            &db,
            "test_client_id",
            "test_subject",
            "openid profile",
            3600, // TTL
        )
        .await
        .expect("Failed to issue access token");

        // Manually revoke the token
        use entities::access_token::{Column, Entity};
        use sea_orm::EntityTrait;

        Entity::update_many()
            .col_expr(Column::Revoked, sea_orm::sea_query::Expr::value(1))
            .filter(Column::Token.eq(&token.token))
            .exec(db)
            .await
            .expect("Failed to revoke token");

        // Should return None for revoked token
        let result = get_access_token(&db, &token.token)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_rotation() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        // Create initial refresh token
        let token1 = issue_refresh_token(
            &db,
            "test_subject",
            "test_client_id",
            "openid profile",
            86400, // TTL
            None,  // parent_token
        )
        .await
        .expect("Failed to issue refresh token");

        // Rotate to new token
        let token2 = issue_refresh_token(
            &db,
            "test_client_id",
            "test_subject",
            "openid profile",
            86400,
            Some(token1.token.clone()),
        )
        .await
        .expect("Failed to rotate refresh token");

        // Verify parent chain
        let rt2 = get_refresh_token(&db, &token2.token)
            .await
            .expect("Failed to get token")
            .expect("Token not found");

        assert_eq!(rt2.parent_token, Some(token1.token));
    }

    #[tokio::test]
    async fn test_revoke_refresh_token() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let token = issue_refresh_token(
            &db,
            "test_subject",
            "test_client_id",
            "openid profile",
            86400, // TTL
            None,  // parent_token
        )
        .await
        .expect("Failed to issue refresh token");

        revoke_refresh_token(&db, &token.token)
            .await
            .expect("Failed to revoke token");

        // Should return None for revoked token
        let result = get_refresh_token(&db, &token.token)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    // ============================================================================
    // User Management Tests
    // ============================================================================

    #[tokio::test]
    async fn test_create_user() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        assert!(!user.subject.is_empty());
        assert_eq!(user.username, "testuser");
        assert!(!user.password_hash.is_empty());
        // Verify it's Argon2 hash format
        assert!(user.password_hash.starts_with("$argon2"));
    }

    #[tokio::test]
    async fn test_get_user_by_username() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let created = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let retrieved = get_user_by_username(&db, "testuser")
            .await
            .expect("Failed to get user")
            .expect("User not found");

        assert_eq!(retrieved.subject, created.subject);
        assert_eq!(retrieved.username, "testuser");
    }

    #[tokio::test]
    async fn test_verify_user_password_success() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let subject = verify_user_password(&db, "testuser", "password123")
            .await
            .expect("Failed to verify password")
            .expect("Verification failed");

        // Verify it's a valid subject (not empty)
        assert!(!subject.is_empty());
    }

    #[tokio::test]
    async fn test_verify_user_password_wrong() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let result = verify_user_password(&db, "testuser", "wrongpassword")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_verify_user_password_disabled() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        // Disable the user
        update_user(&db, &user.subject, false, None, None)
            .await
            .expect("Failed to disable user");

        // Verification should fail for disabled user
        let result = verify_user_password(&db, "testuser", "password123")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_user() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        update_user(
            &db,
            &user.subject,
            false,
            Some("test@example.com".to_string()),
            Some(true),
        )
        .await
        .expect("Failed to update user");

        let updated = get_user_by_subject(&db, &user.subject)
            .await
            .expect("Failed to get user")
            .expect("User not found");

        assert_eq!(updated.enabled, 0);
        assert_eq!(updated.email, Some("test@example.com".to_string()));
        assert_eq!(updated.requires_2fa, 1);
    }

    #[tokio::test]
    async fn test_update_user_email() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        update_user(
            &db,
            &user.subject,
            true,
            Some("new@example.com".to_string()),
            None,
        )
        .await
        .expect("Failed to update email");

        let updated = get_user_by_subject(&db, &user.subject)
            .await
            .expect("Failed to get user")
            .expect("User not found");

        assert_eq!(updated.email, Some("new@example.com".to_string()));
    }

    // ============================================================================
    // Session Management Tests
    // ============================================================================

    #[tokio::test]
    async fn test_create_session() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let auth_time = chrono::Utc::now().timestamp();
        let session = create_session(&db, &user.subject, auth_time, 3600, None, None)
            .await
            .expect("Failed to create session");

        assert!(!session.session_id.is_empty());
        assert_eq!(session.subject, user.subject);
    }

    #[tokio::test]
    async fn test_get_session_valid() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let auth_time = chrono::Utc::now().timestamp();
        let created = create_session(&db, &user.subject, auth_time, 3600, None, None)
            .await
            .expect("Failed to create session");

        let retrieved = get_session(&db, &created.session_id)
            .await
            .expect("Failed to get session")
            .expect("Session not found");

        assert_eq!(retrieved.session_id, created.session_id);
        assert_eq!(retrieved.subject, user.subject);
    }

    #[tokio::test]
    async fn test_get_session_expired() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let auth_time = chrono::Utc::now().timestamp() - 7200; // 2 hours ago
        let session = create_session(&db, &user.subject, auth_time, 3600, None, None) // 1 hour TTL
            .await
            .expect("Failed to create session");

        // Should return None for expired session
        let result = get_session(&db, &session.session_id)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_session() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let auth_time = chrono::Utc::now().timestamp();
        let session = create_session(&db, &user.subject, auth_time, 3600, None, None)
            .await
            .expect("Failed to create session");

        delete_session(&db, &session.session_id)
            .await
            .expect("Failed to delete session");

        let result = get_session(&db, &session.session_id)
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let user = create_user(&db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        // Create an expired session
        let past_auth_time = chrono::Utc::now().timestamp() - 7200;
        create_session(&db, &user.subject, past_auth_time, 3600, None, None)
            .await
            .expect("Failed to create session");

        let deleted_count = cleanup_expired_sessions(&db)
            .await
            .expect("Failed to cleanup sessions");

        assert_eq!(deleted_count, 1);
    }

    // ============================================================================
    // Property Storage Tests
    // ============================================================================

    #[tokio::test]
    async fn test_set_and_get_property() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let value = serde_json::json!({"key": "value"});
        set_property(&db, "owner1", "test_key", &value)
            .await
            .expect("Failed to set property");

        let retrieved = get_property(&db, "owner1", "test_key")
            .await
            .expect("Failed to get property")
            .expect("Property not found");

        assert_eq!(retrieved, value);
    }

    #[tokio::test]
    async fn test_set_property_upsert() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let value1 = serde_json::json!({"version": 1});
        set_property(&db, "owner1", "test_key", &value1)
            .await
            .expect("Failed to set property");

        let value2 = serde_json::json!({"version": 2});
        set_property(&db, "owner1", "test_key", &value2)
            .await
            .expect("Failed to update property");

        let retrieved = get_property(&db, "owner1", "test_key")
            .await
            .expect("Failed to get property")
            .expect("Property not found");

        assert_eq!(retrieved, value2);
    }

    #[tokio::test]
    async fn test_property_complex_json() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let value = serde_json::json!({
            "nested": {
                "array": [1, 2, 3],
                "object": {
                    "key": "value"
                }
            }
        });

        set_property(&db, "owner1", "complex", &value)
            .await
            .expect("Failed to set property");

        let retrieved = get_property(&db, "owner1", "complex")
            .await
            .expect("Failed to get property")
            .expect("Property not found");

        assert_eq!(retrieved, value);
    }
}
