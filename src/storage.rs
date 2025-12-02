use crate::entities;
use crate::errors::CrabError;
use crate::settings::Database as DbCfg;
use base64ct::Encoding;
use chrono::Utc;
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
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

/// Update user enabled and email_verified flags
pub async fn update_user(
    db: &DatabaseConnection,
    username: &str,
    enabled: bool,
    email_verified: bool,
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
    active.enabled = Set(if enabled { 1 } else { 0 });
    active.email_verified = Set(if email_verified { 1 } else { 0 });
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
    ttl_secs: i64,
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> Result<Session, CrabError> {
    let session_id = random_id();
    let now = Utc::now().timestamp();
    let expires_at = now + ttl_secs;

    let session = entities::session::ActiveModel {
        session_id: Set(session_id.clone()),
        subject: Set(subject.to_string()),
        auth_time: Set(now),
        created_at: Set(now),
        expires_at: Set(expires_at),
        user_agent: Set(user_agent.clone()),
        ip_address: Set(ip_address.clone()),
    };

    session.insert(db).await?;

    Ok(Session {
        session_id,
        subject: subject.to_string(),
        auth_time: now,
        created_at: now,
        expires_at,
        user_agent,
        ip_address,
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
