use crate::errors::CrabError;
use crate::settings::Database as DbCfg;
use chrono::Utc;
use rand::RngCore;
use base64ct::Encoding;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
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
    // bootstrap schema
    db.execute(Statement::from_string(DbBackend::Sqlite, "PRAGMA foreign_keys = ON"))
        .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            client_secret TEXT NOT NULL,
            client_name TEXT,
            redirect_uris TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS properties (
            owner TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(owner, key)
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            subject TEXT NOT NULL,
            nonce TEXT,
            code_challenge TEXT NOT NULL,
            code_challenge_method TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            auth_time INTEGER
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS access_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            scope TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS users (
            subject TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            email_verified INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            auth_time INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            user_agent TEXT,
            ip_address TEXT
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)"
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            scope TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            parent_token TEXT
        )
        "#
    ))
    .await?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)"
    ))
    .await?;

    Ok(db)
}

pub async fn create_client(db: &DatabaseConnection, input: NewClient) -> Result<Client, CrabError> {
    let client_id = random_id();
    let client_secret = random_id();
    let created_at = Utc::now().timestamp();
    let redirect_uris_json = serde_json::to_string(&input.redirect_uris)?;

    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO clients (client_id, client_secret, client_name, redirect_uris, created_at)
           VALUES (?, ?, ?, ?, ?)"#,
        [
            client_id.clone().into(),
            client_secret.clone().into(),
            input.client_name.clone().into(),
            redirect_uris_json.into(),
            created_at.into(),
        ],
    ))
    .await?;

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
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT value FROM properties WHERE owner = ? AND key = ?",
            [owner.into(), key.into()],
        ))
        .await?
    {
        let value_str: String = row.try_get("", "value").unwrap_or_default();
        let json: Value = serde_json::from_str(&value_str)?;
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
    let now = Utc::now().timestamp();
    let json = serde_json::to_string(value)?;
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO properties (owner, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(owner, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"#,
        [owner.into(), key.into(), json.into(), now.into()],
    ))
    .await?;
    Ok(())
}

pub async fn get_client(db: &DatabaseConnection, client_id: &str) -> Result<Option<Client>, CrabError> {
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT client_id, client_secret, client_name, redirect_uris, created_at FROM clients WHERE client_id = ?"#,
            [client_id.into()],
        ))
        .await?
    {
        let client_id: String = row.try_get("", "client_id").unwrap_or_default();
        let client_secret: String = row.try_get("", "client_secret").unwrap_or_default();
        let client_name: Option<String> = row.try_get("", "client_name").ok();
        let redirect_uris_json: String = row.try_get("", "redirect_uris").unwrap_or_default();
        let redirect_uris: Vec<String> = serde_json::from_str(&redirect_uris_json).unwrap_or_default();
        let created_at: i64 = row.try_get("", "created_at").unwrap_or_default();
        Ok(Some(Client { client_id, client_secret, client_name, redirect_uris, created_at }))
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
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO auth_codes (code, client_id, redirect_uri, scope, subject, nonce, code_challenge, code_challenge_method, created_at, expires_at, consumed, auth_time)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)"#,
        [
            code.clone().into(),
            client_id.into(),
            redirect_uri.into(),
            scope.into(),
            subject.into(),
            nonce.clone().into(),
            code_challenge.into(),
            code_challenge_method.into(),
            now.into(),
            expires_at.into(),
            auth_time.into(),
        ],
    ))
    .await?;
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
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT code, client_id, redirect_uri, scope, subject, nonce, code_challenge, code_challenge_method, created_at, expires_at, consumed, auth_time
               FROM auth_codes WHERE code = ?"#,
            [code.into()],
        ))
        .await?
    {
        let consumed: i64 = row.try_get("", "consumed").unwrap_or_default();
        let expires_at: i64 = row.try_get("", "expires_at").unwrap_or_default();
        let now = Utc::now().timestamp();
        if consumed != 0 || now > expires_at {
            return Ok(None);
        }

        // Mark as consumed
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"UPDATE auth_codes SET consumed = ? WHERE code = ?"#,
            [1.into(), code.into()],
        ))
        .await?;

        let code_val: String = row.try_get("", "code").unwrap_or_default();
        let client_id: String = row.try_get("", "client_id").unwrap_or_default();
        let redirect_uri: String = row.try_get("", "redirect_uri").unwrap_or_default();
        let scope: String = row.try_get("", "scope").unwrap_or_default();
        let subject: String = row.try_get("", "subject").unwrap_or_default();
        let nonce: Option<String> = row.try_get("", "nonce").ok();
        let code_challenge: String = row.try_get("", "code_challenge").unwrap_or_default();
        let code_challenge_method: String = row.try_get("", "code_challenge_method").unwrap_or_default();
        let created_at: i64 = row.try_get("", "created_at").unwrap_or_default();
        let expires_at: i64 = row.try_get("", "expires_at").unwrap_or_default();
        let auth_time: Option<i64> = row.try_get("", "auth_time").ok();
        Ok(Some(AuthCode { code: code_val, client_id, redirect_uri, scope, subject, nonce, code_challenge, code_challenge_method, created_at, expires_at, consumed: 1, auth_time }))
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
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO access_tokens (token, client_id, subject, scope, created_at, expires_at, revoked)
           VALUES (?, ?, ?, ?, ?, ?, 0)"#,
        [token.clone().into(), client_id.into(), subject.into(), scope.into(), now.into(), expires_at.into()],
    ))
    .await?;
    Ok(AccessToken { token, client_id: client_id.to_string(), subject: subject.to_string(), scope: scope.to_string(), created_at: now, expires_at, revoked: 0 })
}

pub async fn get_access_token(db: &DatabaseConnection, token: &str) -> Result<Option<AccessToken>, CrabError> {
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT token, client_id, subject, scope, created_at, expires_at, revoked FROM access_tokens WHERE token = ?"#,
            [token.into()],
        ))
        .await?
    {
        let revoked: i64 = row.try_get("", "revoked").unwrap_or_default();
        let expires_at: i64 = row.try_get("", "expires_at").unwrap_or_default();
        let now = Utc::now().timestamp();
        if revoked != 0 || now > expires_at { return Ok(None); }
        let token: String = row.try_get("", "token").unwrap_or_default();
        let client_id: String = row.try_get("", "client_id").unwrap_or_default();
        let subject: String = row.try_get("", "subject").unwrap_or_default();
        let scope: String = row.try_get("", "scope").unwrap_or_default();
        let created_at: i64 = row.try_get("", "created_at").unwrap_or_default();
        Ok(Some(AccessToken { token, client_id, subject, scope, created_at, expires_at, revoked }))
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
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::{SaltString, rand_core::OsRng};

    let subject = random_id();
    let created_at = Utc::now().timestamp();

    // Hash password with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CrabError::Other(format!("Password hashing failed: {}", e)))?
        .to_string();

    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO users (subject, username, password_hash, email, email_verified, created_at, enabled)
           VALUES (?, ?, ?, ?, 0, ?, 1)"#,
        [
            subject.clone().into(),
            username.into(),
            password_hash.clone().into(),
            email.clone().into(),
            created_at.into(),
        ],
    ))
    .await?;

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
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT subject, username, password_hash, email, email_verified, created_at, enabled
               FROM users WHERE username = ?"#,
            [username.into()],
        ))
        .await?
    {
        let subject: String = row.try_get("", "subject").unwrap_or_default();
        let username: String = row.try_get("", "username").unwrap_or_default();
        let password_hash: String = row.try_get("", "password_hash").unwrap_or_default();
        let email: Option<String> = row.try_get("", "email").ok();
        let email_verified: i64 = row.try_get("", "email_verified").unwrap_or_default();
        let created_at: i64 = row.try_get("", "created_at").unwrap_or_default();
        let enabled: i64 = row.try_get("", "enabled").unwrap_or_default();

        Ok(Some(User {
            subject,
            username,
            password_hash,
            email,
            email_verified,
            created_at,
            enabled,
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
    use argon2::{Argon2, PasswordVerifier, PasswordHash};

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

    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO sessions (session_id, subject, auth_time, created_at, expires_at, user_agent, ip_address)
           VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        [
            session_id.clone().into(),
            subject.into(),
            now.into(),
            now.into(),
            expires_at.into(),
            user_agent.clone().into(),
            ip_address.clone().into(),
        ],
    ))
    .await?;

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
    if let Some(row) = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT session_id, subject, auth_time, created_at, expires_at, user_agent, ip_address
               FROM sessions WHERE session_id = ?"#,
            [session_id.into()],
        ))
        .await?
    {
        let session_id: String = row.try_get("", "session_id").unwrap_or_default();
        let subject: String = row.try_get("", "subject").unwrap_or_default();
        let auth_time: i64 = row.try_get("", "auth_time").unwrap_or_default();
        let created_at: i64 = row.try_get("", "created_at").unwrap_or_default();
        let expires_at: i64 = row.try_get("", "expires_at").unwrap_or_default();
        let user_agent: Option<String> = row.try_get("", "user_agent").ok();
        let ip_address: Option<String> = row.try_get("", "ip_address").ok();

        // Check if session is expired
        let now = Utc::now().timestamp();
        if now > expires_at {
            return Ok(None);
        }

        Ok(Some(Session {
            session_id,
            subject,
            auth_time,
            created_at,
            expires_at,
            user_agent,
            ip_address,
        }))
    } else {
        Ok(None)
    }
}

pub async fn delete_session(
    db: &DatabaseConnection,
    session_id: &str,
) -> Result<(), CrabError> {
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "DELETE FROM sessions WHERE session_id = ?",
        [session_id.into()],
    ))
    .await?;
    Ok(())
}

pub async fn cleanup_expired_sessions(db: &DatabaseConnection) -> Result<u64, CrabError> {
    let now = Utc::now().timestamp();
    let result = db
        .execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM sessions WHERE expires_at < ?",
            [now.into()],
        ))
        .await?;
    Ok(result.rows_affected())
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

    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"INSERT INTO refresh_tokens (token, client_id, subject, scope, created_at, expires_at, revoked, parent_token)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?)"#,
        [
            token.clone().into(),
            client_id.into(),
            subject.into(),
            scope.into(),
            now.into(),
            expires_at.into(),
            parent_token.clone().into(),
        ],
    ))
    .await?;

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
    let result = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"SELECT token, client_id, subject, scope, created_at, expires_at, revoked, parent_token
               FROM refresh_tokens WHERE token = ?"#,
            [token.into()],
        ))
        .await?;

    if let Some(row) = result {
        let token: String = row.try_get("", "token")?;
        let client_id: String = row.try_get("", "client_id")?;
        let subject: String = row.try_get("", "subject")?;
        let scope: String = row.try_get("", "scope")?;
        let created_at: i64 = row.try_get("", "created_at")?;
        let expires_at: i64 = row.try_get("", "expires_at")?;
        let revoked: i64 = row.try_get("", "revoked")?;
        let parent_token: Option<String> = row.try_get("", "parent_token").ok();

        // Check if token is expired or revoked
        let now = Utc::now().timestamp();
        if revoked != 0 || now > expires_at {
            return Ok(None);
        }

        Ok(Some(RefreshToken {
            token,
            client_id,
            subject,
            scope,
            created_at,
            expires_at,
            revoked,
            parent_token,
        }))
    } else {
        Ok(None)
    }
}

pub async fn revoke_refresh_token(
    db: &DatabaseConnection,
    token: &str,
) -> Result<(), CrabError> {
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?",
        [token.into()],
    ))
    .await?;
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
    issue_refresh_token(db, client_id, subject, scope, ttl_secs, Some(old_token.to_string())).await
}

pub async fn cleanup_expired_refresh_tokens(db: &DatabaseConnection) -> Result<u64, CrabError> {
    let now = Utc::now().timestamp();
    let result = db
        .execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM refresh_tokens WHERE expires_at < ?",
            [now.into()],
        ))
        .await?;
    Ok(result.rows_affected())
}
