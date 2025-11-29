use miette::{miette, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub server: Server,
    pub database: Database,
    pub keys: Keys,
    pub federation: Federation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
    /// If set, this is used as the issuer/public base URL, e.g., https://idp.example.com
    pub public_base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    /// SeaORM/SQLx connection string, e.g., sqlite://crabidp.db?mode=rwc
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keys {
    /// Path to persist JWKS (public keys). Default: data/jwks.json
    pub jwks_path: PathBuf,
    /// Optional explicit key id to set on generated keys
    pub key_id: Option<String>,
    /// JWS algorithm for ID tokens (currently RS256)
    pub alg: String,
    /// Path to persist the private key in PEM (PKCS#8). Default: data/private_key.pem
    pub private_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Federation {
    /// List of trust anchor URLs or fingerprints (placeholder for real federation)
    pub trust_anchors: Vec<String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            public_base_url: None,
        }
    }
}

impl Default for Database {
    fn default() -> Self {
        Self { url: "sqlite://crabidp.db?mode=rwc".to_string() }
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self {
            jwks_path: PathBuf::from("data/jwks.json"),
            key_id: None,
            alg: "RS256".to_string(),
            private_key_path: PathBuf::from("data/private_key.pem"),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: Server::default(),
            database: Database::default(),
            keys: Keys::default(),
            federation: Federation::default(),
        }
    }
}

impl Settings {
    pub fn load(path: &str) -> Result<Self> {
        let mut builder = config::Config::builder()
            .set_default("server.host", Server::default().host)
            .into_diagnostic()?
            .set_default("server.port", Server::default().port)
            .into_diagnostic()?
            .set_default(
                "database.url",
                Database::default().url,
            )
            .into_diagnostic()?
            .set_default(
                "keys.jwks_path",
                Keys::default().jwks_path.to_string_lossy().to_string(),
            )
            .into_diagnostic()?
            .set_default("keys.alg", Keys::default().alg)
            .into_diagnostic()?
            .set_default(
                "keys.private_key_path",
                Keys::default().private_key_path.to_string_lossy().to_string(),
            )
            .into_diagnostic()?;

        // Optional file
        if Path::new(path).exists() {
            builder = builder.add_source(config::File::with_name(path));
        }

        // Environment overrides: CRABIDP__SERVER__PORT=9090, etc.
        builder = builder.add_source(
            config::Environment::with_prefix("CRABIDP").separator("__"),
        );

        let cfg = builder.build().into_diagnostic()?;
        let mut s: Settings = cfg.try_deserialize().into_diagnostic()?;

        // Normalize jwks path to be relative to current dir
        if s.keys.jwks_path.is_relative() {
            s.keys.jwks_path = std::env::current_dir()
                .into_diagnostic()?
                .join(&s.keys.jwks_path);
        }
        if s.keys.private_key_path.is_relative() {
            s.keys.private_key_path = std::env::current_dir()
                .into_diagnostic()?
                .join(&s.keys.private_key_path);
        }

        Ok(s)
    }

    pub fn issuer(&self) -> String {
        if let Some(base) = &self.server.public_base_url {
            base.trim_end_matches('/').to_string()
        } else {
            format!("http://{}:{}", self.server.host, self.server.port)
        }
    }
}
