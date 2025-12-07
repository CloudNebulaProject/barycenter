use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Enable public user registration. If false, only admin API can create users.
    #[serde(default = "default_allow_public_registration")]
    pub allow_public_registration: bool,
    /// Admin GraphQL API port (defaults to port + 1)
    pub admin_port: Option<u16>,
}

fn default_allow_public_registration() -> bool {
    false // Secure by default - registration disabled
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    /// SeaORM/SQLx connection string
    /// Examples:
    /// - SQLite: sqlite://barycenter.db?mode=rwc
    /// - PostgreSQL: postgresql://user:password@localhost/barycenter
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
            allow_public_registration: false,
            admin_port: None, // Defaults to port + 1 if not set
        }
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            url: "sqlite://barycenter.db?mode=rwc".to_string(),
        }
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

impl Settings {
    pub fn load(path: &str) -> Result<Self> {
        let mut builder = config::Config::builder()
            .set_default("server.host", Server::default().host)
            .into_diagnostic()?
            .set_default("server.port", Server::default().port)
            .into_diagnostic()?
            .set_default("database.url", Database::default().url)
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
                Keys::default()
                    .private_key_path
                    .to_string_lossy()
                    .to_string(),
            )
            .into_diagnostic()?;

        // Optional file
        if Path::new(path).exists() {
            builder = builder.add_source(config::File::with_name(path));
        }

        // Environment overrides: BARYCENTER__SERVER__PORT=9090, etc.
        builder =
            builder.add_source(config::Environment::with_prefix("BARYCENTER").separator("__"));

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_settings_load_defaults() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("nonexistent.toml");

        // Load settings with nonexistent file - should use defaults
        let settings = Settings::load(config_path.to_str().unwrap())
            .expect("Failed to load settings");

        assert_eq!(settings.server.host, "0.0.0.0");
        assert_eq!(settings.server.port, 8080);
        assert_eq!(settings.server.allow_public_registration, false);
        assert_eq!(settings.database.url, "sqlite://barycenter.db?mode=rwc");
        assert_eq!(settings.keys.alg, "RS256");
    }

    #[test]
    fn test_settings_load_from_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("test_config.toml");

        // Write a test config file
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 9090
public_base_url = "https://idp.example.com"
allow_public_registration = true

[database]
url = "postgresql://user:pass@localhost/testdb"

[keys]
alg = "RS256"
jwks_path = "test_jwks.json"
private_key_path = "test_private.pem"
"#;
        fs::write(&config_path, config_content).expect("Failed to write config");

        // Load settings
        let settings = Settings::load(config_path.to_str().unwrap())
            .expect("Failed to load settings");

        assert_eq!(settings.server.host, "127.0.0.1");
        assert_eq!(settings.server.port, 9090);
        assert_eq!(
            settings.server.public_base_url,
            Some("https://idp.example.com".to_string())
        );
        assert_eq!(settings.server.allow_public_registration, true);
        assert_eq!(settings.database.url, "postgresql://user:pass@localhost/testdb");
    }

    #[test]
    fn test_settings_env_override() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("test_config.toml");

        // Write a base config
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080
"#;
        fs::write(&config_path, config_content).expect("Failed to write config");

        // Set environment variable
        env::set_var("BARYCENTER__SERVER__PORT", "9999");
        env::set_var("BARYCENTER__SERVER__HOST", "192.168.1.1");

        // Load settings - env should override file
        let settings = Settings::load(config_path.to_str().unwrap())
            .expect("Failed to load settings");

        assert_eq!(settings.server.host, "192.168.1.1");
        assert_eq!(settings.server.port, 9999);

        // Cleanup
        env::remove_var("BARYCENTER__SERVER__PORT");
        env::remove_var("BARYCENTER__SERVER__HOST");
    }

    #[test]
    fn test_settings_issuer_with_public_base_url() {
        let mut settings = Settings::default();
        settings.server.public_base_url = Some("https://idp.example.com".to_string());

        let issuer = settings.issuer();
        assert_eq!(issuer, "https://idp.example.com");
    }

    #[test]
    fn test_settings_issuer_with_trailing_slash() {
        let mut settings = Settings::default();
        settings.server.public_base_url = Some("https://idp.example.com/".to_string());

        let issuer = settings.issuer();
        // Should trim trailing slash
        assert_eq!(issuer, "https://idp.example.com");
    }

    #[test]
    fn test_settings_issuer_fallback() {
        let mut settings = Settings::default();
        settings.server.host = "localhost".to_string();
        settings.server.port = 3000;
        settings.server.public_base_url = None;

        let issuer = settings.issuer();
        assert_eq!(issuer, "http://localhost:3000");
    }

    #[test]
    fn test_settings_path_normalization() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("test_config.toml");

        // Write config with relative paths
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[database]
url = "sqlite://test.db"

[keys]
alg = "RS256"
jwks_path = "relative/jwks.json"
private_key_path = "relative/private.pem"
"#;
        fs::write(&config_path, config_content).expect("Failed to write config");

        let settings = Settings::load(config_path.to_str().unwrap())
            .expect("Failed to load settings");

        // Paths should be normalized to absolute
        assert!(settings.keys.jwks_path.is_absolute());
        assert!(settings.keys.private_key_path.is_absolute());

        // Should end with the relative path components
        assert!(settings.keys.jwks_path.ends_with("relative/jwks.json"));
        assert!(settings.keys.private_key_path.ends_with("relative/private.pem"));
    }

    #[test]
    fn test_allow_public_registration_default() {
        let settings = Settings::default();

        // Should default to false (secure by default)
        assert_eq!(settings.server.allow_public_registration, false);

        // Also test the default function directly
        assert_eq!(default_allow_public_registration(), false);
    }
}
