use crate::errors::CrabError;
use crate::settings::Keys;
use base64ct::Encoding;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, RS256};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use rand::RngCore;
use serde_json::{json, Value};
use std::fs;
use std::sync::Arc;

#[derive(Clone)]
pub struct JwksManager {
    cfg: Keys,
    public_jwks_value: Arc<Value>,
    private_jwk: Arc<Jwk>,
}

impl JwksManager {
    pub async fn new(cfg: Keys) -> Result<Self, CrabError> {
        // Ensure parent dirs exist
        if let Some(parent) = cfg.jwks_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = cfg.private_key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // If private key exists, load it; otherwise generate and persist both private and public
        let private_jwk = if cfg.private_key_path.exists() {
            let s = fs::read_to_string(&cfg.private_key_path)?;
            // Stored as JSON
            serde_json::from_str::<Jwk>(&s)?
        } else {
            let mut jwk = Jwk::generate_rsa_key(2048)?;
            let kid = cfg.key_id.clone().unwrap_or_else(random_kid);
            jwk.set_key_id(&kid);
            jwk.set_algorithm(cfg.alg.as_str());
            jwk.set_key_use("sig");
            // Persist private key as JSON
            let priv_json = serde_json::to_string_pretty(&jwk)?;
            fs::write(&cfg.private_key_path, priv_json)?;
            jwk
        };

        // Ensure JWKS file exists or update from private_jwk
        if !cfg.jwks_path.exists() {
            let mut public = private_jwk.to_public_key()?;
            // Copy metadata from private key to public key
            if let Some(kid) = private_jwk.key_id() {
                public.set_key_id(kid);
            }
            if let Some(alg) = private_jwk.algorithm() {
                public.set_algorithm(alg);
            }
            if let Some(use_) = private_jwk.key_use() {
                public.set_key_use(use_);
            }
            let jwk_val: Value = serde_json::to_value(public)?;
            let jwks = json!({ "keys": [jwk_val] });
            fs::write(&cfg.jwks_path, serde_json::to_string_pretty(&jwks)?)?;
        }

        // Load public JWKS value
        let public_jwks_value: Value = serde_json::from_str(&fs::read_to_string(&cfg.jwks_path)?)?;

        Ok(Self {
            cfg,
            public_jwks_value: Arc::new(public_jwks_value),
            private_jwk: Arc::new(private_jwk),
        })
    }

    pub fn jwks_json(&self) -> Value {
        (*self.public_jwks_value).clone()
    }

    pub fn private_jwk(&self) -> Jwk {
        (*self.private_jwk).clone()
    }

    pub fn sign_jwt_rs256(&self, payload: &JwtPayload) -> Result<String, CrabError> {
        // Use RS256 signer from josekit
        let signer = RS256.signer_from_jwk(&self.private_jwk)?;
        let mut header = JwsHeader::new();
        if let Some(kid) = self.private_jwk.key_id() {
            header.set_key_id(kid);
        }
        header.set_algorithm("RS256");
        let token = jwt::encode_with_signer(payload, &header, &signer)?;
        Ok(token)
    }
}

fn random_kid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64ct::Base64UrlUnpadded::encode_string(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::path::PathBuf;

    /// Helper to create test Keys config
    fn test_keys_config(temp_dir: &TempDir) -> Keys {
        Keys {
            jwks_path: temp_dir.path().join("jwks.json"),
            private_key_path: temp_dir.path().join("private_key.json"),
            alg: "RS256".to_string(),
            key_id: Some("test-kid-123".to_string()),
        }
    }

    #[tokio::test]
    async fn test_jwks_manager_generates_key() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        let manager = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create JwksManager");

        let private_jwk = manager.private_jwk();

        // Verify it's RSA key
        assert_eq!(private_jwk.key_type(), "RSA");
        assert_eq!(private_jwk.algorithm(), Some("RS256"));
        assert_eq!(private_jwk.key_use(), Some("sig"));
        assert_eq!(private_jwk.key_id(), Some("test-kid-123"));

        // Verify 2048-bit key (check modulus size)
        if let Some(n) = private_jwk.parameter("n") {
            if let Some(n_str) = n.as_str() {
                let decoded = base64ct::Base64UrlUnpadded::decode_vec(n_str)
                    .expect("Failed to decode modulus");
                // 2048-bit key = 256 bytes modulus
                assert_eq!(decoded.len(), 256);
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_manager_persists_private_key() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        let _manager = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create JwksManager");

        // Verify private key file exists
        assert!(cfg.private_key_path.exists());

        // Verify it contains valid JSON JWK
        let content = fs::read_to_string(&cfg.private_key_path)
            .expect("Failed to read private key");
        let jwk: Jwk = serde_json::from_str(&content)
            .expect("Failed to parse private key JSON");

        assert_eq!(jwk.key_type(), "RSA");
        assert!(jwk.parameter("d").is_some()); // Private exponent exists
    }

    #[tokio::test]
    async fn test_jwks_manager_persists_jwks() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        let _manager = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create JwksManager");

        // Verify JWKS file exists
        assert!(cfg.jwks_path.exists());

        // Verify it contains valid JWKS structure
        let content = fs::read_to_string(&cfg.jwks_path)
            .expect("Failed to read JWKS");
        let jwks: Value = serde_json::from_str(&content)
            .expect("Failed to parse JWKS JSON");

        assert!(jwks.get("keys").is_some());
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);

        // Verify public key (should not have private parameters)
        let public_key = &jwks["keys"][0];
        assert!(public_key.get("n").is_some()); // Modulus
        assert!(public_key.get("e").is_some()); // Exponent
        assert!(public_key.get("d").is_none()); // No private exponent
    }

    #[tokio::test]
    async fn test_jwks_manager_loads_existing() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        // Create first manager
        let manager1 = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create first JwksManager");

        let kid1 = manager1.private_jwk().key_id().unwrap().to_string();

        // Create second manager - should reuse the same key
        let manager2 = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create second JwksManager");

        let kid2 = manager2.private_jwk().key_id().unwrap().to_string();

        // Verify same key was loaded
        assert_eq!(kid1, kid2);

        // Verify modulus is identical (same key)
        let jwk1 = manager1.private_jwk();
        let jwk2 = manager2.private_jwk();

        assert_eq!(
            jwk1.parameter("n"),
            jwk2.parameter("n")
        );
    }

    #[tokio::test]
    async fn test_sign_jwt_rs256() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        let manager = JwksManager::new(cfg.clone())
            .await
            .expect("Failed to create JwksManager");

        // Create a test payload
        let mut payload = JwtPayload::new();
        payload.set_issuer("https://example.com");
        payload.set_subject("user123");
        let exp_time: std::time::SystemTime = (chrono::Utc::now() + chrono::Duration::hours(1)).into();
        payload.set_expires_at(&exp_time);

        // Sign the JWT
        let token = manager.sign_jwt_rs256(&payload)
            .expect("Failed to sign JWT");

        // Verify token is not empty and has 3 parts (header.payload.signature)
        assert!(!token.is_empty());
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header contains kid
        let header_json = base64ct::Base64UrlUnpadded::decode_vec(parts[0])
            .expect("Failed to decode header");
        let header: Value = serde_json::from_slice(&header_json)
            .expect("Failed to parse header");

        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "test-kid-123");
    }

    #[tokio::test]
    async fn test_jwks_json_format() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cfg = test_keys_config(&temp_dir);

        let manager = JwksManager::new(cfg)
            .await
            .expect("Failed to create JwksManager");

        let jwks = manager.jwks_json();

        // Verify JWKS structure
        assert!(jwks.is_object());
        assert!(jwks.get("keys").is_some());
        assert!(jwks["keys"].is_array());

        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);

        // Verify first key structure
        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["kid"], "test-kid-123");
        assert!(key.get("n").is_some());
        assert!(key.get("e").is_some());
        assert!(key.get("d").is_none()); // Public key only
    }

    #[test]
    fn test_random_kid_uniqueness() {
        // Generate multiple kids
        let kid1 = random_kid();
        let kid2 = random_kid();
        let kid3 = random_kid();

        // Verify they're all different
        assert_ne!(kid1, kid2);
        assert_ne!(kid2, kid3);
        assert_ne!(kid1, kid3);

        // Verify length (16 bytes base64url-encoded)
        // 16 bytes = 128 bits, base64url without padding is 22 chars
        assert_eq!(kid1.len(), 22);
        assert_eq!(kid2.len(), 22);
        assert_eq!(kid3.len(), 22);

        // Verify all are valid base64url
        for kid in [kid1, kid2, kid3] {
            assert!(kid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        }
    }
}
