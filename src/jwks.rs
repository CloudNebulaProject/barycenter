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
            let public = private_jwk.to_public_key()?;
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
