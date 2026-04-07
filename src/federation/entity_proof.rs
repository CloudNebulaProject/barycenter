//! Entity Proof endpoint for Barycenter's P2P federation protocol.
//!
//! Serves `GET /.well-known/barycenter-entity` — a self-signed JWS that lets
//! remote peers cryptographically verify this Barycenter instance is the
//! legitimate IdP for its domain.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use base64ct::Encoding;
use josekit::jws::{JwsHeader, RS256};
use josekit::jwt::{self, JwtPayload};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::web::AppState;

/// Claims contained in an entity proof JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityProofClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub domain: String,
    pub federation: FederationInfo,
    pub jwks: Value,
}

/// Federation metadata embedded in the entity proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationInfo {
    pub protocol: String,
    pub webfinger_domain: String,
    pub callback_endpoint: String,
    pub peer_request_endpoint: String,
}

/// Errors that can occur when verifying an entity proof from a peer.
#[derive(Debug)]
pub enum EntityProofError {
    InvalidSignature,
    Expired,
    DomainMismatch(String, String),
    IssuerMismatch(String, String),
    MalformedPayload(String),
}

impl fmt::Display for EntityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid JWS signature"),
            Self::Expired => write!(f, "entity proof has expired"),
            Self::DomainMismatch(expected, actual) => {
                write!(f, "domain mismatch: expected {expected}, got {actual}")
            }
            Self::IssuerMismatch(expected, actual) => {
                write!(f, "issuer mismatch: expected {expected}, got {actual}")
            }
            Self::MalformedPayload(msg) => write!(f, "malformed payload: {msg}"),
        }
    }
}

impl std::error::Error for EntityProofError {}

/// Handler for `GET /.well-known/barycenter-entity`.
///
/// Returns a self-signed JWS (compact serialization) containing the entity
/// proof for this Barycenter instance.
pub async fn entity_proof(State(state): State<AppState>) -> impl IntoResponse {
    // 1. Check if federation is enabled
    if !state.settings.federation.enabled {
        return (StatusCode::NOT_FOUND, HeaderMap::new(), String::new());
    }

    let issuer = state.settings.issuer();

    // Determine the domain: prefer webfinger resource_domain, else extract from issuer
    let domain = if state.settings.webfinger.enabled
        && !state.settings.webfinger.resource_domain.is_empty()
    {
        state.settings.webfinger.resource_domain.clone()
    } else {
        extract_domain_from_issuer(&issuer)
    };

    let webfinger_domain = domain.clone();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // 2. Build the JWT payload
    let mut payload = JwtPayload::new();
    payload.set_issuer(&issuer);
    payload.set_subject(&issuer);
    payload
        .set_claim(
            "iat",
            Some(serde_json::Value::Number(serde_json::Number::from(now))),
        )
        .ok();
    payload
        .set_claim(
            "exp",
            Some(serde_json::Value::Number(serde_json::Number::from(
                now + 86400,
            ))),
        )
        .ok();
    payload
        .set_claim("domain", Some(serde_json::Value::String(domain)))
        .ok();
    payload
        .set_claim(
            "federation",
            Some(json!({
                "protocol": "barycenter-p2p-v1",
                "webfinger_domain": webfinger_domain,
                "callback_endpoint": format!("{}/federation/callback", issuer),
                "peer_request_endpoint": format!("{}/federation/peer-request", issuer),
            })),
        )
        .ok();
    payload
        .set_claim("jwks", Some(state.jwks.jwks_json()))
        .ok();

    // 3. Sign with RS256 using the server's private key
    let private_jwk = state.jwks.private_jwk();
    let signer = match RS256.signer_from_jwk(&private_jwk) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create JWS signer: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderMap::new(),
                String::new(),
            );
        }
    };

    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header
        .set_claim("typ", Some(serde_json::Value::String("entity-proof+jwt".to_string())))
        .ok();
    if let Some(kid) = private_jwk.key_id() {
        header.set_key_id(kid);
    }

    let jws = match jwt::encode_with_signer(&payload, &header, &signer) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to sign entity proof: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderMap::new(),
                String::new(),
            );
        }
    };

    // 4. Return with appropriate content type and CORS headers
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/entity-statement+jwt"),
    );
    headers.insert(
        "access-control-allow-origin",
        HeaderValue::from_static("*"),
    );

    (StatusCode::OK, headers, jws)
}

/// Verify an entity proof JWS received from a remote peer.
///
/// This performs the following checks:
/// 1. Decodes the JWS header and unverified payload to extract the inline JWKS
/// 2. Verifies the JWS signature against the inline JWKS
/// 3. Validates claims: iss == sub, domain, issuer, expiration, and issuance time
pub fn verify_entity_proof(
    jws_compact: &str,
    expected_domain: &str,
    expected_issuer: &str,
) -> Result<EntityProofClaims, EntityProofError> {
    // 1. Split the JWS to get unverified parts
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() != 3 {
        return Err(EntityProofError::MalformedPayload(
            "JWS must have 3 parts".to_string(),
        ));
    }

    // 2. Decode payload WITHOUT verification to extract the inline JWKS
    let payload_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| EntityProofError::MalformedPayload(format!("invalid base64 payload: {e}")))?;

    let claims_value: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| EntityProofError::MalformedPayload(format!("invalid JSON payload: {e}")))?;

    // Extract the inline JWKS
    let jwks_value = claims_value
        .get("jwks")
        .ok_or_else(|| EntityProofError::MalformedPayload("missing jwks claim".to_string()))?;

    let keys = jwks_value
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| {
            EntityProofError::MalformedPayload("jwks must contain a keys array".to_string())
        })?;

    // 3. Decode header to get kid/alg
    let header_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[0])
        .map_err(|e| EntityProofError::MalformedPayload(format!("invalid base64 header: {e}")))?;

    let header_value: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| EntityProofError::MalformedPayload(format!("invalid JSON header: {e}")))?;

    let header_kid = header_value.get("kid").and_then(|v| v.as_str());

    // Find the matching key in the inline JWKS
    let matching_key = if let Some(kid) = header_kid {
        keys.iter()
            .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
    } else {
        keys.first()
    };

    let key_value = matching_key.ok_or_else(|| {
        EntityProofError::MalformedPayload("no matching key found in inline JWKS".to_string())
    })?;

    let key_map: serde_json::Map<String, Value> = key_value
        .as_object()
        .ok_or_else(|| {
            EntityProofError::MalformedPayload("JWK must be a JSON object".to_string())
        })?
        .clone();

    let jwk = josekit::jwk::Jwk::from_map(key_map)
        .map_err(|e| EntityProofError::MalformedPayload(format!("invalid JWK: {e}")))?;

    // 4. Verify the JWS signature against the inline JWKS
    let verifier = RS256
        .verifier_from_jwk(&jwk)
        .map_err(|_| EntityProofError::InvalidSignature)?;

    let (verified_payload, _header) = jwt::decode_with_verifier(jws_compact, &verifier)
        .map_err(|_| EntityProofError::InvalidSignature)?;

    // 5. Parse the verified claims
    let claims: EntityProofClaims = serde_json::from_value(
        serde_json::to_value(verified_payload.claims_set())
            .map_err(|e| EntityProofError::MalformedPayload(format!("failed to serialize claims: {e}")))?,
    )
    .map_err(|e| EntityProofError::MalformedPayload(format!("failed to parse claims: {e}")))?;

    // 6. Validate: iss == sub
    if claims.iss != claims.sub {
        return Err(EntityProofError::MalformedPayload(format!(
            "iss ({}) must equal sub ({})",
            claims.iss, claims.sub
        )));
    }

    // 7. Validate domain
    if claims.domain != expected_domain {
        return Err(EntityProofError::DomainMismatch(
            expected_domain.to_string(),
            claims.domain.clone(),
        ));
    }

    // 8. Validate issuer
    if claims.iss != expected_issuer {
        return Err(EntityProofError::IssuerMismatch(
            expected_issuer.to_string(),
            claims.iss.clone(),
        ));
    }

    // 9. Validate time bounds
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if claims.exp <= now {
        return Err(EntityProofError::Expired);
    }

    if claims.iat > now {
        return Err(EntityProofError::MalformedPayload(
            "iat is in the future".to_string(),
        ));
    }

    Ok(claims)
}

/// Extract the domain (host) from an issuer URL.
fn extract_domain_from_issuer(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_issuer() {
        assert_eq!(
            extract_domain_from_issuer("https://idp.example.com"),
            "idp.example.com"
        );
        assert_eq!(
            extract_domain_from_issuer("http://localhost:9090"),
            "localhost"
        );
        assert_eq!(
            extract_domain_from_issuer("https://auth.example.com/path"),
            "auth.example.com"
        );
    }

    #[test]
    fn test_entity_proof_error_display() {
        assert_eq!(
            EntityProofError::InvalidSignature.to_string(),
            "invalid JWS signature"
        );
        assert_eq!(EntityProofError::Expired.to_string(), "entity proof has expired");
        assert_eq!(
            EntityProofError::DomainMismatch("a.com".into(), "b.com".into()).to_string(),
            "domain mismatch: expected a.com, got b.com"
        );
        assert_eq!(
            EntityProofError::IssuerMismatch("a".into(), "b".into()).to_string(),
            "issuer mismatch: expected a, got b"
        );
        assert_eq!(
            EntityProofError::MalformedPayload("test".into()).to_string(),
            "malformed payload: test"
        );
    }
}
