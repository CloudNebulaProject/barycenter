//! Semi-automated mutual peer registration protocol for Barycenter P2P federation.
//!
//! This module implements the six-step peering handshake:
//! 1. Admin A calls `initiate_peering` with peer B's issuer URL.
//! 2. We auto-register at peer B via `/connect/register`.
//! 3. We send a signed peer-request JWS to B's `/federation/peer-request`.
//! 4. Peer B receives, verifies, and stores the request as `pending_approval`.
//! 5. Admin B approves, auto-registers at A, sends signed peer-confirm to A.
//! 6. Peer A receives the confirmation and activates the peer.

use base64ct::Encoding as _;
use crate::federation::storage;
use crate::federation::verification;
use crate::jwks::JwksManager;
use crate::settings::Settings;
use chrono::Utc;
use josekit::jws::{JwsHeader, RS256};
use josekit::jwt::{self, JwtPayload};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Result / error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitiatePeeringResult {
    pub peer_domain: String,
    pub status: String,
    pub client_id_at_peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRequestAccepted {
    pub request_id: String,
    pub requesting_domain: String,
    pub requesting_issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovePeeringResult {
    pub peer_domain: String,
    pub status: String,
    pub client_id_at_peer: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PeeringError {
    #[error("OIDC discovery failed for {issuer}: {reason}")]
    DiscoveryFailed { issuer: String, reason: String },

    #[error("client registration at {issuer} failed: {reason}")]
    RegistrationFailed { issuer: String, reason: String },

    #[error("failed to sign JWS: {0}")]
    SigningFailed(String),

    #[error("failed to send peer-request to {endpoint}: {reason}")]
    SendFailed { endpoint: String, reason: String },

    #[error("JWS verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid peer-request claims: {0}")]
    InvalidClaims(String),

    #[error("peer request not found: {0}")]
    RequestNotFound(String),

    #[error("peer request expired or not pending: status={0}")]
    InvalidRequestStatus(String),

    #[error("no pending_mutual peer found for issuer: {0}")]
    NoPendingPeer(String),

    #[error("peer verification failed: {0}")]
    PeerVerificationFailed(String),

    #[error("database error: {0}")]
    DatabaseError(String),
}

impl From<crate::errors::CrabError> for PeeringError {
    fn from(e: crate::errors::CrabError) -> Self {
        PeeringError::DatabaseError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Internal: OIDC discovery fetch
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OidcDiscovery {
    issuer: Option<String>,
    registration_endpoint: Option<String>,
    jwks_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistrationResponse {
    client_id: String,
    client_secret: String,
}

fn http_client() -> Result<reqwest::Client, PeeringError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Barycenter/0.2")
        .build()
        .map_err(|e| PeeringError::DiscoveryFailed {
            issuer: String::new(),
            reason: e.to_string(),
        })
}

async fn fetch_discovery(
    http: &reqwest::Client,
    peer_issuer: &str,
) -> Result<OidcDiscovery, PeeringError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        peer_issuer.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| PeeringError::DiscoveryFailed {
            issuer: peer_issuer.to_string(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(PeeringError::DiscoveryFailed {
            issuer: peer_issuer.to_string(),
            reason: format!("HTTP {}", resp.status()),
        });
    }

    resp.json::<OidcDiscovery>()
        .await
        .map_err(|e| PeeringError::DiscoveryFailed {
            issuer: peer_issuer.to_string(),
            reason: e.to_string(),
        })
}

async fn register_at_peer(
    http: &reqwest::Client,
    registration_endpoint: &str,
    our_issuer: &str,
    our_domain: &str,
) -> Result<RegistrationResponse, PeeringError> {
    let body = serde_json::json!({
        "redirect_uris": [format!("{}/federation/callback", our_issuer)],
        "client_name": format!("{} federation", our_domain),
    });

    let resp = http
        .post(registration_endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|e| PeeringError::RegistrationFailed {
            issuer: registration_endpoint.to_string(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(PeeringError::RegistrationFailed {
            issuer: registration_endpoint.to_string(),
            reason: format!("HTTP {}: {}", status, body_text),
        });
    }

    resp.json::<RegistrationResponse>()
        .await
        .map_err(|e| PeeringError::RegistrationFailed {
            issuer: registration_endpoint.to_string(),
            reason: e.to_string(),
        })
}

fn extract_domain(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

fn sign_jws(
    jwks_mgr: &JwksManager,
    claims: &serde_json::Value,
    typ: &str,
) -> Result<String, PeeringError> {
    let private_jwk = jwks_mgr.private_jwk();
    let signer = RS256
        .signer_from_jwk(&private_jwk)
        .map_err(|e| PeeringError::SigningFailed(e.to_string()))?;

    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header
        .set_claim(
            "typ",
            Some(serde_json::Value::String(typ.to_string())),
        )
        .ok();
    if let Some(kid) = private_jwk.key_id() {
        header.set_key_id(kid);
    }

    let mut payload = JwtPayload::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            payload.set_claim(k, Some(v.clone())).ok();
        }
    }

    jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| PeeringError::SigningFailed(e.to_string()))
}

/// Verify a JWS by fetching the sender's JWKS from their issuer's
/// `/.well-known/jwks.json` and checking the signature.
async fn verify_jws_from_issuer(
    http: &reqwest::Client,
    jws_compact: &str,
    sender_issuer: &str,
) -> Result<serde_json::Value, PeeringError> {
    // Fetch the sender's JWKS
    let jwks_url = format!(
        "{}/.well-known/jwks.json",
        sender_issuer.trim_end_matches('/')
    );
    let jwks_resp = http
        .get(&jwks_url)
        .send()
        .await
        .map_err(|e| PeeringError::VerificationFailed(format!("fetch JWKS: {e}")))?;

    if !jwks_resp.status().is_success() {
        return Err(PeeringError::VerificationFailed(format!(
            "JWKS fetch HTTP {}",
            jwks_resp.status()
        )));
    }

    let jwks_value: serde_json::Value = jwks_resp
        .json()
        .await
        .map_err(|e| PeeringError::VerificationFailed(format!("parse JWKS: {e}")))?;

    let keys = jwks_value
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| {
            PeeringError::VerificationFailed("JWKS missing keys array".to_string())
        })?;

    // Decode JWS header to find kid
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() != 3 {
        return Err(PeeringError::VerificationFailed(
            "JWS must have 3 parts".to_string(),
        ));
    }

    let header_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[0])
        .map_err(|e| PeeringError::VerificationFailed(format!("decode header: {e}")))?;
    let header_value: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| PeeringError::VerificationFailed(format!("parse header: {e}")))?;

    let header_kid = header_value.get("kid").and_then(|v| v.as_str());

    // Find matching key
    let matching_key = if let Some(kid) = header_kid {
        keys.iter()
            .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
    } else {
        keys.first()
    };

    let key_value = matching_key.ok_or_else(|| {
        PeeringError::VerificationFailed("no matching key in JWKS".to_string())
    })?;

    let key_map: serde_json::Map<String, serde_json::Value> = key_value
        .as_object()
        .ok_or_else(|| PeeringError::VerificationFailed("JWK not an object".to_string()))?
        .clone();

    let jwk = josekit::jwk::Jwk::from_map(key_map)
        .map_err(|e| PeeringError::VerificationFailed(format!("invalid JWK: {e}")))?;

    let verifier = RS256
        .verifier_from_jwk(&jwk)
        .map_err(|_| PeeringError::VerificationFailed("cannot create verifier".to_string()))?;

    let (verified_payload, _header) = jwt::decode_with_verifier(jws_compact, &verifier)
        .map_err(|_| PeeringError::VerificationFailed("invalid JWS signature".to_string()))?;

    // Convert to serde_json::Value
    serde_json::to_value(verified_payload.claims_set())
        .map_err(|e| PeeringError::VerificationFailed(format!("serialize claims: {e}")))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Step 1-3: Admin initiates peering with a remote peer.
///
/// - Fetches remote OIDC discovery
/// - Auto-registers at the peer's `/connect/register`
/// - Sends a signed peer-request JWS to the peer
/// - Stores the peer locally with status `pending_mutual`
pub async fn initiate_peering(
    db: &DatabaseConnection,
    jwks_mgr: &JwksManager,
    settings: &Settings,
    peer_issuer_url: &str,
) -> Result<InitiatePeeringResult, PeeringError> {
    let peer_issuer = peer_issuer_url.trim_end_matches('/');
    let our_issuer = settings.issuer();
    let our_domain = extract_domain(&our_issuer);
    let peer_domain = extract_domain(peer_issuer);

    let http = http_client()?;

    // Step 2a: Discover peer
    let discovery = fetch_discovery(&http, peer_issuer).await?;
    let reg_endpoint = discovery.registration_endpoint.ok_or_else(|| {
        PeeringError::DiscoveryFailed {
            issuer: peer_issuer.to_string(),
            reason: "no registration_endpoint in discovery".to_string(),
        }
    })?;

    // Step 2b: Register at peer
    let reg = register_at_peer(&http, &reg_endpoint, &our_issuer, &our_domain).await?;

    // Step 3a: Build signed peer-request JWS
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let claims = serde_json::json!({
        "iss": our_issuer,
        "sub": our_issuer,
        "iat": now,
        "exp": now + 86400, // 24h
        "type": "peer-request",
        "requesting_issuer": our_issuer,
        "requesting_domain": our_domain,
        "client_id_at_target": reg.client_id,
        "callback_endpoint": format!("{}/federation/callback", our_issuer),
    });

    let jws = sign_jws(jwks_mgr, &claims, "peer-request+jwt")?;

    // Step 3b: POST to peer
    let peer_request_endpoint = format!("{}/federation/peer-request", peer_issuer);
    let resp = http
        .post(&peer_request_endpoint)
        .header("content-type", "application/peer-request+jwt")
        .body(jws)
        .send()
        .await
        .map_err(|e| PeeringError::SendFailed {
            endpoint: peer_request_endpoint.clone(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(PeeringError::SendFailed {
            endpoint: peer_request_endpoint,
            reason: format!("HTTP {}: {}", status, body_text),
        });
    }

    // Step 3c: Store peer locally as pending_mutual
    let peer_id = storage::create_trusted_peer(
        db,
        &peer_domain,
        peer_issuer,
        &reg.client_id,
        Some(&reg.client_secret),
        "prompt",
        "pin_on_first_use",
    )
    .await?;

    storage::update_trusted_peer_status(db, &peer_id, "pending_mutual").await?;

    Ok(InitiatePeeringResult {
        peer_domain,
        status: "pending_mutual".to_string(),
        client_id_at_peer: reg.client_id,
    })
}

/// Step 4: Handle an incoming peer-request JWS.
///
/// - Verifies the JWS signature by fetching the sender's JWKS
/// - Validates the claims
/// - Stores in peer_requests with status `pending_approval`
pub async fn handle_peer_request(
    db: &DatabaseConnection,
    _jwks_mgr: &JwksManager,
    _settings: &Settings,
    jws_body: &str,
) -> Result<PeerRequestAccepted, PeeringError> {
    let http = http_client()?;

    // First, decode unverified to get the issuer so we know where to fetch JWKS
    let parts: Vec<&str> = jws_body.split('.').collect();
    if parts.len() != 3 {
        return Err(PeeringError::InvalidClaims("JWS must have 3 parts".to_string()));
    }

    let payload_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| PeeringError::InvalidClaims(format!("invalid base64: {e}")))?;
    let unverified: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| PeeringError::InvalidClaims(format!("invalid JSON: {e}")))?;

    let requesting_issuer = unverified
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PeeringError::InvalidClaims("missing iss".to_string()))?
        .to_string();

    // Verify the JWS signature
    let claims = verify_jws_from_issuer(&http, jws_body, &requesting_issuer).await?;

    // Validate required claims
    let claim_type = claims
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if claim_type != "peer-request" {
        return Err(PeeringError::InvalidClaims(format!(
            "expected type=peer-request, got {}",
            claim_type
        )));
    }

    let requesting_domain = claims
        .get("requesting_domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PeeringError::InvalidClaims("missing requesting_domain".to_string()))?
        .to_string();

    let client_id_at_us = claims
        .get("client_id_at_target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PeeringError::InvalidClaims("missing client_id_at_target".to_string()))?
        .to_string();

    let callback_endpoint = claims
        .get("callback_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PeeringError::InvalidClaims("missing callback_endpoint".to_string()))?
        .to_string();

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if exp <= now {
        return Err(PeeringError::InvalidClaims("peer-request has expired".to_string()));
    }

    // Compute expiration as ISO string
    let expires_at = chrono::DateTime::from_timestamp(exp, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

    // Store the request
    let request_id = storage::create_peer_request(
        db,
        &requesting_issuer,
        &requesting_domain,
        &client_id_at_us,
        &callback_endpoint,
        jws_body,
        &expires_at,
    )
    .await?;

    tracing::info!(
        request_id,
        requesting_issuer,
        requesting_domain,
        "Received peer-request, stored as pending_approval"
    );

    Ok(PeerRequestAccepted {
        request_id,
        requesting_domain,
        requesting_issuer,
    })
}

/// Step 5: Admin B approves an incoming peer request.
///
/// - Loads the request
/// - Auto-registers at the requester's `/connect/register`
/// - Creates a trusted_peer with status `active`
/// - Sends a signed peer-confirm JWS to the requester
pub async fn approve_peer_request(
    db: &DatabaseConnection,
    jwks_mgr: &JwksManager,
    settings: &Settings,
    request_id: &str,
) -> Result<ApprovePeeringResult, PeeringError> {
    // Load request
    let request = storage::get_peer_request(db, request_id)
        .await?
        .ok_or_else(|| PeeringError::RequestNotFound(request_id.to_string()))?;

    if request.status != "pending_approval" {
        return Err(PeeringError::InvalidRequestStatus(request.status));
    }

    // Check not expired
    let now_iso = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    if request.expires_at < now_iso {
        storage::update_peer_request_status(db, request_id, "expired").await?;
        return Err(PeeringError::InvalidRequestStatus("expired".to_string()));
    }

    let our_issuer = settings.issuer();
    let our_domain = extract_domain(&our_issuer);
    let peer_issuer = request.requesting_issuer.trim_end_matches('/');
    let peer_domain = &request.requesting_domain;

    let http = http_client()?;

    // Step 5a: Discover peer and register at their /connect/register
    let discovery = fetch_discovery(&http, peer_issuer).await?;
    let reg_endpoint = discovery.registration_endpoint.ok_or_else(|| {
        PeeringError::DiscoveryFailed {
            issuer: peer_issuer.to_string(),
            reason: "no registration_endpoint in discovery".to_string(),
        }
    })?;

    let reg = register_at_peer(&http, &reg_endpoint, &our_issuer, &our_domain).await?;

    // Step 5b: Create trusted_peer as active
    let peer_id = storage::create_trusted_peer(
        db,
        peer_domain,
        peer_issuer,
        &reg.client_id,
        Some(&reg.client_secret),
        "prompt",
        "pin_on_first_use",
    )
    .await?;

    storage::update_trusted_peer_status(db, &peer_id, "active").await?;

    // Step 5c: Send signed peer-confirm
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let confirm_claims = serde_json::json!({
        "iss": our_issuer,
        "sub": our_issuer,
        "iat": now,
        "exp": now + 3600, // 1h validity for confirmation
        "type": "peer-confirm",
        "confirming_issuer": our_issuer,
        "confirming_domain": our_domain,
        "client_id_at_target": reg.client_id,
        "original_request_client_id": request.client_id_at_us,
    });

    let jws = sign_jws(jwks_mgr, &confirm_claims, "peer-confirm+jwt")?;

    // Determine confirm endpoint from the requester's issuer
    let confirm_endpoint = format!("{}/federation/peer-confirm", peer_issuer);
    let resp = http
        .post(&confirm_endpoint)
        .header("content-type", "application/peer-confirm+jwt")
        .body(jws)
        .send()
        .await
        .map_err(|e| PeeringError::SendFailed {
            endpoint: confirm_endpoint.clone(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        tracing::warn!(
            "peer-confirm POST to {} returned HTTP {}",
            confirm_endpoint,
            resp.status()
        );
        // We still mark approved locally even if the remote side is slow
    }

    // Step 5d: Update request status
    storage::update_peer_request_status(db, request_id, "approved").await?;

    tracing::info!(
        request_id,
        peer_domain,
        peer_issuer,
        "Peer request approved and peer-confirm sent"
    );

    Ok(ApprovePeeringResult {
        peer_domain: peer_domain.to_string(),
        status: "active".to_string(),
        client_id_at_peer: reg.client_id,
    })
}

/// Step 6: Handle an incoming peer-confirm JWS.
///
/// - Verifies the JWS signature
/// - Finds our pending_mutual peer
/// - Runs verification
/// - Activates the peer
pub async fn handle_peer_confirm(
    db: &DatabaseConnection,
    _settings: &Settings,
    jws_body: &str,
) -> Result<(), PeeringError> {
    let http = http_client()?;

    // Decode unverified to get issuer
    let parts: Vec<&str> = jws_body.split('.').collect();
    if parts.len() != 3 {
        return Err(PeeringError::InvalidClaims("JWS must have 3 parts".to_string()));
    }

    let payload_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| PeeringError::InvalidClaims(format!("invalid base64: {e}")))?;
    let unverified: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| PeeringError::InvalidClaims(format!("invalid JSON: {e}")))?;

    let confirming_issuer = unverified
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PeeringError::InvalidClaims("missing iss".to_string()))?
        .to_string();

    // Verify JWS
    let claims = verify_jws_from_issuer(&http, jws_body, &confirming_issuer).await?;

    // Validate type
    let claim_type = claims
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if claim_type != "peer-confirm" {
        return Err(PeeringError::InvalidClaims(format!(
            "expected type=peer-confirm, got {}",
            claim_type
        )));
    }

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if exp <= now {
        return Err(PeeringError::InvalidClaims("peer-confirm has expired".to_string()));
    }

    let confirming_domain = claims
        .get("confirming_domain")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Find our pending_mutual peer for this issuer
    let peer = storage::get_trusted_peer_by_issuer_url(db, confirming_issuer.trim_end_matches('/'))
        .await?
        .ok_or_else(|| PeeringError::NoPendingPeer(confirming_issuer.clone()))?;

    if peer.status != "pending_mutual" {
        return Err(PeeringError::NoPendingPeer(format!(
            "peer exists but status={}, expected pending_mutual",
            peer.status
        )));
    }

    // Run verification to populate discovery endpoints
    match verification::verify_peer(&peer.domain, &peer.issuer_url).await {
        Ok(result) => {
            storage::update_trusted_peer_discovery(
                db,
                &peer.id,
                Some(&result.token_endpoint),
                Some(&result.authorization_endpoint),
                result.userinfo_endpoint.as_deref(),
                Some(&result.jwks_uri),
                result.pinned_jwks.as_deref(),
            )
            .await?;

            storage::update_trusted_peer_verification(
                db,
                &peer.id,
                Some(&result.verification_level),
                Some(result.webfinger_issuer_match),
            )
            .await?;
        }
        Err(e) => {
            tracing::warn!(
                peer_domain = peer.domain,
                "Verification failed during peer-confirm, activating anyway: {}",
                e
            );
            // Still activate - the confirmation JWS itself is already verified
        }
    }

    // Activate the peer
    storage::update_trusted_peer_status(db, &peer.id, "active").await?;

    tracing::info!(
        confirming_issuer,
        confirming_domain,
        peer_id = peer.id,
        "Peer confirmed and activated"
    );

    Ok(())
}
