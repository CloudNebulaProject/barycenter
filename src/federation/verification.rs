//! Peer verification for Barycenter's P2P federation protocol.
//!
//! When `addTrustedPeer` is called, this module verifies the remote peer by
//! performing WebFinger discovery, OIDC discovery, and optionally validating
//! an entity proof.

use serde::{Deserialize, Serialize};

use crate::federation::entity_proof;
use crate::federation::storage::TrustedPeer;
use crate::federation::webfinger::WebFingerClient;

// ---------------------------------------------------------------------------
// Result / error types
// ---------------------------------------------------------------------------

/// The outcome of verifying a remote peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// `"entity_proof"` or `"discovery_only"`.
    pub verification_level: String,
    /// Whether the WebFinger issuer href matched the expected issuer URL.
    pub webfinger_issuer_match: bool,
    /// The peer's authorization endpoint from OIDC discovery.
    pub authorization_endpoint: String,
    /// The peer's token endpoint from OIDC discovery.
    pub token_endpoint: String,
    /// The peer's userinfo endpoint (optional).
    pub userinfo_endpoint: Option<String>,
    /// The peer's JWKS URI from OIDC discovery.
    pub jwks_uri: String,
    /// The fetched JWKS document as a JSON string (for pinning).
    pub pinned_jwks: Option<String>,
}

/// Errors that can occur during peer verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("no federation WebFinger entry for domain: {0}")]
    WebFingerNoEntry(String),

    #[error("WebFinger issuer mismatch: expected {expected}, found {found}")]
    WebFingerIssuerMismatch { expected: String, found: String },

    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("discovery issuer mismatch: expected {expected}, found {found}")]
    DiscoveryIssuerMismatch { expected: String, found: String },

    #[error("entity proof verification failed: {0}")]
    EntityProofFailed(String),

    #[error("network error: {0}")]
    NetworkError(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify a remote peer by domain and issuer URL.
///
/// Performs WebFinger lookup, OIDC discovery, optional entity proof
/// verification, and JWKS fetching.
pub async fn verify_peer(
    domain: &str,
    issuer_url: &str,
) -> Result<VerificationResult, VerificationError> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Barycenter/0.2")
        .build()
        .map_err(|e| VerificationError::NetworkError(e.to_string()))?;

    // --- a) WebFinger check ---
    let wf_client = WebFingerClient::new();
    let federation_acct = format!("_federation@{}", domain);

    let discovered_issuer = wf_client
        .discover_issuer(&federation_acct)
        .await
        .map_err(|e| match e {
            crate::federation::webfinger::WebFingerError::NotFound
            | crate::federation::webfinger::WebFingerError::NoIssuerLink => {
                VerificationError::WebFingerNoEntry(domain.to_string())
            }
            other => VerificationError::NetworkError(other.to_string()),
        })?;

    let webfinger_issuer_match = discovered_issuer == issuer_url;
    if !webfinger_issuer_match {
        return Err(VerificationError::WebFingerIssuerMismatch {
            expected: issuer_url.to_string(),
            found: discovered_issuer,
        });
    }

    // --- b) OIDC Discovery check ---
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let discovery_resp = http
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| VerificationError::DiscoveryFailed(e.to_string()))?;

    if !discovery_resp.status().is_success() {
        return Err(VerificationError::DiscoveryFailed(format!(
            "HTTP {}",
            discovery_resp.status()
        )));
    }

    let discovery: serde_json::Value = discovery_resp
        .json()
        .await
        .map_err(|e| VerificationError::DiscoveryFailed(e.to_string()))?;

    let disc_issuer = discovery
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if disc_issuer != issuer_url {
        return Err(VerificationError::DiscoveryIssuerMismatch {
            expected: issuer_url.to_string(),
            found: disc_issuer.to_string(),
        });
    }

    let authorization_endpoint = discovery
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerificationError::DiscoveryFailed(
                "missing authorization_endpoint in discovery".to_string(),
            )
        })?
        .to_string();

    let token_endpoint = discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerificationError::DiscoveryFailed("missing token_endpoint in discovery".to_string())
        })?
        .to_string();

    let userinfo_endpoint = discovery
        .get("userinfo_endpoint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerificationError::DiscoveryFailed("missing jwks_uri in discovery".to_string())
        })?
        .to_string();

    // --- c) Entity proof check (optional upgrade) ---
    let entity_proof_url = wf_client
        .discover_entity_proof_url(&federation_acct)
        .await
        .ok()
        .flatten();

    let verification_level = if let Some(proof_url) = entity_proof_url {
        match try_verify_entity_proof(&http, &proof_url, domain, issuer_url).await {
            Ok(()) => "entity_proof".to_string(),
            Err(msg) => {
                tracing::warn!(
                    domain,
                    "entity proof verification failed, falling back to discovery_only: {}",
                    msg
                );
                "discovery_only".to_string()
            }
        }
    } else {
        tracing::info!(domain, "no entity proof URL found; verification_level=discovery_only");
        "discovery_only".to_string()
    };

    // --- d) Fetch and pin JWKS ---
    let pinned_jwks = match http.get(&jwks_uri).send().await {
        Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
        Ok(resp) => {
            tracing::warn!(domain, "failed to fetch JWKS: HTTP {}", resp.status());
            None
        }
        Err(e) => {
            tracing::warn!(domain, "failed to fetch JWKS: {}", e);
            None
        }
    };

    Ok(VerificationResult {
        verification_level,
        webfinger_issuer_match,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        jwks_uri,
        pinned_jwks,
    })
}

/// Convenience wrapper: re-verify an existing trusted peer.
pub async fn reverify_peer(
    peer: &TrustedPeer,
) -> Result<VerificationResult, VerificationError> {
    verify_peer(&peer.domain, &peer.issuer_url).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Fetch and verify the entity proof JWS from the given URL.
async fn try_verify_entity_proof(
    http: &reqwest::Client,
    proof_url: &str,
    expected_domain: &str,
    expected_issuer: &str,
) -> Result<(), String> {
    let resp = http
        .get(proof_url)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let jws = resp.text().await.map_err(|e| format!("body read: {e}"))?;

    entity_proof::verify_entity_proof(&jws, expected_domain, expected_issuer)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
