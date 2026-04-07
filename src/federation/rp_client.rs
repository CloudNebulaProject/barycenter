use base64ct::Encoding;
use josekit::jwk::Jwk;
use josekit::jws::RS256;
use josekit::jwt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::storage::TrustedPeer;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RpClientError {
    #[error("discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("token validation failed: {0}")]
    TokenValidationFailed(String),

    #[error("userinfo request failed: {0}")]
    UserInfoFailed(String),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("invalid issuer: expected {expected}, got {got}")]
    InvalidIssuer { expected: String, got: String },

    #[error("invalid audience: expected {expected}, got {got}")]
    InvalidAudience { expected: String, got: String },

    #[error("token expired")]
    TokenExpired,

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: String, got: String },

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),
}

// ---------------------------------------------------------------------------
// Response / claims types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value, // can be string or array
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Option<Vec<String>>,
    pub acr: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoClaims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
}

// ---------------------------------------------------------------------------
// OIDC Relying Party client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OidcRpClient {
    http_client: reqwest::Client,
}

impl OidcRpClient {
    /// Create a new `OidcRpClient` with a 15-second timeout and Barycenter user-agent.
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Barycenter/0.2")
            .build()
            .expect("failed to build reqwest client");

        Self { http_client }
    }

    /// Fetch and parse the OpenID Provider metadata from the well-known endpoint.
    pub async fn discover(&self, issuer_url: &str) -> Result<ProviderMetadata, RpClientError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(RpClientError::DiscoveryFailed(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        let metadata: ProviderMetadata = response.json().await.map_err(|e| {
            RpClientError::DiscoveryFailed(format!("failed to parse metadata: {}", e))
        })?;

        // Validate that the returned issuer matches what we requested.
        let expected = issuer_url.trim_end_matches('/');
        let got = metadata.issuer.trim_end_matches('/');
        if expected != got {
            return Err(RpClientError::InvalidIssuer {
                expected: expected.to_string(),
                got: got.to_string(),
            });
        }

        Ok(metadata)
    }

    /// Build the authorization URL to redirect the user to the peer IdP.
    pub fn build_authorize_url(
        &self,
        peer: &TrustedPeer,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
    ) -> Result<String, RpClientError> {
        let auth_endpoint = peer.authorization_endpoint.as_deref().ok_or_else(|| {
            RpClientError::DiscoveryFailed(
                "peer has no authorization_endpoint configured".to_string(),
            )
        })?;

        let params = [
            ("response_type", "code"),
            ("client_id", &peer.client_id),
            ("redirect_uri", redirect_uri),
            ("scope", &peer.scopes),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ];

        let query = serde_urlencoded::to_string(&params).map_err(|e| {
            RpClientError::DiscoveryFailed(format!("failed to encode parameters: {}", e))
        })?;

        Ok(format!("{}?{}", auth_endpoint, query))
    }

    /// Exchange an authorization code for tokens at the peer's token endpoint.
    pub async fn exchange_code(
        &self,
        peer: &TrustedPeer,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, RpClientError> {
        let token_endpoint = peer.token_endpoint.as_deref().ok_or_else(|| {
            RpClientError::TokenExchangeFailed("peer has no token_endpoint configured".to_string())
        })?;

        let client_secret = peer.client_secret.as_deref().ok_or_else(|| {
            RpClientError::TokenExchangeFailed("peer has no client_secret configured".to_string())
        })?;

        // Build client_secret_basic Authorization header.
        let credentials = format!("{}:{}", peer.client_id, client_secret);
        let encoded = base64ct::Base64::encode_string(credentials.as_bytes());

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];

        let response = self
            .http_client
            .post(token_endpoint)
            .header("Authorization", format!("Basic {}", encoded))
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Try to parse as an OAuth error response.
            if let Ok(err) = serde_json::from_str::<TokenErrorResponse>(&body) {
                let msg = match err.error_description {
                    Some(desc) => format!("{}: {}", err.error, desc),
                    None => err.error,
                };
                return Err(RpClientError::TokenExchangeFailed(msg));
            }

            return Err(RpClientError::TokenExchangeFailed(format!(
                "HTTP {} – {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            RpClientError::TokenExchangeFailed(format!("failed to parse token response: {}", e))
        })?;

        Ok(token_response)
    }

    /// Validate an ID token JWT against the peer's pinned JWKS.
    ///
    /// Checks signature, issuer, audience, expiration, and nonce.
    pub fn validate_id_token(
        &self,
        id_token_jwt: &str,
        peer: &TrustedPeer,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, RpClientError> {
        // Resolve JWKS based on the peer's pin mode.
        // - pin_on_first_use / pin_explicit: use pinned_jwks (must exist)
        // - trust_discovery: pinned_jwks is optional; if missing, caller should
        //   have fetched live JWKS before calling this method. We still require
        //   the keys to be passed via pinned_jwks field.
        let jwks_json = peer.pinned_jwks.as_deref().ok_or_else(|| {
            let mode = &peer.jwks_pin_mode;
            RpClientError::TokenValidationFailed(format!(
                "peer has no pinned_jwks (jwks_pin_mode={}) – keys needed for token verification. \
                 Use refreshPeerDiscovery to fetch and pin the peer's keys.",
                mode
            ))
        })?;

        let jwks: serde_json::Value = serde_json::from_str(jwks_json).map_err(|e| {
            RpClientError::TokenValidationFailed(format!("failed to parse pinned JWKS: {}", e))
        })?;

        let keys = jwks
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| {
                RpClientError::TokenValidationFailed(
                    "pinned_jwks does not contain a keys array".to_string(),
                )
            })?;

        // Extract the kid from the JWT header to pick the right key.
        let header_part = id_token_jwt.split('.').next().ok_or_else(|| {
            RpClientError::TokenValidationFailed("malformed JWT – no header".to_string())
        })?;

        let header_bytes =
            base64ct::Base64UrlUnpadded::decode_vec(header_part).map_err(|e| {
                RpClientError::TokenValidationFailed(format!("failed to decode JWT header: {}", e))
            })?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
            RpClientError::TokenValidationFailed(format!("failed to parse JWT header: {}", e))
        })?;

        let token_kid = header.get("kid").and_then(|k| k.as_str());

        // Find the matching key in the JWKS.
        let jwk_value = if let Some(kid) = token_kid {
            keys.iter()
                .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
                .ok_or_else(|| {
                    RpClientError::SignatureVerification(format!(
                        "no key with kid '{}' in peer JWKS",
                        kid
                    ))
                })?
        } else if keys.len() == 1 {
            &keys[0]
        } else {
            return Err(RpClientError::SignatureVerification(
                "JWT has no kid and peer JWKS contains multiple keys".to_string(),
            ));
        };

        let jwk = Jwk::from_bytes(
            serde_json::to_string(jwk_value)
                .map_err(|e| RpClientError::SignatureVerification(e.to_string()))?
                .as_bytes(),
        )
        .map_err(|e| RpClientError::SignatureVerification(format!("invalid JWK: {}", e)))?;

        // Verify the RS256 signature.
        let verifier = RS256.verifier_from_jwk(&jwk).map_err(|e| {
            RpClientError::SignatureVerification(format!("failed to create verifier: {}", e))
        })?;

        let (payload, _header) = jwt::decode_with_verifier(id_token_jwt, &verifier).map_err(
            |e| {
                RpClientError::SignatureVerification(format!("signature verification failed: {}", e))
            },
        )?;

        // Parse the payload into our claims struct.
        let payload_json = serde_json::to_value(payload.claims_set()).map_err(|e| {
            RpClientError::TokenValidationFailed(format!("failed to serialise claims: {}", e))
        })?;

        let claims: IdTokenClaims = serde_json::from_value(payload_json).map_err(|e| {
            RpClientError::TokenValidationFailed(format!("failed to parse ID token claims: {}", e))
        })?;

        // -- Validate issuer --
        let expected_iss = peer.issuer_url.trim_end_matches('/');
        let got_iss = claims.iss.trim_end_matches('/');
        if expected_iss != got_iss {
            return Err(RpClientError::InvalidIssuer {
                expected: expected_iss.to_string(),
                got: got_iss.to_string(),
            });
        }

        // -- Validate audience --
        let aud_matches = match &claims.aud {
            serde_json::Value::String(s) => s == &peer.client_id,
            serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(&peer.client_id)),
            _ => false,
        };
        if !aud_matches {
            return Err(RpClientError::InvalidAudience {
                expected: peer.client_id.clone(),
                got: claims.aud.to_string(),
            });
        }

        // -- Validate expiration --
        let now = chrono::Utc::now().timestamp();
        if claims.exp <= now {
            return Err(RpClientError::TokenExpired);
        }

        // -- Validate iat freshness (must be within last 10 minutes) --
        let max_iat_age_secs = 600; // 10 minutes
        if now - claims.iat > max_iat_age_secs {
            return Err(RpClientError::TokenValidationFailed(format!(
                "ID token iat is too old: issued {}s ago (max {}s)",
                now - claims.iat,
                max_iat_age_secs
            )));
        }
        if claims.iat > now + 60 {
            // Allow 60s clock skew into the future
            return Err(RpClientError::TokenValidationFailed(format!(
                "ID token iat is in the future: {}s ahead",
                claims.iat - now
            )));
        }

        // -- Validate nonce --
        match &claims.nonce {
            Some(n) if n != expected_nonce => {
                return Err(RpClientError::NonceMismatch {
                    expected: expected_nonce.to_string(),
                    got: n.clone(),
                });
            }
            None => {
                return Err(RpClientError::NonceMismatch {
                    expected: expected_nonce.to_string(),
                    got: String::new(),
                });
            }
            _ => {} // matches
        }

        Ok(claims)
    }

    /// Fetch user info from the peer's userinfo endpoint using the access token.
    pub async fn fetch_userinfo(
        &self,
        peer: &TrustedPeer,
        access_token: &str,
    ) -> Result<UserInfoClaims, RpClientError> {
        let userinfo_endpoint = peer.userinfo_endpoint.as_deref().ok_or_else(|| {
            RpClientError::UserInfoFailed("peer has no userinfo_endpoint configured".to_string())
        })?;

        let response = self
            .http_client
            .get(userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(RpClientError::UserInfoFailed(format!(
                "HTTP {} from userinfo endpoint",
                response.status()
            )));
        }

        let claims: UserInfoClaims = response.json().await.map_err(|e| {
            RpClientError::UserInfoFailed(format!("failed to parse userinfo response: {}", e))
        })?;

        Ok(claims)
    }

    /// Generate a PKCE code_verifier and its S256 code_challenge.
    ///
    /// Returns `(code_verifier, code_challenge)` as base64url-encoded strings.
    pub fn generate_pkce() -> (String, String) {
        let mut verifier_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut verifier_bytes);
        let code_verifier = base64ct::Base64UrlUnpadded::encode_string(&verifier_bytes);

        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let digest = hasher.finalize();
        let code_challenge = base64ct::Base64UrlUnpadded::encode_string(&digest);

        (code_verifier, code_challenge)
    }
}

impl Default for OidcRpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce_produces_valid_pair() {
        let (verifier, challenge) = OidcRpClient::generate_pkce();

        // Verifier should be 43 chars (32 bytes base64url-unpadded).
        assert_eq!(verifier.len(), 43);

        // Recompute the challenge from the verifier.
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        let expected_challenge = base64ct::Base64UrlUnpadded::encode_string(&digest);

        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn test_generate_pkce_uniqueness() {
        let (v1, _) = OidcRpClient::generate_pkce();
        let (v2, _) = OidcRpClient::generate_pkce();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_build_authorize_url() {
        let client = OidcRpClient::new();
        let peer = TrustedPeer {
            id: "peer1".to_string(),
            domain: "other.example.com".to_string(),
            issuer_url: "https://other.example.com".to_string(),
            client_id: "my-client-id".to_string(),
            client_secret: Some("secret".to_string()),
            token_endpoint: Some("https://other.example.com/token".to_string()),
            authorization_endpoint: Some("https://other.example.com/authorize".to_string()),
            userinfo_endpoint: Some("https://other.example.com/userinfo".to_string()),
            jwks_uri: Some("https://other.example.com/.well-known/jwks.json".to_string()),
            pinned_jwks: None,
            jwks_pin_mode: "tofu".to_string(),
            scopes: "openid email profile".to_string(),
            mapping_policy: "prompt".to_string(),
            trust_peer_acr: false,
            sync_profile: false,
            status: "active".to_string(),
            verification_level: None,
            verified_at: None,
            webfinger_issuer_match: None,
            last_discovery_refresh: None,
            last_discovery_error: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let url = client
            .build_authorize_url(&peer, "state123", "nonce456", "challenge789", "http://localhost/callback")
            .unwrap();

        assert!(url.starts_with("https://other.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client-id"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("nonce=nonce456"));
        assert!(url.contains("code_challenge=challenge789"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=openid+email+profile"));
    }
}
