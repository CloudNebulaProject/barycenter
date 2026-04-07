//! WebFinger link registration with an external webfingerd instance.
//!
//! Barycenter registers itself as the authoritative OIDC issuer for its domain
//! at the configured webfingerd instance. This enables remote peers to discover
//! this Barycenter via standard WebFinger queries.

use crate::settings::WebFinger;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Rel type for OIDC issuer discovery (per OIDC Discovery 1.0 Section 2).
pub const REL_OIDC_ISSUER: &str = "http://openid.net/specs/connect/1.0/issuer";

/// Custom property indicating this issuer supports Barycenter P2P federation.
pub const PROP_FEDERATION_CAPABLE: &str = "https://barycenter.dev/rel/federation-capable";

/// Custom property pointing to the signed entity proof document.
pub const PROP_ENTITY_PROOF: &str = "https://barycenter.dev/rel/entity-proof";

/// Request body for POST /api/v1/links on webfingerd.
#[derive(Debug, Serialize)]
struct LinkRegistration {
    resource_uri: String,
    rel: String,
    href: String,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    link_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

/// Request body for POST /api/v1/links/batch on webfingerd.
#[derive(Debug, Serialize)]
struct BatchLinkRegistration {
    links: Vec<LinkRegistration>,
}

/// Response from webfingerd link registration.
#[derive(Debug, Deserialize)]
struct LinkResponse {
    #[allow(dead_code)]
    id: String,
}

/// Response from webfingerd batch registration.
#[derive(Debug, Deserialize)]
struct BatchLinkResponse {
    #[allow(dead_code)]
    links: Vec<LinkResponse>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("WebFinger not enabled")]
    NotEnabled,
    #[error("HTTP request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("webfingerd returned {status}: {body}")]
    ApiError { status: u16, body: String },
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Client for registering links with an external webfingerd instance.
pub struct WebFingerRegistrar {
    http_client: reqwest::Client,
    base_url: String,
    service_token: String,
    resource_domain: String,
}

impl WebFingerRegistrar {
    /// Create a new registrar from WebFinger settings.
    pub fn from_settings(settings: &WebFinger) -> Result<Self, RegistrationError> {
        if !settings.enabled {
            return Err(RegistrationError::NotEnabled);
        }
        if settings.base_url.is_empty() {
            return Err(RegistrationError::Config(
                "webfinger.base_url is required when webfinger is enabled".into(),
            ));
        }
        if settings.resource_domain.is_empty() {
            return Err(RegistrationError::Config(
                "webfinger.resource_domain is required when webfinger is enabled".into(),
            ));
        }

        let token = settings
            .resolve_service_token()
            .map_err(|e| RegistrationError::Config(e.to_string()))?;

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Barycenter/0.2")
            .build()
            .map_err(reqwest::Error::from)?;

        Ok(Self {
            http_client,
            base_url: settings.base_url.trim_end_matches('/').to_string(),
            service_token: token,
            resource_domain: settings.resource_domain.clone(),
        })
    }

    /// Register this Barycenter instance as the federation endpoint for the domain.
    ///
    /// Creates a WebFinger resource `acct:_federation@{domain}` with:
    /// - A link with `rel=http://openid.net/specs/connect/1.0/issuer` pointing to the issuer URL
    /// - Properties indicating federation capability and entity proof URL
    pub async fn register_federation_endpoint(
        &self,
        issuer_url: &str,
    ) -> Result<(), RegistrationError> {
        let resource_uri = format!("acct:_federation@{}", self.resource_domain);
        let entity_proof_url = format!("{}/.well-known/barycenter-entity", issuer_url);

        let link = LinkRegistration {
            resource_uri: resource_uri.clone(),
            rel: REL_OIDC_ISSUER.to_string(),
            href: issuer_url.to_string(),
            link_type: None,
            properties: Some(serde_json::json!({
                PROP_FEDERATION_CAPABLE: "true",
                PROP_ENTITY_PROOF: entity_proof_url,
            })),
            ttl_seconds: None, // permanent
        };

        self.post_link(&link).await?;
        info!(
            resource = %resource_uri,
            issuer = %issuer_url,
            "Registered federation endpoint at webfingerd"
        );
        Ok(())
    }

    /// Register an OIDC issuer link for a single user.
    ///
    /// Creates `acct:{username}@{domain}` → issuer link.
    pub async fn register_user_issuer(
        &self,
        username: &str,
        issuer_url: &str,
    ) -> Result<(), RegistrationError> {
        let resource_uri = format!("acct:{}@{}", username, self.resource_domain);

        let link = LinkRegistration {
            resource_uri: resource_uri.clone(),
            rel: REL_OIDC_ISSUER.to_string(),
            href: issuer_url.to_string(),
            link_type: None,
            properties: None,
            ttl_seconds: None,
        };

        self.post_link(&link).await?;
        info!(
            resource = %resource_uri,
            "Registered user issuer link at webfingerd"
        );
        Ok(())
    }

    /// Register OIDC issuer links for multiple users in a single batch request.
    pub async fn register_users_batch(
        &self,
        usernames: &[String],
        issuer_url: &str,
    ) -> Result<(), RegistrationError> {
        if usernames.is_empty() {
            return Ok(());
        }

        let links: Vec<LinkRegistration> = usernames
            .iter()
            .map(|username| LinkRegistration {
                resource_uri: format!("acct:{}@{}", username, self.resource_domain),
                rel: REL_OIDC_ISSUER.to_string(),
                href: issuer_url.to_string(),
                link_type: None,
                properties: None,
                ttl_seconds: None,
            })
            .collect();

        let batch = BatchLinkRegistration { links };
        let url = format!("{}/api/v1/links/batch", self.base_url);

        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(&self.service_token)
            .json(&batch)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            info!(
                count = usernames.len(),
                "Batch registered user issuer links at webfingerd"
            );
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            // 409 Conflict means links already exist — treat as success
            if status.as_u16() == 409 {
                info!(
                    count = usernames.len(),
                    "Batch user links already exist at webfingerd (409 Conflict, treating as success)"
                );
                Ok(())
            } else {
                Err(RegistrationError::ApiError {
                    status: status.as_u16(),
                    body,
                })
            }
        }
    }

    /// Delete a user's OIDC issuer link from webfingerd.
    ///
    /// Queries for the link first, then deletes it by ID.
    pub async fn deregister_user_issuer(
        &self,
        username: &str,
    ) -> Result<(), RegistrationError> {
        let resource_uri = format!("acct:{}@{}", username, self.resource_domain);
        let url = format!(
            "{}/api/v1/links?resource={}",
            self.base_url,
            urlencoding::encode(&resource_uri)
        );

        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(&self.service_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            // Link may not exist — not an error
            warn!(
                resource = %resource_uri,
                status = %resp.status(),
                "Failed to query links for deregistration"
            );
            return Ok(());
        }

        #[derive(Deserialize)]
        struct LinkEntry {
            id: String,
            rel: String,
        }

        let links: Vec<LinkEntry> = resp.json().await.unwrap_or_default();
        for link in links {
            if link.rel == REL_OIDC_ISSUER {
                let delete_url = format!("{}/api/v1/links/{}", self.base_url, link.id);
                let del_resp = self
                    .http_client
                    .delete(&delete_url)
                    .bearer_auth(&self.service_token)
                    .send()
                    .await?;

                if del_resp.status().is_success() {
                    info!(
                        resource = %resource_uri,
                        link_id = %link.id,
                        "Deregistered user issuer link from webfingerd"
                    );
                } else {
                    warn!(
                        resource = %resource_uri,
                        status = %del_resp.status(),
                        "Failed to delete user issuer link from webfingerd"
                    );
                }
            }
        }
        Ok(())
    }

    /// Post a single link to webfingerd's /api/v1/links endpoint.
    async fn post_link(&self, link: &LinkRegistration) -> Result<(), RegistrationError> {
        let url = format!("{}/api/v1/links", self.base_url);

        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(&self.service_token)
            .json(link)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            // 409 Conflict means link already exists — treat as success (upsert semantics)
            if status.as_u16() == 409 {
                info!(
                    resource = %link.resource_uri,
                    "Link already exists at webfingerd (409 Conflict, treating as success)"
                );
                Ok(())
            } else {
                Err(RegistrationError::ApiError {
                    status: status.as_u16(),
                    body,
                })
            }
        }
    }
}

/// Register this Barycenter instance at webfingerd on startup.
///
/// Called from the server startup sequence. Failures are logged but do not
/// prevent the server from starting — federation is optional.
pub async fn register_at_webfingerd_on_startup(
    settings: &crate::settings::Settings,
) {
    if !settings.webfinger.enabled {
        return;
    }

    let registrar = match WebFingerRegistrar::from_settings(&settings.webfinger) {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to initialize WebFinger registrar: {}", e);
            return;
        }
    };

    let issuer_url = settings.issuer();

    // Register the federation endpoint
    if settings.federation.enabled {
        if let Err(e) = registrar.register_federation_endpoint(&issuer_url).await {
            warn!("Failed to register federation endpoint at webfingerd: {}", e);
        }
    }

    // Note: User link registration is handled separately in user_sync and
    // the admin API when users are created/deleted. We don't bulk-register
    // all users on every startup to avoid overwhelming webfingerd.
    info!("WebFinger startup registration complete");
}
