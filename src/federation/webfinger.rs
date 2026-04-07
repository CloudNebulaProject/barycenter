use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use chrono::{DateTime, Utc};

/// Cache time-to-live in seconds.
const CACHE_TTL_SECS: i64 = 300;

/// OpenID Connect issuer link relation.
const OIDC_ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

/// Barycenter entity proof link relation.
const ENTITY_PROOF_REL: &str = "https://barycenter.dev/rel/entity-proof";

// ---------------------------------------------------------------------------
// JRD types (RFC 7033)
// ---------------------------------------------------------------------------

/// JSON Resource Descriptor document as defined in RFC 7033.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JrdDocument {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, Option<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<JrdLink>>,
}

/// A single link inside a JRD document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JrdLink {
    pub rel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub titles: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, Option<String>>>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during WebFinger resolution.
#[derive(Debug, thiserror::Error)]
pub enum WebFingerError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("resource not found")]
    NotFound,

    #[error("no issuer link in WebFinger response")]
    NoIssuerLink,

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CacheEntry {
    issuer: String,
    expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// WebFingerClient
// ---------------------------------------------------------------------------

/// HTTP client for WebFinger (RFC 7033) discovery.
#[derive(Debug, Clone)]
pub struct WebFingerClient {
    http_client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl WebFingerClient {
    /// Create a new `WebFingerClient` with sensible defaults.
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Barycenter/0.2")
            .build()
            .expect("failed to build reqwest client");

        Self {
            http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Discover the OpenID Connect issuer for an email-like identifier.
    ///
    /// The identifier should look like `user@domain` (e.g. `toasty@wegmueller.it`).
    /// The method queries the domain's WebFinger endpoint and returns the issuer
    /// URL from the link with rel `http://openid.net/specs/connect/1.0/issuer`.
    pub async fn discover_issuer(&self, identifier: &str) -> Result<String, WebFingerError> {
        // Check cache first.
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(identifier) {
                if entry.expires_at > Utc::now() {
                    return Ok(entry.issuer.clone());
                }
            }
        }

        let domain = Self::extract_domain(identifier)?;
        let jrd = self.fetch_webfinger(&domain, identifier).await?;

        let links = jrd.links.as_ref().ok_or(WebFingerError::NoIssuerLink)?;
        let issuer_link = links
            .iter()
            .find(|l| l.rel == OIDC_ISSUER_REL)
            .ok_or(WebFingerError::NoIssuerLink)?;

        let issuer = issuer_link
            .href
            .as_ref()
            .ok_or_else(|| {
                WebFingerError::InvalidResponse("issuer link has no href".to_string())
            })?
            .clone();

        // Cache the result.
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                identifier.to_string(),
                CacheEntry {
                    issuer: issuer.clone(),
                    expires_at: Utc::now() + chrono::Duration::seconds(CACHE_TTL_SECS),
                },
            );
        }

        Ok(issuer)
    }

    /// Discover the entity proof URL for an email-like identifier.
    ///
    /// Returns `Ok(Some(url))` if the WebFinger response contains a link with
    /// the `https://barycenter.dev/rel/entity-proof` property, or `Ok(None)` if
    /// no such property exists.
    pub async fn discover_entity_proof_url(
        &self,
        identifier: &str,
    ) -> Result<Option<String>, WebFingerError> {
        let domain = Self::extract_domain(identifier)?;
        let jrd = self.fetch_webfinger(&domain, identifier).await?;

        let links = match jrd.links.as_ref() {
            Some(links) => links,
            None => return Ok(None),
        };

        for link in links {
            if let Some(props) = &link.properties {
                if props.contains_key(ENTITY_PROOF_REL) {
                    return Ok(link.href.clone());
                }
            }
        }

        Ok(None)
    }

    /// Extract the domain part from an email-like identifier.
    ///
    /// Returns an error if the identifier does not contain an `@` sign or if
    /// the domain part is empty.
    pub fn extract_domain(identifier: &str) -> Result<String, WebFingerError> {
        let parts: Vec<&str> = identifier.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(WebFingerError::InvalidIdentifier(format!(
                "identifier '{}' does not contain '@'",
                identifier
            )));
        }

        let domain = parts[1];
        if domain.is_empty() {
            return Err(WebFingerError::InvalidIdentifier(
                "domain part is empty".to_string(),
            ));
        }

        Ok(domain.to_string())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Perform the actual WebFinger HTTP request and parse the JRD response.
    async fn fetch_webfinger(
        &self,
        domain: &str,
        identifier: &str,
    ) -> Result<JrdDocument, WebFingerError> {
        let url = format!(
            "https://{}/.well-known/webfinger?resource=acct:{}&rel={}",
            domain,
            urlencoding::encode(identifier),
            urlencoding::encode(OIDC_ISSUER_REL),
        );

        let response = self.http_client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(WebFingerError::NotFound);
        }

        if !response.status().is_success() {
            return Err(WebFingerError::InvalidResponse(format!(
                "unexpected status {}",
                response.status()
            )));
        }

        let jrd: JrdDocument = response.json().await.map_err(|e| {
            WebFingerError::InvalidResponse(format!("failed to parse JRD: {}", e))
        })?;

        Ok(jrd)
    }
}

impl Default for WebFingerClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // extract_domain
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_domain_valid() {
        assert_eq!(
            WebFingerClient::extract_domain("toasty@wegmueller.it").unwrap(),
            "wegmueller.it"
        );
        assert_eq!(
            WebFingerClient::extract_domain("user@sub.domain.com").unwrap(),
            "sub.domain.com"
        );
    }

    #[test]
    fn test_extract_domain_invalid_no_at() {
        assert!(WebFingerClient::extract_domain("nodomain").is_err());
    }

    #[test]
    fn test_extract_domain_empty_local_part() {
        // "@empty" has a valid domain part "empty"
        let result = WebFingerClient::extract_domain("@empty");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "empty");
    }

    #[test]
    fn test_extract_domain_empty_domain_part() {
        assert!(WebFingerClient::extract_domain("user@").is_err());
    }

    #[test]
    fn test_extract_domain_empty_string() {
        assert!(WebFingerClient::extract_domain("").is_err());
    }

    #[test]
    fn test_extract_domain_multiple_at_signs() {
        // splitn(2, '@') means "local@host@extra" -> domain = "host@extra"
        let result = WebFingerClient::extract_domain("local@host@extra").unwrap();
        assert_eq!(result, "host@extra");
    }

    // -----------------------------------------------------------------------
    // JRD deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_jrd_deserialization() {
        let jrd_json = r#"{
            "subject": "acct:alice@example.com",
            "aliases": ["https://example.com/@alice"],
            "links": [
                {
                    "rel": "http://openid.net/specs/connect/1.0/issuer",
                    "href": "https://auth.example.com"
                },
                {
                    "rel": "self",
                    "href": "https://example.com/users/alice",
                    "type": "application/activity+json"
                }
            ]
        }"#;
        let doc: JrdDocument = serde_json::from_str(jrd_json).unwrap();
        assert_eq!(doc.subject, "acct:alice@example.com");
        assert_eq!(doc.aliases.as_ref().unwrap().len(), 1);
        assert_eq!(doc.links.as_ref().unwrap().len(), 2);

        let issuer_link = doc
            .links
            .as_ref()
            .unwrap()
            .iter()
            .find(|l| l.rel == "http://openid.net/specs/connect/1.0/issuer")
            .unwrap();
        assert_eq!(issuer_link.href.as_deref(), Some("https://auth.example.com"));
        assert!(issuer_link.type_.is_none());

        let self_link = doc
            .links
            .as_ref()
            .unwrap()
            .iter()
            .find(|l| l.rel == "self")
            .unwrap();
        assert_eq!(
            self_link.type_.as_deref(),
            Some("application/activity+json")
        );
    }

    #[test]
    fn test_jrd_no_links() {
        let jrd_json = r#"{"subject": "acct:nobody@example.com"}"#;
        let doc: JrdDocument = serde_json::from_str(jrd_json).unwrap();
        assert_eq!(doc.subject, "acct:nobody@example.com");
        assert!(doc.links.is_none());
        assert!(doc.aliases.is_none());
        assert!(doc.properties.is_none());
    }

    #[test]
    fn test_jrd_with_properties() {
        let jrd_json = r#"{
            "subject": "acct:_federation@example.com",
            "links": [{
                "rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://auth.example.com",
                "properties": {
                    "https://barycenter.dev/rel/federation-capable": "true",
                    "https://barycenter.dev/rel/entity-proof": "https://auth.example.com/.well-known/barycenter-entity"
                }
            }]
        }"#;
        let doc: JrdDocument = serde_json::from_str(jrd_json).unwrap();
        let link = &doc.links.as_ref().unwrap()[0];
        let props = link.properties.as_ref().unwrap();
        assert_eq!(props.len(), 2);
        assert_eq!(
            props
                .get("https://barycenter.dev/rel/entity-proof")
                .unwrap()
                .as_deref(),
            Some("https://auth.example.com/.well-known/barycenter-entity")
        );
        assert_eq!(
            props
                .get("https://barycenter.dev/rel/federation-capable")
                .unwrap()
                .as_deref(),
            Some("true")
        );
    }

    #[test]
    fn test_jrd_with_null_property_value() {
        let jrd_json = r#"{
            "subject": "acct:test@example.com",
            "properties": {
                "https://example.com/some-flag": null
            }
        }"#;
        let doc: JrdDocument = serde_json::from_str(jrd_json).unwrap();
        let props = doc.properties.as_ref().unwrap();
        assert_eq!(props.get("https://example.com/some-flag").unwrap(), &None);
    }

    #[test]
    fn test_jrd_roundtrip_serialization() {
        let doc = JrdDocument {
            subject: "acct:test@example.com".to_string(),
            aliases: Some(vec!["https://example.com/@test".to_string()]),
            properties: None,
            links: Some(vec![JrdLink {
                rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
                href: Some("https://auth.example.com".to_string()),
                type_: None,
                titles: None,
                properties: None,
            }]),
        };

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: JrdDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.subject, doc.subject);
        assert_eq!(parsed.links.as_ref().unwrap().len(), 1);
        assert_eq!(
            parsed.links.as_ref().unwrap()[0].href.as_deref(),
            Some("https://auth.example.com")
        );
    }

    #[test]
    fn test_jrd_link_with_titles() {
        let jrd_json = r#"{
            "subject": "acct:test@example.com",
            "links": [{
                "rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://auth.example.com",
                "titles": {
                    "en": "Example Auth Server",
                    "de": "Beispiel Auth Server"
                }
            }]
        }"#;
        let doc: JrdDocument = serde_json::from_str(jrd_json).unwrap();
        let link = &doc.links.as_ref().unwrap()[0];
        let titles = link.titles.as_ref().unwrap();
        assert_eq!(titles.get("en").unwrap(), "Example Auth Server");
        assert_eq!(titles.get("de").unwrap(), "Beispiel Auth Server");
    }

    // -----------------------------------------------------------------------
    // WebFingerError Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_webfinger_error_display() {
        let err = WebFingerError::InvalidIdentifier("bad".to_string());
        assert_eq!(err.to_string(), "invalid identifier: bad");

        let err = WebFingerError::NotFound;
        assert_eq!(err.to_string(), "resource not found");

        let err = WebFingerError::NoIssuerLink;
        assert_eq!(err.to_string(), "no issuer link in WebFinger response");

        let err = WebFingerError::InvalidResponse("oops".to_string());
        assert_eq!(err.to_string(), "invalid response: oops");
    }
}
