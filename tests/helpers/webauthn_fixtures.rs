use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Load a WebAuthn fixture from the fixtures directory
///
/// # Example
/// ```
/// let fixture = load_fixture("hardware_key_registration");
/// ```
pub fn load_fixture(name: &str) -> WebAuthnFixture {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(format!("{}.json", name));

    let contents =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Fixture not found: {:?}", path));

    serde_json::from_str(&contents).expect("Invalid fixture JSON")
}

/// Check if a fixture exists
pub fn fixture_exists(name: &str) -> bool {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(format!("{}.json", name));

    path.exists()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebAuthnFixture {
    PasskeyRegistration(RegistrationFixture),
    PasskeyAuthentication(AuthenticationFixture),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFixture {
    pub challenge_response: Value,
    pub credential_response: CredentialRegistrationResponse,
    pub server_response: Option<Value>,
    pub metadata: FixtureMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFixture {
    pub challenge_response: Value,
    pub credential_response: CredentialAuthenticationResponse,
    pub metadata: FixtureMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRegistrationResponse {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuthenticationResponse {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureMetadata {
    pub captured_at: String,
    pub authenticator_attachment: Option<String>,
    pub user_agent: String,
}

impl WebAuthnFixture {
    /// Get the authenticator attachment type (e.g., "platform" or "cross-platform")
    pub fn authenticator_attachment(&self) -> Option<&str> {
        match self {
            WebAuthnFixture::PasskeyRegistration(fix) => {
                fix.metadata.authenticator_attachment.as_deref()
            }
            WebAuthnFixture::PasskeyAuthentication(fix) => {
                fix.metadata.authenticator_attachment.as_deref()
            }
        }
    }

    /// Check if this is a platform authenticator (TouchID, Windows Hello, etc.)
    pub fn is_platform_authenticator(&self) -> bool {
        self.authenticator_attachment() == Some("platform")
    }

    /// Check if this is a cross-platform authenticator (USB security key, etc.)
    pub fn is_cross_platform_authenticator(&self) -> bool {
        self.authenticator_attachment() == Some("cross-platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Only run when fixtures exist
    fn test_load_fixture() {
        if fixture_exists("hardware_key_registration") {
            let fixture = load_fixture("hardware_key_registration");
            match fixture {
                WebAuthnFixture::PasskeyRegistration(reg) => {
                    assert!(!reg.credential_response.id.is_empty());
                    assert!(!reg.credential_response.raw_id.is_empty());
                }
                _ => panic!("Expected registration fixture"),
            }
        }
    }

    #[test]
    fn test_fixture_exists() {
        // Should not panic even if fixture doesn't exist
        let _ = fixture_exists("nonexistent_fixture");
    }
}
