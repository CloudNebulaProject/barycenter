use crate::errors::CrabError;
use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct WebAuthnManager {
    webauthn: Arc<Webauthn>,
}

impl WebAuthnManager {
    pub async fn new(rp_id: &str, origin: &Url) -> Result<Self, CrabError> {
        let builder = WebauthnBuilder::new(rp_id, origin).map_err(|e| {
            CrabError::Configuration(format!("Failed to create WebAuthn builder: {}", e))
        })?;

        let webauthn = builder.build().map_err(|e| {
            CrabError::Configuration(format!("Failed to build WebAuthn instance: {}", e))
        })?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
        })
    }

    /// Start passkey registration flow
    /// Returns (challenge response for client, server state to store)
    pub fn start_passkey_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), CrabError> {
        self.webauthn
            .start_passkey_registration(user_id, username, display_name, None)
            .map_err(|e| {
                CrabError::WebAuthnError(format!("Failed to start passkey registration: {}", e))
            })
    }

    /// Finish passkey registration flow
    /// Verifies the attestation response from the client
    pub fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, CrabError> {
        self.webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|e| {
                CrabError::WebAuthnError(format!("Failed to finish passkey registration: {}", e))
            })
    }

    /// Start passkey authentication flow
    /// passkeys: list of user's registered passkeys
    /// Returns (challenge response for client, server state to store)
    pub fn start_passkey_authentication(
        &self,
        passkeys: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), CrabError> {
        self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                CrabError::WebAuthnError(format!("Failed to start passkey authentication: {}", e))
            })
    }

    /// Finish passkey authentication flow
    /// Verifies the assertion response from the client
    pub fn finish_passkey_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, CrabError> {
        self.webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|e| {
                CrabError::WebAuthnError(format!("Failed to finish passkey authentication: {}", e))
            })
    }
}
