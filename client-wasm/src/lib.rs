use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Check if WebAuthn is supported in the current browser
#[wasm_bindgen]
pub fn supports_webauthn() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return false,
    };

    // Check if PublicKeyCredential is available
    js_sys::Reflect::has(&window, &JsValue::from_str("PublicKeyCredential")).unwrap_or(false)
}

/// Check if conditional UI (autofill) is supported
#[wasm_bindgen]
pub async fn supports_conditional_ui() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return false,
    };

    // Check if PublicKeyCredential.isConditionalMediationAvailable exists
    let public_key_credential =
        match js_sys::Reflect::get(&window, &JsValue::from_str("PublicKeyCredential")) {
            Ok(pkc) => pkc,
            Err(_) => return false,
        };

    let is_conditional_available = match js_sys::Reflect::get(
        &public_key_credential,
        &JsValue::from_str("isConditionalMediationAvailable"),
    ) {
        Ok(func) => func,
        Err(_) => return false,
    };

    // Call the function if it exists
    if is_conditional_available.is_function() {
        let func = js_sys::Function::from(is_conditional_available);
        match func.call0(&public_key_credential) {
            Ok(promise_val) => {
                let promise = js_sys::Promise::from(promise_val);
                match wasm_bindgen_futures::JsFuture::from(promise).await {
                    Ok(result) => result.as_bool().unwrap_or(false),
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Register a new passkey
///
/// Takes a JSON string containing PublicKeyCredentialCreationOptions
/// Returns a JSON string containing the credential response
#[wasm_bindgen]
pub async fn register_passkey(options_json: &str) -> Result<String, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window object"))?;

    let navigator = window.navigator();
    let credentials = navigator.credentials();

    // Parse the options from JSON string to serde_json::Value first
    let options: serde_json::Value = serde_json::from_str(options_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse options JSON: {}", e)))?;

    // Convert to JsValue
    let options_value: JsValue = serde_wasm_bindgen::to_value(&options)
        .map_err(|e| JsValue::from_str(&format!("Failed to convert options to JsValue: {}", e)))?;

    // Create CredentialCreationOptions
    let credential_creation_options = js_sys::Object::new();
    js_sys::Reflect::set(
        &credential_creation_options,
        &JsValue::from_str("publicKey"),
        &options_value,
    )?;

    // Call navigator.credentials.create()
    let promise = credentials.create_with_options(&web_sys::CredentialCreationOptions::from(
        JsValue::from(credential_creation_options),
    ))?;

    let result = wasm_bindgen_futures::JsFuture::from(promise).await?;

    // Convert the credential to JSON
    let credential_json = serialize_credential_response(&result)?;

    Ok(credential_json)
}

/// Authenticate with a passkey
///
/// Takes a JSON string containing PublicKeyCredentialRequestOptions
/// and an optional mediation mode ("conditional" for autofill)
/// Returns a JSON string containing the assertion response
#[wasm_bindgen]
pub async fn authenticate_passkey(
    options_json: &str,
    mediation: Option<String>,
) -> Result<String, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window object"))?;

    let navigator = window.navigator();
    let credentials = navigator.credentials();

    // Parse the options from JSON string to serde_json::Value first
    let options: serde_json::Value = serde_json::from_str(options_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse options JSON: {}", e)))?;

    // Convert to JsValue
    let options_value: JsValue = serde_wasm_bindgen::to_value(&options)
        .map_err(|e| JsValue::from_str(&format!("Failed to convert options to JsValue: {}", e)))?;

    // Create CredentialRequestOptions
    let credential_request_options = js_sys::Object::new();
    js_sys::Reflect::set(
        &credential_request_options,
        &JsValue::from_str("publicKey"),
        &options_value,
    )?;

    // Add mediation if specified (for conditional UI)
    if let Some(med) = mediation {
        js_sys::Reflect::set(
            &credential_request_options,
            &JsValue::from_str("mediation"),
            &JsValue::from_str(&med),
        )?;
    }

    // Call navigator.credentials.get()
    let promise = credentials.get_with_options(&web_sys::CredentialRequestOptions::from(
        JsValue::from(credential_request_options),
    ))?;

    let result = wasm_bindgen_futures::JsFuture::from(promise).await?;

    // Convert the assertion to JSON
    let assertion_json = serialize_assertion_response(&result)?;

    Ok(assertion_json)
}

/// Serialize credential response (for registration)
fn serialize_credential_response(credential: &JsValue) -> Result<String, JsValue> {
    // The credential returned is a PublicKeyCredential
    // We need to extract and serialize the response

    #[derive(Serialize)]
    struct CredentialResponse {
        id: String,
        raw_id: Vec<u8>,
        response: AttestationResponse,
        #[serde(rename = "type")]
        type_: String,
    }

    #[derive(Serialize)]
    struct AttestationResponse {
        attestation_object: Vec<u8>,
        client_data_json: Vec<u8>,
    }

    // Extract fields using js-sys Reflect
    let id = js_sys::Reflect::get(credential, &JsValue::from_str("id"))?
        .as_string()
        .ok_or_else(|| JsValue::from_str("Missing id"))?;

    let raw_id = js_sys::Reflect::get(credential, &JsValue::from_str("rawId"))?;
    let raw_id_bytes = js_sys::Uint8Array::new(&raw_id).to_vec();

    let response_obj = js_sys::Reflect::get(credential, &JsValue::from_str("response"))?;

    let attestation_object =
        js_sys::Reflect::get(&response_obj, &JsValue::from_str("attestationObject"))?;
    let attestation_bytes = js_sys::Uint8Array::new(&attestation_object).to_vec();

    let client_data_json =
        js_sys::Reflect::get(&response_obj, &JsValue::from_str("clientDataJSON"))?;
    let client_data_bytes = js_sys::Uint8Array::new(&client_data_json).to_vec();

    let type_ = js_sys::Reflect::get(credential, &JsValue::from_str("type"))?
        .as_string()
        .unwrap_or_else(|| "public-key".to_string());

    let response = CredentialResponse {
        id,
        raw_id: raw_id_bytes,
        response: AttestationResponse {
            attestation_object: attestation_bytes,
            client_data_json: client_data_bytes,
        },
        type_,
    };

    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Serialize assertion response (for authentication)
fn serialize_assertion_response(credential: &JsValue) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct AssertionResponse {
        id: String,
        raw_id: Vec<u8>,
        response: AuthenticatorResponse,
        #[serde(rename = "type")]
        type_: String,
    }

    #[derive(Serialize)]
    struct AuthenticatorResponse {
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<Vec<u8>>,
    }

    // Extract fields
    let id = js_sys::Reflect::get(credential, &JsValue::from_str("id"))?
        .as_string()
        .ok_or_else(|| JsValue::from_str("Missing id"))?;

    let raw_id = js_sys::Reflect::get(credential, &JsValue::from_str("rawId"))?;
    let raw_id_bytes = js_sys::Uint8Array::new(&raw_id).to_vec();

    let response_obj = js_sys::Reflect::get(credential, &JsValue::from_str("response"))?;

    let authenticator_data =
        js_sys::Reflect::get(&response_obj, &JsValue::from_str("authenticatorData"))?;
    let authenticator_data_bytes = js_sys::Uint8Array::new(&authenticator_data).to_vec();

    let client_data_json =
        js_sys::Reflect::get(&response_obj, &JsValue::from_str("clientDataJSON"))?;
    let client_data_bytes = js_sys::Uint8Array::new(&client_data_json).to_vec();

    let signature = js_sys::Reflect::get(&response_obj, &JsValue::from_str("signature"))?;
    let signature_bytes = js_sys::Uint8Array::new(&signature).to_vec();

    // userHandle is optional
    let user_handle = js_sys::Reflect::get(&response_obj, &JsValue::from_str("userHandle"))
        .ok()
        .and_then(|uh| {
            if uh.is_null() || uh.is_undefined() {
                None
            } else {
                Some(js_sys::Uint8Array::new(&uh).to_vec())
            }
        });

    let type_ = js_sys::Reflect::get(credential, &JsValue::from_str("type"))?
        .as_string()
        .unwrap_or_else(|| "public-key".to_string());

    let response = AssertionResponse {
        id,
        raw_id: raw_id_bytes,
        response: AuthenticatorResponse {
            authenticator_data: authenticator_data_bytes,
            client_data_json: client_data_bytes,
            signature: signature_bytes,
            user_handle,
        },
        type_,
    };

    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_supports_webauthn() {
        // This will only work in a real browser environment
        let _result = supports_webauthn();
    }
}
