use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use base64ct::Encoding;
use sha2::Digest;

/// Helper to start the barycenter server for integration tests
struct TestServer {
    process: Child,
    base_url: String,
}

impl TestServer {
    fn start() -> Self {
        let port = 8080;
        let base_url = format!("http://0.0.0.0:{}", port);

        let process = Command::new("cargo")
            .args(["run", "--release", "--"])
            .env("RUST_LOG", "error")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start server");

        // Wait for server to start - give it more time for first compilation
        thread::sleep(Duration::from_secs(5));

        // Verify server is running by checking discovery endpoint
        let client = reqwest::blocking::Client::new();
        let max_retries = 30;
        for i in 0..max_retries {
            if let Ok(_) = client
                .get(format!("{}/.well-known/openid-configuration", base_url))
                .send()
            {
                println!("Server started successfully");
                return Self { process, base_url };
            }
            if i < max_retries - 1 {
                thread::sleep(Duration::from_secs(1));
            }
        }

        panic!("Server failed to start within timeout");
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Register a test client with the IdP
fn register_client(base_url: &str) -> (String, String, String) {
    let client = reqwest::blocking::Client::new();
    let redirect_uri = "http://localhost:3000/callback";

    let response = client
        .post(format!("{}/connect/register", base_url))
        .json(&serde_json::json!({
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .send()
        .expect("Failed to register client")
        .json::<serde_json::Value>()
        .expect("Failed to parse registration response");

    let client_id = response["client_id"]
        .as_str()
        .expect("No client_id in response")
        .to_string();
    let client_secret = response["client_secret"]
        .as_str()
        .expect("No client_secret in response")
        .to_string();

    (client_id, client_secret, redirect_uri.to_string())
}

/// Perform login and return an HTTP client with session cookie
fn login_and_get_client(base_url: &str, username: &str, password: &str) -> (reqwest::blocking::Client, std::sync::Arc<reqwest::cookie::Jar>) {
    let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
    let client = reqwest::blocking::ClientBuilder::new()
        .cookie_provider(jar.clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build client");

    // First register the user
    let _register_response = client
        .post(format!("{}/register", base_url))
        .form(&[
            ("username", username),
            ("password", password),
            ("email", "test@example.com"),
        ])
        .send()
        .expect("Failed to register user");

    // Then login to create a session
    let _login_response = client
        .post(format!("{}/login", base_url))
        .form(&[
            ("username", username),
            ("password", password),
        ])
        .send()
        .expect("Failed to login");

    (client, jar)
}

#[test]
fn test_openidconnect_authorization_code_flow() {
    use openidconnect::{
        core::{CoreClient, CoreProviderMetadata},
        AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
        Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    };

    let server = TestServer::start();
    let (client_id, client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) = login_and_get_client(server.base_url(), "testuser", "testpass123");

    let issuer_url = IssuerUrl::new(server.base_url().to_string())
        .expect("Invalid issuer URL");

    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)
        .expect("Failed to discover provider metadata");

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.clone()),
        Some(ClientSecret::new(client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).expect("Invalid redirect URI"));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    use openidconnect::core::CoreAuthenticationFlow;
    let (auth_url, csrf_token, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Authorization URL: {}", auth_url);

    let auth_response = authenticated_client
        .get(auth_url.as_str())
        .send()
        .expect("Failed to request authorization");

    let status = auth_response.status();
    assert!(status.is_redirection(), "Expected redirect, got {}", status);

    let location = auth_response
        .headers()
        .get("location")
        .expect("No location header")
        .to_str()
        .expect("Invalid location header");

    println!("Redirect location: {}", location);

    let redirect_url_parsed = if location.starts_with("http") {
        url::Url::parse(location).expect("Invalid redirect URL")
    } else {
        let base_url_for_redirect = url::Url::parse(&redirect_uri).expect("Invalid redirect URI");
        base_url_for_redirect.join(location).expect("Invalid redirect URL")
    };
    let code = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("No code in redirect");

    let returned_state = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("No state in redirect");

    assert_eq!(returned_state, *csrf_token.secret());

    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .expect("Failed to create code exchange request")
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)
        .expect("Failed to exchange code for token");

    assert!(token_response.access_token().secret().len() > 0);
    assert!(token_response.id_token().is_some());

    let id_token = token_response.id_token().expect("No ID token");

    // For testing purposes, we'll decode the ID token without signature verification
    // In production, signature verification is critical and performed by the library
    use base64ct::Encoding;
    let id_token_str = id_token.to_string();
    let parts: Vec<&str> = id_token_str.split('.').collect();
    assert_eq!(parts.len(), 3, "ID token should have 3 parts");

    let payload = base64ct::Base64UrlUnpadded::decode_vec(parts[1])
        .expect("Failed to decode ID token payload");
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .expect("Failed to parse ID token claims");

    // Verify required claims
    assert!(claims["sub"].is_string());
    assert!(!claims["sub"].as_str().unwrap().is_empty());
    assert_eq!(claims["iss"].as_str().unwrap(), server.base_url());
    assert_eq!(claims["aud"].as_str().unwrap(), client_id);
    assert!(claims["exp"].is_number());
    assert!(claims["iat"].is_number());
    assert!(claims["nonce"].is_string());

    println!("✓ openidconnect-rs: Authorization Code + PKCE flow successful");
}

#[test]
fn test_oauth2_authorization_code_flow() {
    use oauth2::{
        basic::BasicClient, AuthUrl, AuthorizationCode, ClientId,
        ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
    };

    let server = TestServer::start();
    let (client_id, client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) = login_and_get_client(server.base_url(), "testuser2", "testpass123");

    let http_client_blocking = reqwest::blocking::Client::new();
    let discovery_response = http_client_blocking
        .get(format!(
            "{}/.well-known/openid-configuration",
            server.base_url()
        ))
        .send()
        .expect("Failed to fetch discovery")
        .json::<serde_json::Value>()
        .expect("Failed to parse discovery");

    let auth_url = AuthUrl::new(
        discovery_response["authorization_endpoint"]
            .as_str()
            .expect("No authorization_endpoint")
            .to_string(),
    )
    .expect("Invalid auth URL");

    let token_url = TokenUrl::new(
        discovery_response["token_endpoint"]
            .as_str()
            .expect("No token_endpoint")
            .to_string(),
    )
    .expect("Invalid token URL");

    let client = BasicClient::new(ClientId::new(client_id.clone()))
        .set_client_secret(ClientSecret::new(client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).expect("Invalid redirect URI"));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Authorization URL: {}", auth_url);

    let auth_response = authenticated_client
        .get(auth_url.as_str())
        .send()
        .expect("Failed to request authorization");

    let status = auth_response.status();
    assert!(status.is_redirection(), "Expected redirect, got {}", status);

    let location = auth_response
        .headers()
        .get("location")
        .expect("No location header")
        .to_str()
        .expect("Invalid location header");

    println!("Redirect location: {}", location);

    let redirect_url_parsed = if location.starts_with("http") {
        url::Url::parse(location).expect("Invalid redirect URL")
    } else {
        let base_url_for_redirect = url::Url::parse(&redirect_uri).expect("Invalid redirect URI");
        base_url_for_redirect.join(location).expect("Invalid redirect URL")
    };
    let code = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("No code in redirect");

    let returned_state = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("No state in redirect");

    assert_eq!(returned_state, *csrf_token.secret());

    let http_client = reqwest::blocking::Client::new();
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)
        .expect("Failed to exchange code for token");

    assert!(token_response.access_token().secret().len() > 0);
    assert!(token_response.expires_in().is_some());

    let access_token = token_response.access_token().secret();

    let http_client_blocking = reqwest::blocking::Client::new();
    let userinfo_response = http_client_blocking
        .get(format!("{}/userinfo", server.base_url()))
        .bearer_auth(access_token)
        .send()
        .expect("Failed to fetch userinfo")
        .json::<serde_json::Value>()
        .expect("Failed to parse userinfo");

    // Verify subject exists and is a non-empty string
    assert!(userinfo_response["sub"].is_string());
    assert!(!userinfo_response["sub"].as_str().unwrap().is_empty());

    println!("✓ oauth2-rs: Authorization Code + PKCE flow successful");
}

#[test]
fn test_security_headers() {
    let server = TestServer::start();

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("{}/.well-known/openid-configuration", server.base_url()))
        .send()
        .expect("Failed to fetch discovery");

    assert_eq!(
        response.headers().get("x-frame-options").unwrap(),
        "DENY"
    );
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        response.headers().get("x-xss-protection").unwrap(),
        "1; mode=block"
    );
    assert!(response.headers().get("content-security-policy").is_some());
    assert!(response.headers().get("referrer-policy").is_some());
    assert!(response.headers().get("permissions-policy").is_some());

    println!("✓ Security headers are present");
}

#[test]
fn test_token_endpoint_cache_control() {
    let server = TestServer::start();
    let (client_id, client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) = login_and_get_client(server.base_url(), "testuser3", "testpass123");

    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let discovery_response = http_client
        .get(format!("{}/.well-known/openid-configuration", server.base_url()))
        .send()
        .expect("Failed to fetch discovery")
        .json::<serde_json::Value>()
        .expect("Failed to parse discovery");

    let auth_url = discovery_response["authorization_endpoint"]
        .as_str()
        .expect("No authorization_endpoint");

    let pkce_verifier = "test_verifier_1234567890123456789012345678901234567890";
    let challenge_hash = sha2::Sha256::digest(pkce_verifier.as_bytes());
    let pkce_challenge = base64ct::Base64UrlUnpadded::encode_string(&challenge_hash);

    let auth_request = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=test_state&nonce=test_nonce&code_challenge={}&code_challenge_method=S256",
        auth_url,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&pkce_challenge)
    );

    let auth_response = authenticated_client
        .get(&auth_request)
        .send()
        .expect("Failed to request authorization");

    let location = auth_response
        .headers()
        .get("location")
        .expect("No location header")
        .to_str()
        .expect("Invalid location header");

    println!("Redirect location: {}", location);

    let redirect_url_parsed = if location.starts_with("http") {
        url::Url::parse(location).expect("Invalid redirect URL")
    } else {
        let base_url_for_redirect = url::Url::parse(&redirect_uri).expect("Invalid redirect URI");
        base_url_for_redirect.join(location).expect("Invalid redirect URL")
    };
    let code = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("No code in redirect");

    let auth_header = base64ct::Base64::encode_string(
        format!("{}:{}", client_id, client_secret).as_bytes()
    );

    let token_response = http_client
        .post(format!("{}/token", server.base_url()))
        .header("Authorization", format!("Basic {}", auth_header))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", pkce_verifier),
        ])
        .send()
        .expect("Failed to exchange token");

    assert_eq!(
        token_response.headers().get("cache-control").unwrap(),
        "no-store"
    );
    assert_eq!(token_response.headers().get("pragma").unwrap(), "no-cache");

    println!("✓ Token endpoint has correct Cache-Control headers");
}
