use base64ct::Encoding;
use sha2::Digest;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Helper to start the barycenter server for integration tests
struct TestServer {
    process: Child,
    base_url: String,
    admin_url: String,
    database_url: String,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    fn start() -> Self {
        Self::start_with_skip_consent(true)
    }

    fn start_with_consent() -> Self {
        Self::start_with_skip_consent(false)
    }

    fn start_with_skip_consent(skip_consent: bool) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("Failed to reserve a test server port");
        let port = listener
            .local_addr()
            .expect("Failed to read reserved test server port")
            .port();
        let admin_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("Failed to reserve a test admin port");
        let admin_port = admin_listener
            .local_addr()
            .expect("Failed to read reserved test admin port")
            .port();
        drop(listener);
        drop(admin_listener);

        let temp_dir = tempfile::tempdir().expect("Failed to create test server directory");
        let database_url = format!(
            "sqlite://{}?mode=rwc",
            temp_dir.path().join("barycenter.db").display()
        );
        let base_url = format!("http://localhost:{}", port);

        // Use the pre-built binary from target/debug instead of recompiling with cargo run
        // This avoids compilation timeouts in CI
        // The test binary is in target/debug/deps/, we need to go up to target/debug/
        let binary_path = std::env::current_exe()
            .ok()
            .and_then(|p| {
                // Go up from target/debug/deps/test-binary to target/debug
                p.parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.join("barycenter"))
            })
            .unwrap_or_else(|| {
                // Fallback to relative path
                std::path::PathBuf::from("target/debug/barycenter")
            });

        // Use piped stderr so we can capture errors if server fails to start
        let mut command = Command::new(&binary_path);
        command
            .env("RUST_LOG", "error")
            .env("BARYCENTER__SERVER__PORT", port.to_string())
            .env("BARYCENTER__SERVER__ADMIN_PORT", admin_port.to_string())
            .env("BARYCENTER__DATABASE__URL", &database_url)
            .env(
                "BARYCENTER__KEYS__JWKS_PATH",
                temp_dir.path().join("jwks.json"),
            )
            .env(
                "BARYCENTER__KEYS__PRIVATE_KEY_PATH",
                temp_dir.path().join("private_key.pem"),
            )
            .env("BARYCENTER__SERVER__ALLOW_PUBLIC_REGISTRATION", "true") // Enable registration for tests
            .env("BARYCENTER__SERVER__PUBLIC_BASE_URL", &base_url) // Set public base URL for WebAuthn
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if skip_consent {
            command.env("BARYCENTER_SKIP_CONSENT", "1");
        } else {
            command.env_remove("BARYCENTER_SKIP_CONSENT");
        }

        let mut process = command.spawn().expect("Failed to start server");

        // Wait for server to start
        thread::sleep(Duration::from_secs(2));

        // Verify server is running by checking discovery endpoint
        let client = reqwest::blocking::Client::new();
        let max_retries = 30;
        for i in 0..max_retries {
            if client
                .get(format!("{}/.well-known/openid-configuration", base_url))
                .send()
                .is_ok()
            {
                println!("Server started successfully");
                return Self {
                    process,
                    base_url,
                    admin_url: format!("http://localhost:{}", admin_port),
                    database_url,
                    _temp_dir: temp_dir,
                };
            }
            if i < max_retries - 1 {
                thread::sleep(Duration::from_secs(1));
            }
        }

        // Server failed to start - try to get stderr output
        use std::io::Read;
        if let Some(mut stderr) = process.stderr.take() {
            let mut error_output = String::new();
            let _ = stderr.read_to_string(&mut error_output);
            if !error_output.is_empty() {
                eprintln!("Server stderr output:\n{}", error_output);
            }
        }

        // Reap the child before panicking so a failed start leaves no zombie server.
        let _ = process.kill();
        let _ = process.wait();
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
fn login_and_get_client(
    base_url: &str,
    username: &str,
    password: &str,
) -> (
    reqwest::blocking::Client,
    std::sync::Arc<reqwest::cookie::Jar>,
) {
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
        .form(&[("username", username), ("password", password)])
        .send()
        .expect("Failed to login");

    (client, jar)
}

#[test]
fn invalid_login_redirects_with_see_other_and_renders_error() {
    let server = TestServer::start();
    let client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build client");

    let response = client
        .post(format!("{}/login", server.base_url()))
        .form(&[
            ("username", "unknown-user"),
            ("password", "wrong-password"),
            ("return_to", "/authorize?client_id=test-client"),
        ])
        .send()
        .expect("Failed to submit invalid login");

    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("Invalid login response did not include a Location header");
    let redirect = reqwest::Url::parse(&format!("{}{}", server.base_url(), location)).unwrap();
    let query: std::collections::HashMap<_, _> = redirect.query_pairs().collect();
    assert_eq!(query.get("error").map(|s| s.as_ref()), Some("credentials"));
    assert_eq!(
        query.get("username").map(|s| s.as_ref()),
        Some("unknown-user")
    );
    assert_eq!(query.get("step").map(|s| s.as_ref()), Some("password"));
    assert_eq!(
        query.get("return_to").map(|s| s.as_ref()),
        Some("/authorize?client_id=test-client")
    );
    assert!(!location.contains("wrong-password"));

    let error_page = client
        .get(format!("{}{}", server.base_url(), location))
        .send()
        .expect("Failed to load login error page");
    assert_eq!(error_page.status(), reqwest::StatusCode::OK);
    assert!(error_page
        .text()
        .expect("Failed to read login error page")
        .contains("We couldn&#x27;t sign you in with that account and password"));
}

#[test]
fn login_rejects_non_local_return_targets() {
    let server = TestServer::start();
    let client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build client");

    client
        .post(format!("{}/register", server.base_url()))
        .form(&[
            ("username", "safe-return-user"),
            ("password", "testpass123"),
            ("email", "safe-return@example.com"),
        ])
        .send()
        .expect("Failed to register user");

    for return_to in [
        "https://attacker.example/",
        "//attacker.example/",
        "/\\attacker.example/",
        "/ok\nno",
    ] {
        let response = client
            .post(format!("{}/login", server.base_url()))
            .form(&[
                ("username", "safe-return-user"),
                ("password", "testpass123"),
                ("return_to", return_to),
            ])
            .send()
            .expect("Failed to submit login");

        assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/")
        );
    }
}

/// Exercise the public/admin boundary and the full consent lifecycle on one client.
#[test]
fn trusted_client_consent_and_admin_management() {
    let server = TestServer::start_with_skip_consent(false);
    let http = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let query_clients = |id: &str| -> serde_json::Value {
        http.post(format!("{}/admin/jobs", server.admin_url))
            .json(&serde_json::json!({
                "query": "query($id: String!) { client(clientId: $id) { clientId clientName redirectUris trusted } clients { clientId clientName redirectUris trusted } }",
                "variables": {"id": id}
            })).send().unwrap().json().unwrap()
    };
    let empty = query_clients("missing-client");
    assert!(empty.get("errors").is_none(), "{empty}");
    assert!(empty["data"]["client"].is_null());
    assert!(empty["data"]["clients"].as_array().unwrap().is_empty());
    let registration = http
        .post(format!("{}/connect/register", server.base_url()))
        .json(&serde_json::json!({
            "client_name": "First-party test",
            "redirect_uris": ["http://localhost:3000/callback"],
            "trusted": true
        }))
        .send()
        .unwrap();
    assert_eq!(registration.status(), reqwest::StatusCode::CREATED);
    let registration: serde_json::Value = registration.json().unwrap();
    let client_id = registration["client_id"].as_str().unwrap();

    let mutation = |id: &str, trusted: bool| -> serde_json::Value {
        http.post(format!("{}/admin/jobs", server.admin_url))
            .json(&serde_json::json!({
                "query": "mutation($id: String!, $trusted: Boolean!) { setClientTrusted(clientId: $id, trusted: $trusted) { clientId clientName redirectUris trusted } }",
                "variables": {"id": id, "trusted": trusted}
            })).send().unwrap().json().unwrap()
    };
    let listing = query_clients(client_id);
    assert!(listing.get("errors").is_none(), "{listing}");
    assert_eq!(listing["data"]["clients"].as_array().unwrap().len(), 1);
    assert_eq!(listing["data"]["clients"][0]["trusted"], false);
    assert_eq!(listing["data"]["client"]["clientId"], client_id);
    assert_eq!(listing["data"]["client"], listing["data"]["clients"][0]);
    assert!(listing["data"]["client"].get("clientSecret").is_none());
    assert!(listing["data"]["clients"][0].get("clientSecret").is_none());
    assert!(!listing
        .to_string()
        .contains(registration["client_secret"].as_str().unwrap()));
    let missing_client = query_clients("missing-client");
    assert!(missing_client.get("errors").is_none(), "{missing_client}");
    assert!(missing_client["data"]["client"].is_null());

    // Explicitly requesting a secret must fail schema validation for both queries.
    for query in [
        "{ clients { clientId clientSecret } }".to_owned(),
        format!("{{ client(clientId: \"{client_id}\") {{ clientId clientSecret }} }}"),
    ] {
        let rejected: serde_json::Value = http
            .post(format!("{}/admin/jobs", server.admin_url))
            .json(&serde_json::json!({"query": query}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert!(rejected["data"].is_null());
        assert!(rejected["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown field \"clientSecret\""));
    }

    // Restoring the original Seaography wiring must keep raw credential reads unavailable.
    for field in [
        "clients { nodes { clientSecret } }",
        "users { nodes { passwordHash } }",
        "sessions { nodes { sessionId } }",
        "accessTokens { nodes { token } }",
        "refreshTokens { nodes { token } }",
    ] {
        let raw_entities: serde_json::Value = http
            .post(format!("{}/admin/graphql", server.admin_url))
            .json(&serde_json::json!({"query": format!("{{ {field} }}")}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert!(raw_entities["data"].is_null(), "{raw_entities}");
        assert!(
            raw_entities["errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("DatabaseConnection"),
            "{raw_entities}"
        );
    }

    let (authenticated, _) = login_and_get_client(server.base_url(), "trusted-user", "testpass123");
    let mut authorize = url::Url::parse(&format!("{}/authorize", server.base_url())).unwrap();
    authorize.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", "http://localhost:3000/callback"),
        ("response_type", "code"),
        ("scope", "openid profile"),
        ("state", "trusted_state"),
        ("code_challenge", "test_challenge"),
        ("code_challenge_method", "S256"),
    ]);
    let location = |http: &reqwest::blocking::Client, prompt: Option<&str>| -> String {
        let mut url = authorize.clone();
        if let Some(prompt) = prompt {
            url.query_pairs_mut().append_pair("prompt", prompt);
        }
        let response = http.get(url).send().unwrap();
        assert!(response.status().is_redirection());
        response.headers()["location"].to_str().unwrap().to_owned()
    };
    assert!(location(&authenticated, None).starts_with("/consent?"));
    assert!(location(&authenticated, Some("none")).contains("error=consent_required"));

    let trusted = mutation(client_id, true);
    assert!(trusted.get("errors").is_none(), "{trusted}");
    assert_eq!(trusted["data"]["setClientTrusted"]["trusted"], true);
    assert_eq!(trusted["data"]["setClientTrusted"]["clientId"], client_id);
    assert!(trusted["data"]["setClientTrusted"]
        .get("clientSecret")
        .is_none());
    let listing = query_clients(client_id);
    assert!(listing.get("errors").is_none(), "{listing}");
    assert_eq!(listing["data"]["client"]["trusted"], true);
    assert_eq!(listing["data"]["clients"][0]["trusted"], true);
    // Trust does not change login, forced reauthentication, or silent consent requirements.
    assert!(location(&http, None).starts_with("/login?"));
    assert!(location(&http, Some("none")).contains("error=login_required"));
    assert!(location(&authenticated, Some("login")).starts_with("/login?"));
    let mut mfa = authorize.clone();
    mfa.query_pairs_mut().append_pair("max_age", "299");
    let mfa_response = authenticated.get(mfa).send().unwrap();
    assert!(mfa_response.headers()["location"]
        .to_str()
        .unwrap()
        .starts_with("/login/2fa?"));
    assert!(location(&authenticated, Some("none")).contains("error=consent_required"));
    assert!(location(&authenticated, Some("consent")).starts_with("/consent?"));
    let redirect = url::Url::parse(&location(&authenticated, None)).unwrap();
    assert_eq!(
        redirect.origin().ascii_serialization(),
        "http://localhost:3000"
    );
    assert!(redirect
        .query_pairs()
        .any(|(key, value)| key == "code" && !value.is_empty()));
    assert!(redirect
        .query_pairs()
        .any(|(key, value)| key == "state" && value == "trusted_state"));
    assert!(location(&authenticated, Some("none")).contains("code="));
    assert!(location(&authenticated, Some("consent")).starts_with("/consent?"));
    assert!(location(&authenticated, None).contains("code="));

    // The implicit grant is stored once and can be revoked using the existing API.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let db = sea_orm::Database::connect(&server.database_url)
            .await
            .unwrap();
        let user = barycenter::storage::get_user_by_username(&db, "trusted-user")
            .await
            .unwrap()
            .unwrap();
        let grants = barycenter::storage::get_consents_by_subject(&db, &user.subject)
            .await
            .unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "openid profile");
        barycenter::storage::revoke_consents_for_client(&db, client_id, &user.subject)
            .await
            .unwrap();
        db.close().await.unwrap();
    });
    assert!(location(&authenticated, Some("none")).contains("error=consent_required"));
    assert!(location(&authenticated, None).contains("code="));
    let untrusted = mutation(client_id, false);
    assert!(untrusted.get("errors").is_none(), "{untrusted}");
    assert_eq!(untrusted["data"]["setClientTrusted"]["trusted"], false);
    let listing = query_clients(client_id);
    assert!(listing.get("errors").is_none(), "{listing}");
    assert_eq!(listing["data"]["client"]["trusted"], false);
    assert_eq!(listing["data"]["clients"][0]["trusted"], false);
    // The recorded grant survives removing trust, but does not cover new scopes.
    assert!(location(&authenticated, None).contains("code="));
    let mut expanded = authorize.clone();
    expanded
        .query_pairs_mut()
        .clear()
        .extend_pairs(authorize.query_pairs().map(|(key, value)| {
            let value = if key == "scope" {
                "openid profile email".into()
            } else {
                value
            };
            (key, value)
        }));
    let response = authenticated.get(expanded).send().unwrap();
    assert!(response.headers()["location"]
        .to_str()
        .unwrap()
        .starts_with("/consent?"));

    let missing = mutation("missing-client", true);
    assert_eq!(
        missing["errors"][0]["extensions"]["code"],
        "barycenter::client::not_found"
    );
    assert!(missing["errors"][0]["extensions"]["help"]
        .as_str()
        .unwrap()
        .contains("client ID"));
    // The mutation is not reachable on the public OIDC service.
    let public = http.post(format!("{}/admin/jobs", server.base_url()))
        .json(&serde_json::json!({"query": "mutation { setClientTrusted(clientId: \"missing-client\", trusted: true) { trusted } }"}))
        .send().unwrap();
    assert_eq!(public.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn client_trust_cli_updates_flag_and_reports_missing_clients() {
    let server = TestServer::start();
    let (client_id, _, _) = register_client(server.base_url());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for untrust in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_barycenter"));
        command
            .env("BARYCENTER__DATABASE__URL", &server.database_url)
            .args(["client", "trust", &client_id]);
        if untrust {
            command.arg("--untrust");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        runtime.block_on(async {
            let db = sea_orm::Database::connect(&server.database_url)
                .await
                .unwrap();
            let client = barycenter::storage::get_client(&db, &client_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(client.trusted, !untrust);
            db.close().await.unwrap();
        });
    }
    let output = Command::new(env!("CARGO_BIN_EXE_barycenter"))
        .env("BARYCENTER__DATABASE__URL", &server.database_url)
        .args(["client", "trust", "missing-client"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("barycenter::client::not_found"), "{stderr}");
    assert!(stderr.contains("admin client listing"), "{stderr}");
}

#[test]
fn prompt_consent_overrides_global_skip() {
    let server = TestServer::start();
    let (client_id, _, redirect_uri) = register_client(server.base_url());
    let (http, _) = login_and_get_client(server.base_url(), "force-consent-user", "testpass123");
    let response = http
        .get(format!("{}/authorize", server.base_url()))
        .query(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", "openid"),
            ("prompt", "consent"),
            ("code_challenge", "test_challenge"),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .unwrap();
    assert!(response.headers()["location"]
        .to_str()
        .unwrap()
        .starts_with("/consent?"));
}

#[test]
fn consent_page_is_embedded_server_rendered_and_completes_authorization() {
    let server = TestServer::start_with_consent();
    let (client_id, _client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) =
        login_and_get_client(server.base_url(), "consent-user", "testpass123");

    let pkce_verifier = "consent_verifier_1234567890123456789012345678901234567890";
    let challenge_hash = sha2::Sha256::digest(pkce_verifier.as_bytes());
    let pkce_challenge = base64ct::Base64UrlUnpadded::encode_string(&challenge_hash);
    let auth_request = format!(
        "{}/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email&state=consent_state&nonce=consent_nonce&code_challenge={}&code_challenge_method=S256",
        server.base_url(),
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&pkce_challenge)
    );

    let auth_response = authenticated_client
        .get(&auth_request)
        .send()
        .expect("Failed to request authorization");
    assert!(auth_response.status().is_redirection());
    let consent_location = auth_response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("Authorization response did not redirect to consent")
        .to_string();
    assert!(consent_location.starts_with("/consent?"));

    let consent_response = authenticated_client
        .get(format!("{}{}", server.base_url(), consent_location))
        .send()
        .expect("Failed to load consent page");
    assert_eq!(consent_response.status(), reqwest::StatusCode::OK);
    let csp = consent_response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    let callback_origin = url::Url::parse(&redirect_uri)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert!(csp.ends_with(&format!("form-action 'self' {callback_origin}")));
    let invalid_context = authenticated_client
        .get(format!("{}/consent", server.base_url()))
        .query(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://attacker.example/callback"),
            ("response_type", "code"),
            ("scope", "openid"),
        ])
        .send()
        .unwrap();
    assert!(invalid_context.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .ends_with("form-action 'self'"));
    let login_context = authenticated_client
        .get(format!("{}/login", server.base_url()))
        .query(&[(
            "return_to",
            auth_request.strip_prefix(server.base_url()).unwrap(),
        )])
        .send()
        .unwrap();
    assert!(login_context.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .ends_with(&format!("form-action 'self' {callback_origin}")));
    let consent_body = consent_response
        .text()
        .expect("Failed to read consent page");
    assert!(consent_body.contains(&client_id));
    assert!(consent_body.contains("consent-user"));
    assert!(consent_body.contains("OpenID Connect"));
    assert!(consent_body.contains("Profile Information"));
    assert!(consent_body.contains("Email Address"));
    assert!(consent_body.contains("value=\"consent_state\""));
    assert!(consent_body.contains("value=\"consent_nonce\""));
    assert!(!consent_body.contains("{{"));
    assert!(!consent_body.contains("<script"));
    assert!(!consent_body.contains("window.location.search"));

    let consent_url = url::Url::parse(&format!("{}{}", server.base_url(), consent_location))
        .expect("Invalid consent URL");
    let mut form_params = std::collections::HashMap::new();
    for (key, value) in consent_url.query_pairs() {
        form_params.insert(key.to_string(), value.to_string());
    }
    form_params.insert("action".to_string(), "approve".to_string());

    let approval_response = authenticated_client
        .post(format!("{}/consent", server.base_url()))
        .form(&form_params)
        .send()
        .expect("Failed to approve consent");
    assert_eq!(
        approval_response.status(),
        reqwest::StatusCode::SEE_OTHER,
        "Consent approval must switch the follow-up request to GET"
    );
    let continuation_location = approval_response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("Consent approval did not redirect to authorization");
    let continuation =
        url::Url::parse(&format!("{}{}", server.base_url(), continuation_location)).unwrap();
    assert_eq!(continuation.path(), "/login");
    let params: std::collections::HashMap<_, _> = continuation.query_pairs().collect();
    assert_eq!(params.get("step").map(|s| s.as_ref()), Some("continue"));
    let authorize_location = params.get("return_to").unwrap();
    assert!(authorize_location.starts_with("/authorize?"));
    let boundary = authenticated_client
        .get(continuation.clone())
        .send()
        .unwrap();
    assert_eq!(boundary.status(), reqwest::StatusCode::OK);
    assert_eq!(boundary.headers()["cache-control"], "no-store");
    let boundary_html = boundary.text().unwrap();
    assert!(boundary_html.contains("id=\"continue-sign-in\""));
    assert!(!boundary_html.contains("<form"));

    let final_response = authenticated_client
        .get(format!("{}{}", server.base_url(), authorize_location))
        .send()
        .expect("Failed to complete authorization after consent");
    assert!(final_response.status().is_redirection());
    let callback_location = final_response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("Authorization did not redirect to the client callback");
    let callback_url = url::Url::parse(callback_location).expect("Invalid callback URL");
    assert_eq!(
        callback_url.origin().ascii_serialization(),
        "http://localhost:3000"
    );
    assert_eq!(callback_url.path(), "/callback");
    assert_eq!(
        callback_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string()),
        Some("consent_state".to_string())
    );
    assert!(callback_url
        .query_pairs()
        .any(|(key, value)| key == "code" && !value.is_empty()));
}

#[test]
fn test_openidconnect_authorization_code_flow() {
    use openidconnect::{
        core::{CoreClient, CoreProviderMetadata},
        AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
        OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    };

    let server = TestServer::start();
    let (client_id, client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) =
        login_and_get_client(server.base_url(), "testuser", "testpass123");

    let issuer_url = IssuerUrl::new(server.base_url().to_string()).expect("Invalid issuer URL");

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
            Nonce::new_random,
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
        base_url_for_redirect
            .join(location)
            .expect("Invalid redirect URL")
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

    assert!(!token_response.access_token().secret().is_empty());
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
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).expect("Failed to parse ID token claims");

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
        basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
        PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
    };

    let server = TestServer::start();
    let (client_id, client_secret, redirect_uri) = register_client(server.base_url());
    let (authenticated_client, _jar) =
        login_and_get_client(server.base_url(), "testuser2", "testpass123");

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

    // Check if redirected to consent page
    let location_str = location.to_string();
    let (code, returned_state) = if location_str.starts_with("/consent") {
        println!("Redirected to consent page, approving...");

        // Parse consent URL to extract parameters
        let consent_url = if location_str.starts_with("http") {
            url::Url::parse(&location_str).expect("Invalid consent URL")
        } else {
            url::Url::parse(&format!("{}{}", server.base_url(), location_str))
                .expect("Invalid consent URL")
        };

        // Extract form parameters
        let mut form_params = std::collections::HashMap::new();
        for (k, v) in consent_url.query_pairs() {
            form_params.insert(k.to_string(), v.to_string());
        }

        // Add approval action
        form_params.insert("action".to_string(), "approve".to_string());

        // Submit consent form
        let consent_response = authenticated_client
            .post(format!("{}/consent", server.base_url()))
            .form(&form_params)
            .send()
            .expect("Failed to submit consent");

        assert!(
            consent_response.status().is_redirection(),
            "Expected redirect after consent, got {}",
            consent_response.status()
        );

        // Get the redirect location (should be back to /authorize or to the callback)
        let consent_location = consent_response
            .headers()
            .get("location")
            .expect("No location header after consent")
            .to_str()
            .expect("Invalid location header");

        println!("After consent redirect: {}", consent_location);

        // If redirected back to /authorize, follow it
        let final_location = if consent_location.contains("/authorize") {
            let reauth_response = authenticated_client
                .get(format!("{}{}", server.base_url(), consent_location))
                .send()
                .expect("Failed to re-request authorization");

            assert!(
                reauth_response.status().is_redirection(),
                "Expected redirect after re-auth, got {}",
                reauth_response.status()
            );

            reauth_response
                .headers()
                .get("location")
                .expect("No location header after re-auth")
                .to_str()
                .expect("Invalid location header")
                .to_string()
        } else {
            consent_location.to_string()
        };

        // Parse the final redirect URL
        let redirect_url_parsed = if final_location.starts_with("http") {
            url::Url::parse(&final_location).expect("Invalid redirect URL")
        } else {
            let base = url::Url::parse(&redirect_uri).expect("Invalid redirect URI");
            base.join(&final_location).expect("Invalid redirect URL")
        };

        let code = redirect_url_parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string())
            .expect("No code in redirect");

        let state = redirect_url_parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("No state in redirect");

        (code, state)
    } else {
        // Direct redirect to callback (no consent needed)
        let redirect_url_parsed = if location_str.starts_with("http") {
            url::Url::parse(&location_str).expect("Invalid redirect URL")
        } else {
            let base = url::Url::parse(&redirect_uri).expect("Invalid redirect URI");
            base.join(&location_str).expect("Invalid redirect URL")
        };

        let code = redirect_url_parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string())
            .expect("No code in redirect");

        let state = redirect_url_parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("No state in redirect");

        (code, state)
    };

    assert_eq!(returned_state, *csrf_token.secret());

    let http_client = reqwest::blocking::Client::new();
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)
        .expect("Failed to exchange code for token");

    assert!(!token_response.access_token().secret().is_empty());
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
        .get(format!(
            "{}/.well-known/openid-configuration",
            server.base_url()
        ))
        .send()
        .expect("Failed to fetch discovery");

    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
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
    let (authenticated_client, _jar) =
        login_and_get_client(server.base_url(), "testuser3", "testpass123");

    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let discovery_response = http_client
        .get(format!(
            "{}/.well-known/openid-configuration",
            server.base_url()
        ))
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
        base_url_for_redirect
            .join(location)
            .expect("Invalid redirect URL")
    };
    let code = redirect_url_parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("No code in redirect");

    let auth_header =
        base64ct::Base64::encode_string(format!("{}:{}", client_id, client_secret).as_bytes());

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
