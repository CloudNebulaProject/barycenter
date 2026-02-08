//! See docs/axum.md for axum usage patterns and router/state conventions.
//! See docs/oidc-conformance.md for OIDC OP requirements, current status, and roadmap.
//! This module exposes the HTTP endpoints, some of which are discovery and JWKS
//! as required by OpenID Connect. Authorization, token, and userinfo will follow
//! per the conformance plan.
use crate::errors::CrabError;
use crate::jwks::JwksManager;
use crate::session::SessionCookie;
use crate::settings::Settings;
use crate::storage;
use axum::body::Body;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use miette::IntoDiagnostic;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tower_http::services::ServeDir;
use urlencoding;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub db: DatabaseConnection,
    pub jwks: JwksManager,
    pub webauthn: crate::webauthn_manager::WebAuthnManager,
}

// Security headers middleware
async fn security_headers(request: Request<Body>, next: Next) -> impl IntoResponse {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // X-Frame-Options: Prevent clickjacking
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );

    // X-Content-Type-Options: Prevent MIME sniffing
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection: Legacy XSS protection (still useful for older browsers)
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );

    // Content-Security-Policy: Restrict resource loading (allows WASM for passkeys)
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'"),
    );

    // Referrer-Policy: Control referrer information
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions-Policy: Disable unnecessary browser features
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    response
}

pub async fn serve(
    settings: Settings,
    db: DatabaseConnection,
    jwks: JwksManager,
    webauthn: crate::webauthn_manager::WebAuthnManager,
    seaography_schema: async_graphql::dynamic::Schema,
    jobs_schema: async_graphql::Schema<
        crate::admin_mutations::AdminQuery,
        crate::admin_mutations::AdminMutation,
        async_graphql::EmptySubscription,
    >,
) -> miette::Result<()> {
    let state = AppState {
        settings: Arc::new(settings),
        db,
        jwks,
        webauthn,
    };

    // NOTE: Rate limiting should be implemented at the reverse proxy level (nginx, traefik, etc.)
    // for production deployments. This is more efficient and flexible than application-level
    // rate limiting. Configure your reverse proxy with limits like:
    // - Token endpoint: 10 req/min per IP
    // - Login endpoint: 5 attempts/min per IP
    // - Authorize endpoint: 20 req/min per IP

    let mut router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/connect/register", post(register_client))
        .route(
            "/properties/{owner}/{key}",
            get(get_property).put(set_property),
        )
        .route("/federation/trust-anchors", get(trust_anchors))
        .route("/login", get(login_page).post(login_submit))
        .route("/login/2fa", get(login_2fa_page))
        .route("/logout", get(logout))
        .route("/authorize", get(authorize))
        .route("/consent", get(consent_page).post(consent_submit))
        .route("/token", post(token))
        .route("/revoke", post(token_revoke))
        .route("/userinfo", get(userinfo))
        // Device Authorization Grant (RFC 8628) endpoints
        .route("/device_authorization", post(device_authorization))
        .route("/device", get(device_page))
        .route("/device/verify", post(device_verify))
        .route("/device/consent", post(device_consent))
        // WebAuthn / Passkey endpoints
        .route("/webauthn/register/start", post(passkey_register_start))
        .route("/webauthn/register/finish", post(passkey_register_finish))
        .route("/webauthn/authenticate/start", post(passkey_auth_start))
        .route("/webauthn/authenticate/finish", post(passkey_auth_finish))
        .route("/webauthn/2fa/start", post(passkey_2fa_start))
        .route("/webauthn/2fa/finish", post(passkey_2fa_finish))
        .route("/account/passkeys", get(list_passkeys))
        .route(
            "/account/passkeys/{credential_id}",
            axum::routing::delete(delete_passkey_handler).patch(update_passkey_handler),
        );

    // Conditionally add public registration route
    if state.settings.server.allow_public_registration {
        tracing::info!("Public user registration is ENABLED");
        router = router.route("/register", post(register_user));
    } else {
        tracing::info!("Public user registration is DISABLED - use admin API");
    }

    // Serve static files (WASM, JS, etc.)
    let router = router
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(security_headers))
        .with_state(state.clone());

    let public_addr: SocketAddr = format!(
        "{}:{}",
        state.settings.server.host, state.settings.server.port
    )
    .parse()
    .map_err(|e| miette::miette!("bad listen addr: {e}"))?;

    // Start admin GraphQL server on separate port
    let admin_port = state
        .settings
        .server
        .admin_port
        .unwrap_or(state.settings.server.port + 1);
    let admin_addr: SocketAddr = format!("{}:{}", state.settings.server.host, admin_port)
        .parse()
        .map_err(|e| miette::miette!("bad admin addr: {e}"))?;

    let admin_router = crate::admin_graphql::router(seaography_schema, jobs_schema);

    // Spawn admin server in background
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .into_diagnostic()?;
    tracing::info!(%admin_addr, "Admin GraphQL API listening");
    tracing::info!(
        "GraphQL Playground available at http://{}/admin/playground",
        admin_addr
    );

    tokio::spawn(async move {
        axum::serve(admin_listener, admin_router)
            .await
            .expect("Admin server failed");
    });

    // Start authorization policy server (if enabled)
    if state.settings.authz.enabled {
        let authz_state = std::sync::Arc::new(
            crate::authz::loader::load_policies(&state.settings.authz.policies_dir)
                .map_err(|e| miette::miette!("failed to load authz policies: {e}"))?,
        );
        let authz_port = state
            .settings
            .authz
            .port
            .unwrap_or(state.settings.server.port + 2);
        let authz_addr: SocketAddr = format!("{}:{}", state.settings.server.host, authz_port)
            .parse()
            .map_err(|e| miette::miette!("bad authz addr: {e}"))?;
        let authz_router = crate::authz::web::router(authz_state);
        let authz_listener = tokio::net::TcpListener::bind(authz_addr)
            .await
            .into_diagnostic()?;
        tracing::info!(%authz_addr, "Authorization policy API listening");
        tokio::spawn(async move {
            axum::serve(authz_listener, authz_router)
                .await
                .expect("Authz server failed");
        });
    }

    // Start public server
    tracing::info!(%public_addr, "Public API listening");
    tracing::warn!("Rate limiting should be configured at the reverse proxy level for production");
    let listener = tokio::net::TcpListener::bind(public_addr)
        .await
        .into_diagnostic()?;
    axum::serve(listener, router).await.into_diagnostic()?;
    Ok(())
}

async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = state.settings.issuer();
    let metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "device_authorization_endpoint": format!("{}/device_authorization", issuer),
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
        "registration_endpoint": format!("{}/connect/register", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [state.settings.keys.alg],
        // Additional recommended metadata for better interoperability
        "grant_types_supported": ["authorization_code", "refresh_token", "implicit", "urn:ietf:params:oauth:grant-type:device_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "name", "given_name", "family_name", "email", "email_verified"
        ],
        // OIDC Core 1.0 features
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "display_values_supported": ["page"],
        "ui_locales_supported": ["en"],
        "claim_types_supported": ["normal"],
    });
    Json(metadata)
}

async fn jwks_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.jwks.jwks_json())
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
    display: Option<String>,
    ui_locales: Option<String>,
    claims_locales: Option<String>,
    max_age: Option<String>,
    acr_values: Option<String>,
}

fn url_append_query(mut base: String, params: &[(&str, String)]) -> String {
    let qs = serde_urlencoded::to_string(
        params
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<Vec<(String, String)>>(),
    )
    .unwrap_or_default();
    if base.contains('?') {
        base.push('&');
    } else {
        base.push('?');
    }
    base.push_str(&qs);
    base
}

/// Check if the requested scope contains high-value scopes that require 2FA
fn is_high_value_scope(scope: &str) -> bool {
    // Define scopes that require elevated authentication (2FA)
    let high_value_scopes = ["admin", "payment", "transfer", "delete"];

    scope
        .split_whitespace()
        .any(|s| high_value_scopes.contains(&s))
}

fn oauth_error_redirect(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    desc: &str,
) -> axum::response::Redirect {
    let mut params = vec![("error", error.to_string())];
    if !desc.is_empty() {
        params.push(("error_description", desc.to_string()));
    }
    if let Some(s) = state {
        params.push(("state", s.to_string()));
    }
    let loc = url_append_query(redirect_uri.to_string(), &params);
    axum::response::Redirect::temporary(&loc)
}

// OIDC-specific error codes per OpenID Connect Core 1.0 Section 3.1.2.6
// login_required: Authentication is required but prompt=none was specified
// consent_required: Consent is required but prompt=none was specified
// interaction_required: User interaction is required but prompt=none was specified
// account_selection_required: Account selection is required but prompt=none was specified
fn oidc_error_redirect(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
) -> axum::response::Redirect {
    oauth_error_redirect(redirect_uri, state, error, "")
}

async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    // Validate response_type - support code, id_token, and id_token token
    let valid_response_types = ["code", "id_token", "id_token token"];
    if !valid_response_types.contains(&q.response_type.as_str()) {
        return oauth_error_redirect(
            &q.redirect_uri,
            q.state.as_deref(),
            "unsupported_response_type",
            "only response_type=code, id_token, or 'id_token token' supported",
        )
        .into_response();
    }
    // Validate scope includes openid
    if !q.scope.split_whitespace().any(|s| s == "openid") {
        return oauth_error_redirect(
            &q.redirect_uri,
            q.state.as_deref(),
            "invalid_scope",
            "scope must include openid",
        )
        .into_response();
    }
    // Require PKCE S256
    let (code_challenge, ccm) = match (&q.code_challenge, &q.code_challenge_method) {
        (Some(cc), Some(m)) if m == "S256" => (cc.clone(), m.clone()),
        _ => {
            return oauth_error_redirect(
                &q.redirect_uri,
                q.state.as_deref(),
                "invalid_request",
                "PKCE (S256) required",
            )
            .into_response();
        }
    };

    // Lookup client
    let client = match storage::get_client(&state.db, &q.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return oauth_error_redirect(
                &q.redirect_uri,
                q.state.as_deref(),
                "unauthorized_client",
                "unknown client_id",
            )
            .into_response()
        }
        Err(_) => {
            return oauth_error_redirect(
                &q.redirect_uri,
                q.state.as_deref(),
                "server_error",
                "db error",
            )
            .into_response()
        }
    };
    // Validate redirect_uri exact match
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return oauth_error_redirect(
            &q.redirect_uri,
            q.state.as_deref(),
            "invalid_request",
            "redirect_uri mismatch",
        )
        .into_response();
    }

    // Parse prompt parameter (can be space-separated list)
    let prompt_values: Vec<&str> = q
        .prompt
        .as_ref()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();

    let has_prompt_none = prompt_values.contains(&"none");
    let has_prompt_login = prompt_values.contains(&"login");
    let has_prompt_select_account = prompt_values.contains(&"select_account");

    // Check for existing session (but ignore if prompt=login or prompt=select_account)
    let session_opt = if has_prompt_login || has_prompt_select_account {
        None // Force re-authentication
    } else if let Some(cookie) = SessionCookie::from_headers(&headers) {
        storage::get_session(&state.db, &cookie.session_id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Handle max_age parameter - requires re-authentication if session is too old
    let needs_fresh_auth = if let Some(max_age_str) = &q.max_age {
        if let Ok(max_age) = max_age_str.parse::<i64>() {
            if let Some(ref sess) = session_opt {
                let age = chrono::Utc::now().timestamp() - sess.auth_time;
                age > max_age
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    let (subject, auth_time, session) = match session_opt {
        Some(sess) if sess.expires_at > chrono::Utc::now().timestamp() && !needs_fresh_auth => {
            (sess.subject.clone(), Some(sess.auth_time), Some(sess))
        }
        _ => {
            // No valid session or session too old
            // If prompt=none, return error instead of redirecting
            if has_prompt_none {
                return oidc_error_redirect(&q.redirect_uri, q.state.as_deref(), "login_required")
                    .into_response();
            }

            // Build return_to URL with all parameters
            let mut return_params = vec![
                ("client_id", q.client_id.clone()),
                ("redirect_uri", q.redirect_uri.clone()),
                ("response_type", q.response_type.clone()),
                ("scope", q.scope.clone()),
                ("code_challenge", code_challenge.clone()),
                ("code_challenge_method", ccm.clone()),
            ];
            if let Some(s) = &q.state {
                return_params.push(("state", s.clone()));
            }
            if let Some(n) = &q.nonce {
                return_params.push(("nonce", n.clone()));
            }
            if let Some(p) = &q.prompt {
                return_params.push(("prompt", p.clone()));
            }
            if let Some(d) = &q.display {
                return_params.push(("display", d.clone()));
            }
            if let Some(ui) = &q.ui_locales {
                return_params.push(("ui_locales", ui.clone()));
            }
            if let Some(cl) = &q.claims_locales {
                return_params.push(("claims_locales", cl.clone()));
            }
            if let Some(ma) = &q.max_age {
                return_params.push(("max_age", ma.clone()));
            }
            if let Some(acr) = &q.acr_values {
                return_params.push(("acr_values", acr.clone()));
            }

            let return_to = url_append_query(
                "/authorize".to_string(),
                &return_params
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect::<Vec<_>>(),
            );
            let login_url = format!("/login?return_to={}", urlencoded(&return_to));
            return Redirect::temporary(&login_url).into_response();
        }
    };

    // Check if 2FA is required for this authorization request
    if let Some(sess) = &session {
        // Get user to check 2FA requirements
        let user = match storage::get_user_by_subject(&state.db, &subject).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "server_error",
                    "user not found",
                )
                .into_response();
            }
            Err(_) => {
                return oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "server_error",
                    "db error",
                )
                .into_response();
            }
        };

        // Determine if 2FA is required
        let requires_2fa = user.requires_2fa == 1  // Admin-enforced 2FA
            || is_high_value_scope(&q.scope)        // Context-based: high-value scope
            || q.max_age.as_ref().and_then(|ma| ma.parse::<i64>().ok())
                .is_some_and(|ma| ma < 300); // Context-based: max_age < 5 minutes

        // If 2FA required but not verified, redirect to 2FA page
        if requires_2fa && sess.mfa_verified == 0 {
            // Build return_to URL with all parameters
            let mut return_params = vec![
                ("client_id", q.client_id.clone()),
                ("redirect_uri", q.redirect_uri.clone()),
                ("response_type", q.response_type.clone()),
                ("scope", q.scope.clone()),
                ("code_challenge", code_challenge.clone()),
                ("code_challenge_method", ccm.clone()),
            ];
            if let Some(s) = &q.state {
                return_params.push(("state", s.clone()));
            }
            if let Some(n) = &q.nonce {
                return_params.push(("nonce", n.clone()));
            }
            if let Some(p) = &q.prompt {
                return_params.push(("prompt", p.clone()));
            }
            if let Some(d) = &q.display {
                return_params.push(("display", d.clone()));
            }
            if let Some(ui) = &q.ui_locales {
                return_params.push(("ui_locales", ui.clone()));
            }
            if let Some(cl) = &q.claims_locales {
                return_params.push(("claims_locales", cl.clone()));
            }
            if let Some(ma) = &q.max_age {
                return_params.push(("max_age", ma.clone()));
            }
            if let Some(acr) = &q.acr_values {
                return_params.push(("acr_values", acr.clone()));
            }

            let return_to = url_append_query(
                "/authorize".to_string(),
                &return_params
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect::<Vec<_>>(),
            );
            let tfa_url = format!("/login/2fa?return_to={}", urlencoded(&return_to));
            return Redirect::temporary(&tfa_url).into_response();
        }
    }

    let scope = q.scope.clone();
    let nonce = q.nonce.clone();

    // Check if user has consented to this client/scope combination
    // Skip consent check if:
    // 1. BARYCENTER_SKIP_CONSENT env var is set (for testing)
    // 2. prompt=consent is set (force re-consent)
    let skip_consent = std::env::var("BARYCENTER_SKIP_CONSENT").is_ok();
    let prompt_values: Vec<&str> = q
        .prompt
        .as_ref()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();
    let force_consent = prompt_values.contains(&"consent");

    if !skip_consent
        && (force_consent
            || !storage::has_consent(&state.db, &q.client_id, &subject, &scope)
                .await
                .unwrap_or(false))
    {
        // No consent exists or force re-consent - redirect to consent page
        // If prompt=none, return error instead of redirecting
        if prompt_values.contains(&"none") {
            return oidc_error_redirect(&q.redirect_uri, q.state.as_deref(), "consent_required")
                .into_response();
        }

        // Get client name for the consent page
        let client_name = match storage::get_client(&state.db, &q.client_id).await {
            Ok(Some(client)) => client.client_name,
            _ => None,
        };

        // Build consent URL with all OAuth parameters
        let mut consent_params = vec![
            ("client_id", q.client_id.clone()),
            ("scope", scope.clone()),
            ("redirect_uri", q.redirect_uri.clone()),
            ("response_type", q.response_type.clone()),
            ("code_challenge", code_challenge.clone()),
            ("code_challenge_method", ccm.clone()),
        ];

        if let Some(name) = client_name {
            consent_params.push(("client_name", name));
        }
        if let Some(s) = &q.state {
            consent_params.push(("state", s.clone()));
        }
        if let Some(n) = &nonce {
            consent_params.push(("nonce", n.clone()));
        }
        if let Some(p) = &q.prompt {
            consent_params.push(("prompt", p.clone()));
        }
        if let Some(d) = &q.display {
            consent_params.push(("display", d.clone()));
        }
        if let Some(ui) = &q.ui_locales {
            consent_params.push(("ui_locales", ui.clone()));
        }
        if let Some(cl) = &q.claims_locales {
            consent_params.push(("claims_locales", cl.clone()));
        }
        if let Some(ma) = &q.max_age {
            consent_params.push(("max_age", ma.clone()));
        }
        if let Some(acr) = &q.acr_values {
            consent_params.push(("acr_values", acr.clone()));
        }

        let consent_url = url_append_query(
            "/consent".to_string(),
            &consent_params
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>(),
        );

        return Redirect::temporary(&consent_url).into_response();
    }

    // Handle different response types
    match q.response_type.as_str() {
        "code" => {
            // Authorization Code Flow - issue auth code
            let ttl = 300; // 5 minutes
            match storage::issue_auth_code(
                &state.db,
                &q.client_id,
                &q.redirect_uri,
                &scope,
                &subject,
                nonce,
                &code_challenge,
                &ccm,
                ttl,
                auth_time,
            )
            .await
            {
                Ok(code) => {
                    let mut params = vec![("code", code.code.clone())];
                    if let Some(s) = &q.state {
                        params.push(("state", s.clone()));
                    }
                    let loc = url_append_query(q.redirect_uri.clone(), &params);
                    axum::response::Redirect::temporary(&loc).into_response()
                }
                Err(_) => oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "server_error",
                    "could not issue code",
                )
                .into_response(),
            }
        }
        "id_token" => {
            // Implicit Flow - return ID token in fragment
            // Require nonce for implicit flow (OIDC Core 1.0 Section 3.2.2.1)
            if nonce.is_none() {
                return oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "invalid_request",
                    "nonce required for implicit flow",
                )
                .into_response();
            }

            match build_id_token(
                &state,
                &q.client_id,
                &subject,
                nonce.as_deref(),
                auth_time,
                None,
                session.as_ref().and_then(|s| s.amr.as_deref()),
                session.as_ref().and_then(|s| s.acr.as_deref()),
            )
            .await
            {
                Ok(id_token) => {
                    let mut fragment_params = vec![("id_token", id_token)];
                    if let Some(s) = &q.state {
                        fragment_params.push(("state", s.clone()));
                    }
                    let fragment =
                        serde_urlencoded::to_string(&fragment_params).unwrap_or_default();
                    let loc = format!("{}#{}", q.redirect_uri, fragment);
                    axum::response::Redirect::temporary(&loc).into_response()
                }
                Err(_) => oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "server_error",
                    "could not generate id_token",
                )
                .into_response(),
            }
        }
        "id_token token" => {
            // Implicit Flow - return both ID token and access token in fragment
            // Require nonce for implicit flow
            if nonce.is_none() {
                return oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "invalid_request",
                    "nonce required for implicit flow",
                )
                .into_response();
            }

            // Issue access token
            let access =
                match storage::issue_access_token(&state.db, &q.client_id, &subject, &scope, 3600)
                    .await
                {
                    Ok(t) => t,
                    Err(_) => {
                        return oauth_error_redirect(
                            &q.redirect_uri,
                            q.state.as_deref(),
                            "server_error",
                            "could not issue access token",
                        )
                        .into_response()
                    }
                };

            // Build ID token with at_hash
            match build_id_token(
                &state,
                &q.client_id,
                &subject,
                nonce.as_deref(),
                auth_time,
                Some(&access.token),
                session.as_ref().and_then(|s| s.amr.as_deref()),
                session.as_ref().and_then(|s| s.acr.as_deref()),
            )
            .await
            {
                Ok(id_token) => {
                    let mut fragment_params = vec![
                        ("access_token", access.token),
                        ("token_type", "bearer".to_string()),
                        ("expires_in", "3600".to_string()),
                        ("id_token", id_token),
                    ];
                    if let Some(s) = &q.state {
                        fragment_params.push(("state", s.clone()));
                    }
                    let fragment =
                        serde_urlencoded::to_string(&fragment_params).unwrap_or_default();
                    let loc = format!("{}#{}", q.redirect_uri, fragment);
                    axum::response::Redirect::temporary(&loc).into_response()
                }
                Err(_) => oauth_error_redirect(
                    &q.redirect_uri,
                    q.state.as_deref(),
                    "server_error",
                    "could not generate id_token",
                )
                .into_response(),
            }
        }
        _ => oauth_error_redirect(
            &q.redirect_uri,
            q.state.as_deref(),
            "unsupported_response_type",
            "invalid response_type",
        )
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ConsentQuery {
    client_id: String,
    client_name: Option<String>,
    scope: String,
    redirect_uri: String,
    response_type: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
    display: Option<String>,
    ui_locales: Option<String>,
    claims_locales: Option<String>,
    max_age: Option<String>,
    acr_values: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    client_id: String,
    scope: String,
    redirect_uri: String,
    response_type: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    action: String, // "approve" or "deny"
}

async fn consent_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsentQuery>,
) -> impl IntoResponse {
    // Verify user is authenticated
    let session = match SessionCookie::from_headers(&headers) {
        Some(cookie) => match storage::get_session(&state.db, &cookie.session_id).await {
            Ok(Some(sess)) if sess.expires_at > chrono::Utc::now().timestamp() => sess,
            _ => {
                // Session expired or invalid - redirect to login
                let return_to = format!(
                    "/consent?client_id={}&scope={}&redirect_uri={}&response_type={}&code_challenge={}&code_challenge_method={}{}",
                    urlencoded(&q.client_id),
                    urlencoded(&q.scope),
                    urlencoded(&q.redirect_uri),
                    urlencoded(&q.response_type),
                    urlencoded(q.code_challenge.as_ref().unwrap_or(&String::new())),
                    urlencoded(q.code_challenge_method.as_ref().unwrap_or(&String::new())),
                    q.state.as_ref().map(|s| format!("&state={}", urlencoded(s))).unwrap_or_default()
                );
                return Redirect::temporary(&format!(
                    "/login?return_to={}",
                    urlencoded(&return_to)
                ))
                .into_response();
            }
        },
        None => {
            // No session cookie - redirect to login
            let return_to = format!(
                "/consent?client_id={}&scope={}&redirect_uri={}&response_type={}&code_challenge={}&code_challenge_method={}{}",
                urlencoded(&q.client_id),
                urlencoded(&q.scope),
                urlencoded(&q.redirect_uri),
                urlencoded(&q.response_type),
                urlencoded(q.code_challenge.as_ref().unwrap_or(&String::new())),
                urlencoded(q.code_challenge_method.as_ref().unwrap_or(&String::new())),
                q.state.as_ref().map(|s| format!("&state={}", urlencoded(s))).unwrap_or_default()
            );
            return Redirect::temporary(&format!("/login?return_to={}", urlencoded(&return_to)))
                .into_response();
        }
    };

    // Get username for display
    let username = match storage::get_user_by_subject(&state.db, &session.subject).await {
        Ok(Some(user)) => user.username,
        _ => "User".to_string(),
    };

    // Get client name
    let client_name = if let Some(name) = q.client_name {
        name
    } else {
        match storage::get_client(&state.db, &q.client_id).await {
            Ok(Some(client)) => client.client_name.unwrap_or_else(|| q.client_id.clone()),
            _ => q.client_id.clone(),
        }
    };

    // Serve the static consent.html file with query parameters
    match tokio::fs::read_to_string("static/consent.html").await {
        Ok(html) => {
            // Build query string for the consent page
            let mut params = vec![
                ("client_id", q.client_id.clone()),
                ("client_name", client_name),
                ("scope", q.scope.clone()),
                ("redirect_uri", q.redirect_uri.clone()),
                ("response_type", q.response_type.clone()),
                ("username", username),
            ];

            if let Some(s) = &q.state {
                params.push(("state", s.clone()));
            }
            if let Some(n) = &q.nonce {
                params.push(("nonce", n.clone()));
            }
            if let Some(cc) = &q.code_challenge {
                params.push(("code_challenge", cc.clone()));
            }
            if let Some(ccm) = &q.code_challenge_method {
                params.push(("code_challenge_method", ccm.clone()));
            }

            // Append query parameters to HTML
            let query_string = serde_urlencoded::to_string(&params).unwrap_or_default();
            let html_with_params = if html.contains("</body>") {
                html.replace(
                    "</body>",
                    &format!(
                        "<script>window.location.search = '?{}';</script></body>",
                        query_string
                    ),
                )
            } else {
                html
            };

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Body::from(html_with_params))
                .unwrap()
                .into_response()
        }
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Consent page not found"))
            .unwrap()
            .into_response(),
    }
}

async fn consent_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> impl IntoResponse {
    // Verify user is authenticated
    let session = match SessionCookie::from_headers(&headers) {
        Some(cookie) => match storage::get_session(&state.db, &cookie.session_id).await {
            Ok(Some(sess)) if sess.expires_at > chrono::Utc::now().timestamp() => sess,
            _ => {
                return oauth_error_redirect(
                    &form.redirect_uri,
                    form.state.as_deref(),
                    "access_denied",
                    "session expired",
                )
                .into_response();
            }
        },
        None => {
            return oauth_error_redirect(
                &form.redirect_uri,
                form.state.as_deref(),
                "access_denied",
                "not authenticated",
            )
            .into_response();
        }
    };

    // Handle deny action
    if form.action == "deny" {
        return oauth_error_redirect(
            &form.redirect_uri,
            form.state.as_deref(),
            "access_denied",
            "user denied consent",
        )
        .into_response();
    }

    // Handle approve action
    if form.action == "approve" {
        // Store consent (no expiration - lasts until revoked)
        if let Err(e) = storage::grant_consent(
            &state.db,
            &form.client_id,
            &session.subject,
            &form.scope,
            None, // No expiration
        )
        .await
        {
            tracing::error!("Failed to store consent: {}", e);
            return oauth_error_redirect(
                &form.redirect_uri,
                form.state.as_deref(),
                "server_error",
                "failed to store consent",
            )
            .into_response();
        }

        // Redirect back to /authorize with all parameters to complete the flow
        let mut params = vec![
            ("client_id", form.client_id.clone()),
            ("redirect_uri", form.redirect_uri.clone()),
            ("response_type", form.response_type.clone()),
            ("scope", form.scope.clone()),
        ];

        if let Some(s) = &form.state {
            params.push(("state", s.clone()));
        }
        if let Some(n) = &form.nonce {
            params.push(("nonce", n.clone()));
        }
        if let Some(cc) = &form.code_challenge {
            params.push(("code_challenge", cc.clone()));
        }
        if let Some(ccm) = &form.code_challenge_method {
            params.push(("code_challenge_method", ccm.clone()));
        }

        let authorize_url = url_append_query(
            "/authorize".to_string(),
            &params
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>(),
        );

        return Redirect::temporary(&authorize_url).into_response();
    }

    // Invalid action
    oauth_error_redirect(
        &form.redirect_uri,
        form.state.as_deref(),
        "invalid_request",
        "invalid action",
    )
    .into_response()
}

// Helper function to build ID token
async fn build_id_token(
    state: &AppState,
    client_id: &str,
    subject: &str,
    nonce: Option<&str>,
    auth_time: Option<i64>,
    access_token: Option<&str>, // For at_hash calculation
    amr: Option<&str>,          // Authentication Method References (JSON array)
    acr: Option<&str>,          // Authentication Context Reference
) -> Result<String, CrabError> {
    let now = SystemTime::now();
    let exp_unix = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + 3600;

    let mut payload = josekit::jwt::JwtPayload::new();
    payload.set_issuer(state.settings.issuer());
    payload.set_subject(subject.to_string());
    payload.set_audience(vec![client_id.to_string()]);
    payload.set_issued_at(&now);
    let _ = payload.set_claim("exp", Some(serde_json::json!(exp_unix)));

    if let Some(n) = nonce {
        let _ = payload.set_claim("nonce", Some(serde_json::Value::String(n.to_string())));
    }

    if let Some(at) = auth_time {
        let _ = payload.set_claim("auth_time", Some(serde_json::json!(at)));
    }

    // Add AMR claim (Authentication Method References)
    if let Some(amr_json) = amr {
        if let Ok(amr_value) = serde_json::from_str::<serde_json::Value>(amr_json) {
            let _ = payload.set_claim("amr", Some(amr_value));
        }
    }

    // Add ACR claim (Authentication Context Reference)
    if let Some(acr_value) = acr {
        let _ = payload.set_claim(
            "acr",
            Some(serde_json::Value::String(acr_value.to_string())),
        );
    }

    // Add at_hash if access_token is provided (for id_token token response type)
    if let Some(token) = access_token {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        let half = &digest[..16]; // left-most 128 bits
        let at_hash = Base64UrlUnpadded::encode_string(half);
        let _ = payload.set_claim("at_hash", Some(serde_json::Value::String(at_hash)));
    }

    state
        .jwks
        .sign_jwt_rs256(&payload)
        .map_err(|e| CrabError::Other(e.to_string()))
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    device_code: Option<String>, // For device_code grant
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    id_token: Option<String>,
    refresh_token: Option<String>,
}

fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    // Take full digest then base64url without padding
    Base64UrlUnpadded::encode_string(&digest)
}

fn json_with_headers(status: StatusCode, value: Value, headers: &[(&str, String)]) -> Response {
    let mut resp = (status, Json(value)).into_response();
    let h = resp.headers_mut();
    for (name, val) in headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(val),
        ) {
            h.insert(n, v);
        }
    }
    resp
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    // Validate grant_type
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, headers, req).await,
        "refresh_token" => handle_refresh_token_grant(state, headers, req).await,
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code_grant(state, headers, req).await
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn handle_authorization_code_grant(
    state: AppState,
    headers: HeaderMap,
    req: TokenRequest,
) -> Response {
    // Client authentication: client_secret_basic preferred, then client_secret_post
    let (client_id, client_secret) = match authenticate_client(&headers, &req) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let client = match storage::get_client(&state.db, &client_id).await {
        Ok(Some(c)) => c,
        _ => {
            return json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_client"}),
                &[(
                    "www-authenticate",
                    "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
                )],
            )
        }
    };
    if client.client_secret != client_secret {
        return json_with_headers(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_client"}),
            &[(
                "www-authenticate",
                "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
            )],
        );
    }

    // Require code
    let code = match req.code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_request","error_description":"code required"})),
            )
                .into_response()
        }
    };

    // Consume code
    let code_row = match storage::consume_auth_code(&state.db, &code).await {
        Ok(Some(c)) => c,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant"})),
            )
                .into_response()
        }
    };

    // Validate code binding
    let redirect_uri = req.redirect_uri.unwrap_or_default();
    if code_row.client_id != client_id || code_row.redirect_uri != redirect_uri {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    }

    // Validate PKCE S256
    let verifier =
        match &req.code_verifier {
            Some(v) => v,
            None => return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error":"invalid_request","error_description":"code_verifier required"}),
                ),
            )
                .into_response(),
        };
    if code_row.code_challenge_method != "S256" || pkce_s256(verifier) != code_row.code_challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant","error_description":"pkce verification failed"})),
        )
            .into_response();
    }

    // Issue access token
    let access = match storage::issue_access_token(
        &state.db,
        &client_id,
        &code_row.subject,
        &code_row.scope,
        3600,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"server_error","details":e.to_string()})),
            )
                .into_response()
        }
    };

    // Get session to include AMR/ACR claims in ID token
    let session_opt = if let Some(cookie) = SessionCookie::from_headers(&headers) {
        storage::get_session(&state.db, &cookie.session_id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Build ID Token using helper function
    let id_token = match build_id_token(
        &state,
        &client_id,
        &code_row.subject,
        code_row.nonce.as_deref(),
        code_row.auth_time,
        Some(&access.token),
        session_opt.as_ref().and_then(|s| s.amr.as_deref()),
        session_opt.as_ref().and_then(|s| s.acr.as_deref()),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"server_error","details":e.to_string()})),
            )
                .into_response()
        }
    };

    // Issue refresh token if offline_access scope was requested
    let refresh_token = if code_row
        .scope
        .split_whitespace()
        .any(|s| s == "offline_access")
    {
        match storage::issue_refresh_token(
            &state.db,
            &client_id,
            &code_row.subject,
            &code_row.scope,
            2592000,
            None,
        )
        .await
        {
            Ok(rt) => Some(rt.token),
            Err(_) => None, // Don't fail the whole request if refresh token issuance fails
        }
    } else {
        None
    };

    let resp = TokenResponse {
        access_token: access.token,
        token_type: "bearer".into(),
        expires_in: 3600,
        id_token: Some(id_token),
        refresh_token,
    };

    // Add Cache-Control: no-store as required by OAuth 2.0 and OIDC specs
    json_with_headers(
        StatusCode::OK,
        serde_json::to_value(resp).unwrap(),
        &[
            ("cache-control", "no-store".to_string()),
            ("pragma", "no-cache".to_string()),
        ],
    )
}

/// POST /revoke - Token revocation endpoint (RFC 7009)
#[derive(Debug, Deserialize)]
struct TokenRevokeRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn token_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRevokeRequest>,
) -> Response {
    // Client authentication: try Basic auth first, then form body
    let mut basic_client: Option<(String, String)> = None;
    if let Some(auth_val) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Some(b64) = auth_val.strip_prefix("Basic ") {
            if let Ok(mut decoded) = Base64::decode_vec(b64) {
                if let Ok(s) = String::from_utf8(std::mem::take(&mut decoded)) {
                    if let Some((id, sec)) = s.split_once(':') {
                        basic_client = Some((id.to_string(), sec.to_string()));
                    }
                }
            }
        }
    }

    let (client_id, client_secret) = if let Some(pair) = basic_client {
        pair
    } else {
        // Try client_secret_post (form body)
        match (req.client_id.clone(), req.client_secret.clone()) {
            (Some(id), Some(sec)) => (id, sec),
            _ => {
                return json_with_headers(
                    StatusCode::UNAUTHORIZED,
                    json!({"error":"invalid_client"}),
                    &[(
                        "www-authenticate",
                        "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
                    )],
                )
            }
        }
    };

    // Verify client exists and credentials match
    let client = match storage::get_client(&state.db, &client_id).await {
        Ok(Some(c)) => c,
        _ => {
            return json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_client"}),
                &[(
                    "www-authenticate",
                    "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
                )],
            )
        }
    };

    if client.client_secret != client_secret {
        return json_with_headers(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_client"}),
            &[(
                "www-authenticate",
                "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
            )],
        );
    }

    // Per RFC 7009 section 2.2: The authorization server responds with HTTP 200
    // whether the token was revoked or not (to prevent token scanning)
    let _ = storage::revoke_access_token(&state.db, &req.token).await;
    let _ = storage::revoke_refresh_token(&state.db, &req.token).await;

    // Return 200 OK with empty response
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

async fn handle_refresh_token_grant(
    state: AppState,
    headers: HeaderMap,
    req: TokenRequest,
) -> Response {
    // Client authentication
    let (client_id, client_secret) = match authenticate_client(&headers, &req) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let client = match storage::get_client(&state.db, &client_id).await {
        Ok(Some(c)) => c,
        _ => {
            return json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_client"}),
                &[(
                    "www-authenticate",
                    "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
                )],
            )
        }
    };
    if client.client_secret != client_secret {
        return json_with_headers(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_client"}),
            &[(
                "www-authenticate",
                "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
            )],
        );
    }

    // Require refresh_token
    let refresh_token_str =
        match req.refresh_token {
            Some(rt) => rt,
            None => return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error":"invalid_request","error_description":"refresh_token required"}),
                ),
            )
                .into_response(),
        };

    // Get and validate refresh token
    let refresh_token =
        match storage::get_refresh_token(&state.db, &refresh_token_str).await {
            Ok(Some(rt)) => rt,
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant","error_description":"invalid refresh_token"})),
            )
                .into_response(),
        };

    // Validate client_id matches
    if refresh_token.client_id != client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    }

    // Issue new access token
    let access = match storage::issue_access_token(
        &state.db,
        &client_id,
        &refresh_token.subject,
        &refresh_token.scope,
        3600,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"server_error","details":e.to_string()})),
            )
                .into_response()
        }
    };

    // Get session to include AMR/ACR claims in ID token
    let session_opt = if let Some(cookie) = SessionCookie::from_headers(&headers) {
        storage::get_session(&state.db, &cookie.session_id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Build ID Token (no nonce, no auth_time for refresh grants)
    let id_token = match build_id_token(
        &state,
        &client_id,
        &refresh_token.subject,
        None,
        None,
        Some(&access.token),
        session_opt.as_ref().and_then(|s| s.amr.as_deref()),
        session_opt.as_ref().and_then(|s| s.acr.as_deref()),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"server_error","details":e.to_string()})),
            )
                .into_response()
        }
    };

    // Rotate refresh token (issue new one and revoke old one)
    let new_refresh_token = match storage::rotate_refresh_token(
        &state.db,
        &refresh_token_str,
        &client_id,
        &refresh_token.subject,
        &refresh_token.scope,
        2592000,
    )
    .await
    {
        Ok(rt) => Some(rt.token),
        Err(_) => None, // Don't fail the whole request if rotation fails
    };

    let resp = TokenResponse {
        access_token: access.token,
        token_type: "bearer".into(),
        expires_in: 3600,
        id_token: Some(id_token),
        refresh_token: new_refresh_token,
    };

    // Add Cache-Control: no-store as required by OAuth 2.0 and OIDC specs
    json_with_headers(
        StatusCode::OK,
        serde_json::to_value(resp).unwrap(),
        &[
            ("cache-control", "no-store".to_string()),
            ("pragma", "no-cache".to_string()),
        ],
    )
}

async fn handle_device_code_grant(
    state: AppState,
    _headers: HeaderMap,
    req: TokenRequest,
) -> Response {
    // Require device_code parameter
    let device_code_str = match req.device_code {
        Some(dc) => dc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "device_code required"
                })),
            )
                .into_response()
        }
    };

    // Require client_id (device flow uses public clients, so no secret required)
    let client_id = match req.client_id {
        Some(cid) => cid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "client_id required"
                })),
            )
                .into_response()
        }
    };

    // Get device code
    let device_code = match storage::get_device_code(&state.db, &device_code_str).await {
        Ok(Some(dc)) => dc,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "device_code not found or expired"
                })),
            )
                .into_response()
        }
    };

    // Verify device_code bound to same client_id
    if device_code.client_id != client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "device_code not bound to this client"
            })),
        )
            .into_response();
    }

    // Rate limiting: check if polling too fast
    if let Some(last_poll) = device_code.last_poll_at {
        let now = chrono::Utc::now().timestamp();
        let elapsed = now - last_poll;

        if elapsed < device_code.interval {
            // Polling too fast - increment interval and return slow_down
            let _ = storage::increment_device_code_interval(&state.db, &device_code_str).await;

            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "slow_down",
                    "error_description": "Polling too frequently"
                })),
            )
                .into_response();
        }
    }

    // Update last_poll_at
    let _ = storage::update_device_code_poll(&state.db, &device_code_str).await;

    // Check status
    match device_code.status.as_str() {
        "pending" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "authorization_pending",
                    "error_description": "User has not yet authorized the device"
                })),
            )
                .into_response()
        }
        "denied" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "access_denied",
                    "error_description": "User denied the authorization request"
                })),
            )
                .into_response()
        }
        "consumed" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "device_code already used"
                })),
            )
                .into_response()
        }
        "approved" => {
            // Continue to token issuance
        }
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Unknown device_code status"
                })),
            )
                .into_response()
        }
    }

    // Consume device code
    let consumed_device_code = match storage::consume_device_code(&state.db, &device_code_str).await
    {
        Ok(Some(dc)) => dc,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "Failed to consume device_code"
                })),
            )
                .into_response()
        }
    };

    let subject = consumed_device_code.subject.unwrap();

    // Issue access token
    let access = match storage::issue_access_token(
        &state.db,
        &client_id,
        &subject,
        &consumed_device_code.scope,
        3600,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "details": e.to_string()
                })),
            )
                .into_response()
        }
    };

    // Build ID Token with profile claims
    let id_token = match build_id_token(
        &state,
        &client_id,
        &subject,
        None, // No nonce for device flow
        consumed_device_code.auth_time,
        Some(&access.token),
        consumed_device_code.amr.as_deref(),
        consumed_device_code.acr.as_deref(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "details": e.to_string()
                })),
            )
                .into_response()
        }
    };

    // Issue refresh token if offline_access scope requested
    let refresh_token_opt = if consumed_device_code
        .scope
        .split_whitespace()
        .any(|s| s == "offline_access")
    {
        match storage::issue_refresh_token(
            &state.db,
            &client_id,
            &subject,
            &consumed_device_code.scope,
            2592000, // 30 days
            None,    // No parent token for device flow
        )
        .await
        {
            Ok(rt) => Some(rt.token),
            Err(_) => None,
        }
    } else {
        None
    };

    let resp = TokenResponse {
        access_token: access.token,
        token_type: "bearer".into(),
        expires_in: 3600,
        id_token: Some(id_token),
        refresh_token: refresh_token_opt,
    };

    // Add Cache-Control: no-store as required by OAuth 2.0 and OIDC specs
    json_with_headers(
        StatusCode::OK,
        serde_json::to_value(resp).unwrap(),
        &[
            ("cache-control", "no-store".to_string()),
            ("pragma", "no-cache".to_string()),
        ],
    )
}

fn authenticate_client(
    headers: &HeaderMap,
    req: &TokenRequest,
) -> Result<(String, String), Response> {
    // Try client_secret_basic first (Authorization header)
    let mut basic_client: Option<(String, String)> = None;
    if let Some(auth_val) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Some(b64) = auth_val.strip_prefix("Basic ") {
            if let Ok(mut decoded) = Base64::decode_vec(b64) {
                if let Ok(s) = String::from_utf8(std::mem::take(&mut decoded)) {
                    if let Some((id, sec)) = s.split_once(':') {
                        basic_client = Some((id.to_string(), sec.to_string()));
                    }
                }
            }
        }
    }

    if let Some(pair) = basic_client {
        Ok(pair)
    } else {
        // Try client_secret_post (form body)
        match (req.client_id.clone(), req.client_secret.clone()) {
            (Some(id), Some(sec)) => Ok((id, sec)),
            _ => Err(json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_client","error_description":"missing client authentication"}),
                &[(
                    "www-authenticate",
                    "Basic realm=\"token\", error=\"invalid_client\"".to_string(),
                )],
            )),
        }
    }
}

async fn userinfo(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Extract bearer token
    let token_opt = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let token = match token_opt {
        Some(t) => t,
        None => {
            return json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_token"}),
                &[(
                    "www-authenticate",
                    "Bearer realm=\"userinfo\", error=\"invalid_token\"".to_string(),
                )],
            )
        }
    };
    let token_row = match storage::get_access_token(&state.db, &token).await {
        Ok(Some(t)) => t,
        _ => {
            return json_with_headers(
                StatusCode::UNAUTHORIZED,
                json!({"error":"invalid_token"}),
                &[(
                    "www-authenticate",
                    "Bearer realm=\"userinfo\", error=\"invalid_token\"".to_string(),
                )],
            )
        }
    };
    let mut claims = serde_json::Map::new();
    claims.insert(
        "sub".to_string(),
        serde_json::Value::String(token_row.subject.clone()),
    );
    // Optional: email claims from properties
    if let Ok(Some(email)) = storage::get_property(&state.db, &token_row.subject, "email").await {
        if let Some(email_str) = email.as_str() {
            claims.insert(
                "email".to_string(),
                serde_json::Value::String(email_str.to_string()),
            );
        }
    }
    if let Ok(Some(verified)) =
        storage::get_property(&state.db, &token_row.subject, "email_verified").await
    {
        claims.insert("email_verified".to_string(), verified);
    }
    (StatusCode::OK, Json(serde_json::Value::Object(claims))).into_response()
}

#[derive(Debug, Deserialize)]
struct RegistrationRequest {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RegistrationResponse {
    client_id: String,
    client_secret: String,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    client_id_issued_at: i64,
    token_endpoint_auth_method: String,
}

async fn register_client(
    State(state): State<AppState>,
    Json(req): Json<RegistrationRequest>,
) -> impl IntoResponse {
    if req.redirect_uris.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_client_metadata", "error_description": "redirect_uris required"}))).into_response();
    }
    let input = storage::NewClient {
        client_name: req.client_name.clone(),
        redirect_uris: req.redirect_uris.clone(),
    };
    match storage::create_client(&state.db, input).await {
        Ok(client) => {
            let resp = RegistrationResponse {
                client_id: client.client_id,
                client_secret: client.client_secret,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                client_id_issued_at: client.created_at,
                token_endpoint_auth_method: "client_secret_post".into(),
            };
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(resp).unwrap()),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_property(
    State(state): State<AppState>,
    Path((owner, key)): Path<(String, String)>,
) -> impl IntoResponse {
    match storage::get_property(&state.db, &owner, &key).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn set_property(
    State(state): State<AppState>,
    Path((owner, key)): Path<(String, String)>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Extract bearer token
    let token_opt = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let token = match token_opt {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"error": "missing_token", "error_description": "Bearer token required"}),
                ),
            )
                .into_response();
        }
    };

    // Validate token and get subject
    let token_row = match storage::get_access_token(&state.db, &token).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid_token", "error_description": "Invalid or expired token"})),
            )
                .into_response();
        }
    };

    // Check if the authenticated user is trying to set their own property
    if token_row.subject != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "error_description": "You can only set your own properties"
            })),
        )
            .into_response();
    }

    // Extract JSON body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_body", "error_description": e.to_string()})),
            )
                .into_response();
        }
    };

    let v: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_json", "error_description": e.to_string()})),
            )
                .into_response();
        }
    };

    // Set the property
    match storage::set_property(&state.db, &owner, &key, &v).await {
        Ok(_) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "internal_error", "error_description": e.to_string()})),
        )
            .into_response(),
    }
}

async fn trust_anchors(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({ "trust_anchors": state.settings.federation.trust_anchors }))
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
    error: Option<String>,
}

async fn login_page(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let error_html = if let Some(err) = q.error {
        format!("<p style='color: red;'>{}</p>", html_escape(&err))
    } else {
        String::new()
    };

    let return_to = q.return_to.unwrap_or_default();

    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - Barycenter OpenID Provider</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
                h1 {{ color: #333; }}
                label {{ display: block; margin-top: 10px; }}
                input[type="text"], input[type="password"] {{ width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; }}
                button {{ margin-top: 20px; padding: 10px 20px; background-color: #007bff; color: white; border: none; cursor: pointer; }}
                button:hover {{ background-color: #0056b3; }}
                .divider {{ margin: 30px 0; text-align: center; color: #666; }}
                .divider::before, .divider::after {{ content: ""; display: inline-block; width: 40%; height: 1px; background: #ccc; vertical-align: middle; }}
                .divider::before {{ margin-right: 10px; }}
                .divider::after {{ margin-left: 10px; }}
                #passkey-status {{ margin: 10px 0; padding: 10px; background: #e7f3ff; border-left: 4px solid #007bff; display: none; }}
            </style>
            <script type="module">
                import init, {{
                    supports_webauthn,
                    supports_conditional_ui,
                    authenticate_passkey
                }} from '/static/wasm/barycenter_webauthn_client.js';

                async function setupConditionalUI() {{
                    try {{
                        await init();

                        if (!supports_webauthn()) {{
                            console.log('WebAuthn not supported');
                            return;
                        }}

                        const statusDiv = document.getElementById('passkey-status');
                        const usernameInput = document.getElementById('username');

                        if (await supports_conditional_ui()) {{
                            statusDiv.textContent = 'Passkey autofill available';
                            statusDiv.style.display = 'block';

                            // Enable autocomplete for conditional UI
                            usernameInput.setAttribute('autocomplete', 'username webauthn');

                            // Fetch challenge for conditional UI
                            const resp = await fetch('/webauthn/authenticate/start', {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }},
                                body: JSON.stringify({{}})
                            }});

                            if (!resp.ok) {{
                                console.error('Failed to start passkey auth');
                                return;
                            }}

                            const data = await resp.json();

                            // Start conditional UI (non-blocking)
                            authenticate_passkey(
                                JSON.stringify(data.options),
                                'conditional'
                            ).then(async credentialJson => {{
                                const credential = JSON.parse(credentialJson);

                                // Send to server
                                const finishResp = await fetch('/webauthn/authenticate/finish', {{
                                    method: 'POST',
                                    headers: {{ 'Content-Type': 'application/json' }},
                                    body: JSON.stringify({{
                                        credential: credential,
                                        return_to: '{return_to}'
                                    }})
                                }});

                                if (finishResp.ok) {{
                                    const result = await finishResp.json();
                                    window.location.href = result.redirect_to || '/';
                                }} else {{
                                    const error = await finishResp.text();
                                    console.error('Passkey auth failed:', error);
                                }}
                            }}).catch(err => {{
                                // User cancelled or error - this is fine, don't show error
                                console.log('Passkey auth cancelled or failed:', err);
                            }});
                        }} else {{
                            statusDiv.textContent = 'Passkey login available (click username field)';
                            statusDiv.style.display = 'block';
                        }}
                    }} catch (err) {{
                        console.error('WASM initialization error:', err);
                    }}
                }}

                setupConditionalUI();
            </script>
        </head>
        <body>
            <h1>Login</h1>
            {error_html}
            <div id="passkey-status"></div>
            <form method="POST" action="/login">
                <input type="hidden" name="return_to" value="{return_to}">
                <label>
                    Username:
                    <input type="text" id="username" name="username" required autofocus>
                </label>
                <div class="divider">or sign in with password</div>
                <label>
                    Password:
                    <input type="password" name="password">
                </label>
                <button type="submit">Login with Password</button>
            </form>
        </body>
        </html>
    "#
    );

    Html(html)
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    email: Option<String>,
}

async fn register_user(
    State(state): State<AppState>,
    Form(form): Form<RegisterForm>,
) -> impl IntoResponse {
    // Create the user
    match storage::create_user(&state.db, &form.username, &form.password, form.email).await {
        Ok(_) => {
            // Return success response
            Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::from("User created"))
                .unwrap()
                .into_response()
        }
        Err(e) => {
            // Return error response
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Failed to create user: {}", e)))
                .unwrap()
                .into_response()
        }
    }
}

async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    // Verify credentials
    let subject =
        match storage::verify_user_password(&state.db, &form.username, &form.password).await {
            Ok(Some(sub)) => sub,
            _ => {
                // Redirect back to login with error
                let return_to = urlencoded(&form.return_to.unwrap_or_default());
                let error = urlencoded("Invalid username or password");
                return Redirect::temporary(&format!("/login?error={error}&return_to={return_to}"))
                    .into_response();
            }
        };

    // Check if user requires 2FA
    let user = match storage::get_user_by_subject(&state.db, &subject).await {
        Ok(Some(u)) => u,
        _ => {
            let return_to = urlencoded(&form.return_to.unwrap_or_default());
            let error = urlencoded("User not found");
            return Redirect::temporary(&format!("/login?error={error}&return_to={return_to}"))
                .into_response();
        }
    };

    // Create session
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    let now = chrono::Utc::now().timestamp();
    let session =
        match storage::create_session(&state.db, &subject, now, 3600, user_agent, None).await {
            Ok(s) => s,
            Err(_) => {
                let return_to = urlencoded(&form.return_to.unwrap_or_default());
                let error = urlencoded("Failed to create session");
                return Redirect::temporary(&format!("/login?error={error}&return_to={return_to}"))
                    .into_response();
            }
        };

    // Set cookie
    let cookie = SessionCookie::new(session.session_id);
    let cookie_header = cookie.to_cookie_header(&state.settings);

    // If user requires 2FA, redirect to 2FA page with partial session
    let redirect_url = if user.requires_2fa == 1 {
        // Partial session - redirect to 2FA
        let return_to = urlencoded(&form.return_to.unwrap_or_default());
        format!("/login/2fa?return_to={return_to}")
    } else {
        // Full session - redirect to destination
        form.return_to.unwrap_or_else(|| "/".to_string())
    };

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(axum::http::header::SET_COOKIE, cookie_header)
        .header(axum::http::header::LOCATION, redirect_url)
        .body(Body::empty())
        .unwrap()
        .into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(cookie) = SessionCookie::from_headers(&headers) {
        let _ = storage::delete_session(&state.db, &cookie.session_id).await;
    }

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            axum::http::header::SET_COOKIE,
            SessionCookie::delete_cookie_header(),
        )
        .header(axum::http::header::LOCATION, "/")
        .body(Body::empty())
        .unwrap()
        .into_response()
}

/// GET /login/2fa - Show 2FA page
async fn login_2fa_page(
    State(_state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    // Verify user has a partial session
    let _cookie = match SessionCookie::from_headers(&headers) {
        Some(c) => c,
        None => {
            // No session - redirect to login
            let return_to = urlencoded(&q.return_to.unwrap_or_default());
            return Redirect::temporary(&format!("/login?return_to={return_to}")).into_response();
        }
    };

    let return_to = q.return_to.unwrap_or_else(|| "/".to_string());
    let return_to_escaped = html_escape(&return_to);
    let error_html = q
        .error
        .as_ref()
        .map(|e| format!(r#"<p style="color: red;">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Two-Factor Authentication</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
        h1 {{ font-size: 24px; margin-bottom: 10px; }}
        p {{ color: #666; margin-bottom: 30px; }}
        .error {{ color: red; }}
        button {{
            background: #007bff;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
        }}
        button:hover {{ background: #0056b3; }}
        #status {{ margin-top: 20px; color: #666; }}
    </style>
</head>
<body>
    <h1>Two-Factor Authentication</h1>
    <p>Please use your security key or passkey to complete sign-in.</p>
    {error_html}
    <button id="verifyBtn">Verify with Passkey</button>
    <div id="status"></div>
    <input type="hidden" id="returnTo" value="{return_to_escaped}">

    <script>
        document.getElementById('verifyBtn').addEventListener('click', async () => {{
            const status = document.getElementById('status');
            const returnTo = document.getElementById('returnTo').value;

            try {{
                status.textContent = 'Starting 2FA verification...';

                // Start 2FA challenge
                const startResp = await fetch('/webauthn/2fa/start', {{ method: 'POST' }});
                if (!startResp.ok) {{
                    throw new Error('Failed to start 2FA: ' + await startResp.text());
                }}

                const {{ options }} = await startResp.json();
                status.textContent = 'Waiting for passkey...';

                // Get credential from authenticator
                const credential = await navigator.credentials.get({{ publicKey: options.publicKey }});

                status.textContent = 'Verifying...';

                // Complete 2FA
                const finishResp = await fetch('/webauthn/2fa/finish', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ credential }})
                }});

                if (finishResp.ok) {{
                    status.textContent = 'Success! Redirecting...';
                    window.location.href = returnTo || '/';
                }} else {{
                    const error = await finishResp.text();
                    status.textContent = 'Verification failed: ' + error;
                }}
            }} catch (err) {{
                status.textContent = 'Error: ' + err.message;
                console.error(err);
            }}
        }});
    </script>
</body>
</html>"#,
        error_html = error_html,
        return_to_escaped = return_to_escaped
    ))
    .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn urlencoded(s: &str) -> String {
    serde_urlencoded::to_string([("", s)])
        .unwrap_or_default()
        .trim_start_matches('=')
        .to_string()
}

// ============================================================================
// WebAuthn / Passkey Endpoints
// ============================================================================

use webauthn_rs::prelude::*;

// Request/Response types for passkey registration

#[derive(Debug, Deserialize)]
struct PasskeyRegisterStartRequest {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct PasskeyRegisterStartResponse {
    options: CreationChallengeResponse,
}

#[derive(Debug, Deserialize)]
struct PasskeyRegisterFinishRequest {
    credential: RegisterPublicKeyCredential,
    name: Option<String>, // Friendly name for the passkey
}

#[derive(Debug, Serialize)]
struct PasskeyRegisterFinishResponse {
    verified: bool,
    credential_id: String,
}

// Request/Response types for passkey authentication

#[derive(Debug, Deserialize)]
struct PasskeyAuthStartRequest {
    username: Option<String>,
}

#[derive(Debug, Serialize)]
struct PasskeyAuthStartResponse {
    options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize)]
struct PasskeyAuthFinishRequest {
    credential: PublicKeyCredential,
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct PasskeyAuthFinishResponse {
    success: bool,
    redirect_url: Option<String>,
}

// Request/Response types for passkey management

#[derive(Debug, Serialize)]
struct PasskeyInfo {
    credential_id: String,
    name: Option<String>,
    created_at: i64,
    last_used_at: Option<i64>,
    backup_state: i64,
}

#[derive(Debug, Deserialize)]
struct UpdatePasskeyRequest {
    name: Option<String>,
}

/// POST /webauthn/register/start
/// Start passkey registration flow - requires valid session
async fn passkey_register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<PasskeyRegisterStartRequest>,
) -> Result<Json<PasskeyRegisterStartResponse>, (StatusCode, String)> {
    // Get session from cookie
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Get user info
    let user = storage::get_user_by_subject(&state.db, &session.subject)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Start passkey registration
    let user_id = uuid::Uuid::parse_str(&session.subject).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid subject UUID: {}", e),
        )
    })?;

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user.username, &user.username)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Store challenge
    let challenge_b64 = Base64UrlUnpadded::encode_string(&ccr.public_key.challenge);
    let options_json = serde_json::to_string(&reg_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    storage::create_webauthn_challenge(
        &state.db,
        &challenge_b64,
        Some(&session.subject),
        None,
        "registration",
        &options_json,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PasskeyRegisterStartResponse { options: ccr }))
}

/// POST /webauthn/register/finish
/// Complete passkey registration - requires valid session
async fn passkey_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<Json<PasskeyRegisterFinishResponse>, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Get the most recent registration challenge for this subject
    let challenge_data = storage::get_latest_webauthn_challenge_by_subject(
        &state.db,
        &session.subject,
        "registration",
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((
        StatusCode::BAD_REQUEST,
        "No registration challenge found or expired".to_string(),
    ))?;

    // Verify it's a registration challenge for this user
    if challenge_data.challenge_type != "registration" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid challenge type".to_string(),
        ));
    }
    if challenge_data.subject.as_ref() != Some(&session.subject) {
        return Err((
            StatusCode::FORBIDDEN,
            "Challenge subject mismatch".to_string(),
        ));
    }

    // Deserialize registration state
    let reg_state: PasskeyRegistration = serde_json::from_str(&challenge_data.options_json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid state: {}", e),
            )
        })?;

    // Finish registration
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Registration failed: {}", e),
            )
        })?;

    // Serialize the entire Passkey object for storage
    let passkey_json = serde_json::to_string(&passkey).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize passkey: {}", e),
        )
    })?;

    // Parse serialized passkey to extract fields (cred is private, use JSON introspection)
    let passkey_data: serde_json::Value = serde_json::from_str(&passkey_json).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse passkey JSON: {}", e),
        )
    })?;

    // Extract counter from cred.counter
    let counter = passkey_data
        .get("cred")
        .and_then(|c| c.get("counter"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0) as i64;

    // Extract backup flags from cred
    let backup_eligible = passkey_data
        .get("cred")
        .and_then(|c| c.get("backup_eligible"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    let backup_state = passkey_data
        .get("cred")
        .and_then(|c| c.get("backup_state"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    // Use credential ID from the request
    let cred_id_b64 = Base64UrlUnpadded::encode_string(req.credential.id.as_bytes());

    storage::create_passkey(
        &state.db,
        &cred_id_b64,
        &session.subject,
        &passkey_json,
        counter,             // Extracted from passkey
        None,                // aaguid
        backup_eligible,     // Extracted from passkey
        backup_state,        // Extracted from passkey
        None,                // transports
        req.name.as_deref(), // Name from request
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete challenge
    storage::delete_webauthn_challenge(&state.db, &challenge_data.challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PasskeyRegisterFinishResponse {
        verified: true,
        credential_id: cred_id_b64,
    }))
}

/// POST /webauthn/authenticate/start
/// Start passkey authentication flow - public endpoint
async fn passkey_auth_start(
    State(state): State<AppState>,
    Json(req): Json<PasskeyAuthStartRequest>,
) -> Result<Json<PasskeyAuthStartResponse>, (StatusCode, String)> {
    // If username provided, get their passkeys; otherwise allow discoverable
    let passkeys = if let Some(username) = &req.username {
        let user = storage::get_user_by_username(&state.db, username)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

        let db_passkeys = storage::get_passkeys_by_subject(&state.db, &user.subject)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if db_passkeys.is_empty() {
            return Err((StatusCode::NOT_FOUND, "No passkeys registered".to_string()));
        }

        // Convert to webauthn-rs Passkey format
        // TODO: This requires understanding the exact Passkey structure
        // For now, we'll deserialize the entire Passkey object that we stored
        db_passkeys
            .into_iter()
            .filter_map(|pk| {
                // Deserialize the entire Passkey from JSON
                serde_json::from_str::<Passkey>(&pk.public_key_cose).ok()
            })
            .collect()
    } else {
        // Discoverable/resident key flow - empty list allows any registered credential
        Vec::new()
    };

    // Start authentication
    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Store challenge
    let challenge_b64 = Base64UrlUnpadded::encode_string(&rcr.public_key.challenge);
    let options_json = serde_json::to_string(&auth_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Get subject from earlier lookup if username was provided
    let subject = if let Some(username) = &req.username {
        storage::get_user_by_username(&state.db, username)
            .await
            .ok()
            .flatten()
            .map(|u| u.subject)
    } else {
        None
    };

    storage::create_webauthn_challenge(
        &state.db,
        &challenge_b64,
        subject.as_deref(),
        None,
        "authentication",
        &options_json,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PasskeyAuthStartResponse { options: rcr }))
}

/// POST /webauthn/authenticate/finish
/// Complete passkey authentication - creates session
async fn passkey_auth_finish(
    State(state): State<AppState>,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Get passkey by credential ID to find the subject
    let cred_id_b64 = Base64UrlUnpadded::encode_string(req.credential.id.as_bytes());
    let passkey = storage::get_passkey_by_credential_id(&state.db, &cred_id_b64)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Passkey not found".to_string()))?;

    // Get the most recent authentication challenge for this subject
    let challenge_data = storage::get_latest_webauthn_challenge_by_subject(
        &state.db,
        &passkey.subject,
        "authentication",
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((
        StatusCode::BAD_REQUEST,
        "No authentication challenge found or expired".to_string(),
    ))?;

    // Deserialize auth state
    let auth_state: PasskeyAuthentication = serde_json::from_str(&challenge_data.options_json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid state: {}", e),
            )
        })?;

    // Finish authentication
    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("Authentication failed: {}", e),
            )
        })?;

    // Extract counter using public API (AuthenticationResult has accessor methods)
    let new_counter = auth_result.counter() as i64;

    // Update counter for clone detection
    storage::update_passkey_counter(&state.db, &cred_id_b64, new_counter)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Determine AMR based on backup state
    let amr = if passkey.backup_eligible == 1 && passkey.backup_state == 1 {
        vec!["swk".to_string()] // Software key (cloud synced)
    } else {
        vec!["hwk".to_string()] // Hardware key
    };

    // Create session
    let now = chrono::Utc::now().timestamp();
    let session = storage::create_session(&state.db, &passkey.subject, now, 3600, None, None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update session with passkey AMR
    let amr_json = serde_json::to_string(&amr)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    storage::update_session_auth_context(
        &state.db,
        &session.session_id,
        Some(&amr_json),
        Some("aal1"),
        Some(false),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete challenge
    storage::delete_webauthn_challenge(&state.db, &challenge_data.challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Set session cookie and redirect
    let cookie = SessionCookie::new(session.session_id);
    let cookie_header = cookie.to_cookie_header(&state.settings);
    let redirect_url = req.return_to.unwrap_or_else(|| "/".to_string());

    Ok(Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(axum::http::header::SET_COOKIE, cookie_header)
        .header(axum::http::header::LOCATION, redirect_url)
        .body(Body::empty())
        .unwrap())
}

/// POST /webauthn/2fa/start
/// Start 2FA step-up with passkey - requires partial session
async fn passkey_2fa_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PasskeyAuthStartResponse>, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Check not already MFA verified
    if session.mfa_verified == 1 {
        return Err((StatusCode::BAD_REQUEST, "Already MFA verified".to_string()));
    }

    // Get user's passkeys
    let db_passkeys = storage::get_passkeys_by_subject(&state.db, &session.subject)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if db_passkeys.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "No passkeys registered for 2FA".to_string(),
        ));
    }

    // Convert to webauthn-rs format
    let passkeys: Vec<Passkey> = db_passkeys
        .into_iter()
        .filter_map(|pk| {
            // Deserialize the entire Passkey from JSON
            serde_json::from_str::<Passkey>(&pk.public_key_cose).ok()
        })
        .collect();

    // Start authentication
    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Store challenge linked to session
    let challenge_b64 = Base64UrlUnpadded::encode_string(&rcr.public_key.challenge);
    let options_json = serde_json::to_string(&auth_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    storage::create_webauthn_challenge(
        &state.db,
        &challenge_b64,
        Some(&session.subject),
        Some(&session.session_id),
        "2fa",
        &options_json,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PasskeyAuthStartResponse { options: rcr }))
}

/// POST /webauthn/2fa/finish
/// Complete 2FA step-up - upgrades session to MFA
async fn passkey_2fa_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Get the most recent 2FA challenge for this subject
    let challenge_data =
        storage::get_latest_webauthn_challenge_by_subject(&state.db, &session.subject, "2fa")
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::BAD_REQUEST,
                "No 2FA challenge found or expired".to_string(),
            ))?;

    // Verify the challenge is for this session
    if challenge_data.session_id.as_ref() != Some(&session.session_id) {
        return Err((
            StatusCode::FORBIDDEN,
            "Challenge session mismatch".to_string(),
        ));
    }

    // Deserialize auth state
    let auth_state: PasskeyAuthentication = serde_json::from_str(&challenge_data.options_json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid state: {}", e),
            )
        })?;

    // Finish authentication
    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("2FA verification failed: {}", e),
            )
        })?;

    // Get passkey by credential ID from request
    let cred_id_b64 = Base64UrlUnpadded::encode_string(req.credential.id.as_bytes());
    let passkey = storage::get_passkey_by_credential_id(&state.db, &cred_id_b64)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Passkey not found".to_string()))?;

    // Extract counter using public API (AuthenticationResult has accessor methods)
    let new_counter = auth_result.counter() as i64;

    // Update counter for clone detection
    storage::update_passkey_counter(&state.db, &cred_id_b64, new_counter)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Append passkey method to AMR
    let amr_method = if passkey.backup_eligible == 1 && passkey.backup_state == 1 {
        "swk"
    } else {
        "hwk"
    };
    storage::append_session_amr(&state.db, &session.session_id, amr_method)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Upgrade session to MFA
    storage::update_session_auth_context(
        &state.db,
        &session.session_id,
        None,
        Some("aal2"),
        Some(true),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete challenge
    storage::delete_webauthn_challenge(&state.db, &challenge_data.challenge)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return success - JavaScript will handle redirect
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"verified":true,"message":"2FA verification successful"}"#,
        ))
        .unwrap())
}

/// GET /account/passkeys
/// List user's registered passkeys
async fn list_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PasskeyInfo>>, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Get passkeys
    let passkeys = storage::get_passkeys_by_subject(&state.db, &session.subject)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let info: Vec<PasskeyInfo> = passkeys
        .into_iter()
        .map(|pk| PasskeyInfo {
            credential_id: pk.credential_id,
            name: pk.name,
            created_at: pk.created_at,
            last_used_at: pk.last_used_at,
            backup_state: pk.backup_state,
        })
        .collect();

    Ok(Json(info))
}

/// DELETE /account/passkeys/{credential_id}
/// Delete a passkey
async fn delete_passkey_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Verify passkey belongs to user
    let passkey = storage::get_passkey_by_credential_id(&state.db, &credential_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Passkey not found".to_string()))?;

    if passkey.subject != session.subject {
        return Err((
            StatusCode::FORBIDDEN,
            "Passkey belongs to another user".to_string(),
        ));
    }

    // Check user has at least one auth method remaining
    let remaining_passkeys = storage::get_passkeys_by_subject(&state.db, &session.subject)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user = storage::get_user_by_subject(&state.db, &session.subject)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    if remaining_passkeys.len() == 1 && user.password_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot delete last auth method".to_string(),
        ));
    }

    // Delete passkey
    storage::delete_passkey(&state.db, &credential_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /account/passkeys/{credential_id}
/// Update passkey name
async fn update_passkey_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<String>,
    Json(req): Json<UpdatePasskeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Get session
    let cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No session".to_string()))?;

    let session = storage::get_session(&state.db, &cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    // Verify passkey belongs to user
    let passkey = storage::get_passkey_by_credential_id(&state.db, &credential_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Passkey not found".to_string()))?;

    if passkey.subject != session.subject {
        return Err((
            StatusCode::FORBIDDEN,
            "Passkey belongs to another user".to_string(),
        ));
    }

    // Update name
    storage::update_passkey_name(&state.db, &credential_id, req.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// ========================================
// Device Authorization Grant (RFC 8628)
// ========================================

#[derive(Deserialize)]
struct DeviceAuthorizationRequest {
    client_id: Option<String>,
    client_name: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

/// POST /device_authorization - RFC 8628 Device Authorization Endpoint
async fn device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> Result<Json<DeviceAuthorizationResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract device info
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("Unknown")
        .to_string();

    let device_info = serde_json::json!({
        "ip_address": ip_address,
        "user_agent": user_agent,
    })
    .to_string();

    // Determine client_id (auto-register if not provided)
    let (client_id, client_secret, client_name, auto_registered) = if let Some(cid) = req.client_id
    {
        // Validate existing client
        let client = storage::get_client(&state.db, &cid).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Database error: {}", e)
                })),
            )
        })?;

        if client.is_none() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Client not found"
                })),
            ));
        }

        let client = client.unwrap();
        (
            client.client_id,
            client.client_secret,
            client.client_name,
            false,
        )
    } else {
        // Auto-register new client
        let new_client_name = req
            .client_name
            .unwrap_or_else(|| "Auto-registered Device".to_string());
        let new_client = storage::NewClient {
            client_name: Some(new_client_name.clone()),
            redirect_uris: vec![], // Device flow doesn't use redirect URIs
        };

        let client = storage::create_client(&state.db, new_client)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": format!("Failed to create client: {}", e)
                    })),
                )
            })?;

        (
            client.client_id,
            client.client_secret,
            Some(new_client_name),
            true,
        )
    };

    // Validate scope (must include "openid" for OIDC)
    let scope = req.scope.unwrap_or_else(|| "openid".to_string());
    if !scope.split_whitespace().any(|s| s == "openid") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_scope",
                "error_description": "Scope must include 'openid'"
            })),
        ));
    }

    // Create device code
    let device_code = storage::create_device_code(
        &state.db,
        &client_id,
        client_name,
        &scope,
        Some(device_info),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": format!("Failed to create device code: {}", e)
            })),
        )
    })?;

    // Build URIs
    let issuer = state.settings.issuer();
    let verification_uri = format!("{}/device", issuer);
    let verification_uri_complete =
        format!("{}/device?user_code={}", issuer, device_code.user_code);

    Ok(Json(DeviceAuthorizationResponse {
        device_code: device_code.device_code,
        user_code: device_code.user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: 1800,
        interval: 5,
        client_id: if auto_registered {
            Some(client_id)
        } else {
            None
        },
        client_secret: if auto_registered {
            Some(client_secret)
        } else {
            None
        },
    }))
}

#[derive(Deserialize)]
struct DevicePageQuery {
    user_code: Option<String>,
}

/// GET /device - Device verification page
async fn device_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DevicePageQuery>,
) -> Result<Html<String>, Redirect> {
    // Check if user has session
    let session_cookie = SessionCookie::from_headers(&headers);
    if let Some(cookie) = session_cookie {
        if let Ok(Some(_session)) = storage::get_session(&state.db, &cookie.session_id).await {
            // User is authenticated, show form
            let prefilled_code = query.user_code.as_deref().unwrap_or("");

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Verification</title>
    <style>
        body {{ font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .container {{ background: #f5f5f5; padding: 30px; border-radius: 8px; }}
        h1 {{ margin-top: 0; }}
        input {{ font-size: 18px; padding: 10px; width: 100%; box-sizing: border-box; margin: 10px 0; text-transform: uppercase; }}
        button {{ background: #007bff; color: white; border: none; padding: 12px 24px; font-size: 16px; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #0056b3; }}
        .instructions {{ background: white; padding: 15px; border-left: 4px solid #007bff; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Verification</h1>
        <div class="instructions">
            <p>Enter the code shown on your device to authorize access.</p>
            <p>Format: <strong>XXXX-XXXX</strong> (8 characters)</p>
        </div>
        <form method="POST" action="/device/verify">
            <input type="text" name="user_code" placeholder="Enter code (e.g., WDJB-MJHT)" value="{}" maxlength="9" pattern="[A-Z]{{4}}-[A-Z]{{4}}" required autofocus>
            <button type="submit">Verify Device</button>
        </form>
    </div>
</body>
</html>"#,
                prefilled_code
            );

            return Ok(Html(html));
        }
    }

    // No session, redirect to login
    let return_to = if let Some(code) = query.user_code {
        format!(
            "/login?return_to={}",
            urlencoding::encode(&format!("/device?user_code={}", code))
        )
    } else {
        "/login?return_to=/device".to_string()
    };

    Err(Redirect::to(&return_to))
}

#[derive(Deserialize)]
struct DeviceVerifyRequest {
    user_code: String,
}

/// POST /device/verify - Verify user code and show consent page
async fn device_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceVerifyRequest>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Require authenticated session
    let session_cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    let _session = storage::get_session(&state.db, &session_cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session not found".to_string()))?;

    // Lookup device code by user_code
    let device_code =
        storage::get_device_code_by_user_code(&state.db, &req.user_code.to_uppercase())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::NOT_FOUND,
                "Device code not found or expired".to_string(),
            ))?;

    // Parse device_info
    let device_info: serde_json::Value =
        serde_json::from_str(device_code.device_info.as_deref().unwrap_or("{}"))
            .unwrap_or(json!({}));

    let ip_address = device_info["ip_address"].as_str().unwrap_or("Unknown");
    let user_agent = device_info["user_agent"].as_str().unwrap_or("Unknown");

    // Render consent page
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Device</title>
    <style>
        body {{ font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .container {{ background: #f5f5f5; padding: 30px; border-radius: 8px; }}
        h1 {{ margin-top: 0; }}
        .device-info {{ background: white; padding: 15px; border-radius: 4px; margin: 20px 0; }}
        .device-info dt {{ font-weight: bold; margin-top: 10px; }}
        .device-info dd {{ margin-left: 0; color: #555; }}
        .code-display {{ background: #007bff; color: white; padding: 15px; text-align: center; font-size: 24px; font-family: monospace; border-radius: 4px; margin: 20px 0; letter-spacing: 2px; }}
        .buttons {{ display: flex; gap: 10px; margin-top: 20px; }}
        button {{ flex: 1; padding: 12px; font-size: 16px; border: none; border-radius: 4px; cursor: pointer; }}
        .approve {{ background: #28a745; color: white; }}
        .approve:hover {{ background: #218838; }}
        .deny {{ background: #dc3545; color: white; }}
        .deny:hover {{ background: #c82333; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Device</h1>
        <div class="warning">
            <strong>Verify this is your device!</strong> Only approve if you recognize the device information below.
        </div>
        <div class="code-display">{}</div>
        <div class="device-info">
            <dl>
                <dt>Client:</dt>
                <dd>{}</dd>
                <dt>Requested Scopes:</dt>
                <dd>{}</dd>
                <dt>IP Address:</dt>
                <dd>{}</dd>
                <dt>User Agent:</dt>
                <dd>{}</dd>
            </dl>
        </div>
        <div class="buttons">
            <form method="POST" action="/device/consent" style="flex: 1;">
                <input type="hidden" name="user_code" value="{}">
                <input type="hidden" name="approved" value="true">
                <button type="submit" class="approve">Approve</button>
            </form>
            <form method="POST" action="/device/consent" style="flex: 1;">
                <input type="hidden" name="user_code" value="{}">
                <input type="hidden" name="approved" value="false">
                <button type="submit" class="deny">Deny</button>
            </form>
        </div>
    </div>
</body>
</html>"#,
        device_code.user_code,
        device_code
            .client_name
            .as_deref()
            .unwrap_or("Unknown Application"),
        device_code.scope,
        ip_address,
        user_agent,
        device_code.user_code,
        device_code.user_code
    );

    Ok(Html(html))
}

#[derive(Deserialize)]
struct DeviceConsentRequest {
    user_code: String,
    #[serde(default)]
    approved: bool,
}

/// POST /device/consent - Handle device authorization approval/denial
async fn device_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceConsentRequest>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Require authenticated session
    let session_cookie = SessionCookie::from_headers(&headers)
        .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    let session = storage::get_session(&state.db, &session_cookie.session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session not found".to_string()))?;

    // Lookup device code by user_code
    let device_code =
        storage::get_device_code_by_user_code(&state.db, &req.user_code.to_uppercase())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::NOT_FOUND,
                "Device code not found or expired".to_string(),
            ))?;

    // TODO: Check 2FA requirements (admin-enforced, high-value scopes, max_age)
    // For now, we'll skip 2FA checks and proceed directly

    if req.approved {
        // Approve the device code
        storage::approve_device_code(
            &state.db,
            &device_code.device_code,
            &session.subject,
            session.auth_time,
            session.amr,
            session.acr,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Show success page
        Ok(Html(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Approved</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { background: #d4edda; border: 1px solid #c3e6cb; padding: 30px; border-radius: 8px; text-align: center; }
        h1 { color: #155724; margin-top: 0; }
        p { color: #155724; font-size: 18px; }
        .checkmark { font-size: 48px; color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Device Approved</h1>
        <p>You can now return to your device and continue.</p>
    </div>
</body>
</html>"#
                .to_string(),
        ))
    } else {
        // Deny the device code
        storage::deny_device_code(&state.db, &device_code.device_code)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Show denial page
        Ok(Html(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Denied</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { background: #f8d7da; border: 1px solid #f5c6cb; padding: 30px; border-radius: 8px; text-align: center; }
        h1 { color: #721c24; margin-top: 0; }
        p { color: #721c24; font-size: 18px; }
        .cross { font-size: 48px; color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="cross">✗</div>
        <h1>Device Access Denied</h1>
        <p>The authorization request has been rejected.</p>
    </div>
</body>
</html>"#
                .to_string(),
        ))
    }
}
