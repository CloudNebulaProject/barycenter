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

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub db: DatabaseConnection,
    pub jwks: JwksManager,
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

    // Content-Security-Policy: Restrict resource loading
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'"),
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
) -> miette::Result<()> {
    let state = AppState {
        settings: Arc::new(settings),
        db,
        jwks,
    };

    // NOTE: Rate limiting should be implemented at the reverse proxy level (nginx, traefik, etc.)
    // for production deployments. This is more efficient and flexible than application-level
    // rate limiting. Configure your reverse proxy with limits like:
    // - Token endpoint: 10 req/min per IP
    // - Login endpoint: 5 attempts/min per IP
    // - Authorize endpoint: 20 req/min per IP

    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/connect/register", post(register_client))
        .route("/properties/{owner}/{key}", get(get_property))
        .route("/federation/trust-anchors", get(trust_anchors))
        .route("/register", post(register_user))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .layer(middleware::from_fn(security_headers))
        .with_state(state.clone());

    let addr: SocketAddr = format!(
        "{}:{}",
        state.settings.server.host, state.settings.server.port
    )
    .parse()
    .map_err(|e| miette::miette!("bad listen addr: {e}"))?;
    tracing::info!(%addr, "listening");
    tracing::warn!("Rate limiting should be configured at the reverse proxy level for production");
    let listener = tokio::net::TcpListener::bind(addr)
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
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
        "registration_endpoint": format!("{}/connect/register", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [state.settings.keys.alg],
        // Additional recommended metadata for better interoperability
        "grant_types_supported": ["authorization_code", "refresh_token", "implicit"],
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

    let (subject, auth_time) = match session_opt {
        Some(sess) if sess.expires_at > chrono::Utc::now().timestamp() && !needs_fresh_auth => {
            (sess.subject.clone(), Some(sess.auth_time))
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

    let scope = q.scope.clone();
    let nonce = q.nonce.clone();

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

// Helper function to build ID token
async fn build_id_token(
    state: &AppState,
    client_id: &str,
    subject: &str,
    nonce: Option<&str>,
    auth_time: Option<i64>,
    access_token: Option<&str>, // For at_hash calculation
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

    // Build ID Token using helper function
    let id_token = match build_id_token(
        &state,
        &client_id,
        &code_row.subject,
        code_row.nonce.as_deref(),
        code_row.auth_time,
        Some(&access.token),
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

    // Build ID Token (no nonce, no auth_time for refresh grants)
    let id_token = match build_id_token(
        &state,
        &client_id,
        &refresh_token.subject,
        None,
        None,
        Some(&access.token),
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
    Json(v): Json<Value>,
) -> impl IntoResponse {
    match storage::set_property(&state.db, &owner, &key, &v).await {
        Ok(_) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
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
            </style>
        </head>
        <body>
            <h1>Login</h1>
            {error_html}
            <form method="POST" action="/login">
                <input type="hidden" name="return_to" value="{return_to}">
                <label>
                    Username:
                    <input type="text" name="username" required autofocus>
                </label>
                <label>
                    Password:
                    <input type="password" name="password" required>
                </label>
                <button type="submit">Login</button>
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

    // Create session
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    let session = match storage::create_session(&state.db, &subject, 3600, user_agent, None).await {
        Ok(s) => s,
        Err(_) => {
            let return_to = urlencoded(&form.return_to.unwrap_or_default());
            let error = urlencoded("Failed to create session");
            return Redirect::temporary(&format!("/login?error={error}&return_to={return_to}"))
                .into_response();
        }
    };

    // Set cookie and redirect
    let cookie = SessionCookie::new(session.session_id);
    let cookie_header = cookie.to_cookie_header(&state.settings);

    let redirect_url = form.return_to.unwrap_or_else(|| "/".to_string());

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
