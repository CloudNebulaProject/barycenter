# Error Handling

Barycenter uses a centralized error type, `CrabError`, combined with miette diagnostics to provide clear, actionable error messages for developers and operators. Client-facing errors follow the OAuth 2.0 error response specification.

## CrabError Enum

The `CrabError` enum is the primary error type used throughout the application. It provides automatic conversion from common error types and can carry diagnostic metadata.

```rust
pub enum CrabError {
    /// SeaORM database errors
    DbErr(sea_orm::DbErr),

    /// File system I/O errors
    IoErr(std::io::Error),

    /// JSON serialization/deserialization errors
    JsonErr(serde_json::Error),

    /// Generic errors with a descriptive message
    Other(String),
}
```

### Automatic Conversions

`CrabError` implements `From` for common error types, allowing the `?` operator to work seamlessly:

```rust
// Database errors are automatically converted
let client = client::Entity::find_by_id(client_id)
    .one(&state.db)
    .await?;  // DbErr -> CrabError::DbErr

// I/O errors are automatically converted
let key_data = std::fs::read_to_string(&key_path)?;  // io::Error -> CrabError::IoErr

// JSON errors are automatically converted
let parsed: Value = serde_json::from_str(&body)?;  // serde_json::Error -> CrabError::JsonErr
```

### The Other Variant

For errors that do not fit the specific variants, `CrabError::Other(String)` provides a catch-all:

```rust
// Using Other for custom error conditions
if scope.is_empty() {
    return Err(CrabError::Other("Scope must not be empty".to_string()));
}
```

## Miette Diagnostics

Barycenter uses [miette](https://docs.rs/miette) to annotate errors with diagnostic information that helps operators understand what went wrong and what to do about it. Miette provides structured error reports with:

- **Error code**: A unique identifier for the error type.
- **Help text**: Actionable guidance on how to resolve the error.
- **Labels**: Source code spans or context pointing to the problematic input.
- **Related errors**: Additional errors that may be relevant.

### Diagnostic Pattern

When creating errors, follow this pattern to provide thorough diagnostics:

```rust
use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Diagnostic, Debug)]
#[error("Failed to load private key from {path}")]
#[diagnostic(
    code(barycenter::jwks::key_load_failed),
    help("Ensure the private key file exists at the configured path and has 600 permissions. \
          The file should contain a JSON-encoded RSA private key. \
          If the file is missing, delete the JWKS file as well and restart to regenerate both.")
)]
pub struct KeyLoadError {
    pub path: String,
    #[source]
    pub source: std::io::Error,
}
```

The `help` text should inform the user exactly what they need to do to resolve the issue. Include specific file paths, permission values, or configuration keys when relevant.

### Diagnostic Guidelines

When writing diagnostic messages:

1. **Be specific**: Instead of "Configuration error", say "Database URL is not a valid connection string".
2. **Be actionable**: Instead of "Key file not found", say "Create the key file at /var/lib/barycenter/private_key.json or set keys.private_key_path in config.toml".
3. **Include context**: Reference the configuration key, file path, or environment variable that needs to change.
4. **Suggest recovery**: If the error is recoverable (e.g., regenerating keys), explain the steps.

## OAuth Error Responses

Client-facing errors in the OAuth and OpenID Connect flows follow the specifications defined in RFC 6749 (OAuth 2.0) and OpenID Connect Core.

### Authorization Endpoint Errors

Errors at the authorization endpoint are communicated by redirecting the user agent back to the client's redirect URI with error parameters:

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback?error=invalid_request&error_description=Missing+code_challenge+parameter&state=abc123
```

The error is appended as query parameters to the redirect URI:

| Parameter | Description |
|-----------|-------------|
| `error` | An error code from the OAuth 2.0 specification |
| `error_description` | A human-readable description of the error |
| `state` | The `state` value from the authorization request (if provided) |

**Common authorization endpoint errors:**

| Error Code | When It Occurs |
|------------|----------------|
| `invalid_request` | Missing required parameter, unsupported parameter value, or malformed request |
| `unauthorized_client` | Client is not authorized for the requested grant type or redirect URI |
| `invalid_scope` | The requested scope is invalid or missing the required `openid` scope |
| `access_denied` | The user denied the authorization request |

**Important**: If the `redirect_uri` or `client_id` is invalid, Barycenter does **not** redirect. Instead, it displays an error page directly, because redirecting to an unvalidated URI would be a security risk (open redirect).

### Token Endpoint Errors

Errors at the token endpoint are returned as JSON in the response body with an appropriate HTTP status code:

```json
{
    "error": "invalid_grant",
    "error_description": "Authorization code has expired"
}
```

| HTTP Status | Error Code | When It Occurs |
|-------------|------------|----------------|
| 400 | `invalid_request` | Missing required parameter or unsupported grant type |
| 400 | `invalid_grant` | Authorization code is expired, consumed, or PKCE verification failed |
| 401 | `invalid_client` | Client authentication failed (bad credentials) |
| 400 | `unsupported_grant_type` | The grant type is not supported |

### UserInfo Endpoint Errors

Errors at the userinfo endpoint use the `WWW-Authenticate` header per RFC 6750 (Bearer Token Usage):

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Access token has expired"
```

## Internal vs. Client-Facing Errors

Barycenter distinguishes between internal errors (for operators) and client-facing errors (for OAuth clients):

| Aspect | Internal Errors | Client-Facing Errors |
|--------|----------------|---------------------|
| Audience | Operators and developers | OAuth clients and end users |
| Detail level | Full stack traces, file paths, configuration details | Generic error codes with safe descriptions |
| Format | Miette diagnostic output to logs | OAuth error response (redirect or JSON) |
| Sensitive info | May include database details, file paths | Never includes internal details |

Internal errors are logged with full diagnostic information. Client-facing errors expose only the OAuth error code and a safe description that does not leak implementation details.

```rust
// Internal: logged with full context
tracing::error!("Failed to verify PKCE: stored_challenge={}, computed={}", stored, computed);

// Client-facing: safe error response
return Ok(Json(TokenErrorResponse {
    error: "invalid_grant".to_string(),
    error_description: Some("PKCE verification failed".to_string()),
}));
```
