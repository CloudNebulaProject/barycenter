use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum CrabError {
    #[error("I/O error: {0}")]
    #[diagnostic(code(barycenter::io))]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    #[diagnostic(code(barycenter::config))]
    Config(#[from] config::ConfigError),

    #[error("Serialization error: {0}")]
    #[diagnostic(code(barycenter::serde))]
    Serde(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    #[diagnostic(code(barycenter::db))]
    Db(#[from] sea_orm::DbErr),

    #[error("JOSE error: {0}")]
    #[diagnostic(code(barycenter::jose))]
    Jose(String),

    #[error("WebAuthn error: {0}")]
    #[diagnostic(
        code(barycenter::webauthn),
        help("Check passkey configuration and client response format")
    )]
    WebAuthnError(String),

    #[error("Configuration error: {0}")]
    #[diagnostic(
        code(barycenter::configuration),
        help("Check your configuration settings")
    )]
    Configuration(String),

    #[error("Bad request: {0}")]
    #[diagnostic(code(barycenter::bad_request))]
    BadRequest(String),

    #[error("{0}")]
    #[diagnostic(code(barycenter::other))]
    Other(String),
}

impl From<josekit::JoseError> for CrabError {
    fn from(value: josekit::JoseError) -> Self {
        CrabError::Jose(value.to_string())
    }
}
