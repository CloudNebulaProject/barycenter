use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum CrabError {
    #[error("I/O error: {0}")]
    #[diagnostic(code(crabidp::io))]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    #[diagnostic(code(crabidp::config))]
    Config(#[from] config::ConfigError),

    #[error("Serialization error: {0}")]
    #[diagnostic(code(crabidp::serde))]
    Serde(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    #[diagnostic(code(crabidp::db))]
    Db(#[from] sea_orm::DbErr),

    #[error("JOSE error: {0}")]
    #[diagnostic(code(crabidp::jose))]
    Jose(String),

    #[error("Bad request: {0}")]
    #[diagnostic(code(crabidp::bad_request))]
    BadRequest(String),

    #[error("{0}")]
    #[diagnostic(code(crabidp::other))]
    Other(String),
}

impl From<josekit::JoseError> for CrabError {
    fn from(value: josekit::JoseError) -> Self {
        CrabError::Jose(value.to_string())
    }
}
