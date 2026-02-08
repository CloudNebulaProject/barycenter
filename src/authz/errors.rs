use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use miette::Diagnostic;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum AuthzError {
    #[error("Failed to load policy file `{path}`")]
    #[diagnostic(
        code(barycenter::authz::policy_load),
        help("Check that the file exists and contains valid KDL syntax")
    )]
    PolicyLoadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid policy: {0}")]
    #[diagnostic(
        code(barycenter::authz::invalid_policy),
        help("Each policy file must contain valid `resource`, `role`, `rule`, or `grant` KDL nodes")
    )]
    InvalidPolicy(String),

    #[error("Invalid grant: {0}")]
    #[diagnostic(
        code(barycenter::authz::invalid_grant),
        help("Grant syntax: grant \"relation\" on=\"type/id\" to=\"subject_type/id\" (optionally to=\"type/id#relation\")")
    )]
    InvalidGrant(String),

    #[error("Invalid condition expression: {0}")]
    #[diagnostic(
        code(barycenter::authz::invalid_condition),
        help("Supported operators: ==, !=, >, <, >=, <=, &&, ||, !, in. Paths use dot notation (e.g. request.ip)")
    )]
    InvalidCondition(String),

    #[error("Undefined resource type `{0}`")]
    #[diagnostic(
        code(barycenter::authz::undefined_resource),
        help("Define the resource type with: resource \"<name>\" {{ relations {{ ... }} permissions {{ ... }} }}")
    )]
    UndefinedResourceType(String),

    #[error("Undefined role `{0}`")]
    #[diagnostic(
        code(barycenter::authz::undefined_role),
        help("Define the role with: role \"<name>\" {{ permissions {{ ... }} }}")
    )]
    UndefinedRole(String),

    #[error("Cyclic role inheritance detected: {0}")]
    #[diagnostic(
        code(barycenter::authz::cyclic_roles),
        help("Check the `includes` lists in your role definitions for circular references")
    )]
    CyclicRoleInheritance(String),

    #[error("KDL parse error: {0}")]
    #[diagnostic(
        code(barycenter::authz::kdl_parse),
        help("Check your KDL file syntax — see https://kdl.dev for the specification")
    )]
    KdlParse(String),

    #[error("I/O error: {0}")]
    #[diagnostic(code(barycenter::authz::io))]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AuthzError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AuthzError::InvalidPolicy(_)
            | AuthzError::InvalidGrant(_)
            | AuthzError::InvalidCondition(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        let body = json!({ "error": message });
        (status, Json(body)).into_response()
    }
}
