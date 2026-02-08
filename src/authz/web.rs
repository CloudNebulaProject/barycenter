use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::authz::engine;
use crate::authz::types::{CheckRequest, CheckResponse, ExpandRequest, ExpandResponse};
use crate::authz::AuthzState;

pub fn router(state: Arc<AuthzState>) -> Router {
    Router::new()
        .route("/v1/check", post(handle_check))
        .route("/v1/expand", post(handle_expand))
        .route("/healthz", get(health))
        .with_state(state)
}

async fn handle_check(
    State(state): State<Arc<AuthzState>>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    match engine::check(
        &state,
        &req.principal,
        &req.permission,
        &req.resource,
        &req.context,
    ) {
        Ok(allowed) => Json(CheckResponse { allowed }).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn handle_expand(
    State(state): State<Arc<AuthzState>>,
    Json(req): Json<ExpandRequest>,
) -> impl IntoResponse {
    match engine::expand(&state, &req.permission, &req.resource) {
        Ok(subjects) => Json(ExpandResponse { subjects }).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}
