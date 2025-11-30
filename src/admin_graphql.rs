use async_graphql::dynamic::Schema as DynamicSchema;
use async_graphql::EmptySubscription;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

use crate::admin_mutations::{AdminMutation, AdminQuery};
use crate::entities;

/// Initialize the Seaography admin GraphQL schema with all entities
pub fn build_seaography_schema(db: DatabaseConnection) -> DynamicSchema {
    use seaography::{Builder, BuilderContext};

    // Create a static BuilderContext for Seaography
    let context: &'static BuilderContext = Box::leak(Box::new(BuilderContext::default()));

    let mut builder = Builder::new(context, db.clone());

    // Register all entities
    builder.register_entity::<entities::user::Entity>(vec![]);
    builder.register_entity::<entities::client::Entity>(vec![]);
    builder.register_entity::<entities::session::Entity>(vec![]);
    builder.register_entity::<entities::access_token::Entity>(vec![]);
    builder.register_entity::<entities::auth_code::Entity>(vec![]);
    builder.register_entity::<entities::refresh_token::Entity>(vec![]);
    builder.register_entity::<entities::property::Entity>(vec![]);
    builder.register_entity::<entities::job_execution::Entity>(vec![]);

    // Build and return the schema
    builder.schema_builder().finish().unwrap()
}

/// Build custom job management GraphQL schema
pub fn build_jobs_schema(
    db: DatabaseConnection,
) -> async_graphql::Schema<AdminQuery, AdminMutation, EmptySubscription> {
    async_graphql::Schema::build(AdminQuery, AdminMutation, EmptySubscription)
        .data(Arc::new(db))
        .finish()
}

#[derive(Clone)]
pub struct SeaographyState {
    pub schema: DynamicSchema,
}

#[derive(Clone)]
pub struct JobsState {
    pub schema: async_graphql::Schema<AdminQuery, AdminMutation, EmptySubscription>,
}

/// Seaography GraphQL POST handler for entity CRUD
async fn seaography_handler(
    State(state): State<Arc<SeaographyState>>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    state.schema.execute(req.into_inner()).await.into()
}

/// Jobs GraphQL POST handler for job management
async fn jobs_handler(
    State(state): State<Arc<JobsState>>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    state.schema.execute(req.into_inner()).await.into()
}

/// Seaography GraphQL playground (GraphiQL) handler
async fn seaography_playground() -> impl IntoResponse {
    axum::response::Html(
        async_graphql::http::GraphiQLSource::build()
            .endpoint("/admin/graphql")
            .finish(),
    )
}

/// Jobs GraphQL playground (GraphiQL) handler
async fn jobs_playground() -> impl IntoResponse {
    axum::response::Html(
        async_graphql::http::GraphiQLSource::build()
            .endpoint("/admin/jobs")
            .finish(),
    )
}

/// Create the admin API router with both Seaography and custom job endpoints
pub fn router(
    seaography_schema: DynamicSchema,
    jobs_schema: async_graphql::Schema<AdminQuery, AdminMutation, EmptySubscription>,
) -> Router {
    let seaography_state = Arc::new(SeaographyState {
        schema: seaography_schema,
    });
    let jobs_state = Arc::new(JobsState {
        schema: jobs_schema,
    });

    Router::new()
        // Seaography entity CRUD
        .route("/admin/graphql", post(seaography_handler))
        .route("/admin/playground", get(seaography_playground))
        .with_state(seaography_state)
        // Custom job management
        .route("/admin/jobs", post(jobs_handler))
        .route("/admin/jobs/playground", get(jobs_playground))
        .with_state(jobs_state)
}
