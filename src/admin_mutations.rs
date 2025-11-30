use async_graphql::*;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use std::sync::Arc;

use crate::jobs;

/// Custom mutations for admin operations
#[derive(Default)]
pub struct AdminMutation;

#[Object]
impl AdminMutation {
    /// Manually trigger a background job by name
    async fn trigger_job(&self, ctx: &Context<'_>, job_name: String) -> Result<JobTriggerResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        match jobs::trigger_job_manually(db.as_ref(), &job_name).await {
            Ok(_) => Ok(JobTriggerResult {
                success: true,
                message: format!("Job '{}' triggered successfully", job_name),
                job_name,
            }),
            Err(e) => Ok(JobTriggerResult {
                success: false,
                message: format!("Failed to trigger job '{}': {}", job_name, e),
                job_name,
            }),
        }
    }
}

/// Result of triggering a job
#[derive(SimpleObject)]
pub struct JobTriggerResult {
    pub success: bool,
    pub message: String,
    pub job_name: String,
}

/// Custom queries for admin operations
#[derive(Default)]
pub struct AdminQuery;

#[Object]
impl AdminQuery {
    /// Get recent job executions with optional filtering
    async fn job_logs(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by job name")] job_name: Option<String>,
        #[graphql(desc = "Limit number of results", default = 100)] limit: i64,
        #[graphql(desc = "Only show failed jobs")] only_failures: Option<bool>,
    ) -> Result<Vec<JobLog>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        use crate::entities::job_execution::{Column, Entity};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let mut query = Entity::find();

        // Filter by job name if provided
        if let Some(name) = job_name {
            query = query.filter(Column::JobName.eq(name));
        }

        // Filter by failures if requested
        if let Some(true) = only_failures {
            query = query.filter(Column::Success.eq(0));
        }

        // Order by most recent first and limit
        let results = query
            .order_by_desc(Column::StartedAt)
            .limit(limit as u64)
            .all(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        Ok(results
            .into_iter()
            .map(|model| JobLog {
                id: model.id,
                job_name: model.job_name,
                started_at: model.started_at,
                completed_at: model.completed_at,
                success: model.success,
                error_message: model.error_message,
                records_processed: model.records_processed,
            })
            .collect())
    }

    /// Get list of available jobs that can be triggered
    async fn available_jobs(&self) -> Result<Vec<JobInfo>> {
        Ok(vec![
            JobInfo {
                name: "cleanup_expired_sessions".to_string(),
                description: "Clean up expired user sessions".to_string(),
                schedule: "Hourly at :00".to_string(),
            },
            JobInfo {
                name: "cleanup_expired_refresh_tokens".to_string(),
                description: "Clean up expired refresh tokens".to_string(),
                schedule: "Hourly at :30".to_string(),
            },
        ])
    }
}

/// Job log entry
#[derive(SimpleObject)]
pub struct JobLog {
    pub id: i64,
    pub job_name: String,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub success: Option<i64>,
    pub error_message: Option<String>,
    pub records_processed: Option<i64>,
}

/// Information about an available job
#[derive(SimpleObject)]
pub struct JobInfo {
    pub name: String,
    pub description: String,
    pub schedule: String,
}
