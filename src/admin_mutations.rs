use async_graphql::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, QuerySelect, Set,
};
use std::sync::Arc;

use crate::entities;
use crate::jobs;
use crate::storage;

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

    /// Set 2FA requirement for a user (admin-enforced 2FA)
    async fn set_user_2fa_required(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Username to modify")] username: String,
        #[graphql(desc = "Whether 2FA should be required")] required: bool,
    ) -> Result<User2FAResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        // Get user by username
        let user = storage::get_user_by_username(db.as_ref(), &username)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new(format!("User '{}' not found", username)))?;

        // Update requires_2fa flag
        use crate::entities::user::{Column, Entity};
        let user_entity = Entity::find()
            .filter(Column::Subject.eq(&user.subject))
            .one(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new("User entity not found"))?;

        let mut active: entities::user::ActiveModel = user_entity.into_active_model();
        active.requires_2fa = Set(if required { 1 } else { 0 });

        active
            .update(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Failed to update user: {}", e)))?;

        Ok(User2FAResult {
            success: true,
            message: format!(
                "2FA requirement {} for user '{}'",
                if required { "enabled" } else { "disabled" },
                username
            ),
            username,
            requires_2fa: required,
        })
    }
}

/// Result of triggering a job
#[derive(SimpleObject)]
pub struct JobTriggerResult {
    pub success: bool,
    pub message: String,
    pub job_name: String,
}

/// Result of setting user 2FA requirement
#[derive(SimpleObject)]
pub struct User2FAResult {
    pub success: bool,
    pub message: String,
    pub username: String,
    pub requires_2fa: bool,
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
            JobInfo {
                name: "cleanup_expired_challenges".to_string(),
                description: "Clean up expired WebAuthn challenges".to_string(),
                schedule: "Every 5 minutes".to_string(),
            },
        ])
    }

    /// Get 2FA status for a user
    async fn user_2fa_status(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Username to query")] username: String,
    ) -> Result<User2FAStatus> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        // Get user by username
        let user = storage::get_user_by_username(db.as_ref(), &username)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new(format!("User '{}' not found", username)))?;

        // Get user's passkeys count
        let passkeys = storage::get_passkeys_by_subject(db.as_ref(), &user.subject)
            .await
            .map_err(|e| Error::new(format!("Failed to get passkeys: {}", e)))?;

        Ok(User2FAStatus {
            username,
            subject: user.subject,
            requires_2fa: user.requires_2fa == 1,
            passkey_enrolled: user.passkey_enrolled_at.is_some(),
            passkey_count: passkeys.len() as i32,
            passkey_enrolled_at: user.passkey_enrolled_at,
        })
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

/// User 2FA status information
#[derive(SimpleObject)]
pub struct User2FAStatus {
    pub username: String,
    pub subject: String,
    pub requires_2fa: bool,
    pub passkey_enrolled: bool,
    pub passkey_count: i32,
    pub passkey_enrolled_at: Option<i64>,
}
