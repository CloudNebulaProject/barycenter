use crate::entities;
use crate::errors::CrabError;
use crate::storage;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    Set,
};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info};

/// Initialize and start the job scheduler with all background tasks
pub async fn init_scheduler(db: DatabaseConnection) -> Result<JobScheduler, CrabError> {
    let sched = JobScheduler::new()
        .await
        .map_err(|e| CrabError::Other(format!("Failed to create job scheduler: {}", e)))?;

    let db_clone = db.clone();

    // Cleanup expired sessions job - runs every hour
    let cleanup_sessions_job = Job::new_async("0 0 * * * *", move |_uuid, _l| {
        let db = db_clone.clone();
        Box::pin(async move {
            info!("Running cleanup_expired_sessions job");
            let execution_id = start_job_execution(&db, "cleanup_expired_sessions")
                .await
                .ok();

            match storage::cleanup_expired_sessions(&db).await {
                Ok(count) => {
                    info!("Cleaned up {} expired sessions", count);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, true, None, Some(count as i64)).await;
                    }
                }
                Err(e) => {
                    error!("Failed to cleanup expired sessions: {}", e);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, false, Some(e.to_string()), None).await;
                    }
                }
            }
        })
    })
    .map_err(|e| CrabError::Other(format!("Failed to create cleanup sessions job: {}", e)))?;

    sched
        .add(cleanup_sessions_job)
        .await
        .map_err(|e| CrabError::Other(format!("Failed to add cleanup sessions job: {}", e)))?;

    let db_clone = db.clone();

    // Cleanup expired refresh tokens job - runs every hour at 30 minutes past
    let cleanup_tokens_job = Job::new_async("0 30 * * * *", move |_uuid, _l| {
        let db = db_clone.clone();
        Box::pin(async move {
            info!("Running cleanup_expired_refresh_tokens job");
            let execution_id = start_job_execution(&db, "cleanup_expired_refresh_tokens")
                .await
                .ok();

            match storage::cleanup_expired_refresh_tokens(&db).await {
                Ok(count) => {
                    info!("Cleaned up {} expired refresh tokens", count);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, true, None, Some(count as i64)).await;
                    }
                }
                Err(e) => {
                    error!("Failed to cleanup expired refresh tokens: {}", e);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, false, Some(e.to_string()), None).await;
                    }
                }
            }
        })
    })
    .map_err(|e| CrabError::Other(format!("Failed to create cleanup tokens job: {}", e)))?;

    sched
        .add(cleanup_tokens_job)
        .await
        .map_err(|e| CrabError::Other(format!("Failed to add cleanup tokens job: {}", e)))?;

    // Start the scheduler
    sched
        .start()
        .await
        .map_err(|e| CrabError::Other(format!("Failed to start job scheduler: {}", e)))?;

    info!("Job scheduler started with {} jobs", 2);

    Ok(sched)
}

/// Record the start of a job execution
pub async fn start_job_execution(
    db: &DatabaseConnection,
    job_name: &str,
) -> Result<i64, CrabError> {
    use entities::job_execution;

    let now = Utc::now().timestamp();

    let execution = job_execution::ActiveModel {
        id: Set(0), // Will be auto-generated
        job_name: Set(job_name.to_string()),
        started_at: Set(now),
        completed_at: Set(None),
        success: Set(None),
        error_message: Set(None),
        records_processed: Set(None),
    };

    let result = execution.insert(db).await?;
    Ok(result.id)
}

/// Record the completion of a job execution
pub async fn complete_job_execution(
    db: &DatabaseConnection,
    execution_id: i64,
    success: bool,
    error_message: Option<String>,
    records_processed: Option<i64>,
) -> Result<(), CrabError> {
    use entities::job_execution::{Column, Entity};

    let now = Utc::now().timestamp();

    if let Some(execution) = Entity::find()
        .filter(Column::Id.eq(execution_id))
        .one(db)
        .await?
    {
        let mut active: entities::job_execution::ActiveModel = execution.into_active_model();
        active.completed_at = Set(Some(now));
        active.success = Set(Some(if success { 1 } else { 0 }));
        active.error_message = Set(error_message);
        active.records_processed = Set(records_processed);
        active.update(db).await?;
    }

    Ok(())
}

/// Manually trigger a job by name (useful for admin API)
pub async fn trigger_job_manually(
    db: &DatabaseConnection,
    job_name: &str,
) -> Result<(), CrabError> {
    info!("Manually triggering job: {}", job_name);
    let execution_id = start_job_execution(db, job_name).await?;

    let result = match job_name {
        "cleanup_expired_sessions" => storage::cleanup_expired_sessions(db).await,
        "cleanup_expired_refresh_tokens" => storage::cleanup_expired_refresh_tokens(db).await,
        _ => {
            return Err(CrabError::Other(format!("Unknown job name: {}", job_name)));
        }
    };

    match result {
        Ok(count) => {
            info!(
                "Manually triggered job {} completed: {} records",
                job_name, count
            );
            complete_job_execution(db, execution_id, true, None, Some(count as i64)).await?;
        }
        Err(e) => {
            error!("Manually triggered job {} failed: {}", job_name, e);
            complete_job_execution(db, execution_id, false, Some(e.to_string()), None).await?;
        }
    }

    Ok(())
}
