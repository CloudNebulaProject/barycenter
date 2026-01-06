use crate::entities;
use crate::errors::CrabError;
use crate::storage;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, NotSet,
    QueryFilter, Set,
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

    let db_clone = db.clone();

    // Cleanup expired WebAuthn challenges job - runs every 5 minutes
    let cleanup_challenges_job = Job::new_async("0 */5 * * * *", move |_uuid, _l| {
        let db = db_clone.clone();
        Box::pin(async move {
            info!("Running cleanup_expired_challenges job");
            let execution_id = start_job_execution(&db, "cleanup_expired_challenges")
                .await
                .ok();

            match storage::cleanup_expired_challenges(&db).await {
                Ok(count) => {
                    info!("Cleaned up {} expired WebAuthn challenges", count);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, true, None, Some(count as i64)).await;
                    }
                }
                Err(e) => {
                    error!("Failed to cleanup expired challenges: {}", e);
                    if let Some(id) = execution_id {
                        let _ =
                            complete_job_execution(&db, id, false, Some(e.to_string()), None).await;
                    }
                }
            }
        })
    })
    .map_err(|e| CrabError::Other(format!("Failed to create cleanup challenges job: {}", e)))?;

    sched
        .add(cleanup_challenges_job)
        .await
        .map_err(|e| CrabError::Other(format!("Failed to add cleanup challenges job: {}", e)))?;

    // Start the scheduler
    sched
        .start()
        .await
        .map_err(|e| CrabError::Other(format!("Failed to start job scheduler: {}", e)))?;

    info!("Job scheduler started with {} jobs", 3);

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
        id: NotSet, // Auto-generated by database
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
        "cleanup_expired_challenges" => storage::cleanup_expired_challenges(db).await,
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use tempfile::NamedTempFile;

    /// Test database helper that keeps temp file alive
    struct TestDb {
        connection: DatabaseConnection,
        _temp_file: NamedTempFile,
    }

    impl TestDb {
        async fn new() -> Self {
            let temp_file = NamedTempFile::new().expect("Failed to create temp file");
            let db_path = temp_file.path().to_str().expect("Invalid temp file path");
            let db_url = format!("sqlite://{}?mode=rwc", db_path);

            let connection = Database::connect(&db_url)
                .await
                .expect("Failed to connect to test database");

            migration::Migrator::up(&connection, None)
                .await
                .expect("Failed to run migrations");

            Self {
                connection,
                _temp_file: temp_file,
            }
        }

        fn connection(&self) -> &DatabaseConnection {
            &self.connection
        }
    }

    #[tokio::test]
    async fn test_start_job_execution() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let execution_id = start_job_execution(db, "test_job")
            .await
            .expect("Failed to start job execution");

        assert!(execution_id > 0);

        // Verify record was created
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::Id.eq(execution_id))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert_eq!(execution.job_name, "test_job");
        assert!(execution.started_at > 0);
        assert!(execution.completed_at.is_none());
        assert!(execution.success.is_none());
    }

    #[tokio::test]
    async fn test_complete_job_execution_success() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let execution_id = start_job_execution(db, "test_job")
            .await
            .expect("Failed to start job execution");

        complete_job_execution(db, execution_id, true, None, Some(42))
            .await
            .expect("Failed to complete job execution");

        // Verify record was updated
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::Id.eq(execution_id))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert!(execution.completed_at.is_some());
        assert_eq!(execution.success, Some(1));
        assert_eq!(execution.records_processed, Some(42));
        assert!(execution.error_message.is_none());
    }

    #[tokio::test]
    async fn test_complete_job_execution_failure() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let execution_id = start_job_execution(db, "test_job")
            .await
            .expect("Failed to start job execution");

        complete_job_execution(
            &db,
            execution_id,
            false,
            Some("Test error message".to_string()),
            None,
        )
        .await
        .expect("Failed to complete job execution");

        // Verify record was updated with error
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::Id.eq(execution_id))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert!(execution.completed_at.is_some());
        assert_eq!(execution.success, Some(0));
        assert_eq!(
            execution.error_message,
            Some("Test error message".to_string())
        );
        assert!(execution.records_processed.is_none());
    }

    #[tokio::test]
    async fn test_trigger_job_manually_cleanup_sessions() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        // Create an expired session
        let user = storage::create_user(db, "testuser", "password123", None)
            .await
            .expect("Failed to create user");

        let past_auth_time = Utc::now().timestamp() - 7200; // 2 hours ago
        storage::create_session(db, &user.subject, past_auth_time, 3600, None, None) // 1 hour TTL
            .await
            .expect("Failed to create session");

        // Trigger cleanup job
        trigger_job_manually(db, "cleanup_expired_sessions")
            .await
            .expect("Failed to trigger job");

        // Verify job execution was recorded
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::JobName.eq("cleanup_expired_sessions"))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert_eq!(execution.success, Some(1));
        assert_eq!(execution.records_processed, Some(1)); // Should have cleaned up 1 session
    }

    #[tokio::test]
    async fn test_trigger_job_manually_cleanup_tokens() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        // Trigger cleanup_expired_refresh_tokens job
        trigger_job_manually(db, "cleanup_expired_refresh_tokens")
            .await
            .expect("Failed to trigger job");

        // Verify job execution was recorded
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::JobName.eq("cleanup_expired_refresh_tokens"))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert_eq!(execution.success, Some(1));
    }

    #[tokio::test]
    async fn test_trigger_job_manually_invalid_name() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let result = trigger_job_manually(db, "invalid_job_name").await;

        assert!(result.is_err());
        match result {
            Err(CrabError::Other(msg)) => {
                assert!(msg.contains("Unknown job name"));
            }
            _ => panic!("Expected CrabError::Other"),
        }
    }

    #[tokio::test]
    async fn test_job_execution_records_processed() {
        let test_db = TestDb::new().await;
        let db = test_db.connection();

        let execution_id = start_job_execution(db, "test_job")
            .await
            .expect("Failed to start job execution");

        // Complete with specific record count
        complete_job_execution(db, execution_id, true, None, Some(123))
            .await
            .expect("Failed to complete job execution");

        // Verify records_processed field
        use entities::job_execution::{Column, Entity};
        let execution = Entity::find()
            .filter(Column::Id.eq(execution_id))
            .one(db)
            .await
            .expect("Failed to query job execution")
            .expect("Job execution not found");

        assert_eq!(execution.records_processed, Some(123));
    }
}
