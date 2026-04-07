use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS peer_requests (
                id TEXT PRIMARY KEY,
                requesting_issuer TEXT NOT NULL,
                requesting_domain TEXT NOT NULL,
                client_id_at_us TEXT NOT NULL,
                callback_endpoint TEXT NOT NULL,
                request_jws TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_approval',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                expires_at TEXT NOT NULL
            )",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared("DROP TABLE IF EXISTS peer_requests")
            .await?;

        Ok(())
    }
}
