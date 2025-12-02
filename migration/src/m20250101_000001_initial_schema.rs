use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Enable foreign keys for SQLite
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA foreign_keys = ON")
                .await?;
        }

        // Create clients table
        manager
            .create_table(
                Table::create()
                    .table(Clients::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Clients::ClientId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(Clients::ClientSecret))
                    .col(string_null(Clients::ClientName))
                    .col(string(Clients::RedirectUris))
                    .col(big_integer(Clients::CreatedAt))
                    .to_owned(),
            )
            .await?;

        // Create properties table
        manager
            .create_table(
                Table::create()
                    .table(Properties::Table)
                    .if_not_exists()
                    .col(string(Properties::Owner))
                    .col(string(Properties::Key))
                    .col(string(Properties::Value))
                    .col(big_integer(Properties::UpdatedAt))
                    .primary_key(Index::create().col(Properties::Owner).col(Properties::Key))
                    .to_owned(),
            )
            .await?;

        // Create auth_codes table
        manager
            .create_table(
                Table::create()
                    .table(AuthCodes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthCodes::Code)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(AuthCodes::ClientId))
                    .col(string(AuthCodes::RedirectUri))
                    .col(string(AuthCodes::Scope))
                    .col(string(AuthCodes::Subject))
                    .col(string_null(AuthCodes::Nonce))
                    .col(string(AuthCodes::CodeChallenge))
                    .col(string(AuthCodes::CodeChallengeMethod))
                    .col(big_integer(AuthCodes::CreatedAt))
                    .col(big_integer(AuthCodes::ExpiresAt))
                    .col(
                        ColumnDef::new(AuthCodes::Consumed)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(big_integer_null(AuthCodes::AuthTime))
                    .to_owned(),
            )
            .await?;

        // Create access_tokens table
        manager
            .create_table(
                Table::create()
                    .table(AccessTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AccessTokens::Token)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(AccessTokens::ClientId))
                    .col(string(AccessTokens::Subject))
                    .col(string(AccessTokens::Scope))
                    .col(big_integer(AccessTokens::CreatedAt))
                    .col(big_integer(AccessTokens::ExpiresAt))
                    .col(
                        ColumnDef::new(AccessTokens::Revoked)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Subject)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Username)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(string(Users::PasswordHash))
                    .col(string_null(Users::Email))
                    .col(
                        ColumnDef::new(Users::EmailVerified)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(big_integer(Users::CreatedAt))
                    .col(
                        ColumnDef::new(Users::Enabled)
                            .big_integer()
                            .not_null()
                            .default(1),
                    )
                    .to_owned(),
            )
            .await?;

        // Create sessions table
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sessions::SessionId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(Sessions::Subject))
                    .col(big_integer(Sessions::AuthTime))
                    .col(big_integer(Sessions::CreatedAt))
                    .col(big_integer(Sessions::ExpiresAt))
                    .col(string_null(Sessions::UserAgent))
                    .col(string_null(Sessions::IpAddress))
                    .to_owned(),
            )
            .await?;

        // Create index on sessions.expires_at
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sessions_expires")
                    .table(Sessions::Table)
                    .col(Sessions::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // Create refresh_tokens table
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshTokens::Token)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(RefreshTokens::ClientId))
                    .col(string(RefreshTokens::Subject))
                    .col(string(RefreshTokens::Scope))
                    .col(big_integer(RefreshTokens::CreatedAt))
                    .col(big_integer(RefreshTokens::ExpiresAt))
                    .col(
                        ColumnDef::new(RefreshTokens::Revoked)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(string_null(RefreshTokens::ParentToken))
                    .to_owned(),
            )
            .await?;

        // Create index on refresh_tokens.expires_at
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_refresh_tokens_expires")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // Create job_executions table with backend-specific ID type
        let id_col = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => ColumnDef::new(JobExecutions::Id)
                .big_integer()
                .not_null()
                .auto_increment()
                .primary_key()
                .to_owned(),
            _ => ColumnDef::new(JobExecutions::Id)
                .integer()
                .not_null()
                .auto_increment()
                .primary_key()
                .to_owned(),
        };

        manager
            .create_table(
                Table::create()
                    .table(JobExecutions::Table)
                    .if_not_exists()
                    .col(id_col)
                    .col(string(JobExecutions::JobName))
                    .col(big_integer(JobExecutions::StartedAt))
                    .col(big_integer_null(JobExecutions::CompletedAt))
                    .col(big_integer_null(JobExecutions::Success))
                    .col(string_null(JobExecutions::ErrorMessage))
                    .col(big_integer_null(JobExecutions::RecordsProcessed))
                    .to_owned(),
            )
            .await?;

        // Create index on job_executions.started_at
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_job_executions_started")
                    .table(JobExecutions::Table)
                    .col(JobExecutions::StartedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(JobExecutions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RefreshTokens::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Sessions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AccessTokens::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AuthCodes::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Properties::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Clients::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Clients {
    Table,
    ClientId,
    ClientSecret,
    ClientName,
    RedirectUris,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Properties {
    Table,
    Owner,
    Key,
    Value,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AuthCodes {
    Table,
    Code,
    ClientId,
    RedirectUri,
    Scope,
    Subject,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    CreatedAt,
    ExpiresAt,
    Consumed,
    AuthTime,
}

#[derive(DeriveIden)]
enum AccessTokens {
    Table,
    Token,
    ClientId,
    Subject,
    Scope,
    CreatedAt,
    ExpiresAt,
    Revoked,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Subject,
    Username,
    PasswordHash,
    Email,
    EmailVerified,
    CreatedAt,
    Enabled,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    SessionId,
    Subject,
    AuthTime,
    CreatedAt,
    ExpiresAt,
    UserAgent,
    IpAddress,
}

#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    Token,
    ClientId,
    Subject,
    Scope,
    CreatedAt,
    ExpiresAt,
    Revoked,
    ParentToken,
}

#[derive(DeriveIden)]
enum JobExecutions {
    Table,
    Id,
    JobName,
    StartedAt,
    CompletedAt,
    Success,
    ErrorMessage,
    RecordsProcessed,
}
