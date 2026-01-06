use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create device_codes table for OAuth 2.0 Device Authorization Grant (RFC 8628)
        manager
            .create_table(
                Table::create()
                    .table(DeviceCode::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DeviceCode::DeviceCode)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(DeviceCode::UserCode).string().not_null())
                    .col(ColumnDef::new(DeviceCode::ClientId).string().not_null())
                    .col(ColumnDef::new(DeviceCode::ClientName).string())
                    .col(ColumnDef::new(DeviceCode::Scope).string().not_null())
                    .col(ColumnDef::new(DeviceCode::DeviceInfo).string())
                    .col(
                        ColumnDef::new(DeviceCode::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DeviceCode::ExpiresAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(DeviceCode::LastPollAt).big_integer())
                    .col(
                        ColumnDef::new(DeviceCode::Interval)
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .col(
                        ColumnDef::new(DeviceCode::Status)
                            .string()
                            .not_null()
                            .default("pending"),
                    )
                    .col(ColumnDef::new(DeviceCode::Subject).string())
                    .col(ColumnDef::new(DeviceCode::AuthTime).big_integer())
                    .col(ColumnDef::new(DeviceCode::Amr).string())
                    .col(ColumnDef::new(DeviceCode::Acr).string())
                    .to_owned(),
            )
            .await?;

        // Create index on user_code for fast lookups during verification
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_device_codes_user_code")
                    .table(DeviceCode::Table)
                    .col(DeviceCode::UserCode)
                    .to_owned(),
            )
            .await?;

        // Create index on expires_at for efficient cleanup job
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_device_codes_expires_at")
                    .table(DeviceCode::Table)
                    .col(DeviceCode::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // Create index on status for filtering pending/approved codes
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_device_codes_status")
                    .table(DeviceCode::Table)
                    .col(DeviceCode::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(DeviceCode::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum DeviceCode {
    Table,
    DeviceCode,
    UserCode,
    ClientId,
    ClientName,
    Scope,
    DeviceInfo,
    CreatedAt,
    ExpiresAt,
    LastPollAt,
    Interval,
    Status,
    Subject,
    AuthTime,
    Amr,
    Acr,
}
