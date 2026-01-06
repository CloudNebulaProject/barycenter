use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create consents table
        manager
            .create_table(
                Table::create()
                    .table(Consent::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Consent::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Consent::ClientId).string().not_null())
                    .col(ColumnDef::new(Consent::Subject).string().not_null())
                    .col(ColumnDef::new(Consent::Scope).string().not_null())
                    .col(ColumnDef::new(Consent::GrantedAt).big_integer().not_null())
                    .col(ColumnDef::new(Consent::ExpiresAt).big_integer())
                    .col(
                        ColumnDef::new(Consent::Revoked)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on client_id + subject for fast lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_consent_client_subject")
                    .table(Consent::Table)
                    .col(Consent::ClientId)
                    .col(Consent::Subject)
                    .to_owned(),
            )
            .await?;

        // Create index on subject for user consent lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_consent_subject")
                    .table(Consent::Table)
                    .col(Consent::Subject)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Consent::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Consent {
    Table,
    Id,
    ClientId,
    Subject,
    Scope,
    GrantedAt,
    ExpiresAt,
    Revoked,
}
