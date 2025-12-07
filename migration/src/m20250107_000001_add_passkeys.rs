use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create passkeys table
        manager
            .create_table(
                Table::create()
                    .table(Passkeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Passkeys::CredentialId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(Passkeys::Subject))
                    .col(string(Passkeys::PublicKeyCose))
                    .col(
                        ColumnDef::new(Passkeys::Counter)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(string_null(Passkeys::Aaguid))
                    .col(big_integer(Passkeys::BackupEligible))
                    .col(big_integer(Passkeys::BackupState))
                    .col(string_null(Passkeys::Transports))
                    .col(string_null(Passkeys::Name))
                    .col(big_integer(Passkeys::CreatedAt))
                    .col(big_integer_null(Passkeys::LastUsedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkeys_subject")
                            .from(Passkeys::Table, Passkeys::Subject)
                            .to(Users::Table, Users::Subject)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on passkeys.subject for lookup
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_passkeys_subject")
                    .table(Passkeys::Table)
                    .col(Passkeys::Subject)
                    .to_owned(),
            )
            .await?;

        // Create webauthn_challenges table
        manager
            .create_table(
                Table::create()
                    .table(WebauthnChallenges::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WebauthnChallenges::Challenge)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string_null(WebauthnChallenges::Subject))
                    .col(string_null(WebauthnChallenges::SessionId))
                    .col(string(WebauthnChallenges::ChallengeType))
                    .col(big_integer(WebauthnChallenges::CreatedAt))
                    .col(big_integer(WebauthnChallenges::ExpiresAt))
                    .col(string(WebauthnChallenges::OptionsJson))
                    .to_owned(),
            )
            .await?;

        // Create index on webauthn_challenges.expires_at for cleanup job
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_webauthn_challenges_expires")
                    .table(WebauthnChallenges::Table)
                    .col(WebauthnChallenges::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebauthnChallenges::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Passkeys::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Passkeys {
    Table,
    CredentialId,
    Subject,
    PublicKeyCose,
    Counter,
    Aaguid,
    BackupEligible,
    BackupState,
    Transports,
    Name,
    CreatedAt,
    LastUsedAt,
}

#[derive(DeriveIden)]
enum WebauthnChallenges {
    Table,
    Challenge,
    Subject,
    SessionId,
    ChallengeType,
    CreatedAt,
    ExpiresAt,
    OptionsJson,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Subject,
}
