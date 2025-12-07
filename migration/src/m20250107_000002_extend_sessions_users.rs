use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Extend Sessions table with authentication context fields
        // SQLite requires separate ALTER TABLE statements for each column
        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .add_column(string_null(Sessions::Amr))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .add_column(string_null(Sessions::Acr))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .add_column(
                        ColumnDef::new(Sessions::MfaVerified)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Extend Users table with 2FA and passkey enrollment fields
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::Requires2fa)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(big_integer_null(Users::PasskeyEnrolledAt))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove columns from Users table
        // SQLite requires separate ALTER TABLE statements for each column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PasskeyEnrolledAt)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Requires2fa)
                    .to_owned(),
            )
            .await?;

        // Remove columns from Sessions table
        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .drop_column(Sessions::MfaVerified)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .drop_column(Sessions::Acr)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sessions::Table)
                    .drop_column(Sessions::Amr)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Amr,
    Acr,
    MfaVerified,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    #[sea_orm(iden = "requires_2fa")]
    Requires2fa,
    PasskeyEnrolledAt,
}
