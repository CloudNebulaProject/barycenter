use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.create_table(
            Table::create()
                .table(Resets::Table)
                .col(
                    ColumnDef::new(Resets::Subject)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Resets::TokenHash)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(Resets::Email).string().not_null())
                .col(
                    ColumnDef::new(Resets::PasswordHashAtIssue)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(Resets::ExpiresAt).big_integer().not_null())
                .col(
                    ColumnDef::new(Resets::Consumed)
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .to_owned(),
        )
        .await
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.drop_table(Table::drop().table(Resets::Table).to_owned())
            .await
    }
}
#[derive(DeriveIden)]
enum Resets {
    #[sea_orm(iden = "password_resets")]
    Table,
    Subject,
    TokenHash,
    Email,
    PasswordHashAtIssue,
    ExpiresAt,
    Consumed,
}
