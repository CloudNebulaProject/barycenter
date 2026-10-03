use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.create_table(
            Table::create()
                .table(Invitations::Table)
                .col(
                    ColumnDef::new(Invitations::Username)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Invitations::TokenHash)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(Invitations::Email).string().not_null())
                .col(
                    ColumnDef::new(Invitations::ExpiresAt)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Invitations::Consumed)
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .to_owned(),
        )
        .await
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.drop_table(Table::drop().table(Invitations::Table).to_owned())
            .await
    }
}
#[derive(DeriveIden)]
enum Invitations {
    #[sea_orm(iden = "onboarding_invitations")]
    Table,
    Username,
    TokenHash,
    Email,
    ExpiresAt,
    Consumed,
}
