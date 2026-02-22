use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rename device_code -> device_codes to match the SeaORM entity table_name
        manager
            .rename_table(
                Table::rename()
                    .table(Alias::new("device_code"), Alias::new("device_codes"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(Alias::new("device_codes"), Alias::new("device_code"))
                    .to_owned(),
            )
            .await
    }
}
