use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
// Keep this aligned with `Consent::Table` in the existing consent migration,
// which created the table as the singular `consent`.
#[sea_orm(table_name = "consent")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub client_id: String,
    pub subject: String,
    pub scope: String,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
