use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "passkeys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: String,
    pub subject: String,
    pub public_key_cose: String,
    pub counter: i64,
    pub aaguid: Option<String>,
    pub backup_eligible: i64,
    pub backup_state: i64,
    pub transports: Option<String>,
    pub name: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
