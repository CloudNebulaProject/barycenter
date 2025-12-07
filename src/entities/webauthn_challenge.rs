use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "webauthn_challenges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub challenge: String,
    pub subject: Option<String>,
    pub session_id: Option<String>,
    pub challenge_type: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub options_json: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
