use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "federation_auth_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub peer_id: String,
    #[sea_orm(unique)]
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub original_authorize_params: String,
    pub original_session_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
