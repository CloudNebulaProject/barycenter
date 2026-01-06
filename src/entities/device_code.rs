use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "device_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub scope: String,
    pub device_info: Option<String>, // JSON: {ip_address, user_agent}
    pub created_at: i64,
    pub expires_at: i64,
    pub last_poll_at: Option<i64>,
    pub interval: i64,
    pub status: String, // "pending" | "approved" | "denied" | "consumed"
    pub subject: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Option<String>, // JSON array: ["pwd", "hwk"]
    pub acr: Option<String>, // "aal1" or "aal2"
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
