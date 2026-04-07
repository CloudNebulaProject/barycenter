use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "trusted_peers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub domain: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub pinned_jwks: Option<String>,
    pub jwks_pin_mode: String,
    pub scopes: String,
    pub mapping_policy: String,
    pub trust_peer_acr: bool,
    pub sync_profile: bool,
    pub status: String,
    pub verification_level: Option<String>,
    pub verified_at: Option<String>,
    pub webfinger_issuer_match: Option<bool>,
    pub last_discovery_refresh: Option<String>,
    pub last_discovery_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
