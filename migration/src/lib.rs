pub use sea_orm_migration::prelude::*;

mod m20250101_000001_initial_schema;
mod m20250107_000001_add_passkeys;
mod m20250107_000002_extend_sessions_users;
mod m20250108_000001_add_consent_table;
mod m20250109_000001_add_device_codes;
mod m20250222_000001_rename_device_code_table;
mod m20260407_000001_create_federation_tables;
mod m20260407_000002_create_peer_requests;

mod m20261003_000001_onboarding_invitations;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250101_000001_initial_schema::Migration),
            Box::new(m20250107_000001_add_passkeys::Migration),
            Box::new(m20250107_000002_extend_sessions_users::Migration),
            Box::new(m20250108_000001_add_consent_table::Migration),
            Box::new(m20250109_000001_add_device_codes::Migration),
            Box::new(m20250222_000001_rename_device_code_table::Migration),
            Box::new(m20260407_000001_create_federation_tables::Migration),
            Box::new(m20260407_000002_create_peer_requests::Migration),
            Box::new(m20261003_000001_onboarding_invitations::Migration),
        ]
    }
}

// Keep UTC RFC3339 text defaults consistent with the federation entities.
fn timestamp_default(backend: sea_orm_migration::sea_orm::DbBackend) -> &'static str {
    match backend {
        sea_orm_migration::sea_orm::DbBackend::Postgres => {
            "(to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))"
        }
        _ => "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    }
}
