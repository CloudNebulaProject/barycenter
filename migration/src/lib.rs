pub use sea_orm_migration::prelude::*;

mod m20250101_000001_initial_schema;
mod m20250107_000001_add_passkeys;
mod m20250107_000002_extend_sessions_users;
mod m20250108_000001_add_consent_table;
mod m20250109_000001_add_device_codes;
mod m20250222_000001_rename_device_code_table;

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
        ]
    }
}
