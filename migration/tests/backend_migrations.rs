use migration::{Migrator, MigratorTrait};
use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, TransactionTrait};

async fn verify_defaults(db: &impl ConnectionTrait) {
    db.execute_unprepared("INSERT INTO trusted_peers (id, domain, issuer_url, client_id) VALUES ('probe', 'probe.example', 'https://probe.example', 'probe')")
        .await.unwrap();
    let row = db
        .query_one(sea_orm_migration::sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT created_at, trust_peer_acr, sync_profile FROM trusted_peers WHERE id = 'probe'"
                .to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    let timestamp: String = row.try_get("", "created_at").unwrap();
    assert_eq!(timestamp.len(), 20);
    assert!(timestamp.ends_with('Z'));
    assert!(!row.try_get::<bool>("", "trust_peer_acr").unwrap());
    assert!(!row.try_get::<bool>("", "sync_profile").unwrap());

    db.execute_unprepared("INSERT INTO clients (client_id, client_secret, redirect_uris, created_at) VALUES ('client_probe', 'test-only', '[]', 0)")
        .await.unwrap();
    assert!(!client_trusted(db).await);
    db.execute_unprepared("UPDATE clients SET trusted = TRUE WHERE client_id = 'client_probe'")
        .await
        .unwrap();
    assert!(client_trusted(db).await);

    // A savepoint keeps the PostgreSQL test transaction usable after the expected error.
    db.execute_unprepared("SAVEPOINT trusted_not_null")
        .await
        .unwrap();
    assert!(db
        .execute_unprepared("UPDATE clients SET trusted = NULL WHERE client_id = 'client_probe'")
        .await
        .is_err());
    db.execute_unprepared("ROLLBACK TO SAVEPOINT trusted_not_null")
        .await
        .unwrap();
    db.execute_unprepared("RELEASE SAVEPOINT trusted_not_null")
        .await
        .unwrap();
}

async fn client_trusted(db: &impl ConnectionTrait) -> bool {
    db.query_one(sea_orm_migration::sea_orm::Statement::from_string(
        db.get_database_backend(),
        "SELECT trusted FROM clients WHERE client_id = 'client_probe'".to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "trusted")
    .unwrap()
}

async fn verify_trusted_rollback_and_upgrade<C: ConnectionTrait>(db: &C)
where
    for<'c> &'c C: sea_orm_migration::IntoSchemaManagerConnection<'c>,
{
    // Roll back only the trust migration, retaining the existing client row.
    Migrator::down(db, Some(1)).await.unwrap();
    Migrator::up(db, None).await.unwrap();
    // Existing clients must never become trusted during upgrade.
    assert!(!client_trusted(db).await);
}

#[tokio::test]
async fn sqlite_fresh_migrations_and_defaults() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    verify_defaults(&db).await;
    verify_trusted_rollback_and_upgrade(&db).await;
}

#[tokio::test]
#[ignore = "requires an explicitly supplied dedicated PostgreSQL test database"]
async fn postgres_fresh_migrations_and_defaults() {
    let db = Database::connect(std::env::var("MIGRATION_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    assert_eq!(db.get_database_backend(), DbBackend::Postgres);
    let tx = db.begin().await.unwrap();
    let name = format!(
        "migration_probe_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    tx.execute_unprepared(&format!(
        "CREATE SCHEMA {name}; SET LOCAL search_path TO {name}"
    ))
    .await
    .unwrap();
    Migrator::up(&tx, None).await.unwrap();
    verify_defaults(&tx).await;
    verify_trusted_rollback_and_upgrade(&tx).await;
    tx.rollback().await.unwrap();
}
