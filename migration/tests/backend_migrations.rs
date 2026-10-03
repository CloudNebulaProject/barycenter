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
}

#[tokio::test]
async fn sqlite_fresh_migrations_and_defaults() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    verify_defaults(&db).await;
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
    tx.rollback().await.unwrap();
}
