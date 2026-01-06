use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use tempfile::NamedTempFile;

/// Test database with automatic cleanup
pub struct TestDb {
    connection: DatabaseConnection,
    _temp_file: NamedTempFile,
}

impl TestDb {
    /// Create a new test database with migrations applied
    pub async fn new() -> Self {
        // Create temporary SQLite database file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_str().expect("Invalid temp file path");
        let db_url = format!("sqlite://{}?mode=rwc", db_path);

        // Connect to database
        let connection = Database::connect(&db_url)
            .await
            .expect("Failed to connect to test database");

        // Run migrations
        migration::Migrator::up(&connection, None)
            .await
            .expect("Failed to run migrations");

        Self {
            connection,
            _temp_file: temp_file,
        }
    }

    /// Get database connection
    pub fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

/// Create a test user for testing
pub async fn seed_test_user(
    db: &DatabaseConnection,
    username: &str,
    password: &str,
) -> barycenter::storage::User {
    barycenter::storage::create_user(db, username, password, None)
        .await
        .expect("Failed to create test user")
}

/// Create a test OAuth client for testing
pub async fn seed_test_client(db: &DatabaseConnection) -> barycenter::storage::Client {
    use barycenter::storage::NewClient;

    barycenter::storage::create_client(
        db,
        NewClient {
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        },
    )
    .await
    .expect("Failed to create test client")
}
