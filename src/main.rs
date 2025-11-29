mod errors;
mod jwks;
mod session;
mod settings;
mod storage;
mod web;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "barycenter",
    version,
    about = "OpenID Connect Identity Provider"
)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // logging
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    // load settings
    let settings = settings::Settings::load(&cli.config)?;
    tracing::info!(?settings, "Loaded configuration");

    // init storage (database)
    let db = storage::init(&settings.database).await?;

    // ensure test users exist
    ensure_test_users(&db).await?;

    // init jwks (generate if missing)
    let jwks_mgr = jwks::JwksManager::new(settings.keys.clone()).await?;

    // start web server
    web::serve(settings, db, jwks_mgr).await?;
    Ok(())
}

async fn ensure_test_users(db: &sea_orm::DatabaseConnection) -> Result<()> {
    // Check if admin exists
    if storage::get_user_by_username(db, "admin")
        .await
        .into_diagnostic()?
        .is_none()
    {
        storage::create_user(
            db,
            "admin",
            "password123",
            Some("admin@example.com".to_string()),
        )
        .await
        .into_diagnostic()?;
        tracing::info!("Created default admin user (username: admin, password: password123)");
    }
    Ok(())
}
