use barycenter::*;
use clap::Parser;
use miette::{IntoDiagnostic, Result};
use sea_orm_migration::MigratorTrait;
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Parser, Debug)]
enum Command {
    /// Sync users from a JSON file (idempotent)
    SyncUsers {
        /// Path to JSON file containing users
        #[arg(short, long)]
        file: String,
    },
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

    // run migrations
    migration::Migrator::up(&db, None).await.into_diagnostic()?;
    tracing::info!("Database migrations applied successfully");

    // Handle subcommands
    match cli.command {
        Some(Command::SyncUsers { file }) => {
            // Run user sync and exit
            user_sync::sync_users_from_file(&db, &file).await?;
            tracing::info!("User sync completed successfully");
            return Ok(());
        }
        None => {
            // Normal server startup
            // ensure test users exist
            ensure_test_users(&db).await?;

            // init jwks (generate if missing)
            let jwks_mgr = jwks::JwksManager::new(settings.keys.clone()).await?;

            // init webauthn manager
            let issuer_url = url::Url::parse(&settings.issuer()).into_diagnostic()?;
            let rp_id = issuer_url
                .host_str()
                .ok_or_else(|| miette::miette!("Invalid issuer URL: missing host"))?;
            let webauthn_mgr = webauthn_manager::WebAuthnManager::new(rp_id, &issuer_url).await?;

            // build admin GraphQL schemas
            let seaography_schema = admin_graphql::build_seaography_schema(db.clone());
            let jobs_schema = admin_graphql::build_jobs_schema(db.clone());

            // init and start background job scheduler
            let _scheduler = jobs::init_scheduler(db.clone()).await?;

            // start web server (includes both public and admin servers)
            web::serve(
                settings,
                db,
                jwks_mgr,
                webauthn_mgr,
                seaography_schema,
                jobs_schema,
            )
            .await?;
        }
    }

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
