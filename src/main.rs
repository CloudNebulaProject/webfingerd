use axum_extra::extract::cookie::Key;
use metrics_exporter_prometheus::PrometheusBuilder;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

use webfingerd::cache::Cache;
use webfingerd::challenge::RealChallengeVerifier;
use webfingerd::config::Settings;
use webfingerd::handler;
use webfingerd::reaper;
use webfingerd::state::AppState;

#[tokio::main]
async fn main() {
    // Structured JSON logging with env filter
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    // Load configuration
    let settings = Settings::load().expect("failed to load configuration");
    tracing::info!(listen = %settings.server.listen, "starting webfingerd");

    // Connect to database
    let db_url = format!("sqlite://{}?mode=rwc", settings.database.path);
    let opt = ConnectOptions::new(&db_url);
    let db = Database::connect(opt)
        .await
        .expect("failed to connect to database");

    // Enable WAL mode for better concurrent read performance
    if settings.database.wal_mode {
        db.execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL".to_string(),
        ))
        .await
        .expect("failed to set WAL mode");
        tracing::info!("SQLite WAL mode enabled");
    }

    // Run migrations
    migration::Migrator::up(&db, None)
        .await
        .expect("failed to run migrations");
    tracing::info!("database migrations applied");

    // Hydrate cache from database
    let cache = Cache::new();
    cache
        .hydrate(&db)
        .await
        .expect("failed to hydrate cache");
    tracing::info!("cache hydrated");

    // Install Prometheus metrics recorder
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install metrics recorder");

    // Derive cookie signing key — hash the secret to get 64 bytes for Key::from
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    hasher.update(settings.ui.session_secret.as_bytes());
    let hash = hasher.finalize();
    let cookie_key = Key::from(&hash[..]);

    // Spawn background reaper for expired links
    reaper::spawn_reaper(
        db.clone(),
        cache.clone(),
        settings.cache.reaper_interval_secs,
    );
    tracing::info!(
        interval_secs = settings.cache.reaper_interval_secs,
        "reaper task spawned"
    );

    // Build application state
    let state = AppState {
        db,
        cache,
        settings: Arc::new(settings.clone()),
        challenge_verifier: Arc::new(RealChallengeVerifier),
        metrics_handle,
        cookie_key,
    };

    // Build router
    let app = handler::router(state);

    // Bind and serve with graceful shutdown
    let listener = tokio::net::TcpListener::bind(&settings.server.listen)
        .await
        .expect("failed to bind");
    tracing::info!(listen = %settings.server.listen, "webfingerd started");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down");
        })
        .await
        .expect("server error");
}
