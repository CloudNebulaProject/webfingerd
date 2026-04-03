use axum_extra::extract::cookie::Key;
use metrics_exporter_prometheus::PrometheusBuilder;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;
use webfingerd::cache::Cache;
use webfingerd::config::*;
use webfingerd::state::AppState;

pub async fn setup_test_db() -> DatabaseConnection {
    let opt = ConnectOptions::new("sqlite::memory:");
    let db = Database::connect(opt).await.unwrap();
    db.execute(Statement::from_string(
        sea_orm::DatabaseBackend::Sqlite,
        "PRAGMA journal_mode=WAL".to_string(),
    ))
    .await
    .unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

pub fn test_settings() -> Settings {
    Settings {
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
            base_url: "http://localhost:8080".into(),
        },
        database: DatabaseConfig {
            path: ":memory:".into(),
            wal_mode: true,
        },
        cache: CacheConfig {
            reaper_interval_secs: 1,
        },
        rate_limit: RateLimitConfig {
            public_rpm: 1000,
            api_rpm: 1000,
            batch_rpm: 100,
            batch_max_links: 500,
        },
        challenge: ChallengeConfig {
            dns_txt_prefix: "_webfinger-challenge".into(),
            http_well_known_path: ".well-known/webfinger-verify".into(),
            challenge_ttl_secs: 3600,
        },
        ui: UiConfig {
            enabled: false,
            session_secret: "test-secret-that-must-be-at-least-sixty-four-bytes-long-for-cookie-signing-key-requirements".into(),
        },
    }
}

pub async fn test_state() -> AppState {
    test_state_with_settings(test_settings()).await
}

pub async fn test_state_with_settings(settings: Settings) -> AppState {
    let db = setup_test_db().await;
    let cache = Cache::new();
    cache.hydrate(&db).await.unwrap();
    // Each test gets its own metrics recorder. If install_recorder fails because
    // another test already installed one, build a standalone recorder and grab its handle.
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .unwrap_or_else(|_| {
            let recorder = PrometheusBuilder::new().build_recorder();
            recorder.handle()
        });

    let cookie_key = Key::from(settings.ui.session_secret.as_bytes());

    AppState {
        db,
        cache,
        settings: Arc::new(settings),
        challenge_verifier: Arc::new(webfingerd::challenge::MockChallengeVerifier),
        metrics_handle,
        cookie_key,
    }
}
