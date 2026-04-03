# webfingerd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a multi-tenant WebFinger server (RFC 7033) with ACME-style domain onboarding, scoped service authorization, in-memory cache, and management UI.

**Architecture:** Single axum binary. In-memory DashMap cache backed by SQLite/SeaORM (write-through). Three-tier auth: domain owner → scoped service tokens → links. Background TTL reaper. Server-rendered management UI via askama.

**Tech Stack:** Rust, axum 0.8, tokio, sea-orm (SQLite), dashmap, governor, askama, argon2, config, tracing, metrics, hickory-resolver, reqwest, glob-match

**Spec:** `docs/superpowers/specs/2026-04-03-webfingerd-design.md`

---

## File Structure

```
Cargo.toml                          # Workspace root
migration/
  Cargo.toml                        # SeaORM migration crate
  src/
    lib.rs                          # Migration registry
    m20260403_000001_create_domains.rs
    m20260403_000002_create_resources.rs
    m20260403_000003_create_service_tokens.rs
    m20260403_000004_create_links.rs
src/
  main.rs                           # Entry point: CLI, config load, server start
  lib.rs                            # Re-exports for tests
  config.rs                         # Settings struct, TOML + env loading
  error.rs                          # AppError enum, IntoResponse impl
  state.rs                          # AppState: DbConn, cache, config, metrics
  cache.rs                          # CachedResource, DashMap ops, hydration
  auth.rs                           # Token hashing (argon2), extractors for owner/service tokens
  entity/
    mod.rs                          # Entity module re-exports
    domains.rs                      # SeaORM entity: domains
    resources.rs                    # SeaORM entity: resources
    service_tokens.rs               # SeaORM entity: service_tokens
    links.rs                        # SeaORM entity: links
  handler/
    mod.rs                          # Router assembly
    webfinger.rs                    # GET /.well-known/webfinger
    host_meta.rs                    # GET /.well-known/host-meta
    domains.rs                      # Domain onboarding CRUD + verify + rotate
    tokens.rs                       # Service token CRUD
    links.rs                        # Link registration CRUD + batch
    health.rs                       # GET /healthz
    metrics.rs                      # GET /metrics
  challenge.rs                      # ChallengeVerifier trait + DNS-01/HTTP-01 impls
  reaper.rs                         # Background TTL reaper task
  middleware/
    mod.rs                          # Middleware re-exports
    rate_limit.rs                   # Governor-based rate limiting
    request_id.rs                   # Request ID generation + propagation
    # CORS is handled inline in handler/mod.rs via tower_http::CorsLayer
  ui/
    mod.rs                          # UI router, session auth
    templates.rs                    # Askama template structs
    handlers.rs                     # UI page handlers
  templates/
    layout.html                     # Base template with minimal CSS
    login.html                      # Owner token login
    dashboard.html                  # Domain list
    domain_detail.html              # Single domain view
    token_management.html           # Service token CRUD
    link_browser.html               # Read-only link list
tests/
  common/mod.rs                     # Test helpers: setup DB, create test app
  test_webfinger.rs                 # WebFinger query endpoint tests
  test_host_meta.rs                 # host-meta endpoint tests
  test_domains.rs                   # Domain onboarding + verify flow tests
  test_tokens.rs                    # Service token CRUD tests
  test_links.rs                     # Link registration + scope enforcement tests
  test_cache.rs                     # Cache hydration, write-through, expiry tests
  test_reaper.rs                    # TTL reaper tests
  test_rate_limit.rs                # Rate limiting tests
```

---

## Task 1: Project Scaffold + Configuration

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `src/error.rs`
- Create: `config.toml` (example config)

- [ ] **Step 1: Initialize Cargo workspace**

```bash
cargo init --name webfingerd
mkdir migration && cd migration && cargo init --lib --name migration && cd ..
```

Add to root `Cargo.toml`:
```toml
[workspace]
members = [".", "migration"]

[package]
name = "webfingerd"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.8", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
sea-orm = { version = "1", features = ["sqlx-sqlite", "runtime-tokio-rustls"] }
sea-orm-migration = "1"
dashmap = "6"
governor = "0.8"
askama = "0.12"
askama_axum = "0.4"
argon2 = "0.5"
config = "0.14"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
metrics = "0.24"
metrics-exporter-prometheus = "0.16"
hickory-resolver = "0.25"
reqwest = { version = "0.12", features = ["rustls-tls"], default-features = false }
glob-match = "0.2"
urlencoding = "2"
async-trait = "0.1"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "request-id", "trace", "util"] }
axum-extra = { version = "0.10", features = ["cookie-signed"] }
rand = "0.8"
base64 = "0.22"
thiserror = "2"

[dev-dependencies]
axum-test = "16"
tempfile = "3"
```

- [ ] **Step 2: Write config.rs**

Create `src/config.rs`:
```rust
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub rate_limit: RateLimitConfig,
    pub challenge: ChallengeConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub wal_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub reaper_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub public_rpm: u32,
    pub api_rpm: u32,
    pub batch_rpm: u32,
    pub batch_max_links: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChallengeConfig {
    pub dns_txt_prefix: String,
    pub http_well_known_path: String,
    pub challenge_ttl_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UiConfig {
    pub enabled: bool,
    pub session_secret: String,
}

impl Settings {
    pub fn load() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config").required(false))
            .add_source(
                config::Environment::with_prefix("WEBFINGERD")
                    .separator("__"),
            )
            .build()?;

        let s: Self = settings.try_deserialize()?;

        if s.ui.enabled && s.ui.session_secret.is_empty() {
            return Err(config::ConfigError::Message(
                "ui.session_secret is required when ui is enabled".into(),
            ));
        }

        Ok(s)
    }
}
```

- [ ] **Step 3: Write error.rs**

Create `src/error.rs`:
```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limited")]
    RateLimited,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::Internal(msg) => {
                tracing::error!("internal error: {msg}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
            AppError::Database(err) => {
                tracing::error!("database error: {err}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
```

- [ ] **Step 4: Write minimal main.rs and lib.rs**

Create `src/lib.rs`:
```rust
pub mod config;
pub mod error;
```

Create `src/main.rs`:
```rust
use tracing_subscriber::{fmt, EnvFilter};
use webfingerd::config::Settings;

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let settings = Settings::load().expect("failed to load configuration");
    tracing::info!(listen = %settings.server.listen, "starting webfingerd");
}
```

- [ ] **Step 5: Create example config.toml**

Create `config.toml`:
```toml
[server]
listen = "0.0.0.0:8080"
base_url = "http://localhost:8080"

[database]
path = "webfingerd.db"
wal_mode = true

[cache]
reaper_interval_secs = 30

[rate_limit]
public_rpm = 60
api_rpm = 300
batch_rpm = 10
batch_max_links = 500

[challenge]
dns_txt_prefix = "_webfinger-challenge"
http_well_known_path = ".well-known/webfinger-verify"
challenge_ttl_secs = 3600

[ui]
enabled = false
session_secret = ""
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build`
Expected: Successful compilation.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: project scaffold with config and error types"
```

---

## Task 2: Database Migrations

**Files:**
- Create: `migration/Cargo.toml`, `migration/src/lib.rs`
- Create: `migration/src/m20260403_000001_create_domains.rs`
- Create: `migration/src/m20260403_000002_create_resources.rs`
- Create: `migration/src/m20260403_000003_create_service_tokens.rs`
- Create: `migration/src/m20260403_000004_create_links.rs`

- [ ] **Step 1: Set up migration crate**

`migration/Cargo.toml`:
```toml
[package]
name = "migration"
version = "0.1.0"
edition = "2021"

[dependencies]
sea-orm-migration = "1"
```

`migration/src/lib.rs`:
```rust
pub use sea_orm_migration::prelude::*;

mod m20260403_000001_create_domains;
mod m20260403_000002_create_resources;
mod m20260403_000003_create_service_tokens;
mod m20260403_000004_create_links;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260403_000001_create_domains::Migration),
            Box::new(m20260403_000002_create_resources::Migration),
            Box::new(m20260403_000003_create_service_tokens::Migration),
            Box::new(m20260403_000004_create_links::Migration),
        ]
    }
}
```

- [ ] **Step 2: Write domains migration**

`migration/src/m20260403_000001_create_domains.rs`:
```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Domains::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Domains::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Domains::Domain).string().not_null().unique_key())
                    .col(ColumnDef::new(Domains::OwnerTokenHash).string().not_null())
                    .col(ColumnDef::new(Domains::RegistrationSecret).string().not_null())
                    .col(ColumnDef::new(Domains::ChallengeType).string().not_null())
                    .col(ColumnDef::new(Domains::ChallengeToken).string().null())
                    .col(ColumnDef::new(Domains::Verified).boolean().not_null().default(false))
                    .col(ColumnDef::new(Domains::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Domains::VerifiedAt).date_time().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Domains::Table).to_owned()).await
    }
}

#[derive(DeriveIden)]
pub enum Domains {
    Table,
    Id,
    Domain,
    OwnerTokenHash,
    RegistrationSecret,
    ChallengeType,
    ChallengeToken,
    Verified,
    CreatedAt,
    VerifiedAt,
}
```

- [ ] **Step 3: Write resources migration**

`migration/src/m20260403_000002_create_resources.rs`:
```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Resources::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Resources::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Resources::DomainId).string().not_null())
                    .col(ColumnDef::new(Resources::ResourceUri).string().not_null().unique_key())
                    .col(ColumnDef::new(Resources::Aliases).string().null())
                    .col(ColumnDef::new(Resources::Properties).string().null())
                    .col(ColumnDef::new(Resources::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Resources::UpdatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Resources::Table, Resources::DomainId)
                            .to(super::m20260403_000001_create_domains::Domains::Table,
                                super::m20260403_000001_create_domains::Domains::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Resources::Table).to_owned()).await
    }
}

#[derive(DeriveIden)]
pub enum Resources {
    Table,
    Id,
    DomainId,
    ResourceUri,
    Aliases,
    Properties,
    CreatedAt,
    UpdatedAt,
}
```

- [ ] **Step 4: Write service_tokens migration**

`migration/src/m20260403_000003_create_service_tokens.rs`:
```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ServiceTokens::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ServiceTokens::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(ServiceTokens::DomainId).string().not_null())
                    .col(ColumnDef::new(ServiceTokens::Name).string().not_null())
                    .col(ColumnDef::new(ServiceTokens::TokenHash).string().not_null())
                    .col(ColumnDef::new(ServiceTokens::AllowedRels).string().not_null())
                    .col(ColumnDef::new(ServiceTokens::ResourcePattern).string().not_null())
                    .col(ColumnDef::new(ServiceTokens::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(ServiceTokens::RevokedAt).date_time().null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(ServiceTokens::Table, ServiceTokens::DomainId)
                            .to(super::m20260403_000001_create_domains::Domains::Table,
                                super::m20260403_000001_create_domains::Domains::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(ServiceTokens::Table).to_owned()).await
    }
}

#[derive(DeriveIden)]
pub enum ServiceTokens {
    Table,
    Id,
    DomainId,
    Name,
    TokenHash,
    AllowedRels,
    ResourcePattern,
    CreatedAt,
    RevokedAt,
}
```

- [ ] **Step 5: Write links migration**

`migration/src/m20260403_000004_create_links.rs`:
```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Links::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Links::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Links::ResourceId).string().not_null())
                    .col(ColumnDef::new(Links::ServiceTokenId).string().not_null())
                    .col(ColumnDef::new(Links::DomainId).string().not_null())
                    .col(ColumnDef::new(Links::Rel).string().not_null())
                    .col(ColumnDef::new(Links::Href).string().null())
                    .col(ColumnDef::new(Links::Type).string().null())
                    .col(ColumnDef::new(Links::Titles).string().null())
                    .col(ColumnDef::new(Links::Properties).string().null())
                    .col(ColumnDef::new(Links::Template).string().null())
                    .col(ColumnDef::new(Links::TtlSeconds).integer().null())
                    .col(ColumnDef::new(Links::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Links::ExpiresAt).date_time().null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Links::Table, Links::ResourceId)
                            .to(super::m20260403_000002_create_resources::Resources::Table,
                                super::m20260403_000002_create_resources::Resources::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Links::Table, Links::ServiceTokenId)
                            .to(super::m20260403_000003_create_service_tokens::ServiceTokens::Table,
                                super::m20260403_000003_create_service_tokens::ServiceTokens::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Links::Table, Links::DomainId)
                            .to(super::m20260403_000001_create_domains::Domains::Table,
                                super::m20260403_000001_create_domains::Domains::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique constraint for upsert behavior
        manager
            .create_index(
                Index::create()
                    .name("idx_links_resource_rel_href")
                    .table(Links::Table)
                    .col(Links::ResourceId)
                    .col(Links::Rel)
                    .col(Links::Href)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Links::Table).to_owned()).await
    }
}

#[derive(DeriveIden)]
pub enum Links {
    Table,
    Id,
    ResourceId,
    ServiceTokenId,
    DomainId,
    Rel,
    Href,
    Type,
    Titles,
    Properties,
    Template,
    TtlSeconds,
    CreatedAt,
    ExpiresAt,
}
```

- [ ] **Step 6: Verify migrations compile**

Run: `cargo build -p migration`
Expected: Successful compilation.

- [ ] **Step 7: Commit**

```bash
git add migration/
git commit -m "feat: add database migrations for domains, resources, service_tokens, links"
```

---

## Task 3: SeaORM Entities

**Files:**
- Create: `src/entity/mod.rs`, `src/entity/domains.rs`, `src/entity/resources.rs`
- Create: `src/entity/service_tokens.rs`, `src/entity/links.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write domains entity**

Create `src/entity/domains.rs`:
```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "domains")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub domain: String,
    pub owner_token_hash: String,
    pub registration_secret: String,
    pub challenge_type: String,
    pub challenge_token: Option<String>,
    pub verified: bool,
    pub created_at: chrono::NaiveDateTime,
    pub verified_at: Option<chrono::NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::resources::Entity")]
    Resources,
    #[sea_orm(has_many = "super::service_tokens::Entity")]
    ServiceTokens,
    #[sea_orm(has_many = "super::links::Entity")]
    Links,
}

impl Related<super::resources::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Resources.def()
    }
}

impl Related<super::service_tokens::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ServiceTokens.def()
    }
}

impl Related<super::links::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Links.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

- [ ] **Step 2: Write resources entity**

Create `src/entity/resources.rs`:
```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resources")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub domain_id: String,
    #[sea_orm(unique)]
    pub resource_uri: String,
    pub aliases: Option<String>,
    pub properties: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::domains::Entity",
        from = "Column::DomainId",
        to = "super::domains::Column::Id"
    )]
    Domain,
    #[sea_orm(has_many = "super::links::Entity")]
    Links,
}

impl Related<super::domains::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Domain.def()
    }
}

impl Related<super::links::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Links.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

- [ ] **Step 3: Write service_tokens entity**

Create `src/entity/service_tokens.rs`:
```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "service_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub token_hash: String,
    pub allowed_rels: String,
    pub resource_pattern: String,
    pub created_at: chrono::NaiveDateTime,
    pub revoked_at: Option<chrono::NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::domains::Entity",
        from = "Column::DomainId",
        to = "super::domains::Column::Id"
    )]
    Domain,
    #[sea_orm(has_many = "super::links::Entity")]
    Links,
}

impl Related<super::domains::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Domain.def()
    }
}

impl Related<super::links::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Links.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

- [ ] **Step 4: Write links entity**

Create `src/entity/links.rs`:
```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "links")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub resource_id: String,
    pub service_token_id: String,
    pub domain_id: String,
    pub rel: String,
    pub href: Option<String>,
    #[sea_orm(column_name = "type")]
    pub link_type: Option<String>,
    pub titles: Option<String>,
    pub properties: Option<String>,
    pub template: Option<String>,
    pub ttl_seconds: Option<i32>,
    pub created_at: chrono::NaiveDateTime,
    pub expires_at: Option<chrono::NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::resources::Entity",
        from = "Column::ResourceId",
        to = "super::resources::Column::Id"
    )]
    Resource,
    #[sea_orm(
        belongs_to = "super::service_tokens::Entity",
        from = "Column::ServiceTokenId",
        to = "super::service_tokens::Column::Id"
    )]
    ServiceToken,
    #[sea_orm(
        belongs_to = "super::domains::Entity",
        from = "Column::DomainId",
        to = "super::domains::Column::Id"
    )]
    Domain,
}

impl Related<super::resources::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Resource.def()
    }
}

impl Related<super::service_tokens::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ServiceToken.def()
    }
}

impl Related<super::domains::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Domain.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

- [ ] **Step 5: Write entity mod.rs and update lib.rs**

Create `src/entity/mod.rs`:
```rust
pub mod domains;
pub mod links;
pub mod resources;
pub mod service_tokens;
```

Update `src/lib.rs`:
```rust
pub mod config;
pub mod entity;
pub mod error;
```

- [ ] **Step 6: Verify compilation**

Run: `cargo build`
Expected: Successful compilation.

- [ ] **Step 7: Commit**

```bash
git add src/entity/
git commit -m "feat: add SeaORM entities for all tables"
```

---

## Task 4: AppState + Database Bootstrap + Cache

**Files:**
- Create: `src/state.rs`, `src/cache.rs`, `src/auth.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Write cache.rs**

Create `src/cache.rs`:
```rust
use dashmap::DashMap;
use sea_orm::*;
use std::sync::Arc;

use crate::entity::{links, resources};

#[derive(Debug, Clone)]
pub struct CachedLink {
    pub rel: String,
    pub href: Option<String>,
    pub link_type: Option<String>,
    pub titles: Option<String>,
    pub properties: Option<String>,
    pub template: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CachedResource {
    pub subject: String,
    pub aliases: Option<Vec<String>>,
    pub properties: Option<serde_json::Value>,
    pub links: Vec<CachedLink>,
}

#[derive(Debug, Clone)]
pub struct Cache {
    inner: Arc<DashMap<String, CachedResource>>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn get(&self, resource_uri: &str) -> Option<CachedResource> {
        self.inner.get(resource_uri).map(|r| r.value().clone())
    }

    pub fn set(&self, resource_uri: String, resource: CachedResource) {
        self.inner.insert(resource_uri, resource);
    }

    pub fn remove(&self, resource_uri: &str) {
        self.inner.remove(resource_uri);
    }

    /// Remove all cache entries for the given resource URIs.
    /// Callers should query the DB for all resource URIs belonging to a domain
    /// before deleting, then pass them here. This handles non-acct: URI schemes.
    pub fn remove_many(&self, resource_uris: &[String]) {
        for uri in resource_uris {
            self.inner.remove(uri);
        }
    }

    /// Load all non-expired resources and links from DB into cache.
    pub async fn hydrate(&self, db: &DatabaseConnection) -> Result<(), DbErr> {
        let now = chrono::Utc::now().naive_utc();

        let all_resources = resources::Entity::find().all(db).await?;

        for resource in all_resources {
            let resource_links = links::Entity::find()
                .filter(links::Column::ResourceId.eq(&resource.id))
                .filter(
                    Condition::any()
                        .add(links::Column::ExpiresAt.is_null())
                        .add(links::Column::ExpiresAt.gt(now)),
                )
                .all(db)
                .await?;

            if resource_links.is_empty() {
                continue;
            }

            let cached = CachedResource {
                subject: resource.resource_uri.clone(),
                aliases: resource
                    .aliases
                    .as_deref()
                    .and_then(|a| serde_json::from_str(a).ok()),
                properties: resource
                    .properties
                    .as_deref()
                    .and_then(|p| serde_json::from_str(p).ok()),
                links: resource_links
                    .into_iter()
                    .map(|l| CachedLink {
                        rel: l.rel,
                        href: l.href,
                        link_type: l.link_type,
                        titles: l.titles,
                        properties: l.properties,
                        template: l.template,
                    })
                    .collect(),
            };

            self.set(resource.resource_uri, cached);
        }

        Ok(())
    }

    /// Rebuild cache entry for a single resource from DB.
    pub async fn refresh_resource(
        &self,
        db: &DatabaseConnection,
        resource_uri: &str,
    ) -> Result<(), DbErr> {
        let now = chrono::Utc::now().naive_utc();

        let resource = resources::Entity::find()
            .filter(resources::Column::ResourceUri.eq(resource_uri))
            .one(db)
            .await?;

        let Some(resource) = resource else {
            self.remove(resource_uri);
            return Ok(());
        };

        let resource_links = links::Entity::find()
            .filter(links::Column::ResourceId.eq(&resource.id))
            .filter(
                Condition::any()
                    .add(links::Column::ExpiresAt.is_null())
                    .add(links::Column::ExpiresAt.gt(now)),
            )
            .all(db)
            .await?;

        if resource_links.is_empty() {
            self.remove(resource_uri);
            return Ok(());
        }

        let cached = CachedResource {
            subject: resource.resource_uri.clone(),
            aliases: resource
                .aliases
                .as_deref()
                .and_then(|a| serde_json::from_str(a).ok()),
            properties: resource
                .properties
                .as_deref()
                .and_then(|p| serde_json::from_str(p).ok()),
            links: resource_links
                .into_iter()
                .map(|l| CachedLink {
                    rel: l.rel,
                    href: l.href,
                    link_type: l.link_type,
                    titles: l.titles,
                    properties: l.properties,
                    template: l.template,
                })
                .collect(),
        };

        self.set(resource.resource_uri, cached);
        Ok(())
    }
}
```

- [ ] **Step 2: Write auth.rs**

Create `src/auth.rs`:
```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::Engine;
use rand::Rng;

/// Generate a prefixed token: `{id}.{random_secret}`.
/// The id allows O(1) lookup; the secret is verified via argon2.
/// The `id` parameter is the entity UUID this token belongs to.
pub fn generate_token(id: &str) -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{id}.{secret}")
}

/// Generate a non-prefixed secret (for registration secrets that don't need lookup).
pub fn generate_secret() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token (or its secret part) with argon2.
pub fn hash_token(token: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(token.as_bytes(), &salt)?.to_string())
}

/// Verify a token against a stored argon2 hash.
pub fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Split a prefixed token into (id, secret).
/// Returns None if the token is not in `id.secret` format.
pub fn split_token(token: &str) -> Option<(&str, &str)> {
    token.split_once('.')
}
```

**Token format:** All tokens use the format `{entity_id}.{random_secret}`. This enables
O(1) database lookup by ID, then a single argon2 verify against the stored hash of the
full token. This avoids the O(n) scan + argon2-per-row anti-pattern.

Callers use `auth::split_token()` to extract the ID, look up the entity by ID, then
`auth::verify_token(full_token, stored_hash)` to verify. The hash is computed over the
full `{id}.{secret}` string.

- [ ] **Step 3: Write state.rs**

Create `src/state.rs`:
```rust
use sea_orm::DatabaseConnection;
use std::sync::Arc;

use crate::cache::Cache;
use crate::challenge::ChallengeVerifier;
use crate::config::Settings;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub cache: Cache,
    pub settings: Arc<Settings>,
    pub challenge_verifier: Arc<dyn ChallengeVerifier>,
}
```

- [ ] **Step 4: Update main.rs with DB bootstrap**

Update `src/main.rs`:
```rust
use sea_orm::{ConnectOptions, Database, ConnectionTrait, Statement};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

use webfingerd::cache::Cache;
use webfingerd::config::Settings;
use webfingerd::state::AppState;

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let settings = Settings::load().expect("failed to load configuration");

    // Connect to SQLite
    let db_url = format!("sqlite://{}?mode=rwc", settings.database.path);
    let mut opt = ConnectOptions::new(&db_url);
    opt.sqlx_logging(false);
    let db = Database::connect(opt)
        .await
        .expect("failed to connect to database");

    // Enable WAL mode
    if settings.database.wal_mode {
        db.execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL".to_string(),
        ))
        .await
        .expect("failed to enable WAL mode");
    }

    // Run migrations
    migration::Migrator::up(&db, None)
        .await
        .expect("failed to run migrations");

    // Hydrate cache
    let cache = Cache::new();
    cache.hydrate(&db).await.expect("failed to hydrate cache");
    tracing::info!("cache hydrated");

    let state = AppState {
        db,
        cache,
        settings: Arc::new(settings.clone()),
        challenge_verifier: Arc::new(webfingerd::challenge::RealChallengeVerifier),
    };

    let listener = tokio::net::TcpListener::bind(&settings.server.listen)
        .await
        .expect("failed to bind");
    tracing::info!(listen = %settings.server.listen, "starting webfingerd");

    axum::serve(listener, axum::Router::new().with_state(state))
        .await
        .expect("server error");
}
```

- [ ] **Step 5: Update lib.rs**

```rust
pub mod auth;
pub mod cache;
pub mod config;
pub mod entity;
pub mod error;
pub mod state;
```

- [ ] **Step 6: Verify compilation**

Run: `cargo build`
Expected: Successful compilation.

- [ ] **Step 7: Commit**

```bash
git add src/state.rs src/cache.rs src/auth.rs src/main.rs src/lib.rs
git commit -m "feat: add AppState, in-memory cache with hydration, auth helpers"
```

---

## Task 5: Test Helpers

**Files:**
- Create: `tests/common/mod.rs`

- [ ] **Step 1: Write test helpers**

Create `tests/common/mod.rs`:
```rust
use axum::Router;
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
            session_secret: "test-secret-at-least-32-bytes-long-for-signing".into(),
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
    AppState {
        db,
        cache,
        settings: Arc::new(settings),
        challenge_verifier: Arc::new(webfingerd::challenge::MockChallengeVerifier),
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo test --no-run`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "feat: add test helpers with in-memory DB and test state"
```

---

## Task 6: WebFinger Query Endpoint

**Files:**
- Create: `src/handler/mod.rs`, `src/handler/webfinger.rs`, `src/handler/health.rs`
- Create: `tests/test_webfinger.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Write failing test for webfinger query**

Create `tests/test_webfinger.rs`:
```rust
mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_webfinger_returns_404_for_unknown_resource() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:nobody@example.com")
        .await;

    response.assert_status_not_found();
}

#[tokio::test]
async fn test_webfinger_returns_400_without_resource_param() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server.get("/.well-known/webfinger").await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_webfinger_returns_jrd_for_known_resource() {
    let state = common::test_state().await;

    // Seed cache directly for this test
    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: Some(vec!["https://example.com/@alice".into()]),
            properties: None,
            links: vec![webfingerd::cache::CachedLink {
                rel: "self".into(),
                href: Some("https://example.com/users/alice".into()),
                link_type: Some("application/activity+json".into()),
                titles: None,
                properties: None,
                template: None,
            }],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["subject"], "acct:alice@example.com");
    assert_eq!(body["aliases"][0], "https://example.com/@alice");
    assert_eq!(body["links"][0]["rel"], "self");
    assert_eq!(
        body["links"][0]["href"],
        "https://example.com/users/alice"
    );
}

#[tokio::test]
async fn test_webfinger_filters_by_rel() {
    let state = common::test_state().await;

    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: None,
            properties: None,
            links: vec![
                webfingerd::cache::CachedLink {
                    rel: "self".into(),
                    href: Some("https://example.com/users/alice".into()),
                    link_type: Some("application/activity+json".into()),
                    titles: None,
                    properties: None,
                    template: None,
                },
                webfingerd::cache::CachedLink {
                    rel: "http://openid.net/specs/connect/1.0/issuer".into(),
                    href: Some("https://auth.example.com".into()),
                    link_type: None,
                    titles: None,
                    properties: None,
                    template: None,
                },
            ],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .add_query_param("rel", "self")
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    let links = body["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["rel"], "self");
}

#[tokio::test]
async fn test_webfinger_cors_headers() {
    let state = common::test_state().await;

    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: None,
            properties: None,
            links: vec![],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;

    assert_eq!(
        response.header("access-control-allow-origin"),
        "*"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test test_webfinger`
Expected: FAIL — `handler` module does not exist.

- [ ] **Step 3: Implement handler module + webfinger handler**

Create `src/handler/mod.rs`:
```rust
mod health;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(health::router())
        .with_state(state)
}
```

Create `src/handler/webfinger.rs`:

**Note:** `serde_urlencoded` (used by axum's `Query`) does not support deserializing
repeated query params (`?rel=a&rel=b`) into a `Vec`. We parse the raw query string
manually to support multiple `rel` parameters per RFC 7033 Section 4.1.

```rust
use axum::extract::State;
use axum::http::{header, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Parse resource and rel params from query string manually,
/// because serde_urlencoded can't handle repeated keys into Vec.
fn parse_webfinger_query(uri: &Uri) -> (Option<String>, Vec<String>) {
    let query_str = uri.query().unwrap_or("");
    let mut resource = None;
    let mut rels = Vec::new();

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let value = urlencoding::decode(value)
                .unwrap_or_default()
                .into_owned();
            match key {
                "resource" => resource = Some(value),
                "rel" => rels.push(value),
                _ => {}
            }
        }
    }

    (resource, rels)
}

async fn webfinger(
    State(state): State<AppState>,
    uri: Uri,
) -> AppResult<Response> {
    let (resource_opt, rels) = parse_webfinger_query(&uri);

    let resource = resource_opt
        .ok_or_else(|| AppError::BadRequest("missing resource parameter".into()))?;

    let cached = state
        .cache
        .get(&resource)
        .ok_or(AppError::NotFound)?;

    let links: Vec<serde_json::Value> = cached
        .links
        .iter()
        .filter(|link| {
            if rels.is_empty() {
                true
            } else {
                rels.iter().any(|r| r == &link.rel)
            }
        })
        .map(|link| {
            let mut obj = serde_json::Map::new();
            obj.insert("rel".into(), json!(link.rel));
            if let Some(href) = &link.href {
                obj.insert("href".into(), json!(href));
            }
            if let Some(t) = &link.link_type {
                obj.insert("type".into(), json!(t));
            }
            if let Some(titles) = &link.titles {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(titles) {
                    obj.insert("titles".into(), v);
                }
            }
            if let Some(props) = &link.properties {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(props) {
                    obj.insert("properties".into(), v);
                }
            }
            if let Some(template) = &link.template {
                obj.insert("template".into(), json!(template));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let mut response_body = serde_json::Map::new();
    response_body.insert("subject".into(), json!(cached.subject));

    if let Some(aliases) = &cached.aliases {
        response_body.insert("aliases".into(), json!(aliases));
    }

    if let Some(properties) = &cached.properties {
        response_body.insert("properties".into(), properties.clone());
    }

    response_body.insert("links".into(), json!(links));

    Ok((
        [
            (header::CONTENT_TYPE, "application/jrd+json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(serde_json::Value::Object(response_body)),
    )
        .into_response())
}

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/webfinger", get(webfinger))
}
```

Create `src/handler/health.rs`:
```rust
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub fn router() -> Router<AppState> {
    Router::new().route("/healthz", get(healthz))
}
```

- [ ] **Step 4: Update lib.rs**

```rust
pub mod auth;
pub mod cache;
pub mod config;
pub mod entity;
pub mod error;
pub mod handler;
pub mod state;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test test_webfinger`
Expected: All 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/handler/ src/lib.rs tests/test_webfinger.rs
git commit -m "feat: add WebFinger query endpoint with rel filtering and CORS"
```

---

## Task 7: host-meta Endpoint

**Files:**
- Create: `src/handler/host_meta.rs`
- Create: `tests/test_host_meta.rs`
- Modify: `src/handler/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `tests/test_host_meta.rs`:
```rust
mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_host_meta_returns_xrd_for_known_domain() {
    let state = common::test_state().await;

    // Seed a verified domain in DB
    use sea_orm::ActiveModelTrait;
    use sea_orm::Set;
    use webfingerd::entity::domains;

    let domain = domains::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        domain: Set("example.com".into()),
        owner_token_hash: Set("hash".into()),
        registration_secret: Set("secret".into()),
        challenge_type: Set("dns-01".into()),
        challenge_token: Set(None),
        verified: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
        verified_at: Set(Some(chrono::Utc::now().naive_utc())),
    };
    domain.insert(&state.db).await.unwrap();

    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/host-meta")
        .add_header("Host", "example.com")
        .await;

    response.assert_status_ok();
    let body = response.text();
    assert!(body.contains("application/xrd+xml") || body.contains("XRD"));
    assert!(body.contains("/.well-known/webfinger"));
}

#[tokio::test]
async fn test_host_meta_returns_404_for_unknown_domain() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/.well-known/host-meta")
        .add_header("Host", "unknown.example.com")
        .await;

    response.assert_status_not_found();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test test_host_meta`
Expected: FAIL.

- [ ] **Step 3: Implement host_meta handler**

Create `src/handler/host_meta.rs`:
```rust
use axum::extract::{Host, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sea_orm::*;

use crate::entity::domains;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

async fn host_meta(
    State(state): State<AppState>,
    Host(hostname): Host,
) -> AppResult<Response> {
    // Strip port if present
    let domain = hostname.split(':').next().unwrap_or(&hostname);

    // Check this domain is registered and verified
    let _domain = domains::Entity::find()
        .filter(domains::Column::Domain.eq(domain))
        .filter(domains::Column::Verified.eq(true))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let base_url = &state.settings.server.base_url;
    let xrd = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="lrdd" type="application/jrd+json" template="{base_url}/.well-known/webfinger?resource={{uri}}" />
</XRD>"#
    );

    Ok((
        [(header::CONTENT_TYPE, "application/xrd+xml; charset=utf-8")],
        xrd,
    )
        .into_response())
}

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/host-meta", get(host_meta))
}
```

- [ ] **Step 4: Update handler/mod.rs**

```rust
mod health;
mod host_meta;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .merge(health::router())
        .with_state(state)
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test test_host_meta`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/handler/host_meta.rs src/handler/mod.rs tests/test_host_meta.rs
git commit -m "feat: add host-meta endpoint with domain-aware XRD response"
```

---

## Task 8: Domain Onboarding API

**Files:**
- Create: `src/handler/domains.rs`, `src/challenge.rs`
- Create: `tests/test_domains.rs`
- Modify: `src/handler/mod.rs`, `src/lib.rs`

- [ ] **Step 1: Write failing tests for domain registration and verification**

Create `tests/test_domains.rs`:
```rust
mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

#[tokio::test]
async fn test_register_domain() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/api/v1/domains")
        .json(&json!({
            "domain": "example.com",
            "challenge_type": "dns-01"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["challenge_token"].is_string());
    assert!(body["registration_secret"].is_string());
    assert_eq!(body["challenge_type"], "dns-01");
}

#[tokio::test]
async fn test_register_duplicate_domain_returns_409() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    let response = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    response.assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_domain_requires_auth() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;
    let id = create_resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // No auth header
    let response = server.get(&format!("/api/v1/domains/{id}")).await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_get_domain_with_valid_owner_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    // Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap();
    let reg_secret = body["registration_secret"].as_str().unwrap();

    // Verify (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;

    verify_resp.assert_status_ok();
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Use owner token to get domain
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["domain"], "example.com");
    assert_eq!(body["verified"], true);
}

#[tokio::test]
async fn test_rotate_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    // Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;
    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap();
    let reg_secret = body["registration_secret"].as_str().unwrap();

    // Verify (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let old_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Rotate
    let rotate_resp = server
        .post(&format!("/api/v1/domains/{id}/rotate-token"))
        .add_header("Authorization", format!("Bearer {old_token}"))
        .await;
    rotate_resp.assert_status_ok();
    let new_token = rotate_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Old token should fail
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {old_token}"))
        .await;
    response.assert_status_unauthorized();

    // New token should work
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {new_token}"))
        .await;
    response.assert_status_ok();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test test_domains`
Expected: FAIL.

- [ ] **Step 3: Implement challenge.rs**

Create `src/challenge.rs`:
```rust
use async_trait::async_trait;
use crate::config::ChallengeConfig;

/// Trait for challenge verification — allows mocking in tests.
#[async_trait]
pub trait ChallengeVerifier: Send + Sync {
    async fn verify_dns(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String>;

    async fn verify_http(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String>;
}

/// Real implementation using DNS lookups and HTTP requests.
pub struct RealChallengeVerifier;

#[async_trait]
impl ChallengeVerifier for RealChallengeVerifier {
    async fn verify_dns(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String> {
        use hickory_resolver::TokioAsyncResolver;

        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| format!("resolver error: {e}"))?;

        let lookup_name = format!("{}.{}", config.dns_txt_prefix, domain);
        let response = resolver
            .txt_lookup(&lookup_name)
            .await
            .map_err(|e| format!("DNS lookup failed: {e}"))?;

        for record in response.iter() {
            let txt = record.to_string();
            if txt.trim_matches('"') == expected_token {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn verify_http(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String> {
        let url = format!(
            "https://{}/{}/{}",
            domain, config.http_well_known_path, expected_token
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        Ok(response.status().is_success())
    }
}

/// Mock that always succeeds — for testing.
pub struct MockChallengeVerifier;

#[async_trait]
impl ChallengeVerifier for MockChallengeVerifier {
    async fn verify_dns(&self, _: &str, _: &str, _: &ChallengeConfig) -> Result<bool, String> {
        Ok(true)
    }
    async fn verify_http(&self, _: &str, _: &str, _: &ChallengeConfig) -> Result<bool, String> {
        Ok(true)
    }
}
```

Add `async-trait = "0.1"` to `[dependencies]` in Cargo.toml.

The `ChallengeVerifier` trait is stored in `AppState` as `Arc<dyn ChallengeVerifier>`.
Production uses `RealChallengeVerifier`, tests use `MockChallengeVerifier`. This makes
the domain verification flow fully testable without real DNS/HTTP.

- [ ] **Step 4: Implement handler/domains.rs**

Create `src/handler/domains.rs`:
```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::challenge;
use crate::entity::domains;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    domain: String,
    challenge_type: String,
}

async fn create_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if req.challenge_type != "dns-01" && req.challenge_type != "http-01" {
        return Err(AppError::BadRequest(
            "challenge_type must be dns-01 or http-01".into(),
        ));
    }

    // Check for duplicate
    let existing = domains::Entity::find()
        .filter(domains::Column::Domain.eq(&req.domain))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::Conflict("domain already registered".into()));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let challenge_token = auth::generate_secret();
    let registration_secret = auth::generate_secret();
    let registration_secret_hash = auth::hash_token(&registration_secret)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let domain = domains::ActiveModel {
        id: Set(id.clone()),
        domain: Set(req.domain.clone()),
        owner_token_hash: Set(String::new()), // Set on verification
        registration_secret: Set(registration_secret_hash),
        challenge_type: Set(req.challenge_type.clone()),
        challenge_token: Set(Some(challenge_token.clone())),
        verified: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
        verified_at: Set(None),
    };

    domain.insert(&state.db).await?;

    let instructions = match req.challenge_type.as_str() {
        "dns-01" => format!(
            "Create a TXT record at {}.{} with value: {}",
            state.settings.challenge.dns_txt_prefix, req.domain, challenge_token
        ),
        "http-01" => format!(
            "Serve the challenge at https://{}/{}/{}",
            req.domain, state.settings.challenge.http_well_known_path, challenge_token
        ),
        _ => unreachable!(),
    };

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "challenge_token": challenge_token,
            "challenge_type": req.challenge_type,
            "registration_secret": registration_secret,
            "instructions": instructions,
        })),
    ))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    registration_secret: String,
}

async fn verify_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VerifyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let domain = domains::Entity::find_by_id(&id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify registration secret
    if !auth::verify_token(&req.registration_secret, &domain.registration_secret) {
        return Err(AppError::Unauthorized);
    }

    if domain.verified {
        return Err(AppError::Conflict("domain already verified".into()));
    }

    let challenge_token = domain
        .challenge_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("no pending challenge".into()))?;

    // Check challenge TTL
    let challenge_age = chrono::Utc::now().naive_utc() - domain.created_at;
    if challenge_age.num_seconds() > state.settings.challenge.challenge_ttl_secs as i64 {
        return Err(AppError::BadRequest("challenge expired".into()));
    }

    // Verify the challenge via the injected verifier (mockable in tests)
    let verified = match domain.challenge_type.as_str() {
        "dns-01" => state.challenge_verifier
            .verify_dns(&domain.domain, challenge_token, &state.settings.challenge)
            .await
            .map_err(|e| AppError::Internal(e))?,
        "http-01" => state.challenge_verifier
            .verify_http(&domain.domain, challenge_token, &state.settings.challenge)
            .await
            .map_err(|e| AppError::Internal(e))?,
        _ => return Err(AppError::Internal("unknown challenge type".into())),
    };

    if !verified {
        return Err(AppError::BadRequest("challenge verification failed".into()));
    }

    // Generate owner token (prefixed with domain ID for O(1) lookup)
    let owner_token = auth::generate_token(&id);
    let owner_token_hash = auth::hash_token(&owner_token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    // Update domain
    let mut active: domains::ActiveModel = domain.into();
    active.verified = Set(true);
    active.verified_at = Set(Some(chrono::Utc::now().naive_utc()));
    active.owner_token_hash = Set(owner_token_hash);
    active.challenge_token = Set(None);
    active.registration_secret = Set(String::new()); // Invalidate
    active.update(&state.db).await?;

    Ok(Json(json!({
        "verified": true,
        "owner_token": owner_token,
    })))
}

/// Extract and verify owner token from Authorization header.
/// The token format is `{domain_id}.{secret}` — the domain_id from the token
/// must match the `id` path parameter to prevent cross-domain access.
pub async fn authenticate_owner(
    db: &DatabaseConnection,
    id: &str,
    auth_header: Option<&str>,
) -> AppResult<domains::Model> {
    let full_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    // Verify the token's embedded ID matches the requested domain
    let (token_domain_id, _) = auth::split_token(full_token)
        .ok_or(AppError::Unauthorized)?;
    if token_domain_id != id {
        return Err(AppError::Unauthorized);
    }

    let domain = domains::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !domain.verified {
        return Err(AppError::Forbidden("domain not verified".into()));
    }

    if !auth::verify_token(full_token, &domain.owner_token_hash) {
        return Err(AppError::Unauthorized);
    }

    Ok(domain)
}

async fn get_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    Ok(Json(json!({
        "id": domain.id,
        "domain": domain.domain,
        "verified": domain.verified,
        "challenge_type": domain.challenge_type,
        "created_at": domain.created_at.to_string(),
        "verified_at": domain.verified_at.map(|v| v.to_string()),
    })))
}

async fn rotate_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    let new_token = auth::generate_token(&domain.id);
    let new_hash = auth::hash_token(&new_token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let mut active: domains::ActiveModel = domain.into();
    active.owner_token_hash = Set(new_hash);
    active.update(&state.db).await?;

    Ok(Json(json!({
        "owner_token": new_token,
    })))
}

async fn delete_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    // Query all resource URIs for this domain before deleting
    use crate::entity::resources;
    let resource_uris: Vec<String> = resources::Entity::find()
        .filter(resources::Column::DomainId.eq(&domain.id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|r| r.resource_uri)
        .collect();

    // Cascade: delete domain (FK cascades handle DB rows)
    domains::Entity::delete_by_id(&domain.id)
        .exec(&state.db)
        .await?;

    // Evict cache entries for all affected resources
    state.cache.remove_many(&resource_uris);

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/domains", post(create_domain))
        .route("/api/v1/domains/{id}", get(get_domain).delete(delete_domain))
        .route("/api/v1/domains/{id}/verify", post(verify_domain))
        .route("/api/v1/domains/{id}/rotate-token", post(rotate_token))
}
```

- [ ] **Step 5: Update handler/mod.rs and lib.rs**

Update `src/handler/mod.rs`:
```rust
pub mod domains;
mod health;
mod host_meta;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .merge(domains::router())
        .merge(health::router())
        .with_state(state)
}
```

Update `src/lib.rs`:
```rust
pub mod auth;
pub mod cache;
pub mod challenge;
pub mod config;
pub mod entity;
pub mod error;
pub mod handler;
pub mod state;
```

- [ ] **Step 6: Run tests**

Run: `cargo test --test test_domains`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/handler/domains.rs src/challenge.rs src/handler/mod.rs src/lib.rs tests/test_domains.rs
git commit -m "feat: add domain onboarding API with ACME-style challenges"
```

---

## Task 9: Service Token API

**Files:**
- Create: `src/handler/tokens.rs`
- Create: `tests/test_tokens.rs`
- Modify: `src/handler/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `tests/test_tokens.rs`:
```rust
mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

/// Helper: register a verified domain and return (id, owner_token).
/// Uses MockChallengeVerifier (injected in test state) so no manual DB manipulation needed.
async fn setup_verified_domain(
    server: &TestServer,
    _state: &webfingerd::state::AppState,
    domain_name: &str,
) -> (String, String) {
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": domain_name, "challenge_type": "dns-01"}))
        .await;
    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap().to_string();
    let reg_secret = body["registration_secret"].as_str().unwrap().to_string();

    // MockChallengeVerifier always succeeds
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    (id, owner_token)
}

#[tokio::test]
async fn test_create_service_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    let response = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["token"].is_string());
    assert_eq!(body["name"], "oxifed");
}

#[tokio::test]
async fn test_create_service_token_rejects_bad_pattern() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    // Pattern without @ or wrong domain
    let response = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "evil",
            "allowed_rels": ["self"],
            "resource_pattern": "*"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_list_service_tokens() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;

    let response = server
        .get(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    let tokens = body.as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["name"], "oxifed");
    // Token hash should NOT be exposed
    assert!(tokens[0].get("token_hash").is_none());
    assert!(tokens[0].get("token").is_none());
}

// NOTE: test_revoke_service_token_deletes_links is in tests/test_links.rs (Task 10)
// because it depends on the link registration endpoint. It is tested there as part
// of the full link lifecycle, not here where the endpoint doesn't exist yet.

#[tokio::test]
async fn test_revoke_service_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    let create_resp = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;
    let body: serde_json::Value = create_resp.json();
    let token_id = body["id"].as_str().unwrap().to_string();

    // Revoke the token
    let response = server
        .delete(&format!("/api/v1/domains/{id}/tokens/{token_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    response.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Token should no longer appear in list
    let list_resp = server
        .get(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let tokens = list_resp.json::<serde_json::Value>();
    let tokens = tokens.as_array().unwrap();
    assert!(tokens.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test test_tokens`
Expected: FAIL.

- [ ] **Step 3: Implement handler/tokens.rs**

Create `src/handler/tokens.rs`:
```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::entity::{domains, links, resources, service_tokens};
use crate::error::{AppError, AppResult};
use crate::handler::domains::authenticate_owner;
use crate::state::AppState;

fn validate_resource_pattern(pattern: &str, domain: &str) -> Result<(), String> {
    if !pattern.contains('@') {
        return Err("resource_pattern must contain '@'".into());
    }
    if pattern == "*" {
        return Err("resource_pattern '*' is too broad".into());
    }
    // Must end with the domain
    let domain_suffix = format!("@{domain}");
    if !pattern.ends_with(&domain_suffix) {
        return Err(format!(
            "resource_pattern must end with @{domain}"
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    name: String,
    allowed_rels: Vec<String>,
    resource_pattern: String,
}

async fn create_token(
    State(state): State<AppState>,
    Path(domain_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let domain = authenticate_owner(&state.db, &domain_id, auth_header).await?;

    validate_resource_pattern(&req.resource_pattern, &domain.domain)
        .map_err(|e| AppError::BadRequest(e))?;

    if req.allowed_rels.is_empty() {
        return Err(AppError::BadRequest("allowed_rels cannot be empty".into()));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let token = auth::generate_token(&id);
    let token_hash = auth::hash_token(&token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let service_token = service_tokens::ActiveModel {
        id: Set(id.clone()),
        domain_id: Set(domain_id),
        name: Set(req.name.clone()),
        token_hash: Set(token_hash),
        allowed_rels: Set(serde_json::to_string(&req.allowed_rels).unwrap()),
        resource_pattern: Set(req.resource_pattern.clone()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        revoked_at: Set(None),
    };

    service_token.insert(&state.db).await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": req.name,
            "token": token,
            "allowed_rels": req.allowed_rels,
            "resource_pattern": req.resource_pattern,
        })),
    ))
}

async fn list_tokens(
    State(state): State<AppState>,
    Path(domain_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    authenticate_owner(&state.db, &domain_id, auth_header).await?;

    let tokens = service_tokens::Entity::find()
        .filter(service_tokens::Column::DomainId.eq(&domain_id))
        .filter(service_tokens::Column::RevokedAt.is_null())
        .all(&state.db)
        .await?;

    let result: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "allowed_rels": serde_json::from_str::<serde_json::Value>(&t.allowed_rels).unwrap_or_default(),
                "resource_pattern": t.resource_pattern,
                "created_at": t.created_at.to_string(),
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

async fn revoke_token(
    State(state): State<AppState>,
    Path((domain_id, token_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    authenticate_owner(&state.db, &domain_id, auth_header).await?;

    let token = service_tokens::Entity::find_by_id(&token_id)
        .filter(service_tokens::Column::DomainId.eq(&domain_id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    // Find all resource URIs affected by links from this token
    let affected_links = links::Entity::find()
        .filter(links::Column::ServiceTokenId.eq(&token_id))
        .find_also_related(resources::Entity)
        .all(&state.db)
        .await?;

    let affected_resource_uris: Vec<String> = affected_links
        .iter()
        .filter_map(|(_, resource)| resource.as_ref().map(|r| r.resource_uri.clone()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Delete all links for this token
    links::Entity::delete_many()
        .filter(links::Column::ServiceTokenId.eq(&token_id))
        .exec(&state.db)
        .await?;

    // Mark token as revoked
    let mut active: service_tokens::ActiveModel = token.into();
    active.revoked_at = Set(Some(chrono::Utc::now().naive_utc()));
    active.update(&state.db).await?;

    // Refresh cache for affected resources
    for uri in affected_resource_uris {
        state.cache.refresh_resource(&state.db, &uri).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/domains/{id}/tokens",
            post(create_token).get(list_tokens),
        )
        .route(
            "/api/v1/domains/{id}/tokens/{tid}",
            delete(revoke_token),
        )
}
```

- [ ] **Step 4: Make authenticate_owner public and update handler/mod.rs**

In `src/handler/domains.rs`, change `authenticate_owner` to `pub async fn`.

Update `src/handler/mod.rs`:
```rust
pub mod domains;
mod health;
mod host_meta;
pub mod tokens;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .merge(domains::router())
        .merge(tokens::router())
        .merge(health::router())
        .with_state(state)
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test test_tokens`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/handler/tokens.rs src/handler/mod.rs src/handler/domains.rs tests/test_tokens.rs
git commit -m "feat: add service token CRUD with pattern validation and revocation cascade"
```

---

## Task 10: Link Registration API

**Files:**
- Create: `src/handler/links.rs`
- Create: `tests/test_links.rs`
- Modify: `src/handler/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `tests/test_links.rs`:
```rust
mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

/// Helper: create verified domain + service token, return (domain_id, owner_token, service_token).
/// Uses MockChallengeVerifier — no manual DB manipulation needed.
async fn setup_domain_and_token(
    server: &TestServer,
    _state: &webfingerd::state::AppState,
    domain_name: &str,
) -> (String, String, String) {
    // Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": domain_name, "challenge_type": "dns-01"}))
        .await;
    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap().to_string();
    let reg_secret = body["registration_secret"].as_str().unwrap().to_string();

    // MockChallengeVerifier always succeeds
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str().unwrap().to_string();

    // Create service token
    let token_resp = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self", "http://webfinger.net/rel/profile-page"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;
    let service_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str().unwrap().to_string();

    (id, owner_token, service_token)
}

#[tokio::test]
async fn test_register_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());

    // Should now be in cache and queryable
    let wf = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;
    wf.assert_status_ok();
    let jrd: serde_json::Value = wf.json();
    assert_eq!(jrd["subject"], "acct:alice@example.com");
    assert_eq!(jrd["links"][0]["rel"], "self");
}

#[tokio::test]
async fn test_register_link_rejected_for_forbidden_rel() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://evil.com"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_register_link_rejected_for_wrong_domain() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@evil.com",
            "rel": "self",
            "href": "https://evil.com/users/alice"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_upsert_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    // First insert
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Upsert with same (resource, rel, href) but different type
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/ld+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Should only have one link
    let wf = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;
    let jrd: serde_json::Value = wf.json();
    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["type"], "application/ld+json");
}

#[tokio::test]
async fn test_batch_link_registration() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links/batch")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "links": [
                {
                    "resource_uri": "acct:alice@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/alice",
                    "type": "application/activity+json"
                },
                {
                    "resource_uri": "acct:bob@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/bob",
                    "type": "application/activity+json"
                }
            ]
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);

    // Both should be queryable
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_ok();

    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:bob@example.com")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn test_batch_all_or_nothing() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    // Second link has forbidden rel — entire batch should fail
    let response = server
        .post("/api/v1/links/batch")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "links": [
                {
                    "resource_uri": "acct:alice@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/alice"
                },
                {
                    "resource_uri": "acct:bob@example.com",
                    "rel": "forbidden-rel",
                    "href": "https://example.com/users/bob"
                }
            ]
        }))
        .await;

    // Batch should fail
    response.assert_status(axum::http::StatusCode::FORBIDDEN);

    // alice should NOT be registered (all-or-nothing)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn test_delete_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let create_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice"
        }))
        .await;
    let link_id = create_resp.json::<serde_json::Value>()["id"]
        .as_str().unwrap().to_string();

    // Delete it
    server
        .delete(&format!("/api/v1/links/{link_id}"))
        .add_header("Authorization", format!("Bearer {service_token}"))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Should be gone
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn test_link_with_ttl() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "ttl_seconds": 300
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_revoke_service_token_deletes_links() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    let (id, owner_token, service_token) =
        setup_domain_and_token(&server, &state, "example.com").await;

    // Register a link
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Verify it exists
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_ok();

    // Extract the token ID from the service token (format: {id}.{secret})
    let token_id = service_token.split('.').next().unwrap();

    // Revoke the service token via owner API
    server
        .delete(&format!("/api/v1/domains/{id}/tokens/{token_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // WebFinger should no longer find the link (cascade delete + cache eviction)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test test_links`
Expected: FAIL.

- [ ] **Step 3: Implement handler/links.rs**

Create `src/handler/links.rs`:
```rust
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::entity::{domains, links, resources, service_tokens};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Authenticate a service token from the Authorization header.
/// Tokens use the format `{token_id}.{secret}` — split on `.`, look up by ID,
/// verify the full token against the stored hash. This is O(1) not O(n).
async fn authenticate_service(
    db: &DatabaseConnection,
    auth_header: Option<&str>,
) -> AppResult<(service_tokens::Model, domains::Model)> {
    let full_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let (token_id, _secret) = auth::split_token(full_token)
        .ok_or(AppError::Unauthorized)?;

    let token = service_tokens::Entity::find_by_id(token_id)
        .filter(service_tokens::Column::RevokedAt.is_null())
        .one(db)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !auth::verify_token(full_token, &token.token_hash) {
        return Err(AppError::Unauthorized);
    }

    let domain = domains::Entity::find_by_id(&token.domain_id)
        .one(db)
        .await?
        .ok_or(AppError::Internal("token domain not found".into()))?;

    if !domain.verified {
        return Err(AppError::Forbidden("domain not verified".into()));
    }

    Ok((token, domain))
}

/// Validate that a link is allowed by the service token's scope.
fn validate_scope(
    token: &service_tokens::Model,
    resource_uri: &str,
    rel: &str,
) -> AppResult<()> {
    // Check rel is allowed
    let allowed_rels: Vec<String> =
        serde_json::from_str(&token.allowed_rels).unwrap_or_default();
    if !allowed_rels.iter().any(|r| r == rel) {
        return Err(AppError::Forbidden(format!(
            "rel '{}' not in allowed_rels",
            rel
        )));
    }

    // Check resource matches pattern
    if !glob_match::glob_match(&token.resource_pattern, resource_uri) {
        return Err(AppError::Forbidden(format!(
            "resource '{}' does not match pattern '{}'",
            resource_uri, token.resource_pattern
        )));
    }

    Ok(())
}

/// Find or create a resource record for the given URI.
/// Accepts `&impl ConnectionTrait` for transaction support.
async fn find_or_create_resource(
    db: &impl sea_orm::ConnectionTrait,
    resource_uri: &str,
    domain_id: &str,
) -> AppResult<resources::Model> {
    if let Some(existing) = resources::Entity::find()
        .filter(resources::Column::ResourceUri.eq(resource_uri))
        .one(db)
        .await?
    {
        return Ok(existing);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    let resource = resources::ActiveModel {
        id: Set(id),
        domain_id: Set(domain_id.to_string()),
        resource_uri: Set(resource_uri.to_string()),
        aliases: Set(None),
        properties: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Ok(resource.insert(db).await?)
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    resource_uri: String,
    rel: String,
    href: Option<String>,
    #[serde(rename = "type")]
    link_type: Option<String>,
    titles: Option<serde_json::Value>,
    properties: Option<serde_json::Value>,
    template: Option<String>,
    ttl_seconds: Option<i32>,
    aliases: Option<Vec<String>>,
}

/// Insert or upsert a single link. Returns the link ID and the resource URI.
/// Accepts `&impl ConnectionTrait` so it works with both `DatabaseConnection` and
/// `DatabaseTransaction` (for all-or-nothing batch semantics).
/// When `refresh_cache` is true, immediately refreshes the cache entry.
/// Batch callers pass false and refresh after commit.
async fn insert_link(
    db: &impl sea_orm::ConnectionTrait,
    cache: &crate::cache::Cache,
    token: &service_tokens::Model,
    domain: &domains::Model,
    req: &CreateLinkRequest,
    db_for_cache: &DatabaseConnection,
    refresh_cache: bool,
) -> AppResult<(String, String)> {
    validate_scope(token, &req.resource_uri, &req.rel)?;

    let resource = find_or_create_resource(db, &req.resource_uri, &domain.id).await?;

    // Update aliases if provided
    if let Some(aliases) = &req.aliases {
        let mut active: resources::ActiveModel = resource.clone().into();
        active.aliases = Set(Some(serde_json::to_string(aliases).unwrap()));
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(db).await?;
    }

    let now = chrono::Utc::now().naive_utc();
    let expires_at = req
        .ttl_seconds
        .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

    // Check for existing link with same (resource_id, rel, href) for upsert
    let existing = links::Entity::find()
        .filter(links::Column::ResourceId.eq(&resource.id))
        .filter(links::Column::Rel.eq(&req.rel))
        .filter(
            match &req.href {
                Some(href) => links::Column::Href.eq(href.as_str()),
                None => links::Column::Href.is_null(),
            }
        )
        .one(db)
        .await?;

    let link_id = if let Some(existing) = existing {
        // Upsert: update existing
        let id = existing.id.clone();
        let mut active: links::ActiveModel = existing.into();
        active.link_type = Set(req.link_type.clone());
        active.titles = Set(req.titles.as_ref().map(|t| t.to_string()));
        active.properties = Set(req.properties.as_ref().map(|p| p.to_string()));
        active.template = Set(req.template.clone());
        active.ttl_seconds = Set(req.ttl_seconds);
        active.expires_at = Set(expires_at);
        active.update(db).await?;
        id
    } else {
        // Insert new
        let id = uuid::Uuid::new_v4().to_string();
        let link = links::ActiveModel {
            id: Set(id.clone()),
            resource_id: Set(resource.id.clone()),
            service_token_id: Set(token.id.clone()),
            domain_id: Set(domain.id.clone()),
            rel: Set(req.rel.clone()),
            href: Set(req.href.clone()),
            link_type: Set(req.link_type.clone()),
            titles: Set(req.titles.as_ref().map(|t| t.to_string())),
            properties: Set(req.properties.as_ref().map(|p| p.to_string())),
            template: Set(req.template.clone()),
            ttl_seconds: Set(req.ttl_seconds),
            created_at: Set(now),
            expires_at: Set(expires_at),
        };
        link.insert(db).await?;
        id
    };

    // Refresh cache if requested (single-link mode). Batch callers skip this
    // and refresh after commit to avoid reading stale data mid-transaction.
    if refresh_cache {
        cache.refresh_resource(db_for_cache, &req.resource_uri).await?;
    }

    Ok((link_id, req.resource_uri.clone()))
}

async fn create_link(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, domain) = authenticate_service(&state.db, auth_header).await?;

    let (link_id, _) = insert_link(&state.db, &state.cache, &token, &domain, &req, &state.db, true).await?;

    let expires_at = req
        .ttl_seconds
        .map(|ttl| {
            (chrono::Utc::now().naive_utc() + chrono::Duration::seconds(ttl as i64)).to_string()
        });

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": link_id,
            "expires_at": expires_at,
        })),
    ))
}

#[derive(Deserialize)]
pub struct BatchRequest {
    links: Vec<CreateLinkRequest>,
}

async fn batch_create_links(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BatchRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, domain) = authenticate_service(&state.db, auth_header).await?;

    if req.links.len() > state.settings.rate_limit.batch_max_links {
        return Err(AppError::BadRequest(format!(
            "batch exceeds maximum of {} links",
            state.settings.rate_limit.batch_max_links
        )));
    }

    // Validate all scopes first (fail fast before starting transaction)
    for (i, link_req) in req.links.iter().enumerate() {
        if let Err(e) = validate_scope(&token, &link_req.resource_uri, &link_req.rel) {
            return Err(AppError::Forbidden(format!("link[{}]: {}", i, e)));
        }
    }

    // All-or-nothing: wrap inserts in a DB transaction
    let txn = state.db.begin().await?;
    let mut results = Vec::new();
    let mut affected_uris = Vec::new();
    for link_req in &req.links {
        let (link_id, uri) =
            insert_link(&txn, &state.cache, &token, &domain, link_req, &state.db, false).await?;
        results.push(json!({"id": link_id}));
        affected_uris.push(uri);
    }
    txn.commit().await?;

    // Refresh cache after commit for all affected resources
    for uri in &affected_uris {
        state.cache.refresh_resource(&state.db, uri).await?;
    }

    Ok((StatusCode::CREATED, Json(json!({"links": results}))))
}

#[derive(Deserialize)]
pub struct ListLinksQuery {
    resource: Option<String>,
}

async fn list_links(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListLinksQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let mut q = links::Entity::find()
        .filter(links::Column::ServiceTokenId.eq(&token.id));

    if let Some(resource) = &query.resource {
        let resource_model = resources::Entity::find()
            .filter(resources::Column::ResourceUri.eq(resource.as_str()))
            .one(&state.db)
            .await?;
        if let Some(r) = resource_model {
            q = q.filter(links::Column::ResourceId.eq(&r.id));
        } else {
            return Ok(Json(json!([])));
        }
    }

    let all_links = q.all(&state.db).await?;

    let result: Vec<serde_json::Value> = all_links
        .into_iter()
        .map(|l| {
            json!({
                "id": l.id,
                "resource_id": l.resource_id,
                "rel": l.rel,
                "href": l.href,
                "type": l.link_type,
                "ttl_seconds": l.ttl_seconds,
                "created_at": l.created_at.to_string(),
                "expires_at": l.expires_at.map(|e| e.to_string()),
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

async fn update_link(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let link = links::Entity::find_by_id(&link_id)
        .filter(links::Column::ServiceTokenId.eq(&token.id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    validate_scope(&token, &req.resource_uri, &req.rel)?;

    let now = chrono::Utc::now().naive_utc();
    let expires_at = req
        .ttl_seconds
        .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

    let mut active: links::ActiveModel = link.into();
    active.rel = Set(req.rel.clone());
    active.href = Set(req.href.clone());
    active.link_type = Set(req.link_type.clone());
    active.titles = Set(req.titles.as_ref().map(|t| t.to_string()));
    active.properties = Set(req.properties.as_ref().map(|p| p.to_string()));
    active.template = Set(req.template.clone());
    active.ttl_seconds = Set(req.ttl_seconds);
    active.expires_at = Set(expires_at);
    active.update(&state.db).await?;

    state
        .cache
        .refresh_resource(&state.db, &req.resource_uri)
        .await?;

    Ok(Json(json!({"id": link_id})))
}

async fn delete_link(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let link = links::Entity::find_by_id(&link_id)
        .filter(links::Column::ServiceTokenId.eq(&token.id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let resource = resources::Entity::find_by_id(&link.resource_id)
        .one(&state.db)
        .await?;

    links::Entity::delete_by_id(&link_id)
        .exec(&state.db)
        .await?;

    // Refresh cache
    if let Some(resource) = resource {
        state
            .cache
            .refresh_resource(&state.db, &resource.resource_uri)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/links", post(create_link).get(list_links))
        .route(
            "/api/v1/links/{lid}",
            put(update_link).delete(delete_link),
        )
        .route("/api/v1/links/batch", post(batch_create_links))
}
```

- [ ] **Step 4: Update handler/mod.rs**

```rust
pub mod domains;
mod health;
mod host_meta;
pub mod links;
pub mod tokens;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .merge(domains::router())
        .merge(tokens::router())
        .merge(links::router())
        .merge(health::router())
        .with_state(state)
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test test_links`
Expected: All tests PASS.

- [ ] **Step 6: Run all tests**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/handler/links.rs src/handler/mod.rs tests/test_links.rs
git commit -m "feat: add link registration API with scope enforcement, upsert, and batch"
```

---

## Task 11: TTL Reaper

**Files:**
- Create: `src/reaper.rs`
- Create: `tests/test_reaper.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Write failing test**

Create `tests/test_reaper.rs`:
```rust
mod common;

use std::time::Duration;
use webfingerd::reaper;

#[tokio::test]
async fn test_reaper_expires_links() {
    let state = common::test_state().await;

    // Insert a resource + link that expires immediately
    use sea_orm::*;
    use webfingerd::entity::{domains, links, resources, service_tokens};
    use webfingerd::auth;

    let now = chrono::Utc::now().naive_utc();
    let past = now - chrono::Duration::seconds(60);

    // Create domain
    let domain = domains::ActiveModel {
        id: Set("d1".into()),
        domain: Set("example.com".into()),
        owner_token_hash: Set(auth::hash_token("test").unwrap()),
        registration_secret: Set(String::new()),
        challenge_type: Set("dns-01".into()),
        challenge_token: Set(None),
        verified: Set(true),
        created_at: Set(now),
        verified_at: Set(Some(now)),
    };
    domain.insert(&state.db).await.unwrap();

    // Create service token
    let token = service_tokens::ActiveModel {
        id: Set("t1".into()),
        domain_id: Set("d1".into()),
        name: Set("test".into()),
        token_hash: Set(auth::hash_token("test").unwrap()),
        allowed_rels: Set(r#"["self"]"#.into()),
        resource_pattern: Set("acct:*@example.com".into()),
        created_at: Set(now),
        revoked_at: Set(None),
    };
    token.insert(&state.db).await.unwrap();

    // Create resource
    let resource = resources::ActiveModel {
        id: Set("r1".into()),
        domain_id: Set("d1".into()),
        resource_uri: Set("acct:alice@example.com".into()),
        aliases: Set(None),
        properties: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    resource.insert(&state.db).await.unwrap();

    // Create expired link
    let link = links::ActiveModel {
        id: Set("l1".into()),
        resource_id: Set("r1".into()),
        service_token_id: Set("t1".into()),
        domain_id: Set("d1".into()),
        rel: Set("self".into()),
        href: Set(Some("https://example.com/users/alice".into())),
        link_type: Set(None),
        titles: Set(None),
        properties: Set(None),
        template: Set(None),
        ttl_seconds: Set(Some(1)),
        created_at: Set(past),
        expires_at: Set(Some(past + chrono::Duration::seconds(1))),
    };
    link.insert(&state.db).await.unwrap();

    // Hydrate cache
    state.cache.hydrate(&state.db).await.unwrap();

    // Should NOT be in cache (already expired)
    assert!(state.cache.get("acct:alice@example.com").is_none());

    // Run reaper once
    reaper::reap_once(&state.db, &state.cache).await.unwrap();

    // Link should be deleted from DB
    let remaining = links::Entity::find().all(&state.db).await.unwrap();
    assert!(remaining.is_empty());

    // Orphaned resource should also be cleaned up
    let remaining_resources = resources::Entity::find().all(&state.db).await.unwrap();
    assert!(remaining_resources.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test test_reaper`
Expected: FAIL.

- [ ] **Step 3: Implement reaper.rs**

Create `src/reaper.rs`:
```rust
use sea_orm::*;
use std::time::Duration;
use tokio::time;

use crate::cache::Cache;
use crate::entity::{links, resources};

/// Run a single reap cycle: delete expired links, clean up orphaned resources.
pub async fn reap_once(db: &DatabaseConnection, cache: &Cache) -> Result<(), DbErr> {
    let now = chrono::Utc::now().naive_utc();

    // Find expired links and their resource URIs
    let expired_links = links::Entity::find()
        .filter(links::Column::ExpiresAt.is_not_null())
        .filter(links::Column::ExpiresAt.lt(now))
        .find_also_related(resources::Entity)
        .all(db)
        .await?;

    let affected_resource_ids: std::collections::HashSet<String> = expired_links
        .iter()
        .map(|(link, _)| link.resource_id.clone())
        .collect();

    let affected_resource_uris: std::collections::HashMap<String, String> = expired_links
        .iter()
        .filter_map(|(link, resource)| {
            resource
                .as_ref()
                .map(|r| (link.resource_id.clone(), r.resource_uri.clone()))
        })
        .collect();

    if affected_resource_ids.is_empty() {
        return Ok(());
    }

    // Delete expired links
    let deleted = links::Entity::delete_many()
        .filter(links::Column::ExpiresAt.is_not_null())
        .filter(links::Column::ExpiresAt.lt(now))
        .exec(db)
        .await?;

    if deleted.rows_affected > 0 {
        tracing::info!(count = deleted.rows_affected, "reaped expired links");
    }

    // Clean up orphaned resources (resources with no remaining links)
    for resource_id in &affected_resource_ids {
        let link_count = links::Entity::find()
            .filter(links::Column::ResourceId.eq(resource_id.as_str()))
            .count(db)
            .await?;

        if link_count == 0 {
            resources::Entity::delete_by_id(resource_id)
                .exec(db)
                .await?;
        }
    }

    // Refresh cache for affected resources
    for (_, uri) in &affected_resource_uris {
        cache.refresh_resource(db, uri).await?;
    }

    Ok(())
}

/// Spawn the background reaper task.
pub fn spawn_reaper(db: DatabaseConnection, cache: Cache, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = reap_once(&db, &cache).await {
                tracing::error!("reaper error: {e}");
            }
        }
    });
}
```

- [ ] **Step 4: Update lib.rs and main.rs**

Add to `src/lib.rs`:
```rust
pub mod reaper;
```

Add reaper spawn to `src/main.rs` after cache hydration:
```rust
    // Spawn TTL reaper
    webfingerd::reaper::spawn_reaper(
        state.db.clone(),
        state.cache.clone(),
        settings.cache.reaper_interval_secs,
    );
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test test_reaper`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/reaper.rs src/lib.rs src/main.rs tests/test_reaper.rs
git commit -m "feat: add background TTL reaper with orphaned resource cleanup"
```

---

## Task 12: Middleware (Rate Limiting, Request ID, CORS)

**Files:**
- Create: `src/middleware/mod.rs`, `src/middleware/rate_limit.rs`, `src/middleware/request_id.rs`
- Create: `tests/test_rate_limit.rs`
- Modify: `src/lib.rs`, `src/handler/mod.rs`

- [ ] **Step 1: Write failing rate limit test**

Create `tests/test_rate_limit.rs`:
```rust
mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_public_rate_limiting() {
    let mut settings = common::test_settings();
    settings.rate_limit.public_rpm = 2; // Very low for testing

    let state = common::test_state_with_settings(settings).await;
    let app = handler::router(state);
    let server = TestServer::new(app).unwrap();

    // First two requests should succeed (even with 404)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:a@a.com")
        .await;
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:b@b.com")
        .await;

    // Third should be rate limited
    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:c@c.com")
        .await;

    response.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}
```

- [ ] **Step 2: Verify test_state_with_settings exists in common/mod.rs**

`test_state_with_settings` was already added in Task 5. No changes needed.

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test test_rate_limit`
Expected: FAIL.

- [ ] **Step 4: Implement middleware**

Create `src/middleware/mod.rs`:
```rust
pub mod rate_limit;
pub mod request_id;
```

Create `src/middleware/request_id.rs`:
```rust
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

// Note: axum 0.8 Next is not generic over body type
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let id = Uuid::new_v4().to_string();
    request
        .headers_mut()
        .insert(X_REQUEST_ID.clone(), HeaderValue::from_str(&id).unwrap());

    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(X_REQUEST_ID.clone(), HeaderValue::from_str(&id).unwrap());

    response
}
```

Create `src/middleware/rate_limit.rs`:
```rust
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Per-key rate limiter using DashMap for keyed limiting (per IP or per token).
#[derive(Clone)]
pub struct KeyedLimiter {
    limiters: Arc<DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    quota: Quota,
}

impl KeyedLimiter {
    pub fn new(rpm: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(rpm).expect("rpm must be > 0"));
        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
        }
    }

    pub fn check_key(&self, key: &str) -> bool {
        let limiter = self.limiters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)))
            .clone();
        limiter.check().is_ok()
    }
}

/// Rate limit middleware for public endpoints (keyed by client IP).
// Note: axum 0.8 Next is not generic over body type
pub async fn rate_limit_by_ip(
    limiter: KeyedLimiter,
    request: Request,
    next: Next,
) -> Response {
    // Extract IP from x-forwarded-for or connection info
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if !limiter.check_key(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            "rate limited",
        )
            .into_response();
    }

    next.run(request).await
}

/// Rate limit middleware for API endpoints (keyed by Bearer token prefix).
pub async fn rate_limit_by_token(
    limiter: KeyedLimiter,
    request: Request,
    next: Next,
) -> Response {
    let key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|t| t.split('.').next()) // Use token ID prefix as key
        .unwrap_or("anonymous")
        .to_string();

    if !limiter.check_key(&key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            "rate limited",
        )
            .into_response();
    }

    next.run(request).await
}
```

- [ ] **Step 5: Wire middleware into handler/mod.rs**

Update `src/handler/mod.rs` to apply rate limiting and CORS:
```rust
pub mod domains;
mod health;
mod host_meta;
pub mod links;
pub mod tokens;
mod webfinger;

use axum::middleware as axum_mw;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use crate::middleware::rate_limit::KeyedLimiter;
use crate::middleware::rate_limit;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let public_limiter = KeyedLimiter::new(state.settings.rate_limit.public_rpm);
    let api_limiter = KeyedLimiter::new(state.settings.rate_limit.api_rpm);

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public endpoints: webfinger + host-meta with per-IP rate limit + CORS
    let public_routes = Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .layer(public_cors)
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = public_limiter.clone();
            rate_limit::rate_limit_by_ip(limiter, req, next)
        }));

    // API endpoints with per-token rate limit (no wildcard CORS)
    let api_routes = Router::new()
        .merge(domains::router())
        .merge(tokens::router())
        .merge(links::router())
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = api_limiter.clone();
            rate_limit::rate_limit_by_token(limiter, req, next)
        }));

    Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .merge(health::router())
        .with_state(state)
}
```

- [ ] **Step 6: Update lib.rs**

Add `pub mod middleware;` to `src/lib.rs`.

- [ ] **Step 7: Run tests**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add src/middleware/ src/handler/mod.rs src/lib.rs tests/test_rate_limit.rs tests/common/mod.rs
git commit -m "feat: add rate limiting, request ID, and CORS middleware"
```

---

## Task 13: Prometheus Metrics + Metrics Endpoint

**Files:**
- Create: `src/handler/metrics.rs`
- Modify: `src/handler/mod.rs`, `src/handler/webfinger.rs`, `src/handler/health.rs`, `src/state.rs`

- [ ] **Step 1: Set up metrics recorder in state.rs**

Add to `src/state.rs`:
```rust
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub cache: Cache,
    pub settings: Arc<Settings>,
    pub metrics_handle: PrometheusHandle,
}
```

- [ ] **Step 2: Create metrics endpoint**

Create `src/handler/metrics.rs`:
```rust
use axum::extract::State;
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics_handle.render()
}

pub fn router() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}
```

- [ ] **Step 3: Add metrics recording to webfinger handler**

Add to `src/handler/webfinger.rs` at the start of the `webfinger` function:
```rust
    metrics::counter!("webfinger_queries_total", "domain" => resource_domain.clone(), "status" => "...").increment(1);
```

Instrument the handler to record `webfinger_queries_total` and `webfinger_query_duration_seconds`. Extract the domain from the resource parameter for labeling.

- [ ] **Step 4: Update main.rs to initialize metrics**

In `src/main.rs`:
```rust
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install metrics recorder");
```

Pass `metrics_handle` into `AppState`.

- [ ] **Step 5: Wire metrics route in handler/mod.rs**

Add `mod metrics;` and merge `metrics::router()` into the router.

- [ ] **Step 6: Update health.rs to check DB and cache**

```rust
async fn healthz(State(state): State<AppState>) -> StatusCode {
    match state.db.execute(Statement::from_string(
        sea_orm::DatabaseBackend::Sqlite,
        "SELECT 1".to_string(),
    )).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
```

- [ ] **Step 7: Run all tests, fix any failures**

Run: `cargo test`
Expected: All tests PASS (may need to update test_state to include metrics_handle).

- [ ] **Step 8: Commit**

```bash
git add src/handler/metrics.rs src/handler/mod.rs src/handler/webfinger.rs src/handler/health.rs src/state.rs src/main.rs tests/common/mod.rs
git commit -m "feat: add Prometheus metrics endpoint and query instrumentation"
```

---

## Task 14: Web UI

**Files:**
- Create: `src/ui/mod.rs`, `src/ui/handlers.rs`, `src/ui/templates.rs`
- Create: `src/templates/layout.html`, `src/templates/login.html`, `src/templates/dashboard.html`
- Create: `src/templates/domain_detail.html`, `src/templates/token_management.html`
- Create: `src/templates/link_browser.html`
- Modify: `src/lib.rs`, `src/handler/mod.rs`

- [ ] **Step 1: Create askama templates**

Create `src/templates/layout.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}webfingerd{% endblock %}</title>
  <style>
    :root { --bg: #fafafa; --fg: #222; --accent: #2563eb; --border: #ddd; --muted: #666; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); max-width: 960px; margin: 0 auto; padding: 1rem; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1.5rem; }
    header h1 { font-size: 1.25rem; }
    header a { color: var(--accent); text-decoration: none; }
    a { color: var(--accent); }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { font-weight: 600; color: var(--muted); font-size: 0.875rem; }
    .btn { display: inline-block; padding: 0.4rem 0.8rem; background: var(--accent); color: #fff; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 0.875rem; }
    .btn-danger { background: #dc2626; }
    input, textarea { padding: 0.4rem; border: 1px solid var(--border); border-radius: 4px; width: 100%; margin-bottom: 0.5rem; }
    label { display: block; font-weight: 600; margin-bottom: 0.25rem; font-size: 0.875rem; }
    .card { background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; }
    .badge-green { background: #dcfce7; color: #166534; }
    .badge-yellow { background: #fef9c3; color: #854d0e; }
    .flash { padding: 0.75rem; margin-bottom: 1rem; border-radius: 4px; }
    .flash-error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
    .flash-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
  </style>
</head>
<body>
  <header>
    <h1>webfingerd</h1>
    {% block nav %}{% endblock %}
  </header>
  {% block content %}{% endblock %}
</body>
</html>
```

Create `src/templates/login.html`:
```html
{% extends "layout.html" %}
{% block title %}Login - webfingerd{% endblock %}
{% block content %}
<div class="card" style="max-width: 400px; margin: 2rem auto;">
  <h2 style="margin-bottom: 1rem;">Domain Owner Login</h2>
  {% if let Some(error) = error %}
  <div class="flash flash-error">{{ error }}</div>
  {% endif %}
  <form method="post" action="/ui/login">
    <label for="token">Owner Token</label>
    <input type="password" name="token" id="token" required placeholder="Paste your owner token">
    <button type="submit" class="btn" style="width: 100%; margin-top: 0.5rem;">Login</button>
  </form>
</div>
{% endblock %}
```

Create `src/templates/dashboard.html`:
```html
{% extends "layout.html" %}
{% block title %}Dashboard - webfingerd{% endblock %}
{% block nav %}<a href="/ui/logout">Logout</a>{% endblock %}
{% block content %}
<h2>Your Domains</h2>
{% if domains.is_empty() %}
<p>No domains found for this token.</p>
{% else %}
<table>
  <thead><tr><th>Domain</th><th>Status</th><th>Links</th><th></th></tr></thead>
  <tbody>
  {% for d in domains %}
  <tr>
    <td><a href="/ui/domains/{{ d.id }}">{{ d.domain }}</a></td>
    <td>{% if d.verified %}<span class="badge badge-green">Verified</span>{% else %}<span class="badge badge-yellow">Pending</span>{% endif %}</td>
    <td>{{ d.link_count }}</td>
    <td><a href="/ui/domains/{{ d.id }}">Manage</a></td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}
{% endblock %}
```

Create `src/templates/domain_detail.html`, `src/templates/token_management.html`, `src/templates/link_browser.html` with similar patterns (forms for creating/revoking tokens, tables for browsing links).

- [ ] **Step 2: Implement UI module**

Create `src/ui/mod.rs`:
```rust
pub mod handlers;
pub mod templates;

use axum::Router;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    handlers::router()
}
```

Create `src/ui/templates.rs` with askama template structs:
```rust
use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub domains: Vec<DomainSummary>,
}

pub struct DomainSummary {
    pub id: String,
    pub domain: String,
    pub verified: bool,
    pub link_count: u64,
}

// ... additional template structs for domain_detail, token_management, link_browser
```

Create `src/ui/handlers.rs` with the route handlers for login, dashboard, domain detail, token management, and link browser pages.

- [ ] **Step 3: Wire UI into handler/mod.rs**

Conditionally merge `ui::router()` based on `settings.ui.enabled`.

- [ ] **Step 4: Verify compilation and basic manual testing**

Run: `cargo build`
Expected: Compiles. Manual smoke test by running the server and visiting `/ui/login`.

- [ ] **Step 5: Commit**

```bash
git add src/ui/ src/templates/ src/handler/mod.rs src/lib.rs
git commit -m "feat: add server-rendered web UI for domain owner management"
```

---

## Task 15: Structured Logging + main.rs Finalization

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Finalize main.rs**

Ensure `src/main.rs` has:
- Tracing with JSON output and env filter
- Database connection with WAL mode
- Migrations
- Cache hydration
- Metrics recorder installation
- Reaper spawn
- Full router assembly
- Graceful shutdown via `tokio::signal::ctrl_c`

```rust
    // Graceful shutdown
    let listener = tokio::net::TcpListener::bind(&settings.server.listen)
        .await
        .expect("failed to bind");
    tracing::info!(listen = %settings.server.listen, "webfingerd started");

    axum::serve(listener, handler::router(state))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down");
        })
        .await
        .expect("server error");
```

- [ ] **Step 2: Verify full build and all tests**

Run: `cargo build && cargo test`
Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: finalize main.rs with graceful shutdown and full wiring"
```

---

## Task 16: Integration Test — Full Flow

**Files:**
- Create: `tests/test_full_flow.rs`

- [ ] **Step 1: Write end-to-end integration test**

Create `tests/test_full_flow.rs`:
```rust
mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

#[tokio::test]
async fn test_full_webfinger_flow() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app).unwrap();

    // 1. Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "social.alice.example", "challenge_type": "dns-01"}))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = create_resp.json();
    let domain_id = body["id"].as_str().unwrap().to_string();
    let reg_secret = body["registration_secret"].as_str().unwrap().to_string();

    // 2. Verify domain (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str().unwrap().to_string();

    // 3. Create service token for ActivityPub
    let token_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self", "http://webfinger.net/rel/profile-page"],
            "resource_pattern": "acct:*@social.alice.example"
        }))
        .await;
    token_resp.assert_status(axum::http::StatusCode::CREATED);
    let ap_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str().unwrap().to_string();

    // 4. Create service token for OIDC
    let token_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "barycenter",
            "allowed_rels": ["http://openid.net/specs/connect/1.0/issuer"],
            "resource_pattern": "acct:*@social.alice.example"
        }))
        .await;
    let oidc_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str().unwrap().to_string();

    // 5. oxifed registers ActivityPub links
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "self",
            "href": "https://social.alice.example/users/alice",
            "type": "application/activity+json",
            "aliases": ["https://social.alice.example/@alice"]
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://webfinger.net/rel/profile-page",
            "href": "https://social.alice.example/@alice",
            "type": "text/html"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // 6. barycenter registers OIDC issuer link
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {oidc_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://auth.alice.example"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // 7. Query WebFinger — should return all three links
    let wf_resp = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@social.alice.example")
        .await;
    wf_resp.assert_status_ok();
    let jrd: serde_json::Value = wf_resp.json();

    assert_eq!(jrd["subject"], "acct:alice@social.alice.example");
    assert_eq!(jrd["aliases"][0], "https://social.alice.example/@alice");

    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 3);

    // 8. Filter by rel
    let wf_resp = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@social.alice.example")
        .add_query_param("rel", "self")
        .await;
    let jrd: serde_json::Value = wf_resp.json();
    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["rel"], "self");
    // aliases should still be present despite rel filter
    assert!(jrd["aliases"].is_array());

    // 9. Verify scope isolation: oxifed can't register OIDC links
    let bad_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://evil.com"
        }))
        .await;
    bad_resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // 10. Verify scope isolation: barycenter can't register AP links
    let bad_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {oidc_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "self",
            "href": "https://evil.com"
        }))
        .await;
    bad_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
```

- [ ] **Step 2: Run the full flow test**

Run: `cargo test --test test_full_flow`
Expected: PASS.

- [ ] **Step 3: Run entire test suite**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_full_flow.rs
git commit -m "test: add full integration test covering multi-service WebFinger flow"
```

---

## Summary

16 tasks covering:

1. **Project scaffold + config** — Cargo workspace, Settings, AppError
2. **Database migrations** — 4 tables with foreign keys and unique constraints
3. **SeaORM entities** — Type-safe ORM models for all tables
4. **AppState + cache + auth** — DashMap cache, argon2 auth helpers, DB bootstrap
5. **Test helpers** — In-memory DB setup for all tests
6. **WebFinger query endpoint** — RFC 7033 compliant with rel filtering + CORS
7. **host-meta endpoint** — RFC 6415 XRD with domain-aware routing
8. **Domain onboarding API** — Registration, DNS/HTTP challenges, verification, token rotation
9. **Service token API** — CRUD with pattern validation and revocation cascade
10. **Link registration API** — CRUD, upsert, batch (all-or-nothing), scope enforcement
11. **TTL reaper** — Background task for expiring links + orphaned resource cleanup
12. **Middleware** — Rate limiting, request IDs, CORS
13. **Metrics** — Prometheus endpoint + query instrumentation
14. **Web UI** — Server-rendered askama templates for domain management
15. **main.rs finalization** — Full wiring, graceful shutdown
16. **Integration test** — End-to-end multi-service WebFinger flow
