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
