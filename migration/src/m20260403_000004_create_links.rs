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
                            .to(
                                super::m20260403_000002_create_resources::Resources::Table,
                                super::m20260403_000002_create_resources::Resources::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Links::Table, Links::ServiceTokenId)
                            .to(
                                super::m20260403_000003_create_service_tokens::ServiceTokens::Table,
                                super::m20260403_000003_create_service_tokens::ServiceTokens::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Links::Table, Links::DomainId)
                            .to(
                                super::m20260403_000001_create_domains::Domains::Table,
                                super::m20260403_000001_create_domains::Domains::Id,
                            )
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
        manager
            .drop_table(Table::drop().table(Links::Table).to_owned())
            .await
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
