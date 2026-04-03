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
                            .to(
                                super::m20260403_000001_create_domains::Domains::Table,
                                super::m20260403_000001_create_domains::Domains::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ServiceTokens::Table).to_owned())
            .await
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
