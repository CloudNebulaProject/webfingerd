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
            .drop_table(Table::drop().table(Resources::Table).to_owned())
            .await
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
