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
        manager
            .drop_table(Table::drop().table(Domains::Table).to_owned())
            .await
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
