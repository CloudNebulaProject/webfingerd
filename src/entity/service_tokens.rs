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
