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
