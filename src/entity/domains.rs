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
