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
            self.inner.remove(uri.as_str());
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
