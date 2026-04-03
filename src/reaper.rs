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
