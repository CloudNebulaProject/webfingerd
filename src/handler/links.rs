use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{post, put};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::entity::{domains, links, resources, service_tokens};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Authenticate a service token from the Authorization header.
/// Tokens use the format `{token_id}.{secret}` -- split on `.`, look up by ID,
/// verify the full token against the stored hash. This is O(1) not O(n).
async fn authenticate_service(
    db: &DatabaseConnection,
    auth_header: Option<&str>,
) -> AppResult<(service_tokens::Model, domains::Model)> {
    let full_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let (token_id, _secret) = auth::split_token(full_token)
        .ok_or(AppError::Unauthorized)?;

    let token = service_tokens::Entity::find_by_id(token_id)
        .filter(service_tokens::Column::RevokedAt.is_null())
        .one(db)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !auth::verify_token(full_token, &token.token_hash) {
        return Err(AppError::Unauthorized);
    }

    let domain = domains::Entity::find_by_id(&token.domain_id)
        .one(db)
        .await?
        .ok_or(AppError::Internal("token domain not found".into()))?;

    if !domain.verified {
        return Err(AppError::Forbidden("domain not verified".into()));
    }

    Ok((token, domain))
}

/// Validate that a link is allowed by the service token's scope.
fn validate_scope(
    token: &service_tokens::Model,
    resource_uri: &str,
    rel: &str,
) -> AppResult<()> {
    // Check rel is allowed
    let allowed_rels: Vec<String> =
        serde_json::from_str(&token.allowed_rels).unwrap_or_default();
    if !allowed_rels.iter().any(|r| r == rel) {
        return Err(AppError::Forbidden(format!(
            "rel '{}' not in allowed_rels",
            rel
        )));
    }

    // Check resource matches pattern
    if !glob_match::glob_match(&token.resource_pattern, resource_uri) {
        return Err(AppError::Forbidden(format!(
            "resource '{}' does not match pattern '{}'",
            resource_uri, token.resource_pattern
        )));
    }

    Ok(())
}

/// Find or create a resource record for the given URI.
/// Accepts `&impl ConnectionTrait` for transaction support.
async fn find_or_create_resource(
    db: &impl sea_orm::ConnectionTrait,
    resource_uri: &str,
    domain_id: &str,
) -> AppResult<resources::Model> {
    if let Some(existing) = resources::Entity::find()
        .filter(resources::Column::ResourceUri.eq(resource_uri))
        .one(db)
        .await?
    {
        return Ok(existing);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    let resource = resources::ActiveModel {
        id: Set(id),
        domain_id: Set(domain_id.to_string()),
        resource_uri: Set(resource_uri.to_string()),
        aliases: Set(None),
        properties: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Ok(resource.insert(db).await?)
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    resource_uri: String,
    rel: String,
    href: Option<String>,
    #[serde(rename = "type")]
    link_type: Option<String>,
    titles: Option<serde_json::Value>,
    properties: Option<serde_json::Value>,
    template: Option<String>,
    ttl_seconds: Option<i32>,
    aliases: Option<Vec<String>>,
}

/// Insert or upsert a single link. Returns the link ID and the resource URI.
/// Accepts `&impl ConnectionTrait` so it works with both `DatabaseConnection` and
/// `DatabaseTransaction` (for all-or-nothing batch semantics).
/// When `refresh_cache` is true, immediately refreshes the cache entry.
/// Batch callers pass false and refresh after commit.
async fn insert_link(
    db: &impl sea_orm::ConnectionTrait,
    cache: &crate::cache::Cache,
    token: &service_tokens::Model,
    domain: &domains::Model,
    req: &CreateLinkRequest,
    db_for_cache: &DatabaseConnection,
    refresh_cache: bool,
) -> AppResult<(String, String)> {
    validate_scope(token, &req.resource_uri, &req.rel)?;

    let resource = find_or_create_resource(db, &req.resource_uri, &domain.id).await?;

    // Update aliases if provided
    if let Some(aliases) = &req.aliases {
        let mut active: resources::ActiveModel = resource.clone().into();
        active.aliases = Set(Some(serde_json::to_string(aliases).unwrap()));
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        active.update(db).await?;
    }

    let now = chrono::Utc::now().naive_utc();
    let expires_at = req
        .ttl_seconds
        .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

    // Check for existing link with same (resource_id, rel, href) for upsert
    let existing = links::Entity::find()
        .filter(links::Column::ResourceId.eq(&resource.id))
        .filter(links::Column::Rel.eq(&req.rel))
        .filter(match &req.href {
            Some(href) => links::Column::Href.eq(href.as_str()),
            None => links::Column::Href.is_null(),
        })
        .one(db)
        .await?;

    let link_id = if let Some(existing) = existing {
        // Upsert: update existing
        let id = existing.id.clone();
        let mut active: links::ActiveModel = existing.into();
        active.link_type = Set(req.link_type.clone());
        active.titles = Set(req.titles.as_ref().map(|t| t.to_string()));
        active.properties = Set(req.properties.as_ref().map(|p| p.to_string()));
        active.template = Set(req.template.clone());
        active.ttl_seconds = Set(req.ttl_seconds);
        active.expires_at = Set(expires_at);
        active.update(db).await?;
        id
    } else {
        // Insert new
        let id = uuid::Uuid::new_v4().to_string();
        let link = links::ActiveModel {
            id: Set(id.clone()),
            resource_id: Set(resource.id.clone()),
            service_token_id: Set(token.id.clone()),
            domain_id: Set(domain.id.clone()),
            rel: Set(req.rel.clone()),
            href: Set(req.href.clone()),
            link_type: Set(req.link_type.clone()),
            titles: Set(req.titles.as_ref().map(|t| t.to_string())),
            properties: Set(req.properties.as_ref().map(|p| p.to_string())),
            template: Set(req.template.clone()),
            ttl_seconds: Set(req.ttl_seconds),
            created_at: Set(now),
            expires_at: Set(expires_at),
        };
        link.insert(db).await?;
        id
    };

    // Refresh cache if requested (single-link mode). Batch callers skip this
    // and refresh after commit to avoid reading stale data mid-transaction.
    if refresh_cache {
        cache.refresh_resource(db_for_cache, &req.resource_uri).await?;
    }

    Ok((link_id, req.resource_uri.clone()))
}

async fn create_link(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, domain) = authenticate_service(&state.db, auth_header).await?;

    let (link_id, _) =
        insert_link(&state.db, &state.cache, &token, &domain, &req, &state.db, true).await?;

    let expires_at = req.ttl_seconds.map(|ttl| {
        (chrono::Utc::now().naive_utc() + chrono::Duration::seconds(ttl as i64)).to_string()
    });

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": link_id,
            "expires_at": expires_at,
        })),
    ))
}

#[derive(Deserialize)]
pub struct BatchRequest {
    links: Vec<CreateLinkRequest>,
}

async fn batch_create_links(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BatchRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, domain) = authenticate_service(&state.db, auth_header).await?;

    if req.links.len() > state.settings.rate_limit.batch_max_links {
        return Err(AppError::BadRequest(format!(
            "batch exceeds maximum of {} links",
            state.settings.rate_limit.batch_max_links
        )));
    }

    // Validate all scopes first (fail fast before starting transaction)
    for (i, link_req) in req.links.iter().enumerate() {
        if let Err(e) = validate_scope(&token, &link_req.resource_uri, &link_req.rel) {
            return Err(AppError::Forbidden(format!("link[{}]: {}", i, e)));
        }
    }

    // All-or-nothing: wrap inserts in a DB transaction
    let txn = state.db.begin().await?;
    let mut results = Vec::new();
    let mut affected_uris = Vec::new();
    for link_req in &req.links {
        let (link_id, uri) =
            insert_link(&txn, &state.cache, &token, &domain, link_req, &state.db, false).await?;
        results.push(json!({"id": link_id}));
        affected_uris.push(uri);
    }
    txn.commit().await?;

    // Refresh cache after commit for all affected resources
    for uri in &affected_uris {
        state.cache.refresh_resource(&state.db, uri).await?;
    }

    Ok((StatusCode::CREATED, Json(json!({"links": results}))))
}

#[derive(Deserialize)]
pub struct ListLinksQuery {
    resource: Option<String>,
}

async fn list_links(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListLinksQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let mut q = links::Entity::find()
        .filter(links::Column::ServiceTokenId.eq(&token.id));

    if let Some(resource) = &query.resource {
        let resource_model = resources::Entity::find()
            .filter(resources::Column::ResourceUri.eq(resource.as_str()))
            .one(&state.db)
            .await?;
        if let Some(r) = resource_model {
            q = q.filter(links::Column::ResourceId.eq(&r.id));
        } else {
            return Ok(Json(json!([])));
        }
    }

    let all_links = q.all(&state.db).await?;

    let result: Vec<serde_json::Value> = all_links
        .into_iter()
        .map(|l| {
            json!({
                "id": l.id,
                "resource_id": l.resource_id,
                "rel": l.rel,
                "href": l.href,
                "type": l.link_type,
                "ttl_seconds": l.ttl_seconds,
                "created_at": l.created_at.to_string(),
                "expires_at": l.expires_at.map(|e| e.to_string()),
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

async fn update_link(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateLinkRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let link = links::Entity::find_by_id(&link_id)
        .filter(links::Column::ServiceTokenId.eq(&token.id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    validate_scope(&token, &req.resource_uri, &req.rel)?;

    let now = chrono::Utc::now().naive_utc();
    let expires_at = req
        .ttl_seconds
        .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

    let mut active: links::ActiveModel = link.into();
    active.rel = Set(req.rel.clone());
    active.href = Set(req.href.clone());
    active.link_type = Set(req.link_type.clone());
    active.titles = Set(req.titles.as_ref().map(|t| t.to_string()));
    active.properties = Set(req.properties.as_ref().map(|p| p.to_string()));
    active.template = Set(req.template.clone());
    active.ttl_seconds = Set(req.ttl_seconds);
    active.expires_at = Set(expires_at);
    active.update(&state.db).await?;

    state
        .cache
        .refresh_resource(&state.db, &req.resource_uri)
        .await?;

    Ok(Json(json!({"id": link_id})))
}

async fn delete_link(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (token, _) = authenticate_service(&state.db, auth_header).await?;

    let link = links::Entity::find_by_id(&link_id)
        .filter(links::Column::ServiceTokenId.eq(&token.id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let resource = resources::Entity::find_by_id(&link.resource_id)
        .one(&state.db)
        .await?;

    links::Entity::delete_by_id(&link_id)
        .exec(&state.db)
        .await?;

    // Refresh cache
    if let Some(resource) = resource {
        state
            .cache
            .refresh_resource(&state.db, &resource.resource_uri)
            .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/links", post(create_link).get(list_links))
        .route(
            "/api/v1/links/{lid}",
            put(update_link).delete(delete_link),
        )
        .route("/api/v1/links/batch", post(batch_create_links))
}
