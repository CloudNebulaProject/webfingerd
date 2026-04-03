use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::entity::{links, resources, service_tokens};
use crate::error::{AppError, AppResult};
use crate::handler::domains::authenticate_owner;
use crate::state::AppState;

fn validate_resource_pattern(pattern: &str, domain: &str) -> Result<(), String> {
    if !pattern.contains('@') {
        return Err("resource_pattern must contain '@'".into());
    }
    if pattern == "*" {
        return Err("resource_pattern '*' is too broad".into());
    }
    // Must end with the domain
    let domain_suffix = format!("@{domain}");
    if !pattern.ends_with(&domain_suffix) {
        return Err(format!("resource_pattern must end with @{domain}"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    name: String,
    allowed_rels: Vec<String>,
    resource_pattern: String,
}

async fn create_token(
    State(state): State<AppState>,
    Path(domain_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let domain = authenticate_owner(&state.db, &domain_id, auth_header).await?;

    validate_resource_pattern(&req.resource_pattern, &domain.domain)
        .map_err(|e| AppError::BadRequest(e))?;

    if req.allowed_rels.is_empty() {
        return Err(AppError::BadRequest("allowed_rels cannot be empty".into()));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let token = auth::generate_token(&id);
    let token_hash = auth::hash_token(&token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let service_token = service_tokens::ActiveModel {
        id: Set(id.clone()),
        domain_id: Set(domain_id),
        name: Set(req.name.clone()),
        token_hash: Set(token_hash),
        allowed_rels: Set(serde_json::to_string(&req.allowed_rels).unwrap()),
        resource_pattern: Set(req.resource_pattern.clone()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        revoked_at: Set(None),
    };

    service_token.insert(&state.db).await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": req.name,
            "token": token,
            "allowed_rels": req.allowed_rels,
            "resource_pattern": req.resource_pattern,
        })),
    ))
}

async fn list_tokens(
    State(state): State<AppState>,
    Path(domain_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    authenticate_owner(&state.db, &domain_id, auth_header).await?;

    let tokens = service_tokens::Entity::find()
        .filter(service_tokens::Column::DomainId.eq(&domain_id))
        .filter(service_tokens::Column::RevokedAt.is_null())
        .all(&state.db)
        .await?;

    let result: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "allowed_rels": serde_json::from_str::<serde_json::Value>(&t.allowed_rels).unwrap_or_default(),
                "resource_pattern": t.resource_pattern,
                "created_at": t.created_at.to_string(),
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

async fn revoke_token(
    State(state): State<AppState>,
    Path((domain_id, token_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    authenticate_owner(&state.db, &domain_id, auth_header).await?;

    let token = service_tokens::Entity::find_by_id(&token_id)
        .filter(service_tokens::Column::DomainId.eq(&domain_id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    // Find all resource URIs affected by links from this token
    let affected_links = links::Entity::find()
        .filter(links::Column::ServiceTokenId.eq(&token_id))
        .find_also_related(resources::Entity)
        .all(&state.db)
        .await?;

    let affected_resource_uris: Vec<String> = affected_links
        .iter()
        .filter_map(|(_, resource)| resource.as_ref().map(|r| r.resource_uri.clone()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Delete all links for this token
    links::Entity::delete_many()
        .filter(links::Column::ServiceTokenId.eq(&token_id))
        .exec(&state.db)
        .await?;

    // Mark token as revoked
    let mut active: service_tokens::ActiveModel = token.into();
    active.revoked_at = Set(Some(chrono::Utc::now().naive_utc()));
    active.update(&state.db).await?;

    // Refresh cache for affected resources
    for uri in affected_resource_uris {
        state.cache.refresh_resource(&state.db, &uri).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/domains/{id}/tokens",
            post(create_token).get(list_tokens),
        )
        .route(
            "/api/v1/domains/{id}/tokens/{tid}",
            delete(revoke_token),
        )
}
