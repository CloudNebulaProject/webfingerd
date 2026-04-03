use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use sea_orm::*;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::entity::domains;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    domain: String,
    challenge_type: String,
}

async fn create_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if req.challenge_type != "dns-01" && req.challenge_type != "http-01" {
        return Err(AppError::BadRequest(
            "challenge_type must be dns-01 or http-01".into(),
        ));
    }

    // Check for duplicate
    let existing = domains::Entity::find()
        .filter(domains::Column::Domain.eq(&req.domain))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::Conflict("domain already registered".into()));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let challenge_token = auth::generate_secret();
    let registration_secret = auth::generate_secret();
    let registration_secret_hash = auth::hash_token(&registration_secret)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let domain = domains::ActiveModel {
        id: Set(id.clone()),
        domain: Set(req.domain.clone()),
        owner_token_hash: Set(String::new()), // Set on verification
        registration_secret: Set(registration_secret_hash),
        challenge_type: Set(req.challenge_type.clone()),
        challenge_token: Set(Some(challenge_token.clone())),
        verified: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
        verified_at: Set(None),
    };

    domain.insert(&state.db).await?;

    let instructions = match req.challenge_type.as_str() {
        "dns-01" => format!(
            "Create a TXT record at {}.{} with value: {}",
            state.settings.challenge.dns_txt_prefix, req.domain, challenge_token
        ),
        "http-01" => format!(
            "Serve the challenge at https://{}/{}/{}",
            req.domain, state.settings.challenge.http_well_known_path, challenge_token
        ),
        _ => unreachable!(),
    };

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "challenge_token": challenge_token,
            "challenge_type": req.challenge_type,
            "registration_secret": registration_secret,
            "instructions": instructions,
        })),
    ))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    registration_secret: String,
}

async fn verify_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VerifyRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let domain = domains::Entity::find_by_id(&id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify registration secret
    if !auth::verify_token(&req.registration_secret, &domain.registration_secret) {
        return Err(AppError::Unauthorized);
    }

    if domain.verified {
        return Err(AppError::Conflict("domain already verified".into()));
    }

    let challenge_token = domain
        .challenge_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("no pending challenge".into()))?;

    // Check challenge TTL
    let challenge_age = chrono::Utc::now().naive_utc() - domain.created_at;
    if challenge_age.num_seconds() > state.settings.challenge.challenge_ttl_secs as i64 {
        return Err(AppError::BadRequest("challenge expired".into()));
    }

    // Verify the challenge via the injected verifier (mockable in tests)
    let verified = match domain.challenge_type.as_str() {
        "dns-01" => state.challenge_verifier
            .verify_dns(&domain.domain, challenge_token, &state.settings.challenge)
            .await
            .map_err(|e| AppError::Internal(e))?,
        "http-01" => state.challenge_verifier
            .verify_http(&domain.domain, challenge_token, &state.settings.challenge)
            .await
            .map_err(|e| AppError::Internal(e))?,
        _ => return Err(AppError::Internal("unknown challenge type".into())),
    };

    if !verified {
        return Err(AppError::BadRequest("challenge verification failed".into()));
    }

    // Generate owner token (prefixed with domain ID for O(1) lookup)
    let owner_token = auth::generate_token(&id);
    let owner_token_hash = auth::hash_token(&owner_token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    // Update domain
    let mut active: domains::ActiveModel = domain.into();
    active.verified = Set(true);
    active.verified_at = Set(Some(chrono::Utc::now().naive_utc()));
    active.owner_token_hash = Set(owner_token_hash);
    active.challenge_token = Set(None);
    active.registration_secret = Set(String::new()); // Invalidate
    active.update(&state.db).await?;

    Ok(Json(json!({
        "verified": true,
        "owner_token": owner_token,
    })))
}

/// Extract and verify owner token from Authorization header.
/// The token format is `{domain_id}.{secret}` -- the domain_id from the token
/// must match the `id` path parameter to prevent cross-domain access.
pub async fn authenticate_owner(
    db: &DatabaseConnection,
    id: &str,
    auth_header: Option<&str>,
) -> AppResult<domains::Model> {
    let full_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    // Verify the token's embedded ID matches the requested domain
    let (token_domain_id, _) = auth::split_token(full_token)
        .ok_or(AppError::Unauthorized)?;
    if token_domain_id != id {
        return Err(AppError::Unauthorized);
    }

    let domain = domains::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !domain.verified {
        return Err(AppError::Forbidden("domain not verified".into()));
    }

    if !auth::verify_token(full_token, &domain.owner_token_hash) {
        return Err(AppError::Unauthorized);
    }

    Ok(domain)
}

async fn get_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    Ok(Json(json!({
        "id": domain.id,
        "domain": domain.domain,
        "verified": domain.verified,
        "challenge_type": domain.challenge_type,
        "created_at": domain.created_at.to_string(),
        "verified_at": domain.verified_at.map(|v| v.to_string()),
    })))
}

async fn rotate_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    let new_token = auth::generate_token(&domain.id);
    let new_hash = auth::hash_token(&new_token)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;

    let mut active: domains::ActiveModel = domain.into();
    active.owner_token_hash = Set(new_hash);
    active.update(&state.db).await?;

    Ok(Json(json!({
        "owner_token": new_token,
    })))
}

async fn delete_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let domain = authenticate_owner(&state.db, &id, auth_header).await?;

    // Query all resource URIs for this domain before deleting
    use crate::entity::resources;
    let resource_uris: Vec<String> = resources::Entity::find()
        .filter(resources::Column::DomainId.eq(&domain.id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|r| r.resource_uri)
        .collect();

    // Cascade: delete domain (FK cascades handle DB rows)
    domains::Entity::delete_by_id(&domain.id)
        .exec(&state.db)
        .await?;

    // Evict cache entries for all affected resources
    state.cache.remove_many(&resource_uris);

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/domains", post(create_domain))
        .route("/api/v1/domains/{id}", get(get_domain).delete(delete_domain))
        .route("/api/v1/domains/{id}/verify", post(verify_domain))
        .route("/api/v1/domains/{id}/rotate-token", post(rotate_token))
}
