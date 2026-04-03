use axum::extract::State;
use axum_extra::extract::Host;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sea_orm::*;

use crate::entity::domains;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

async fn host_meta(
    State(state): State<AppState>,
    Host(hostname): Host,
) -> AppResult<Response> {
    // Strip port if present
    let domain = hostname.split(':').next().unwrap_or(&hostname);

    // Check this domain is registered and verified
    let _domain = domains::Entity::find()
        .filter(domains::Column::Domain.eq(domain))
        .filter(domains::Column::Verified.eq(true))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let base_url = &state.settings.server.base_url;
    let xrd = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="lrdd" type="application/jrd+json" template="{base_url}/.well-known/webfinger?resource={{uri}}" />
</XRD>"#
    );

    Ok((
        [(header::CONTENT_TYPE, "application/xrd+xml; charset=utf-8")],
        xrd,
    )
        .into_response())
}

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/host-meta", get(host_meta))
}
