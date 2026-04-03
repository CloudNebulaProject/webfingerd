use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use sea_orm::{ConnectionTrait, Statement};

use crate::state::AppState;

async fn healthz(State(state): State<AppState>) -> StatusCode {
    match state
        .db
        .execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT 1".to_string(),
        ))
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/healthz", get(healthz))
}
