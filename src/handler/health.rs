use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub fn router() -> Router<AppState> {
    Router::new().route("/healthz", get(healthz))
}
