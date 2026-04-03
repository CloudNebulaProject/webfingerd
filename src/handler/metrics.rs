use axum::extract::State;
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics_handle.render()
}

pub fn router() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}
