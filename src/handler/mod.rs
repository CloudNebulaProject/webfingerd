mod health;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(health::router())
        .with_state(state)
}
