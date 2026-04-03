pub mod domains;
mod health;
mod host_meta;
pub mod links;
pub mod tokens;
mod webfinger;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .merge(domains::router())
        .merge(tokens::router())
        .merge(links::router())
        .merge(health::router())
        .with_state(state)
}
