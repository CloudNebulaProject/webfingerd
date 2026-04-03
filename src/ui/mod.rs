pub mod handlers;
pub mod templates;

use axum::Router;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    handlers::router()
}
