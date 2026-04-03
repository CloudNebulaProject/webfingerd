pub mod domains;
mod health;
mod host_meta;
pub mod links;
mod metrics;
pub mod tokens;
mod webfinger;

use axum::middleware as axum_mw;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use crate::middleware::rate_limit::{self, KeyedLimiter};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let public_limiter = KeyedLimiter::new(state.settings.rate_limit.public_rpm);
    let api_limiter = KeyedLimiter::new(state.settings.rate_limit.api_rpm);

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public endpoints: webfinger + host-meta with per-IP rate limit + CORS
    let public_routes = Router::new()
        .merge(webfinger::router())
        .merge(host_meta::router())
        .layer(public_cors)
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = public_limiter.clone();
            rate_limit::rate_limit_by_ip(limiter, req, next)
        }));

    // API endpoints with per-token rate limit (no wildcard CORS)
    let api_routes = Router::new()
        .merge(domains::router())
        .merge(tokens::router())
        .merge(links::router())
        .layer(axum_mw::from_fn(move |req, next| {
            let limiter = api_limiter.clone();
            rate_limit::rate_limit_by_token(limiter, req, next)
        }));

    let mut app = Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .merge(health::router())
        .merge(metrics::router());

    if state.settings.ui.enabled {
        app = app.merge(crate::ui::router());
    }

    app.with_state(state)
}
