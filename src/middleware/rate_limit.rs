use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Per-key rate limiter using DashMap for keyed limiting (per IP or per token).
#[derive(Clone)]
pub struct KeyedLimiter {
    limiters: Arc<DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    quota: Quota,
}

impl KeyedLimiter {
    pub fn new(rpm: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(rpm).expect("rpm must be > 0"));
        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
        }
    }

    pub fn check_key(&self, key: &str) -> bool {
        let limiter = self
            .limiters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)))
            .clone();
        limiter.check().is_ok()
    }
}

/// Rate limit middleware for public endpoints (keyed by client IP).
pub async fn rate_limit_by_ip(limiter: KeyedLimiter, request: Request<Body>, next: Next) -> Response {
    // Extract IP from x-forwarded-for or fall back to "unknown"
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if !limiter.check_key(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            "rate limited",
        )
            .into_response();
    }

    next.run(request).await
}

/// Rate limit middleware for API endpoints (keyed by Bearer token prefix).
pub async fn rate_limit_by_token(limiter: KeyedLimiter, request: Request<Body>, next: Next) -> Response {
    let key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|t| t.split('.').next()) // Use token ID prefix as key
        .unwrap_or("anonymous")
        .to_string();

    if !limiter.check_key(&key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            "rate limited",
        )
            .into_response();
    }

    next.run(request).await
}
