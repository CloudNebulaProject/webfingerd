use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Middleware that generates a unique request ID and attaches it to both the
/// request (for downstream handlers) and the response (for clients).
pub async fn request_id(mut request: Request<Body>, next: Next) -> Response {
    let id = Uuid::new_v4().to_string();
    request
        .headers_mut()
        .insert(X_REQUEST_ID.clone(), HeaderValue::from_str(&id).unwrap());

    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(X_REQUEST_ID.clone(), HeaderValue::from_str(&id).unwrap());

    response
}
