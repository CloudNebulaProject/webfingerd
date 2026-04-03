use axum::extract::State;
use axum::http::{header, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Parse resource and rel params from query string manually,
/// because serde_urlencoded can't handle repeated keys into Vec.
fn parse_webfinger_query(uri: &Uri) -> (Option<String>, Vec<String>) {
    let query_str = uri.query().unwrap_or("");
    let mut resource = None;
    let mut rels = Vec::new();

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let value = urlencoding::decode(value)
                .unwrap_or_default()
                .into_owned();
            match key {
                "resource" => resource = Some(value),
                "rel" => rels.push(value),
                _ => {}
            }
        }
    }

    (resource, rels)
}

async fn webfinger(
    State(state): State<AppState>,
    uri: Uri,
) -> AppResult<Response> {
    let (resource_opt, rels) = parse_webfinger_query(&uri);

    let resource = resource_opt
        .ok_or_else(|| AppError::BadRequest("missing resource parameter".into()))?;

    let cached = state
        .cache
        .get(&resource)
        .ok_or(AppError::NotFound)?;

    let links: Vec<serde_json::Value> = cached
        .links
        .iter()
        .filter(|link| {
            if rels.is_empty() {
                true
            } else {
                rels.iter().any(|r| r == &link.rel)
            }
        })
        .map(|link| {
            let mut obj = serde_json::Map::new();
            obj.insert("rel".into(), json!(link.rel));
            if let Some(href) = &link.href {
                obj.insert("href".into(), json!(href));
            }
            if let Some(t) = &link.link_type {
                obj.insert("type".into(), json!(t));
            }
            if let Some(titles) = &link.titles {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(titles) {
                    obj.insert("titles".into(), v);
                }
            }
            if let Some(props) = &link.properties {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(props) {
                    obj.insert("properties".into(), v);
                }
            }
            if let Some(template) = &link.template {
                obj.insert("template".into(), json!(template));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let mut response_body = serde_json::Map::new();
    response_body.insert("subject".into(), json!(cached.subject));

    if let Some(aliases) = &cached.aliases {
        response_body.insert("aliases".into(), json!(aliases));
    }

    if let Some(properties) = &cached.properties {
        response_body.insert("properties".into(), properties.clone());
    }

    response_body.insert("links".into(), json!(links));

    Ok((
        [
            (header::CONTENT_TYPE, "application/jrd+json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(serde_json::Value::Object(response_body)),
    )
        .into_response())
}

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/webfinger", get(webfinger))
}
