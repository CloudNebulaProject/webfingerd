use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::cookie::{Cookie, SignedCookieJar};
use sea_orm::*;
use serde::Deserialize;

use crate::auth;
use crate::entity::{domains, links, resources, service_tokens};
use crate::state::AppState;
use crate::ui::templates::*;

const SESSION_COOKIE: &str = "webfingerd_session";

/// Extract domain ID from signed session cookie.
fn session_domain_id(jar: &SignedCookieJar) -> Option<String> {
    jar.get(SESSION_COOKIE).map(|c| c.value().to_string())
}

async fn login_page(State(_state): State<AppState>, jar: SignedCookieJar) -> Response {
    let jar = jar.clone();
    // If already logged in, redirect to dashboard
    if session_domain_id(&jar).is_some() {
        return Redirect::to("/ui/dashboard").into_response();
    }

    let template = LoginTemplate { error: None };
    Html(template.to_string()).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_submit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    let jar = jar.clone();

    // Parse token to get domain ID
    let Some((domain_id, _)) = auth::split_token(&form.token) else {
        let template = LoginTemplate {
            error: Some("Invalid token format".into()),
        };
        return Html(template.to_string()).into_response();
    };

    // Look up domain and verify token
    let domain = match domains::Entity::find_by_id(domain_id)
        .one(&state.db)
        .await
    {
        Ok(Some(d)) if d.verified => d,
        _ => {
            let template = LoginTemplate {
                error: Some("Invalid token or domain not verified".into()),
            };
            return Html(template.to_string()).into_response();
        }
    };

    if !auth::verify_token(&form.token, &domain.owner_token_hash) {
        let template = LoginTemplate {
            error: Some("Invalid token".into()),
        };
        return Html(template.to_string()).into_response();
    }

    // Set session cookie with the owner token (so we can authenticate subsequent requests)
    let cookie = Cookie::build((SESSION_COOKIE, form.token))
        .path("/ui")
        .http_only(true)
        .build();

    let jar = jar.add(cookie);
    (jar, Redirect::to("/ui/dashboard")).into_response()
}

async fn logout(jar: SignedCookieJar) -> Response {
    let jar = jar.clone();
    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    (jar, Redirect::to("/ui/login")).into_response()
}

async fn dashboard(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let jar = jar.clone();
    let Some(token) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) else {
        return Redirect::to("/ui/login").into_response();
    };

    let Some((domain_id, _)) = auth::split_token(&token) else {
        return Redirect::to("/ui/login").into_response();
    };

    // Get the domain owned by this token
    let domain = match domains::Entity::find_by_id(domain_id)
        .one(&state.db)
        .await
    {
        Ok(Some(d)) if d.verified && auth::verify_token(&token, &d.owner_token_hash) => d,
        _ => return Redirect::to("/ui/login").into_response(),
    };

    // Count links for this domain
    let link_count = links::Entity::find()
        .filter(links::Column::DomainId.eq(&domain.id))
        .count(&state.db)
        .await
        .unwrap_or(0);

    let template = DashboardTemplate {
        domains: vec![DomainSummary {
            id: domain.id,
            domain: domain.domain,
            verified: domain.verified,
            link_count,
        }],
    };

    Html(template.to_string()).into_response()
}

/// Helper to authenticate session and return (domain_model, token_string).
async fn authenticate_session(
    state: &AppState,
    jar: &SignedCookieJar,
) -> Option<(domains::Model, String)> {
    let token = jar.get(SESSION_COOKIE).map(|c| c.value().to_string())?;
    let (domain_id, _) = auth::split_token(&token)?;

    let domain = domains::Entity::find_by_id(domain_id)
        .one(&state.db)
        .await
        .ok()??;

    if domain.verified && auth::verify_token(&token, &domain.owner_token_hash) {
        Some((domain, token))
    } else {
        None
    }
}

async fn domain_detail(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> Response {
    let jar = jar.clone();
    let Some((domain, _)) = authenticate_session(&state, &jar).await else {
        return Redirect::to("/ui/login").into_response();
    };

    if domain.id != id {
        return Redirect::to("/ui/dashboard").into_response();
    }

    let template = DomainDetailTemplate {
        domain: DomainInfo {
            id: domain.id,
            domain: domain.domain,
            verified: domain.verified,
            challenge_type: domain.challenge_type,
            created_at: domain.created_at.to_string(),
        },
    };

    Html(template.to_string()).into_response()
}

async fn token_management(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> Response {
    let jar = jar.clone();
    let Some((domain, _)) = authenticate_session(&state, &jar).await else {
        return Redirect::to("/ui/login").into_response();
    };

    if domain.id != id {
        return Redirect::to("/ui/dashboard").into_response();
    }

    let tokens = service_tokens::Entity::find()
        .filter(service_tokens::Column::DomainId.eq(&domain.id))
        .all(&state.db)
        .await
        .unwrap_or_default();

    let template = TokenManagementTemplate {
        domain_id: domain.id,
        domain_name: domain.domain,
        tokens: tokens
            .into_iter()
            .map(|t| TokenSummary {
                name: t.name,
                allowed_rels: t.allowed_rels,
                resource_pattern: t.resource_pattern,
                created_at: t.created_at.to_string(),
                revoked: t.revoked_at.is_some(),
            })
            .collect(),
    };

    Html(template.to_string()).into_response()
}

async fn link_browser(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> Response {
    let jar = jar.clone();
    let Some((domain, _)) = authenticate_session(&state, &jar).await else {
        return Redirect::to("/ui/login").into_response();
    };

    if domain.id != id {
        return Redirect::to("/ui/dashboard").into_response();
    }

    let domain_links = links::Entity::find()
        .filter(links::Column::DomainId.eq(&domain.id))
        .find_also_related(resources::Entity)
        .all(&state.db)
        .await
        .unwrap_or_default();

    let template = LinkBrowserTemplate {
        domain_id: domain.id,
        domain_name: domain.domain,
        links: domain_links
            .into_iter()
            .map(|(link, resource)| {
                let resource_uri = resource
                    .map(|r| r.resource_uri)
                    .unwrap_or_else(|| "unknown".into());
                LinkSummary {
                    resource_uri,
                    rel: link.rel,
                    href: link.href.unwrap_or_default(),
                    link_type: link.link_type.unwrap_or_default(),
                    expires_at: link
                        .expires_at
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "never".into()),
                }
            })
            .collect(),
    };

    Html(template.to_string()).into_response()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ui/login", get(login_page).post(login_submit))
        .route("/ui/logout", get(logout))
        .route("/ui/dashboard", get(dashboard))
        .route("/ui/domains/{id}", get(domain_detail))
        .route("/ui/domains/{id}/tokens", get(token_management))
        .route("/ui/domains/{id}/links", get(link_browser))
}
