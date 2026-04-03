mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_webfinger_returns_404_for_unknown_resource() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:nobody@example.com")
        .await;

    response.assert_status_not_found();
}

#[tokio::test]
async fn test_webfinger_returns_400_without_resource_param() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server.get("/.well-known/webfinger").await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_webfinger_returns_jrd_for_known_resource() {
    let state = common::test_state().await;

    // Seed cache directly for this test
    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: Some(vec!["https://example.com/@alice".into()]),
            properties: None,
            links: vec![webfingerd::cache::CachedLink {
                rel: "self".into(),
                href: Some("https://example.com/users/alice".into()),
                link_type: Some("application/activity+json".into()),
                titles: None,
                properties: None,
                template: None,
            }],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["subject"], "acct:alice@example.com");
    assert_eq!(body["aliases"][0], "https://example.com/@alice");
    assert_eq!(body["links"][0]["rel"], "self");
    assert_eq!(
        body["links"][0]["href"],
        "https://example.com/users/alice"
    );
}

#[tokio::test]
async fn test_webfinger_filters_by_rel() {
    let state = common::test_state().await;

    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: None,
            properties: None,
            links: vec![
                webfingerd::cache::CachedLink {
                    rel: "self".into(),
                    href: Some("https://example.com/users/alice".into()),
                    link_type: Some("application/activity+json".into()),
                    titles: None,
                    properties: None,
                    template: None,
                },
                webfingerd::cache::CachedLink {
                    rel: "http://openid.net/specs/connect/1.0/issuer".into(),
                    href: Some("https://auth.example.com".into()),
                    link_type: None,
                    titles: None,
                    properties: None,
                    template: None,
                },
            ],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .add_query_param("rel", "self")
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    let links = body["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["rel"], "self");
}

#[tokio::test]
async fn test_webfinger_cors_headers() {
    let state = common::test_state().await;

    state.cache.set(
        "acct:alice@example.com".into(),
        webfingerd::cache::CachedResource {
            subject: "acct:alice@example.com".into(),
            aliases: None,
            properties: None,
            links: vec![],
        },
    );

    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;

    assert_eq!(
        response.header("access-control-allow-origin"),
        "*"
    );
}
