mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_host_meta_returns_xrd_for_known_domain() {
    let state = common::test_state().await;

    // Seed a verified domain in DB
    use sea_orm::ActiveModelTrait;
    use sea_orm::Set;
    use webfingerd::entity::domains;

    let domain = domains::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        domain: Set("example.com".into()),
        owner_token_hash: Set("hash".into()),
        registration_secret: Set("secret".into()),
        challenge_type: Set("dns-01".into()),
        challenge_token: Set(None),
        verified: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
        verified_at: Set(Some(chrono::Utc::now().naive_utc())),
    };
    domain.insert(&state.db).await.unwrap();

    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/host-meta")
        .add_header("Host", "example.com")
        .await;

    response.assert_status_ok();
    let body = response.text();
    assert!(body.contains("application/jrd+json") || body.contains("XRD"));
    assert!(body.contains("/.well-known/webfinger"));
}

#[tokio::test]
async fn test_host_meta_returns_404_for_unknown_domain() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .get("/.well-known/host-meta")
        .add_header("Host", "unknown.example.com")
        .await;

    response.assert_status_not_found();
}
