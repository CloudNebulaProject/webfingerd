mod common;

use axum_test::TestServer;
use webfingerd::handler;

#[tokio::test]
async fn test_public_rate_limiting() {
    let mut settings = common::test_settings();
    settings.rate_limit.public_rpm = 2; // Very low for testing

    let state = common::test_state_with_settings(settings).await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    // First two requests should succeed (even with 404)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:a@a.com")
        .await;
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:b@b.com")
        .await;

    // Third should be rate limited
    let response = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:c@c.com")
        .await;

    response.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}
