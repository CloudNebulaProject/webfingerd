mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

/// Helper: register a verified domain and return (id, owner_token).
/// Uses MockChallengeVerifier (injected in test state) so no manual DB manipulation needed.
async fn setup_verified_domain(
    server: &TestServer,
    _state: &webfingerd::state::AppState,
    domain_name: &str,
) -> (String, String) {
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": domain_name, "challenge_type": "dns-01"}))
        .await;
    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap().to_string();
    let reg_secret = body["registration_secret"].as_str().unwrap().to_string();

    // MockChallengeVerifier always succeeds
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    (id, owner_token)
}

#[tokio::test]
async fn test_create_service_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    let response = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["token"].is_string());
    assert_eq!(body["name"], "oxifed");
}

#[tokio::test]
async fn test_create_service_token_rejects_bad_pattern() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    // Pattern without @ or wrong domain
    let response = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "evil",
            "allowed_rels": ["self"],
            "resource_pattern": "*"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_list_service_tokens() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;

    let response = server
        .get(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    let tokens = body.as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["name"], "oxifed");
    // Token hash should NOT be exposed
    assert!(tokens[0].get("token_hash").is_none());
    assert!(tokens[0].get("token").is_none());
}

// NOTE: test_revoke_service_token_deletes_links is in tests/test_links.rs (Task 10)
// because it depends on the link registration endpoint. It is tested there as part
// of the full link lifecycle, not here where the endpoint doesn't exist yet.

#[tokio::test]
async fn test_revoke_service_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (id, owner_token) = setup_verified_domain(&server, &state, "example.com").await;

    let create_resp = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;
    let body: serde_json::Value = create_resp.json();
    let token_id = body["id"].as_str().unwrap().to_string();

    // Revoke the token
    let response = server
        .delete(&format!("/api/v1/domains/{id}/tokens/{token_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    response.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Token should no longer appear in list
    let list_resp = server
        .get(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let tokens = list_resp.json::<serde_json::Value>();
    let tokens = tokens.as_array().unwrap();
    assert!(tokens.is_empty());
}
