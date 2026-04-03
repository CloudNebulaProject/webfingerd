mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

#[tokio::test]
async fn test_register_domain() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    let response = server
        .post("/api/v1/domains")
        .json(&json!({
            "domain": "example.com",
            "challenge_type": "dns-01"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["challenge_token"].is_string());
    assert!(body["registration_secret"].is_string());
    assert_eq!(body["challenge_type"], "dns-01");
}

#[tokio::test]
async fn test_register_duplicate_domain_returns_409() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    let response = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    response.assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_domain_requires_auth() {
    let state = common::test_state().await;
    let app = handler::router(state);
    let server = TestServer::new(app);

    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;
    let id = create_resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // No auth header
    let response = server.get(&format!("/api/v1/domains/{id}")).await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_get_domain_with_valid_owner_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    // Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;

    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap();
    let reg_secret = body["registration_secret"].as_str().unwrap();

    // Verify (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;

    verify_resp.assert_status_ok();
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Use owner token to get domain
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["domain"], "example.com");
    assert_eq!(body["verified"], true);
}

#[tokio::test]
async fn test_rotate_token() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    // Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "example.com", "challenge_type": "dns-01"}))
        .await;
    let body: serde_json::Value = create_resp.json();
    let id = body["id"].as_str().unwrap();
    let reg_secret = body["registration_secret"].as_str().unwrap();

    // Verify (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let old_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Rotate
    let rotate_resp = server
        .post(&format!("/api/v1/domains/{id}/rotate-token"))
        .add_header("Authorization", format!("Bearer {old_token}"))
        .await;
    rotate_resp.assert_status_ok();
    let new_token = rotate_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Old token should fail
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {old_token}"))
        .await;
    response.assert_status_unauthorized();

    // New token should work
    let response = server
        .get(&format!("/api/v1/domains/{id}"))
        .add_header("Authorization", format!("Bearer {new_token}"))
        .await;
    response.assert_status_ok();
}
