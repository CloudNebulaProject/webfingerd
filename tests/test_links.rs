mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

/// Helper: create verified domain + service token, return (domain_id, owner_token, service_token).
/// Uses MockChallengeVerifier -- no manual DB manipulation needed.
async fn setup_domain_and_token(
    server: &TestServer,
    _state: &webfingerd::state::AppState,
    domain_name: &str,
) -> (String, String, String) {
    // Register domain
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

    // Create service token
    let token_resp = server
        .post(&format!("/api/v1/domains/{id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self", "http://webfinger.net/rel/profile-page"],
            "resource_pattern": "acct:*@example.com"
        }))
        .await;
    let service_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    (id, owner_token, service_token)
}

#[tokio::test]
async fn test_register_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["id"].is_string());

    // Should now be in cache and queryable
    let wf = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;
    wf.assert_status_ok();
    let jrd: serde_json::Value = wf.json();
    assert_eq!(jrd["subject"], "acct:alice@example.com");
    assert_eq!(jrd["links"][0]["rel"], "self");
}

#[tokio::test]
async fn test_register_link_rejected_for_forbidden_rel() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://evil.com"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_register_link_rejected_for_wrong_domain() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@evil.com",
            "rel": "self",
            "href": "https://evil.com/users/alice"
        }))
        .await;

    response.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_upsert_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    // First insert
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Upsert with same (resource, rel, href) but different type
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/ld+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Should only have one link
    let wf = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await;
    let jrd: serde_json::Value = wf.json();
    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["type"], "application/ld+json");
}

#[tokio::test]
async fn test_batch_link_registration() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links/batch")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "links": [
                {
                    "resource_uri": "acct:alice@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/alice",
                    "type": "application/activity+json"
                },
                {
                    "resource_uri": "acct:bob@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/bob",
                    "type": "application/activity+json"
                }
            ]
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);

    // Both should be queryable
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_ok();

    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:bob@example.com")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn test_batch_all_or_nothing() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    // Second link has forbidden rel -- entire batch should fail
    let response = server
        .post("/api/v1/links/batch")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "links": [
                {
                    "resource_uri": "acct:alice@example.com",
                    "rel": "self",
                    "href": "https://example.com/users/alice"
                },
                {
                    "resource_uri": "acct:bob@example.com",
                    "rel": "forbidden-rel",
                    "href": "https://example.com/users/bob"
                }
            ]
        }))
        .await;

    // Batch should fail
    response.assert_status(axum::http::StatusCode::FORBIDDEN);

    // alice should NOT be registered (all-or-nothing)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn test_delete_link() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let create_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice"
        }))
        .await;
    let link_id = create_resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Delete it
    server
        .delete(&format!("/api/v1/links/{link_id}"))
        .add_header("Authorization", format!("Bearer {service_token}"))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Should be gone
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn test_link_with_ttl() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (_, _, service_token) = setup_domain_and_token(&server, &state, "example.com").await;

    let response = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "ttl_seconds": 300
        }))
        .await;

    response.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_revoke_service_token_deletes_links() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    let (id, owner_token, service_token) =
        setup_domain_and_token(&server, &state, "example.com").await;

    // Register a link
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {service_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@example.com",
            "rel": "self",
            "href": "https://example.com/users/alice",
            "type": "application/activity+json"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Verify it exists
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_ok();

    // Extract the token ID from the service token (format: {id}.{secret})
    let token_id = service_token.split('.').next().unwrap();

    // Revoke the service token via owner API
    server
        .delete(&format!("/api/v1/domains/{id}/tokens/{token_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // WebFinger should no longer find the link (cascade delete + cache eviction)
    server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@example.com")
        .await
        .assert_status_not_found();
}
