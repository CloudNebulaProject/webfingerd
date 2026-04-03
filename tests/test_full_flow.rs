mod common;

use axum_test::TestServer;
use serde_json::json;
use webfingerd::handler;

#[tokio::test]
async fn test_full_webfinger_flow() {
    let state = common::test_state().await;
    let app = handler::router(state.clone());
    let server = TestServer::new(app);

    // 1. Register domain
    let create_resp = server
        .post("/api/v1/domains")
        .json(&json!({"domain": "social.alice.example", "challenge_type": "dns-01"}))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = create_resp.json();
    let domain_id = body["id"].as_str().unwrap().to_string();
    let reg_secret = body["registration_secret"].as_str().unwrap().to_string();

    // 2. Verify domain (MockChallengeVerifier always succeeds)
    let verify_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/verify"))
        .json(&json!({"registration_secret": reg_secret}))
        .await;
    let owner_token = verify_resp.json::<serde_json::Value>()["owner_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. Create service token for ActivityPub (oxifed)
    let token_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "oxifed",
            "allowed_rels": ["self", "http://webfinger.net/rel/profile-page"],
            "resource_pattern": "acct:*@social.alice.example"
        }))
        .await;
    token_resp.assert_status(axum::http::StatusCode::CREATED);
    let ap_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 4. Create service token for OIDC (barycenter)
    let token_resp = server
        .post(&format!("/api/v1/domains/{domain_id}/tokens"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "name": "barycenter",
            "allowed_rels": ["http://openid.net/specs/connect/1.0/issuer"],
            "resource_pattern": "acct:*@social.alice.example"
        }))
        .await;
    let oidc_token = token_resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 5. oxifed registers ActivityPub links with aliases
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "self",
            "href": "https://social.alice.example/users/alice",
            "type": "application/activity+json",
            "aliases": ["https://social.alice.example/@alice"]
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://webfinger.net/rel/profile-page",
            "href": "https://social.alice.example/@alice",
            "type": "text/html"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // 6. barycenter registers OIDC issuer link
    server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {oidc_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://auth.alice.example"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // 7. Query WebFinger — should return all three links
    let wf_resp = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@social.alice.example")
        .await;
    wf_resp.assert_status_ok();
    let jrd: serde_json::Value = wf_resp.json();

    assert_eq!(jrd["subject"], "acct:alice@social.alice.example");
    assert_eq!(jrd["aliases"][0], "https://social.alice.example/@alice");

    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 3);

    // 8. Filter by rel=self — verify only 1 link returned, aliases still present
    let wf_resp = server
        .get("/.well-known/webfinger")
        .add_query_param("resource", "acct:alice@social.alice.example")
        .add_query_param("rel", "self")
        .await;
    let jrd: serde_json::Value = wf_resp.json();
    let links = jrd["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["rel"], "self");
    // aliases should still be present despite rel filter
    assert!(jrd["aliases"].is_array());

    // 9. Verify scope isolation: oxifed can't register OIDC links
    let bad_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {ap_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": "https://evil.com"
        }))
        .await;
    bad_resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // 10. Verify scope isolation: barycenter can't register AP links
    let bad_resp = server
        .post("/api/v1/links")
        .add_header("Authorization", format!("Bearer {oidc_token}"))
        .json(&json!({
            "resource_uri": "acct:alice@social.alice.example",
            "rel": "self",
            "href": "https://evil.com"
        }))
        .await;
    bad_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
