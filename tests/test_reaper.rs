mod common;

use webfingerd::reaper;

#[tokio::test]
async fn test_reaper_expires_links() {
    let state = common::test_state().await;

    // Insert a resource + link that expires immediately
    use sea_orm::*;
    use webfingerd::auth;
    use webfingerd::entity::{domains, links, resources, service_tokens};

    let now = chrono::Utc::now().naive_utc();
    let past = now - chrono::Duration::seconds(60);

    // Create domain
    let domain = domains::ActiveModel {
        id: Set("d1".into()),
        domain: Set("example.com".into()),
        owner_token_hash: Set(auth::hash_token("test").unwrap()),
        registration_secret: Set(String::new()),
        challenge_type: Set("dns-01".into()),
        challenge_token: Set(None),
        verified: Set(true),
        created_at: Set(now),
        verified_at: Set(Some(now)),
    };
    domain.insert(&state.db).await.unwrap();

    // Create service token
    let token = service_tokens::ActiveModel {
        id: Set("t1".into()),
        domain_id: Set("d1".into()),
        name: Set("test".into()),
        token_hash: Set(auth::hash_token("test").unwrap()),
        allowed_rels: Set(r#"["self"]"#.into()),
        resource_pattern: Set("acct:*@example.com".into()),
        created_at: Set(now),
        revoked_at: Set(None),
    };
    token.insert(&state.db).await.unwrap();

    // Create resource
    let resource = resources::ActiveModel {
        id: Set("r1".into()),
        domain_id: Set("d1".into()),
        resource_uri: Set("acct:alice@example.com".into()),
        aliases: Set(None),
        properties: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    resource.insert(&state.db).await.unwrap();

    // Create expired link
    let link = links::ActiveModel {
        id: Set("l1".into()),
        resource_id: Set("r1".into()),
        service_token_id: Set("t1".into()),
        domain_id: Set("d1".into()),
        rel: Set("self".into()),
        href: Set(Some("https://example.com/users/alice".into())),
        link_type: Set(None),
        titles: Set(None),
        properties: Set(None),
        template: Set(None),
        ttl_seconds: Set(Some(1)),
        created_at: Set(past),
        expires_at: Set(Some(past + chrono::Duration::seconds(1))),
    };
    link.insert(&state.db).await.unwrap();

    // Hydrate cache
    state.cache.hydrate(&state.db).await.unwrap();

    // Should NOT be in cache (already expired)
    assert!(state.cache.get("acct:alice@example.com").is_none());

    // Run reaper once
    reaper::reap_once(&state.db, &state.cache).await.unwrap();

    // Link should be deleted from DB
    let remaining = links::Entity::find().all(&state.db).await.unwrap();
    assert!(remaining.is_empty());

    // Orphaned resource should also be cleaned up
    let remaining_resources = resources::Entity::find().all(&state.db).await.unwrap();
    assert!(remaining_resources.is_empty());
}
