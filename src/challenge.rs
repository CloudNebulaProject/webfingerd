use async_trait::async_trait;

/// Trait for verifying domain ownership challenges (DNS-01 and HTTP-01).
#[async_trait]
pub trait ChallengeVerifier: Send + Sync + std::fmt::Debug {
    async fn verify_dns01(&self, domain: &str, expected_token: &str) -> Result<bool, String>;
    async fn verify_http01(&self, domain: &str, expected_token: &str) -> Result<bool, String>;
}

/// Production implementation using real DNS and HTTP lookups.
#[derive(Debug)]
pub struct RealChallengeVerifier;

#[async_trait]
impl ChallengeVerifier for RealChallengeVerifier {
    async fn verify_dns01(&self, _domain: &str, _expected_token: &str) -> Result<bool, String> {
        // TODO: implement with hickory-resolver in a later task
        Ok(false)
    }

    async fn verify_http01(&self, _domain: &str, _expected_token: &str) -> Result<bool, String> {
        // TODO: implement with reqwest in a later task
        Ok(false)
    }
}
