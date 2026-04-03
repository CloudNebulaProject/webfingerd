use async_trait::async_trait;

use crate::config::ChallengeConfig;

/// Trait for challenge verification — allows mocking in tests.
#[async_trait]
pub trait ChallengeVerifier: Send + Sync {
    async fn verify_dns(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String>;

    async fn verify_http(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String>;
}

/// Real implementation using DNS lookups and HTTP requests.
pub struct RealChallengeVerifier;

#[async_trait]
impl ChallengeVerifier for RealChallengeVerifier {
    async fn verify_dns(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String> {
        use hickory_resolver::TokioResolver;

        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| format!("resolver error: {e}"))?
            .build();

        let lookup_name = format!("{}.{}", config.dns_txt_prefix, domain);
        let response = resolver
            .txt_lookup(&lookup_name)
            .await
            .map_err(|e| format!("DNS lookup failed: {e}"))?;

        for record in response.iter() {
            let txt = record.to_string();
            if txt.trim_matches('"') == expected_token {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn verify_http(
        &self,
        domain: &str,
        expected_token: &str,
        config: &ChallengeConfig,
    ) -> Result<bool, String> {
        let url = format!(
            "https://{}/{}/{}",
            domain, config.http_well_known_path, expected_token
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        Ok(response.status().is_success())
    }
}

/// Mock that always succeeds — for testing.
pub struct MockChallengeVerifier;

#[async_trait]
impl ChallengeVerifier for MockChallengeVerifier {
    async fn verify_dns(&self, _: &str, _: &str, _: &ChallengeConfig) -> Result<bool, String> {
        Ok(true)
    }
    async fn verify_http(&self, _: &str, _: &str, _: &ChallengeConfig) -> Result<bool, String> {
        Ok(true)
    }
}
