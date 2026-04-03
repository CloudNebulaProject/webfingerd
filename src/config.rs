use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub rate_limit: RateLimitConfig,
    pub challenge: ChallengeConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub wal_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub reaper_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub public_rpm: u32,
    pub api_rpm: u32,
    pub batch_rpm: u32,
    pub batch_max_links: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChallengeConfig {
    pub dns_txt_prefix: String,
    pub http_well_known_path: String,
    pub challenge_ttl_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UiConfig {
    pub enabled: bool,
    pub session_secret: String,
}

impl Settings {
    pub fn load() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config").required(false))
            .add_source(
                config::Environment::with_prefix("WEBFINGERD")
                    .separator("__"),
            )
            .build()?;

        let s: Self = settings.try_deserialize()?;

        if s.ui.enabled && s.ui.session_secret.is_empty() {
            return Err(config::ConfigError::Message(
                "ui.session_secret is required when ui is enabled".into(),
            ));
        }

        Ok(s)
    }
}
