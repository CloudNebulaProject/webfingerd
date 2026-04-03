use tracing_subscriber::{fmt, EnvFilter};
use webfingerd::config::Settings;

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let settings = Settings::load().expect("failed to load configuration");
    tracing::info!(listen = %settings.server.listen, "starting webfingerd");
}
