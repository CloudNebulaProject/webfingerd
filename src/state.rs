use sea_orm::DatabaseConnection;
use std::sync::Arc;

use crate::cache::Cache;
use crate::challenge::ChallengeVerifier;
use crate::config::Settings;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub cache: Cache,
    pub settings: Arc<Settings>,
    pub challenge_verifier: Arc<dyn ChallengeVerifier>,
}
