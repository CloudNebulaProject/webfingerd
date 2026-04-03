use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use metrics_exporter_prometheus::PrometheusHandle;
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
    pub metrics_handle: PrometheusHandle,
    pub cookie_key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
