use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::configure::ServerConfig;
use crate::enrollment::TokenStore;

// Re-export shared types from pub-impl
pub use pub_impl::{EnrollPayload, EnrollRequest, EnrollResponse};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<ServerConfig>>,
    pub server_signing_key: Arc<encryption::SigningKey>,
    pub server_age_identity: Arc<encryption::AgeIdentity>,
    pub nonce_cache: Arc<NonceCache>,
    pub token_store: Arc<RwLock<TokenStore>>,
    pub config_path: PathBuf,
}

impl AppState {
    pub fn new(
        config: ServerConfig,
        signing_key: encryption::SigningKey,
        age_identity: encryption::AgeIdentity,
        token_store: TokenStore,
        config_path: PathBuf,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            server_signing_key: Arc::new(signing_key),
            server_age_identity: Arc::new(age_identity),
            nonce_cache: Arc::new(NonceCache::new()),
            token_store: Arc::new(RwLock::new(token_store)),
            config_path,
        }
    }
}

/// Nonce cache to prevent replay attacks
pub struct NonceCache {
    /// Map of (client_id, nonce) -> expiry_timestamp
    entries: DashMap<(String, String), i64>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Check if nonce is valid and mark as used
    /// Returns true if nonce is valid (not seen before)
    pub fn check_and_mark(&self, client_id: &str, nonce: &str, timestamp: i64) -> bool {
        let key = (client_id.to_string(), nonce.to_string());

        // Reject if already used
        if self.entries.contains_key(&key) {
            return false;
        }

        // Store with expiry (timestamp + 5 minute window)
        let expiry = timestamp + (5 * 60 * 1000);
        self.entries.insert(key, expiry);

        true
    }

    /// Periodic cleanup of expired entries
    pub fn cleanup(&self) {
        let now = chrono::Utc::now().timestamp_millis();
        self.entries.retain(|_, expiry| *expiry > now);
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// API response types
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct ManifestResponse {
    pub version: u32,
    pub timestamp: i64,
    pub files: Vec<ManifestFileEntry>,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub path: String,
    pub content_hash: String,
    pub size: u64,
    pub group: String,
    /// File modification timestamp (Unix seconds)
    pub modified_at: i64,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }
}
