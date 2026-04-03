use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use encryption::ChunkedEncrypted;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::configure::ServerConfig;
use crate::enrollment::TokenStore;

// Re-export shared types from pub-impl
pub use pub_impl::{EnrollPayload, EnrollRequest, EnrollResponse};

/// Per-group server directives included in the manifest.
/// New optional fields may be added here in the future; all must use `#[serde(default)]`
/// so old clients silently ignore additions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupDirectives {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_sync_token: Option<String>,
    // Future per-group fields go here with #[serde(default)]
}

impl GroupDirectives {
    #[allow(dead_code)]
    pub fn force_sync_token(&self) -> Option<&str> {
        self.force_sync_token.as_deref()
    }
}

/// Top-level directives map included in the manifest, keyed by group name.
/// Uses `BTreeMap` to guarantee deterministic key order for signature verification.
/// `#[serde(default)]` ensures old clients that don't know this field get an empty map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestDirectives(pub BTreeMap<String, GroupDirectives>);

impl ManifestDirectives {
    #[allow(dead_code)]
    pub fn get(&self, group: &str) -> Option<&GroupDirectives> {
        self.0.get(group)
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = (&String, &GroupDirectives)> {
        self.0.iter()
    }
}

/// Cached per-client encrypted file (keyed by (client_id, relative_path))
pub struct CachedEncryption {
    pub payload: ChunkedEncrypted,
    pub expires_at: std::time::Instant,
    pub content_hash: String,
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<ServerConfig>>,
    pub server_signing_key: Arc<encryption::SigningKey>,
    pub server_x25519_identity: Arc<encryption::X25519Identity>,
    pub nonce_cache: Arc<NonceCache>,
    pub chunk_cache: Arc<DashMap<(String, String), CachedEncryption>>,
    pub token_store: Arc<RwLock<TokenStore>>,
    pub config_path: PathBuf,
    /// In-memory force-sync tokens: group name → active directives.
    /// Absent entry means no active directives for that group.
    /// Intentionally transient — cleared on server restart.
    pub group_directives: Arc<DashMap<String, GroupDirectives>>,
}

impl AppState {
    pub fn new(
        config: ServerConfig,
        signing_key: encryption::SigningKey,
        x25519_identity: encryption::X25519Identity,
        token_store: TokenStore,
        config_path: PathBuf,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            server_signing_key: Arc::new(signing_key),
            server_x25519_identity: Arc::new(x25519_identity),
            nonce_cache: Arc::new(NonceCache::new()),
            chunk_cache: Arc::new(DashMap::new()),
            token_store: Arc::new(RwLock::new(token_store)),
            config_path,
            group_directives: Arc::new(DashMap::new()),
        }
    }

    pub fn group_directives(&self) -> &DashMap<String, GroupDirectives> {
        &self.group_directives
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
    /// Per-group directives. Old clients that don't know this field will
    /// deserialize it as the default (empty map) and ignore it entirely.
    #[serde(default)]
    pub directives: ManifestDirectives,
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
