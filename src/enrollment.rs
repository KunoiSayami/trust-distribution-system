use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Token storage file format
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TokenStore {
    pub tokens: Vec<TokenEntry>,
}

impl TokenStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a new token entry
    pub fn add(&mut self, entry: TokenEntry) {
        self.tokens.push(entry);
    }

    /// Find and validate a token by its secret
    pub fn validate(&self, secret: &str) -> Option<&TokenEntry> {
        let secret_hash = hash_secret(secret);
        self.tokens
            .iter()
            .find(|t| t.token_hash == secret_hash && !t.used && !t.is_expired())
    }

    /// Mark a token as used
    pub fn mark_used(&mut self, secret: &str) -> bool {
        let secret_hash = hash_secret(secret);
        if let Some(token) = self.tokens.iter_mut().find(|t| t.token_hash == secret_hash) {
            token.used = true;
            true
        } else {
            false
        }
    }

    /// Remove expired tokens
    pub fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.tokens.retain(|t| t.expires_at > now && !t.used);
    }

    /// List pending (unused, not expired) tokens
    pub fn pending(&self) -> Vec<&TokenEntry> {
        self.tokens
            .iter()
            .filter(|t| !t.used && !t.is_expired())
            .collect()
    }

    /// Revoke a token by client_id
    pub fn revoke(&mut self, client_id: &str) -> bool {
        let initial_len = self.tokens.len();
        self.tokens.retain(|t| t.client_id != client_id);
        self.tokens.len() != initial_len
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    /// SHA-256 hash of the secret (we don't store the raw secret)
    pub token_hash: String,
    /// Client ID this token is for
    pub client_id: String,
    /// Groups the client will be added to
    pub groups: Vec<String>,
    /// When the token was created (unix timestamp seconds)
    pub created_at: i64,
    /// When the token expires (unix timestamp seconds)
    pub expires_at: i64,
    /// Whether the token has been used
    pub used: bool,
}

impl TokenEntry {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.expires_at <= now
    }

    /// Format expires_at as human-readable string
    pub fn expires_at_string(&self) -> String {
        chrono::DateTime::from_timestamp(self.expires_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "invalid".to_string())
    }

    /// Format created_at as human-readable string
    #[allow(unused)]
    pub fn created_at_string(&self) -> String {
        chrono::DateTime::from_timestamp(self.created_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "invalid".to_string())
    }
}

/// Hash a secret for storage
pub fn hash_secret(secret: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(secret.as_bytes())))
}

/// Generate a new enrollment token
pub fn generate_token(
    client_id: &str,
    groups: &[String],
    server_age_recipient: &str,
    server_verify_key: &str,
    expiry_hours: u32,
) -> (String, TokenEntry) {
    // Generate random secret
    let secret: [u8; 32] = rand::thread_rng().r#gen();
    let secret_b64 = BASE64.encode(secret);

    // Create the full token string
    let token = format!(
        "tds-enroll-v1:{}:{}:{}",
        secret_b64, server_age_recipient, server_verify_key
    );

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(expiry_hours as i64);

    let entry = TokenEntry {
        token_hash: hash_secret(&secret_b64),
        client_id: client_id.to_string(),
        groups: groups.to_vec(),
        created_at: now.timestamp(),
        expires_at: expires.timestamp(),
        used: false,
    };

    (token, entry)
}

#[cfg(test)]
mod tests {
    use pub_impl::ParsedToken;

    use super::*;

    #[test]
    fn test_generate_and_parse_token() {
        let (token, entry) = generate_token(
            "test-client",
            &["production".to_string()],
            "age1recipient...",
            "base64verifykey",
            1,
        );

        assert!(token.starts_with("tds-enroll-v1:"));
        assert_eq!(entry.client_id, "test-client");
        assert!(!entry.used);
        assert!(!entry.is_expired());

        let parsed = ParsedToken::parse(&token).unwrap();
        assert_eq!(parsed.server_age_recipient, "age1recipient...");
        assert_eq!(parsed.server_verify_key, "base64verifykey");

        // Verify hash matches
        assert_eq!(hash_secret(&parsed.secret), entry.token_hash);
    }

    #[test]
    fn test_token_store() {
        let (_, entry) = generate_token(
            "test-client",
            &["production".to_string()],
            "age1...",
            "key...",
            1,
        );

        let mut store = TokenStore::default();
        store.add(entry);

        assert_eq!(store.pending().len(), 1);
        assert!(store.revoke("test-client"));
        assert_eq!(store.pending().len(), 0);
    }
}
