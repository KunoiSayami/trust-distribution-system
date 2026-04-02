use anyhow::anyhow;
use serde::{Deserialize, Serialize};

/// Token format prefix
pub const TOKEN_VERSION: &str = "tds-enroll-v2";

// ============================================================================
// Shared enrollment types (used by both server and client)
// ============================================================================

/// Enrollment request sent from client to server
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Token secret for token-based enrollment
    #[serde(default)]
    pub token_secret: String,
    /// Encrypted payload containing client keys
    pub encrypted_payload: String,
    /// Client ID for localhost enrollment (when allow_localhost is enabled)
    pub client_id: Option<String>,
    /// Groups for localhost enrollment (when allow_localhost is enabled)
    pub groups: Option<Vec<String>>,
}

/// Payload inside the encrypted enrollment request
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollPayload {
    pub x25519_public_key: String,
    pub auth_public_key: String,
}

/// Enrollment response from server to client
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub client_id: String,
    pub groups: Vec<String>,
}

/// Parsed enrollment token
#[derive(Debug, Clone)]
pub struct ParsedToken {
    pub secret: String,
    pub server_x25519_recipient: String,
    pub server_verify_key: String,
}

impl ParsedToken {
    /// Parse an enrollment token string
    pub fn parse(token: &str) -> anyhow::Result<Self> {
        // Token format: tds-enroll-v2:SECRET:X25519-PUBLIC-KEY-1:<hex>:VERIFYKEY
        // Use splitn(5) so the key prefix "X25519-PUBLIC-KEY-1:<hex>" is not split apart.
        let parts: Vec<&str> = token.splitn(5, ':').collect();
        if parts.len() != 5 {
            return Err(anyhow!("Invalid token format"));
        }
        if parts[0] != TOKEN_VERSION {
            return Err(anyhow!("Unsupported token version"));
        }

        // Reassemble the recipient key: parts[2] + ":" + parts[3]
        let server_x25519_recipient = format!("{}:{}", parts[2], parts[3]);

        Ok(Self {
            secret: parts[1].to_string(),
            server_x25519_recipient,
            server_verify_key: parts[4].to_string(),
        })
    }

    /// Create a token string from components
    pub fn to_token_string(
        secret: &str,
        server_x25519_recipient: &str,
        server_verify_key: &str,
    ) -> String {
        format!(
            "{}:{}:{}:{}",
            TOKEN_VERSION, secret, server_x25519_recipient, server_verify_key
        )
    }
}

pub fn init_log(verbose: u8) {
    let mut builder = env_logger::Builder::from_default_env();

    if verbose > 4 {
        builder.filter_module("h2::proto", log::LevelFilter::Warn);
    }

    if verbose > 3 {
        builder.filter_module("h2::codec", log::LevelFilter::Warn);
    }

    if verbose > 2 {
        builder.filter_module("hyper_util::client", log::LevelFilter::Warn);
    }
    if verbose > 1 {
        builder.filter_module("reqwest::connect", log::LevelFilter::Warn);
    }

    builder.init();
}
