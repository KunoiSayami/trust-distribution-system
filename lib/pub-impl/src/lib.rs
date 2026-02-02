use anyhow::anyhow;
use serde::{Deserialize, Serialize};

/// Token format prefix
pub const TOKEN_VERSION: &str = "tds-enroll-v1";

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
    pub age_public_key: String,
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
    pub server_age_recipient: String,
    pub server_verify_key: String,
}

impl ParsedToken {
    /// Parse an enrollment token string
    pub fn parse(token: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid token format"));
        }
        if parts[0] != TOKEN_VERSION {
            return Err(anyhow!("Unsupported token version"));
        }

        Ok(Self {
            secret: parts[1].to_string(),
            server_age_recipient: parts[2].to_string(),
            server_verify_key: parts[3].to_string(),
        })
    }

    /// Create a token string from components
    pub fn to_token_string(
        secret: &str,
        server_age_recipient: &str,
        server_verify_key: &str,
    ) -> String {
        format!(
            "{}:{}:{}:{}",
            TOKEN_VERSION, secret, server_age_recipient, server_verify_key
        )
    }
}
