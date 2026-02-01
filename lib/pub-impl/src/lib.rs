use anyhow::anyhow;

/// Token format prefix
pub const TOKEN_VERSION: &str = "tds-enroll-v1";

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
