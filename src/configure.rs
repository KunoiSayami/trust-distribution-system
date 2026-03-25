use anyhow::Context;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration
#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    #[allow(unused)]
    pub version: u32,
    pub server: ServerSettings,
    #[serde(default)]
    pub clients: HashMap<String, ClientEntry>,
    #[serde(default)]
    pub groups: HashMap<String, GroupConfig>,
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // Version
        if self.version != 1 {
            anyhow::bail!(
                "Unsupported config version {}; only version 1 is supported",
                self.version
            );
        }

        // Bind address must be a valid socket address
        let bind = &self.server.bind;
        bind.parse::<SocketAddr>()
            .with_context(|| format!("Invalid bind address {bind:?}"))?;

        // Key files must exist and be readable
        check_file_readable(&self.server.keys.signing_key_path, "signing_key_path")?;
        check_file_readable(&self.server.keys.age_identity_path, "age_identity_path")?;

        // Admin config (if present): validate password_hash and totp_secret are parseable
        if let Some(admin) = &self.server.admin {
            argon2::PasswordHash::new(&admin.password_hash)
                .map_err(|e| anyhow::anyhow!("Invalid admin password_hash: {e}"))?;
            data_encoding::BASE32_NOPAD
                .decode(admin.totp_secret.to_uppercase().as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid admin totp_secret: {e}"))?;
        }

        // Enrollment token expiry must be > 0
        if self.server.enrollment.token_expiry_hours == 0 {
            anyhow::bail!("enrollment.token_expiry_hours must be greater than 0");
        }

        // TLS file existence + readability (if configured)
        if let Some(tls) = &self.server.tls {
            check_file_readable(&tls.cert_path, "TLS cert_path")?;
            check_file_readable(&tls.key_path, "TLS key_path")?;
        }

        // Client auth_public_key: must be valid base64 decoding to 32 bytes (Ed25519)
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        for (client_id, client) in &self.clients {
            let key_bytes = BASE64.decode(&client.auth_public_key).with_context(|| {
                format!("Client {client_id:?}: auth_public_key is not valid base64")
            })?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "Client {client_id:?}: auth_public_key must decode to 32 bytes (got {})",
                    key_bytes.len()
                );
            }
        }

        // Client group references: every group a client references must exist
        for (client_id, client) in &self.clients {
            for group in &client.groups {
                if !self.groups.contains_key(group) {
                    anyhow::bail!("Client {client_id:?} references unknown group {group:?}");
                }
            }
        }

        // Group paths: each configured path must exist and files must be readable
        for (group_name, group) in &self.groups {
            for path_str in &group.paths {
                let path = std::path::Path::new(path_str);
                if !path.exists() {
                    anyhow::bail!("Group {group_name:?} path does not exist: {path:?}");
                }
                if path.is_file() {
                    check_file_readable(path, &format!("Group {group_name:?} path"))?;
                }
            }
        }

        Ok(())
    }

    /// Get all files available for a specific client
    pub fn get_client_files(&self, client_id: &str) -> Vec<FileInfo> {
        let Some(client) = self.clients.get(client_id) else {
            return vec![];
        };

        let mut files = Vec::new();
        for group_name in &client.groups {
            if let Some(group) = self.groups.get(group_name) {
                for path_str in &group.paths {
                    let path = PathBuf::from(path_str);

                    // Auto-detect: check if path is directory or file
                    if path.is_dir() {
                        // Scan directory recursively
                        if let Ok(entries) = Self::scan_directory(path_str) {
                            for (source, relative) in entries {
                                files.push(FileInfo {
                                    source_path: source,
                                    relative_path: relative,
                                    group: group_name.clone(),
                                });
                            }
                        }
                    } else if path.is_file() {
                        // Single file
                        let relative_path = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if !relative_path.is_empty() {
                            files.push(FileInfo {
                                source_path: path,
                                relative_path,
                                group: group_name.clone(),
                            });
                        }
                    }
                    // Skip non-existent paths silently
                }
            }
        }
        files
    }

    /// Recursively scan a directory and return (source_path, relative_path) pairs
    fn scan_directory(dir: &str) -> anyhow::Result<Vec<(PathBuf, String)>> {
        use walkdir::WalkDir;

        let dir_path = PathBuf::from(dir);
        let dir_name = dir_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut results = Vec::new();
        for entry in WalkDir::new(dir).follow_links(true) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let source = entry.path().to_path_buf();
                // Create relative path under the directory name
                let relative = entry
                    .path()
                    .strip_prefix(&dir_path)
                    .map(|p| format!("{}/{}", dir_name, p.to_string_lossy()))
                    .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
                results.push((source, relative));
            }
        }
        Ok(results)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerSettings {
    pub bind: String,
    pub tls: Option<TlsConfig>,
    #[allow(unused)]
    pub proxy: Option<ProxyConfig>,
    pub keys: ServerKeyConfig,
    #[serde(default)]
    pub enrollment: EnrollmentConfig,
    /// Admin authentication config (optional - disables admin endpoint if not set)
    pub admin: Option<AdminConfig>,
}

/// Admin authentication configuration
#[derive(Clone, Debug, Deserialize)]
pub struct AdminConfig {
    /// Argon2id password hash (PHC string format)
    pub password_hash: String,
    /// Base32-encoded TOTP secret
    pub totp_secret: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[allow(unused)]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub use_forwarded_headers: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerKeyConfig {
    pub signing_key_path: PathBuf,
    pub age_identity_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnrollmentConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_token_expiry")]
    pub token_expiry_hours: u32,
    #[serde(default)]
    pub allow_localhost: bool,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            token_expiry_hours: 1,
            allow_localhost: false,
        }
    }
}

fn check_file_readable(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    std::fs::File::open(path).with_context(|| format!("{label} is not readable: {path:?}"))?;
    Ok(())
}

fn default_true() -> bool {
    true
}

fn default_token_expiry() -> u32 {
    1
}

/// Client entry in server config
#[derive(Clone, Debug, Deserialize)]
pub struct ClientEntry {
    pub age_public_key: String,
    pub auth_public_key: String,
    pub groups: Vec<String>,
    pub enrolled_at: Option<String>,
}

/// Group configuration
#[derive(Clone, Debug, Deserialize)]
pub struct GroupConfig {
    #[allow(unused)]
    pub description: Option<String>,
    /// Paths to files or directories (auto-detected)
    #[serde(default)]
    pub paths: Vec<String>,
}

/// File info for serving
#[derive(Clone, Debug)]
pub struct FileInfo {
    pub source_path: PathBuf,
    pub relative_path: String,
    pub group: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config_str = r#"
version = 1

[server]
bind = "127.0.0.1:8080"

[server.keys]
signing_key_path = "/etc/tds/server_signing.key"
age_identity_path = "/etc/tds/server.age"

[clients.test-client]
age_public_key = "age1test..."
auth_public_key = "base64key"
groups = ["production"]

[groups.production]
paths = ["/etc/certs/ca.pem", "/etc/letsencrypt/live/example.com"]
"#;

        let config: ServerConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.server.bind, "127.0.0.1:8080");
        assert!(config.clients.contains_key("test-client"));
        assert!(config.groups.contains_key("production"));
    }
}
