use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Server configuration
#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
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

    /// Get all files available for a specific client
    pub fn get_client_files(&self, client_id: &str) -> Vec<FileInfo> {
        let Some(client) = self.clients.get(client_id) else {
            return vec![];
        };

        let mut files = Vec::new();
        for group_name in &client.groups {
            if let Some(group) = self.groups.get(group_name) {
                // Add individual files
                for file_path in &group.files {
                    if let Some(file_name) = PathBuf::from(file_path).file_name() {
                        files.push(FileInfo {
                            source_path: PathBuf::from(file_path),
                            relative_path: file_name.to_string_lossy().to_string(),
                            group: group_name.clone(),
                        });
                    }
                }

                // Add directory contents
                for dir_path in &group.directories {
                    if let Ok(entries) = Self::scan_directory(dir_path) {
                        for (source, relative) in entries {
                            files.push(FileInfo {
                                source_path: source,
                                relative_path: relative,
                                group: group_name.clone(),
                            });
                        }
                    }
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
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    pub keys: ServerKeyConfig,
    #[serde(default)]
    pub enrollment: EnrollmentConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

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
    #[serde(default)]
    pub enrolled_at: Option<String>,
}

/// Group configuration
#[derive(Clone, Debug, Deserialize)]
pub struct GroupConfig {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub directories: Vec<String>,
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
files = ["/etc/certs/ca.pem"]
directories = ["/etc/letsencrypt/live/example.com"]
"#;

        let config: ServerConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.server.bind, "127.0.0.1:8080");
        assert!(config.clients.contains_key("test-client"));
        assert!(config.groups.contains_key("production"));
    }
}
