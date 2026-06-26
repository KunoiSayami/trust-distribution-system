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
    #[serde(default)]
    pub binaries: HashMap<String, BinaryAsset>,
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
        check_file_readable(
            &self.server.keys.x25519_identity_path,
            "x25519_identity_path",
        )?;

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

        // Client validation
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        for (client_id, client) in &self.clients {
            // client_id must be non-empty and contain only safe characters
            if client_id.is_empty() {
                anyhow::bail!("Client ID must not be empty");
            }
            if client_id
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.')
            {
                anyhow::bail!(
                    "Client {client_id:?}: ID contains invalid characters (allowed: alphanumeric, -, _, .)"
                );
            }

            // auth_public_key: must be valid base64 decoding to 32 bytes (Ed25519)
            let key_bytes = BASE64.decode(&client.auth_public_key).with_context(|| {
                format!("Client {client_id:?}: auth_public_key is not valid base64")
            })?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "Client {client_id:?}: auth_public_key must decode to 32 bytes (got {})",
                    key_bytes.len()
                );
            }

            // x25519_public_key: must be a valid X25519 recipient
            encryption::X25519Recipient::from_str(&client.x25519_public_key).with_context(
                || {
                    format!(
                        "Client {client_id:?}: x25519_public_key is not a valid X25519 recipient"
                    )
                },
            )?;
        }

        // Client group references: every group a client references must exist
        for (client_id, client) in &self.clients {
            for group in &client.groups {
                if !self.groups.contains_key(group) {
                    anyhow::bail!("Client {client_id:?} references unknown group {group:?}");
                }
            }
        }

        // Group names: only alphanumeric, hyphen, underscore (no slash, colon, etc.)
        // The group name is used as a path prefix exposed to clients; unsafe characters
        // would allow path traversal or ambiguous segment splitting.
        for group_name in self.groups.keys() {
            if group_name.is_empty() {
                anyhow::bail!("Group name must not be empty");
            }
            if group_name
                .chars()
                .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
            {
                anyhow::bail!(
                    "Group {group_name:?}: name contains invalid characters (allowed: alphanumeric, -, _)"
                );
            }
        }

        // Group paths: each configured path must exist and files must be readable.
        // Also verify the common parent of all paths in a group is not the filesystem
        // root, which would expose the full directory structure to clients.
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
            if !group.paths.is_empty() {
                let roots: Vec<PathBuf> = group
                    .paths
                    .iter()
                    .map(|p| {
                        let path = PathBuf::from(p);
                        if path.is_dir() {
                            path
                        } else {
                            path.parent().unwrap_or(&path).to_path_buf()
                        }
                    })
                    .collect();
                let common = common_parent(&roots);
                if common == std::path::Path::new("/") {
                    anyhow::bail!(
                        "Group {group_name:?}: paths span the filesystem root — configure a more specific common directory to avoid exposing the full path structure"
                    );
                }
            }
        }

        // Binary assets: each path must exist and be readable
        for (name, asset) in &self.binaries {
            check_file_readable(&asset.path, &format!("Binary {name:?} path"))?;
        }

        // Client binary references: every name a client references must exist in self.binaries
        for (client_id, client) in &self.clients {
            for binary_name in &client.binaries {
                if !self.binaries.contains_key(binary_name) {
                    anyhow::bail!("Client {client_id:?} references unknown binary {binary_name:?}");
                }
            }
        }

        Ok(())
    }

    /// Get all files available for a specific client.
    ///
    /// Relative paths use the format `{group_name}:{path_from_common_parent}` where
    /// the common parent is computed across all path roots in the group. This ensures
    /// no absolute filesystem paths are exposed to clients while still producing unique
    /// identities for same-named files in different subdirectories.
    pub fn get_client_files(&self, client_id: &str) -> Vec<FileInfo> {
        let Some(client) = self.clients.get(client_id) else {
            return vec![];
        };

        let mut files = Vec::new();
        for group_name in &client.groups {
            if let Some(group) = self.groups.get(group_name) {
                // Collect the "root" directory for each configured path:
                // directories use themselves; single files use their parent.
                let roots: Vec<PathBuf> = group
                    .paths
                    .iter()
                    .map(|p| {
                        let path = PathBuf::from(p);
                        if path.is_dir() {
                            path
                        } else {
                            path.parent()
                                .unwrap_or(std::path::Path::new("/"))
                                .to_path_buf()
                        }
                    })
                    .collect();

                let base = if roots.is_empty() {
                    PathBuf::from("/")
                } else {
                    common_parent(&roots)
                };

                for path_str in &group.paths {
                    let path = PathBuf::from(path_str);

                    if path.is_dir() {
                        if let Ok(entries) = Self::scan_directory_rooted(path_str) {
                            for (source, file_rel) in entries {
                                // Path of file relative to the directory entry itself,
                                // then make the directory entry relative to the common base.
                                let dir_rel = path
                                    .strip_prefix(&base)
                                    .unwrap_or(&path)
                                    .to_string_lossy()
                                    .replace('\\', "/");
                                let relative_path = if dir_rel.is_empty() {
                                    format!("{group_name}:{file_rel}")
                                } else {
                                    format!("{group_name}:{dir_rel}/{file_rel}")
                                };
                                files.push(FileInfo {
                                    source_path: source,
                                    relative_path,
                                    group: group_name.clone(),
                                });
                            }
                        }
                    } else if path.is_file() {
                        let rel = path
                            .strip_prefix(&base)
                            .unwrap_or(path.file_name().map(std::path::Path::new).unwrap_or(&path))
                            .to_string_lossy()
                            .replace('\\', "/");
                        if !rel.is_empty() {
                            files.push(FileInfo {
                                source_path: path,
                                relative_path: format!("{group_name}:{rel}"),
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

    /// Get all binary assets available for a specific client
    pub fn get_client_binaries(&self, client_id: &str) -> Vec<BinaryFileInfo> {
        let Some(client) = self.clients.get(client_id) else {
            return vec![];
        };
        client
            .binaries
            .iter()
            .filter_map(|name| {
                self.binaries.get(name).map(|asset| BinaryFileInfo {
                    name: name.clone(),
                    source_path: asset.path.clone(),
                })
            })
            .collect()
    }

    /// Recursively scan a directory and return (source_path, relative_path) pairs.
    /// relative_path is relative to `dir` itself (no leading directory name component),
    /// so callers can prepend whatever prefix they need (e.g. the group name).
    fn scan_directory_rooted(dir: &str) -> anyhow::Result<Vec<(PathBuf, String)>> {
        use walkdir::WalkDir;

        let dir_path = PathBuf::from(dir);

        let mut results = Vec::new();
        for entry in WalkDir::new(dir).follow_links(true) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let source = entry.path().to_path_buf();
                let relative = entry
                    .path()
                    .strip_prefix(&dir_path)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
                results.push((source, relative));
            }
        }
        Ok(results)
    }
}

/// Compute the longest common ancestor directory of a set of paths.
/// Returns `/` if no common ancestor exists above the root.
fn common_parent(paths: &[PathBuf]) -> PathBuf {
    let mut paths = paths.iter();
    let Some(first) = paths.next() else {
        return PathBuf::from("/");
    };

    let mut common: Vec<&std::ffi::OsStr> = first
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    for path in paths {
        let components: Vec<&std::ffi::OsStr> = path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect();
        let shared = common
            .iter()
            .zip(components.iter())
            .take_while(|(a, b)| a == b)
            .count();
        common.truncate(shared);
    }

    if common.is_empty() {
        PathBuf::from("/")
    } else {
        let mut result = PathBuf::from("/");
        for part in common {
            result.push(part);
        }
        result
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
    pub x25519_identity_path: PathBuf,
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
    pub x25519_public_key: String,
    pub auth_public_key: String,
    pub groups: Vec<String>,
    pub enrolled_at: Option<String>,
    /// Names of binary assets assigned to this client
    #[serde(default)]
    pub binaries: Vec<String>,
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

/// Named binary asset available for distribution
#[derive(Clone, Debug, Deserialize)]
pub struct BinaryAsset {
    #[allow(unused)]
    pub description: Option<String>,
    pub path: PathBuf,
}

/// File info for serving
#[derive(Clone, Debug)]
pub struct FileInfo {
    pub source_path: PathBuf,
    pub relative_path: String,
    pub group: String,
}

/// Binary asset info for serving
#[derive(Clone, Debug)]
pub struct BinaryFileInfo {
    pub name: String,
    pub source_path: PathBuf,
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
x25519_identity_path = "/etc/tds/server.x25519"

[clients.test-client]
x25519_public_key = "X25519-PUBLIC-KEY-1:aabbcc"
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
