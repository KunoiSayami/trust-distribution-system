use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Client configuration
#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub version: u32,
    pub client: ClientSettings,
    #[serde(default)]
    pub subscriptions: HashMap<String, Subscription>,
    #[serde(default)]
    pub actions: ActionsConfig,
}

impl ClientConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientSettings {
    pub id: String,
    pub server_url: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,
    pub keys: ClientKeyConfig,
}

fn default_poll_interval() -> u64 {
    300
}

fn default_state_file() -> PathBuf {
    PathBuf::from("/var/lib/tds/state.json")
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientKeyConfig {
    pub age_identity_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub server_verify_key: String,
}

/// Subscription to a file group
#[derive(Clone, Debug, Deserialize)]
pub struct Subscription {
    pub output_directory: PathBuf,
    #[serde(default = "default_true")]
    pub preserve_structure: bool,
    #[serde(default)]
    pub rename: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Actions configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ActionsConfig {
    #[serde(default)]
    pub groups: HashMap<String, ActionConfig>,
    #[serde(default)]
    pub files: HashMap<String, ActionConfig>,
}

/// Action to run after file download
#[derive(Clone, Debug, Deserialize)]
pub struct ActionConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_true")]
    pub on_change_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_config() {
        let config_str = r#"
version = 1

[client]
id = "client-alpha"
server_url = "https://server:8443"
poll_interval = 300
state_file = "/var/lib/tds/state.json"

[client.keys]
age_identity_path = "/etc/tds/client.age"
signing_key_path = "/etc/tds/client_signing.key"
server_verify_key = "base64key"

[subscriptions.production]
output_directory = "/opt/app/certs"
preserve_structure = true

[subscriptions.production.rename]
"ca.pem" = "root-ca.pem"

[actions.groups.production]
command = "/usr/local/bin/update-ca-trust"
args = []
on_change_only = true
"#;

        let config: ClientConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.client.id, "client-alpha");
        assert_eq!(config.client.poll_interval, 300);
        assert!(config.subscriptions.contains_key("production"));
        assert!(config.actions.groups.contains_key("production"));
    }
}
