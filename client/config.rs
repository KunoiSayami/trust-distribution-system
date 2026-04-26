use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Client configuration
#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    #[allow(unused)]
    pub version: u32,
    pub client: ClientSettings,
    #[serde(default)]
    pub subscriptions: HashMap<String, Subscription>,
    #[serde(default)]
    pub actions: ActionsConfig,
    #[serde(default)]
    pub binaries: HashMap<String, BinarySubscription>,
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
    pub x25519_identity_path: PathBuf,
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

/// Subscription to a named binary asset
#[derive(Clone, Debug, Deserialize)]
pub struct BinarySubscription {
    pub output_path: PathBuf,
    /// Set executable bit after download (Unix only). Defaults to true.
    #[serde(default = "default_true")]
    pub make_executable: bool,
}

/// Actions configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ActionsConfig {
    #[serde(default)]
    pub templates: HashMap<String, ActionConfig>,
    #[serde(default)]
    pub groups: HashMap<String, ActionEntry>,
    #[serde(default)]
    pub files: HashMap<String, ActionEntry>,
}

impl ActionsConfig {
    /// Resolve an `ActionEntry` into an iterator of concrete `ActionConfig` references,
    /// following template references and expanding lists.
    pub fn resolve_all<'a>(
        &'a self,
        entry: &'a ActionEntry,
    ) -> Box<dyn Iterator<Item = &'a ActionConfig> + 'a> {
        match entry {
            ActionEntry::Inline(config) => Box::new(std::iter::once(config)),
            ActionEntry::Template(name) => Box::new(self.templates.get(name.as_str()).into_iter()),
            ActionEntry::Many(entries) => {
                Box::new(entries.iter().flat_map(|e| self.resolve_all(e)))
            }
        }
    }
}

/// An action entry: a single inline definition, a template reference, or an ordered list.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ActionEntry {
    /// Ordered list of entries, executed in sequence.
    Many(Vec<ActionEntry>),
    /// Inline action definition.
    Inline(ActionConfig),
    /// Name of a template defined in `[actions.templates]`.
    Template(String),
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
x25519_identity_path = "/etc/tds/client.x25519"
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
        assert!(matches!(
            config.actions.groups.get("production").unwrap(),
            ActionEntry::Inline(_)
        ));
    }

    #[test]
    fn test_parse_client_config_template_reference() {
        let config_str = r#"
version = 1

[client]
id = "client-beta"
server_url = "https://server:8443"

[client.keys]
x25519_identity_path = "/etc/tds/client.x25519"
signing_key_path = "/etc/tds/client_signing.key"
server_verify_key = "base64key"

[actions.templates.reload-nginx]
command = "/usr/bin/systemctl"
args = ["reload", "nginx"]
on_change_only = true

[actions.groups]
web-servers = "reload-nginx"
web-configs = "reload-nginx"
"#;

        let config: ClientConfig = toml::from_str(config_str).unwrap();
        assert!(config.actions.templates.contains_key("reload-nginx"));

        let entry = config.actions.groups.get("web-servers").unwrap();
        assert!(matches!(entry, ActionEntry::Template(n) if n == "reload-nginx"));

        let resolved: Vec<_> = config.actions.resolve_all(entry).collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].command, "/usr/bin/systemctl");

        // Both groups resolve to the same template
        let entry2 = config.actions.groups.get("web-configs").unwrap();
        let resolved2: Vec<_> = config.actions.resolve_all(entry2).collect();
        assert_eq!(resolved2[0].command, "/usr/bin/systemctl");
    }

    #[test]
    fn test_parse_client_config_action_list() {
        let config_str = r#"
version = 1

[client]
id = "client-gamma"
server_url = "https://server:8443"

[client.keys]
x25519_identity_path = "/etc/tds/client.x25519"
signing_key_path = "/etc/tds/client_signing.key"
server_verify_key = "base64key"

[actions.templates.reload-nginx]
command = "/usr/bin/systemctl"
args = ["reload", "nginx"]
on_change_only = true

[actions.groups]
web-servers = ["reload-nginx", {command = "/usr/bin/notify-send", args = ["done"]}]
"#;

        let config: ClientConfig = toml::from_str(config_str).unwrap();
        let entry = config.actions.groups.get("web-servers").unwrap();
        assert!(matches!(entry, ActionEntry::Many(_)));

        let resolved: Vec<_> = config.actions.resolve_all(entry).collect();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].command, "/usr/bin/systemctl");
        assert_eq!(resolved[1].command, "/usr/bin/notify-send");
    }
}
