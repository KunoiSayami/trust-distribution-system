use anyhow::Context;
use std::collections::HashSet;
use std::process::Command;

use crate::config::{ActionConfig, ClientConfig};
use crate::sync::ManifestFileEntry;

/// Execute post-download actions for changed files.
///
/// Actions with `immediate = true` run once per triggering file/group in declaration order.
/// Actions with `immediate = false` (default) are deduplicated by (command, args) across the
/// entire cycle — identical commands triggered by multiple files or groups run only once.
pub fn execute_actions(
    changed_files: &[ManifestFileEntry],
    config: &ClientConfig,
) -> anyhow::Result<()> {
    let changed_groups: HashSet<&str> = changed_files.iter().map(|f| f.group.as_str()).collect();

    let mut immediate_actions: Vec<(&ActionConfig, String)> = Vec::new();
    let mut deferred_seen: HashSet<&ActionConfig> = HashSet::new();
    let mut deferred_actions: Vec<&ActionConfig> = Vec::new();

    // Collect file-level actions
    for file in changed_files {
        if let Some(entry) = config.actions.files.get(&file.path) {
            for action in config.actions.resolve_all(entry) {
                if !action.on_change_only {
                    continue;
                }
                if action.immediate {
                    immediate_actions.push((action, format!("file {}", file.path)));
                } else if deferred_seen.insert(action) {
                    deferred_actions.push(action);
                }
            }
        }
    }

    // Collect group-level actions
    for group in &changed_groups {
        if let Some(entry) = config.actions.groups.get(*group) {
            for action in config.actions.resolve_all(entry) {
                if !action.on_change_only {
                    continue;
                }
                if action.immediate {
                    immediate_actions.push((action, format!("group {group}")));
                } else if deferred_seen.insert(action) {
                    deferred_actions.push(action);
                }
            }
        }
    }

    // Run immediate actions in collection order
    for (action, label) in &immediate_actions {
        log::trace!("Running immediate action for {label}");
        run_action(action).with_context(|| format!("Failed to run action for {label}"))?;
    }

    // Run deduplicated deferred actions
    for action in &deferred_actions {
        log::trace!("Running action: {} {:?}", action.command, action.args);
        run_action(action).with_context(|| format!("Failed to run action: {}", action.command))?;
    }

    Ok(())
}

/// Execute all actions regardless of changes (for initial sync or force)
#[allow(unused)]
pub fn execute_all_actions(config: &ClientConfig) -> anyhow::Result<()> {
    // Execute all group actions
    for (group, entry) in &config.actions.groups {
        for action in config.actions.resolve_all(entry) {
            log::trace!("Running group action for {group}");
            run_action(action)
                .with_context(|| format!("Failed to run action for group {group}"))?;
        }
    }

    // Execute all file actions
    for (file, entry) in &config.actions.files {
        for action in config.actions.resolve_all(entry) {
            log::info!("Running file action for {file}");
            run_action(action).with_context(|| format!("Failed to run action for file {file}"))?;
        }
    }

    Ok(())
}

fn run_action(action: &ActionConfig) -> anyhow::Result<()> {
    let status = Command::new(&action.command)
        .args(&action.args)
        .status()
        .with_context(|| format!("Failed to execute command: {}", action.command))?;

    if !status.success() {
        anyhow::bail!("Command '{}' exited with status: {status}", action.command);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_action_echo() {
        let action = ActionConfig {
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            on_change_only: true,
            immediate: false,
        };

        assert!(run_action(&action).is_ok());
    }
}
