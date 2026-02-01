use anyhow::Context;
use std::collections::HashSet;
use std::process::Command;

use crate::config::{ActionConfig, ClientConfig};
use crate::sync::ManifestFileEntry;

/// Execute post-download actions for changed files
pub fn execute_actions(
    changed_files: &[ManifestFileEntry],
    config: &ClientConfig,
) -> anyhow::Result<()> {
    // Collect unique groups that had changes
    let changed_groups: HashSet<&str> = changed_files.iter().map(|f| f.group.as_str()).collect();

    // Execute file-specific actions first
    for file in changed_files {
        if let Some(action) = config.actions.files.get(&file.path) {
            if action.on_change_only {
                log::info!("Running file action for {}", file.path);
                run_action(action).with_context(|| {
                    format!("Failed to run action for file {}", file.path)
                })?;
            }
        }
    }

    // Execute group actions
    for group in changed_groups {
        if let Some(action) = config.actions.groups.get(group) {
            if action.on_change_only {
                log::info!("Running group action for {}", group);
                run_action(action)
                    .with_context(|| format!("Failed to run action for group {}", group))?;
            }
        }
    }

    Ok(())
}

/// Execute all actions regardless of changes (for initial sync or force)
pub fn execute_all_actions(config: &ClientConfig) -> anyhow::Result<()> {
    // Execute all group actions
    for (group, action) in &config.actions.groups {
        log::info!("Running group action for {}", group);
        run_action(action).with_context(|| format!("Failed to run action for group {}", group))?;
    }

    // Execute all file actions
    for (file, action) in &config.actions.files {
        log::info!("Running file action for {}", file);
        run_action(action).with_context(|| format!("Failed to run action for file {}", file))?;
    }

    Ok(())
}

fn run_action(action: &ActionConfig) -> anyhow::Result<()> {
    let status = Command::new(&action.command)
        .args(&action.args)
        .status()
        .with_context(|| format!("Failed to execute command: {}", action.command))?;

    if !status.success() {
        anyhow::bail!(
            "Command '{}' exited with status: {}",
            action.command,
            status
        );
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
        };

        assert!(run_action(&action).is_ok());
    }
}
