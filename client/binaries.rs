use std::path::Path;

use crate::config::BinarySubscription;

/// Apply post-download actions for a binary asset: set the executable bit if configured.
pub fn apply_post_download(
    subscription: &BinarySubscription,
    output_path: &Path,
) -> anyhow::Result<()> {
    if subscription.make_executable {
        set_executable(output_path)?;
    }
    Ok(())
}

fn set_executable(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
