//! Sandboxing: bind-mount overlays, pivot root, profile mounts/chmods.
//!
//! Centralises the rootfs-isolation logic that was previously inlined in
//! the binary's `Run` / `Up` command handlers.

use std::path::Path;

use anyhow::Result;
use nix::unistd::{Gid, Uid, chown};
use std::os::unix::fs::PermissionsExt;

use crate::{
    PathExpansionState, ProfileChmod, ProfileMount,
    sys::{mount_bind_ro_explicit, mount_bind_rw_explicit},
};

/// Apply a list of profile mounts under `root`, expanding `@` / `~` variables.
pub fn apply_mounts(root: &Path, mounts: &[ProfileMount]) -> Result<()> {
    let vars = PathExpansionState::without_instance();
    for m in mounts {
        let expanded_source = vars.expand(&m.source);
        let expanded_target = vars.expand(&m.target);
        let rel = expanded_target.strip_prefix("/").unwrap();
        let target = root.join(rel);
        if m.read_only {
            mount_bind_ro_explicit(&expanded_source, &target, m.recursive)?;
        } else {
            mount_bind_rw_explicit(&expanded_source, &target, m.recursive)?;
        }
    }
    Ok(())
}

/// Apply a list of profile chmods/chowns under `root`, expanding `@` / `~` variables.
pub fn apply_chmod(root: &Path, chmods: &[ProfileChmod]) -> Result<()> {
    let vars = PathExpansionState::without_instance();
    for c in chmods {
        let expanded_path = vars.expand(&c.path);
        let rel = expanded_path.strip_prefix("/").unwrap();
        let target = root.join(rel);

        if let Some(mode) = c.mode {
            let mut perms = std::fs::metadata(&target)?.permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&target, perms)?;
        }

        if c.uid.is_some() || c.gid.is_some() {
            let uid = c.uid.map(Uid::from_raw);
            let gid = c.gid.map(Gid::from_raw);
            chown(&target, uid, gid)?;
        }
    }
    Ok(())
}
