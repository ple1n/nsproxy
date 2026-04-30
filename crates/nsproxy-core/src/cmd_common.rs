use std::path::Path;

use anyhow::{Result, anyhow, bail};
use nix::sched::CloneFlags;
use nix::unistd::getresuid;
use nsproxy_common::{NSSource, current_boot_time_secs};
use tracing::warn;

use crate::{NsAlive, WrappedBinariesConfig, shell::ShellPrefs, sys::NSEnter};

fn sanitize_ns_alive_for_current_boot(ns_meta: &Path, mut ns_alive: NsAlive) -> NsAlive {
    let current_boot = match current_boot_time_secs() {
        Ok(current_boot) => current_boot,
        Err(err) => {
            warn!(
                ns_meta = %ns_meta.display(),
                "failed to read current boot time; keeping persisted pid metadata: {}",
                err
            );
            return ns_alive;
        }
    };

    if ns_alive.boot_time_secs == Some(current_boot) {
        return ns_alive;
    }

    if ns_alive.child_pid.is_some() || ns_alive.up_pid.is_some() || ns_alive.serve_pid.is_some() {
        warn!(
            ns_meta = %ns_meta.display(),
            stored_boot = ?ns_alive.boot_time_secs,
            current_boot,
            child_pid = ?ns_alive.child_pid,
            up_pid = ?ns_alive.up_pid,
            serve_pid = ?ns_alive.serve_pid,
            "discarding persisted pid metadata from a different boot"
        );
    }

    ns_alive.boot_time_secs = Some(current_boot);
    ns_alive.child_pid = None;
    ns_alive.up_pid = None;
    ns_alive.serve_pid = None;
    ns_alive
}

pub fn check_proxy_mode(proxy_is_set: bool, no_proxy: bool) -> Result<()> {
    match (proxy_is_set, no_proxy) {
        (true, true) => {
            bail!("Cannot specify both --proxy and --no-proxy. They are mutually exclusive.");
        }
        (false, false) => {
            bail!("Must specify either --proxy <URL> or --no-proxy explicitly.");
        }
        _ => Ok(()),
    }
}

pub fn read_ns_alive(ns_meta: &Path) -> Result<NsAlive> {
    std::fs::read_to_string(ns_meta)
        .ok()
        .and_then(|content| serde_json::from_str::<NsAlive>(&content).ok())
    .map(|ns_alive| sanitize_ns_alive_for_current_boot(ns_meta, ns_alive))
        .ok_or_else(|| anyhow!("NS data not found at {:?}", ns_meta))
}

pub fn read_ns_alive_opt(ns_meta: &Path) -> Option<NsAlive> {
    if !ns_meta.exists() {
        return None;
    }
    std::fs::read_to_string(ns_meta)
        .ok()
        .and_then(|content| serde_json::from_str::<NsAlive>(&content).ok())
        .map(|ns_alive| sanitize_ns_alive_for_current_boot(ns_meta, ns_alive))
}

/// Helper function to safely update NsAlive state.
/// This loads the existing state first, applies the update function,
/// and persists the changes back to disk.
/// This prevents multiple processes from clobbering each other's updates.
pub fn update_ns_alive<F>(ns_meta: &Path, update_fn: F) -> Result<()>
where
    F: FnOnce(&mut NsAlive),
{
    // Load existing state or use default
    let mut ns_alive = read_ns_alive_opt(ns_meta).unwrap_or_default();

    // Apply the update
    update_fn(&mut ns_alive);

    match current_boot_time_secs() {
        Ok(current_boot) => {
            ns_alive.boot_time_secs = Some(current_boot);
        }
        Err(err) => {
            warn!(
                ns_meta = %ns_meta.display(),
                "failed to stamp NsAlive with current boot time: {}",
                err
            );
        }
    }

    // Persist back to disk
    let json = serde_json::to_string_pretty(&ns_alive)?;
    std::fs::write(ns_meta, json)?;

    Ok(())
}

pub fn report_clone3_err(er: &anyhow::Error) -> Result<()> {
    warn!("Clone3 failed with {:?}", er);
    let res = getresuid()?;
    if res.real.is_root() {
        warn!("{:?}", res);
    } else {
        warn!("Is this the executable set with SUID? {:?}", res);
    }
    Ok(())
}

pub fn enter_ns(ns_alive: &NsAlive, fallback_netns: &Path) -> Result<()> {
    if let Some(child_pid) = ns_alive.child_pid {
        let ns_source = NSSource::Pid(child_pid as i32);
        ns_source.enter(CloneFlags::CLONE_NEWNS)?;
        ns_source.enter(CloneFlags::CLONE_NEWNET)?;
    } else {
        let ns = NSSource::Path(fallback_netns.to_path_buf());
        ns.enter(CloneFlags::CLONE_NEWNET)?;
    }
    Ok(())
}

pub fn apply_ns_env(shell: &mut ShellPrefs, ns_alive: &NsAlive) {
    shell.set_container_env(ns_alive.profile_name.as_deref());
    shell.set_nsproxy_env(ns_alive.browser_profile.clone());
    shell.set_ns_env(Some(&ns_alive.bind_mount.to_string_lossy()));
}
