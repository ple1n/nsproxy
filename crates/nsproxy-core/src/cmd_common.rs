use std::path::Path;

use anyhow::{Result, anyhow, bail};
use nix::sched::CloneFlags;
use nix::unistd::getresuid;
use nsproxy_common::NSSource;
use tracing::warn;

use crate::{NsAlive, WrappedBinariesConfig, shell::ShellPrefs, sys::NSEnter};

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
        .ok_or_else(|| anyhow!("NS data not found at {:?}", ns_meta))
}

pub fn read_ns_alive_opt(ns_meta: &Path) -> Option<NsAlive> {
    if !ns_meta.exists() {
        return None;
    }
    std::fs::read_to_string(ns_meta)
        .ok()
        .and_then(|content| serde_json::from_str::<NsAlive>(&content).ok())
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
    shell.set_nsproxy_env(ns_alive.browser_profile.clone());
    shell.set_ns_env(Some(&ns_alive.bind_mount.to_string_lossy()));
}
