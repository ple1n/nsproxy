//! Profile discovery utilities for the nsproxy UI.
//! 
//! This module scans the persist root to discover available container profiles.
//! Profiles are directories under /nsp3/{name}, and are considered "instantiated"
//! if they have a valid ns_alive.json file indicating an active namespace.

use std::fs;
use std::path::Path;

use anyhow::Result;
use nsproxy_core::{NsAlive, state_paths};
use serde::{Deserialize, Serialize};

/// Runtime profile information loaded from the persist root
#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: String,
    pub instantiated: bool,
    pub ns_alive: Option<NsAlive>,
}

/// Scan the persist root and discover all profiles.
/// A profile is considered to exist if it has a directory under /nsp3/{name}.
/// A profile is instantiated if ns_alive.json exists and is valid.
pub fn list_profiles() -> Result<Vec<ProfileInfo>> {
    let root = state_paths::persist_root();
    let mut profiles = Vec::new();

    if !root.exists() {
        return Ok(profiles);
    }

    let entries = fs::read_dir(&root)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Skip non-directories
        if !path.is_dir() {
            continue;
        }

        // Skip special directories
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if name == "uplink" || name == "ui" || name.starts_with('.') {
            continue;
        }

        // Check if instantiated by looking for ns_alive.json
        let ns_meta = state_paths::profile_ns_meta(name);
        let (instantiated, ns_alive) = if ns_meta.exists() {
            match load_ns_alive(&ns_meta) {
                Ok(ns) => (ns_alive_running(&ns), Some(ns)),
                Err(_) => (false, None),
            }
        } else {
            (false, None)
        };

        profiles.push(ProfileInfo {
            name: name.to_string(),
            instantiated,
            ns_alive,
        });
    }

    // Sort by name for consistent ordering
    profiles.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(profiles)
}

fn ns_alive_running(ns_alive: &NsAlive) -> bool {
    let Some(pid) = ns_alive.child_pid else {
        return false;
    };
    let proc_path = format!("/proc/{}", pid);
    Path::new(&proc_path).exists()
}

fn load_ns_alive(path: &Path) -> Result<NsAlive> {
    let content = fs::read_to_string(path)?;
    let ns_alive: NsAlive = serde_json::from_str(&content)?;
    Ok(ns_alive)
}
