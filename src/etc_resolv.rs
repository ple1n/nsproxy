use std::io::Write;

use anyhow::Result;
use log::warn;
use nix::mount::{mount, MsFlags};
use tracing::info;

/// run this in a mount namespace; otherwise it applies globally which is probably undesirable
pub fn mount_conf() -> Result<()> {
    let path = "./resolv.conf";
    let copy = include_str!("../resolv.conf");
    if !std::fs::exists(path)? {
        warn!("./resolv.conf not found. writing the default config to it...");
        let mut fd = std::fs::File::create(path)?;
        fd.write_all(copy.as_bytes())?;
    }
    let target = "/etc/resolv.conf";
    info!("bind mount {} onto {}", path, target);
    mount(
        // CAP_SYS_ADMIN
        Some(path),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    Ok(())
}
