use std::{fs, io::Write};

use anyhow::Result;
use log::warn;
use nix::mount::{mount, umount, MsFlags};
use tracing::info;

/// run this in a mount namespace; otherwise it applies globally which is probably undesirable
pub fn mount_conf() -> Result<()> {
    let copy = include_str!("../resolv.conf");
    let path = "/tmp/resolv.conf";
    let mut fd = std::fs::File::create(path)?;
    fd.write_all(copy.as_bytes())?;
    let target = "/etc/resolv.conf";
    info!("try umount first");
    let rx = umount(target);
    if rx.is_ok() {
        info!("umount suceeded");
    }
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
