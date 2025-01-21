use std::{fs, io::Write, path::Path};

use anyhow::Result;
use log::warn;
use nix::mount::{mount, umount, MsFlags};
use tracing::info;
const ETCRESOLV: &str = "/etc/resolv.conf";

/// run this in a mount namespace; otherwise it applies globally which is probably undesirable
pub fn mount_conf() -> Result<()> {
    let copy = include_str!("../resolv.conf");
    let path = "/tmp/resolv.conf";
    
    if Path::new(path).exists() {
        let _ = fs::remove_file(path);
    }
    let mut fd = std::fs::File::create(path)?;
    fd.write_all(copy.as_bytes())?;
    info!("try umount first");
    let rx = umount(ETCRESOLV);
    if rx.is_ok() {
        info!("umount suceeded");
    } else {
        warn!("umount failed. either resolv.conf is not bind-mounted, or there is not sufficient perm");
    }
    info!("bind mount {} onto {}", path, ETCRESOLV);
    mount(
        // CAP_SYS_ADMIN
        Some(path),
        ETCRESOLV,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    Ok(())
}

pub fn cleanup_resolvconf() -> Result<()> {
    info!("restoring {}", ETCRESOLV);
    umount(ETCRESOLV)?;
    Ok(())
}
