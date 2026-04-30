//! Sandboxing: bind-mount overlays, pivot root, profile mounts/chmods.
//!
//! Centralises the rootfs-isolation logic that was previously inlined in
//! the binary's `Run` / `Up` command handlers.

use std::collections::HashSet;
use std::io::BufRead;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use nix::mount::{MntFlags, MsFlags, mount as nix_mount, umount2};
use nix::unistd::{Gid, Uid, chown};
use nsproxy_common::{ExactNS, NSFrom, PidPath, UniqueFile};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use tracing::{info, warn};

use crate::{
    PathExpansionState, ProfileChmod, ProfileMount, Rootfs, SandboxMode, TemplateConfig,
    sys::{
        MountInfo, ensure_mountpoint, mount_bind_ro_explicit, mount_bind_rw_explicit,
        mount_tmpfs, pivot_root_into,
    },
};

/// Apply a list of profile mounts, resolving source/target paths through
/// `vars` (which carries `@`/`~` variable expansion and optional chroot roots).
fn bind_target_matches_source(source: &Path, target: &Path) -> Result<bool> {
    info!("syscall: metadata({:?})", source);
    let src_meta = match std::fs::metadata(source) {
        Ok(meta) => meta,
        Err(err) => {
            return Err(err.into());
        }
    };
    info!("syscall: metadata({:?})", target);
    let dst_meta = match std::fs::metadata(target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(err) => {
            return Err(err.into());
        }
    };

    Ok(src_meta.dev() == dst_meta.dev() && src_meta.ino() == dst_meta.ino())
}

fn bind_target_has_desired_state(
    mount_info: &MountInfo,
    source: &Path,
    target: &Path,
) -> Result<bool> {
    if !mount_info.target_is_mountpoint(target) {
        return Ok(false);
    }

    bind_target_matches_source(source, target)
}

fn reconcile_bind_target(mount_info: &MountInfo, source: &Path, target: &Path) -> Result<bool> {
    if bind_target_has_desired_state(mount_info, source, target)? {
        return Ok(false);
    }

    if mount_info.target_is_mountpoint(target) {
        info!(
            "detaching existing mount at {:?} before remounting source {:?}",
            target, source
        );
        info!("syscall: umount2({:?}, MNT_DETACH)", target);
        umount2(target, MntFlags::MNT_DETACH)?;
    }

    Ok(true)
}

pub fn apply_mounts(vars: &PathExpansionState, mounts: &[ProfileMount]) -> Result<()> {
    let mount_info = MountInfo::load()?;

    for m in mounts {
        let src = vars.expand_source(&m.source);
        let dst = vars.expand_target(&m.target);
        if m.skip_missing && !src.try_exists()? {
            info!(
                "skipping bind mount for {:?}: source missing and skip_missing is enabled",
                src
            );
            continue;
        }
        if !reconcile_bind_target(&mount_info, &src, &dst)? {
            info!(
                "skipping bind mount for {:?}: target {:?} already resolves to source",
                src, dst
            );
            continue;
        }
        if m.read_only {
            info!(
                "syscall: mount_bind_ro_explicit(source={:?}, target={:?}, recursive={})",
                src, dst, m.recursive
            );
            mount_bind_ro_explicit(&src, &dst, m.recursive)?;
        } else {
            info!(
                "syscall: mount_bind_rw_explicit(source={:?}, target={:?}, recursive={})",
                src, dst, m.recursive
            );
            mount_bind_rw_explicit(&src, &dst, m.recursive)?;
        }
    }
    Ok(())
}

/// Apply a list of profile chmods/chowns, resolving paths through `vars`.
pub fn apply_chmod(vars: &PathExpansionState, chmods: &[ProfileChmod]) -> Result<()> {
    for c in chmods {
        let target = vars.expand_target(&c.path);

        if c.mkdir && !target.try_exists()? {
            info!("create_dir_all({:?})", target);
            std::fs::create_dir_all(&target)?;
        }

        if let Some(mode) = c.mode {
            info!("syscall: metadata({:?})", target);
            let mut perms = std::fs::metadata(&target)?.permissions();
            perms.set_mode(mode);
            info!("syscall: set_permissions({:?}, {:o})", target, mode);
            std::fs::set_permissions(&target, perms)?;
        }

        if c.uid.is_some() || c.gid.is_some() {
            let uid = c.uid.map(Uid::from_raw);
            let gid = c.gid.map(Gid::from_raw);
            info!("syscall: chown({:?}, uid={:?}, gid={:?})", target, uid, gid);
            chown(&target, uid, gid)?;
        }
    }
    Ok(())
}

/// Build the minimal filesystem skeleton inside `new_root`.
///
/// This creates stub directories, bind-mounts /usr and /etc read-only,
/// recreates merged-usr symlinks (or bind-mounts them for non-merged distros),
/// bind-mounts /nsp3/config and /dev read-write, and mounts fresh proc/sys/tmp/run.
pub fn build_skeleton(new_root: &Path) -> Result<()> {
    for d in &["usr", "etc", "dev", "proc", "sys", "tmp", "run", "home", "root"] {
        info!("create_dir_all({:?})", new_root.join(d));
        std::fs::create_dir_all(new_root.join(d))?;
    }

    // Bind-mount /usr and /etc read-only (recursive).
    for dir in &["usr", "etc"] {
        let src = PathBuf::from(format!("/{}", dir));
        if src.exists() {
            info!(
                "mount_bind_ro_explicit(source={:?}, target={:?}, recursive=true)",
                src,
                new_root.join(dir)
            );
            mount_bind_ro_explicit(&src, &new_root.join(dir), true)?;
        }
    }

    // Recreate merged-usr symlinks (/bin /lib /lib64 /sbin -> usr/…)
    // if the host uses usr-merge, otherwise bind-mount them.
    for link in &["bin", "lib", "lib64", "lib32", "sbin"] {
        let host_path = PathBuf::from(format!("/{}", link));
        let dst = new_root.join(link);
        info!("read_link({:?})", host_path);
        if let Ok(target) = std::fs::read_link(&host_path) {
            if !dst.exists() {
                info!("symlink({:?} -> {:?})", target, dst);
                let _ = std::os::unix::fs::symlink(&target, &dst);
            }
        } else if host_path.is_dir() {
            info!("create_dir_all({:?})", dst);
            std::fs::create_dir_all(&dst)?;
            info!(
                "mount_bind_ro_explicit(source={:?}, target={:?}, recursive=true)",
                host_path, dst
            );
            mount_bind_ro_explicit(&host_path, &dst, true)?;
        }
    }

    // Expose nsproxy config state within the container.
    let config_root = crate::state_paths::config_root();
    let sandbox_config_root = new_root.join("nsp3/config");
    info!("create_dir_all({:?})", sandbox_config_root);
    std::fs::create_dir_all(&sandbox_config_root)?;
    info!(
        "mount_bind_rw_explicit(source={:?}, target={:?}, recursive=true)",
        config_root, sandbox_config_root
    );
    mount_bind_rw_explicit(&config_root, &sandbox_config_root, true)?;

    // Bind-mount /dev read-write so ptys / tty work.
    info!(
        "mount_bind_rw_explicit(source={:?}, target={:?}, recursive=true)",
        Path::new("/dev"),
        new_root.join("dev")
    );
    mount_bind_rw_explicit(Path::new("/dev"), &new_root.join("dev"), true)?;

    // Mount fresh proc, sysfs, tmpfs for /proc /sys /tmp /run.
    info!(
        "mount(source=proc, target={:?}, fstype=proc, flags=0)",
        new_root.join("proc")
    );
    nix_mount(
        Some("proc"),
        &new_root.join("proc"),
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    info!(
        "mount(source=sysfs, target={:?}, fstype=sysfs, flags=0)",
        new_root.join("sys")
    );
    nix_mount(
        Some("sysfs"),
        &new_root.join("sys"),
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    info!(
        "mount(source=tmpfs, target={:?}, fstype=tmpfs, flags=0, data=mode=1777)",
        new_root.join("tmp")
    );
    nix_mount(
        Some("tmpfs"),
        &new_root.join("tmp"),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=1777"),
    )?;
    info!(
        "mount(source=tmpfs, target={:?}, fstype=tmpfs, flags=0, data=mode=755)",
        new_root.join("run")
    );
    nix_mount(
        Some("tmpfs"),
        &new_root.join("run"),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=755"),
    )?;

    Ok(())
}

/// Construct a complete pivot-root sandbox from a `TemplateConfig`.
///
/// The new root is always staged at `/tmp/nsproxy_pivot`; a fresh tmpfs is
/// mounted there unconditionally.  The old root is placed at `/pivot` and
/// detached after the pivot.
///
/// 1. Mount tmpfs at `/tmp/nsproxy_pivot`
/// 2. Build the filesystem skeleton (bind /usr /etc /dev, mount proc/sys/tmp/run)
/// 3. Apply template mounts
/// 4. Apply template chmods
/// 5. Bind the persistent config root (/nsp3/config) into the new root
/// 6. `pivot_root` into the new root, old root at `/pivot`
pub fn apply_pivot(template: &TemplateConfig, profile_name: &str) -> Result<()> {
    let new_root = match &template.rootfs {
        Rootfs::Default => crate::state_paths::pivot_root(profile_name),
        Rootfs::Tempfs => crate::state_paths::pivot_root_mem(profile_name),
        Rootfs::Path(path) => path.clone(),
    };

    let put_old = new_root.join("pivot");
    match &template.rootfs {
        Rootfs::Tempfs => {
            info!("mount_tmpfs({:?})", new_root);
            mount_tmpfs(&new_root)?;
        }
        Rootfs::Default | Rootfs::Path(_) => {
            info!("create_dir_all({:?})", new_root);
            std::fs::create_dir_all(&new_root)?;
            ensure_mountpoint(&new_root)?;
        }
    }
    build_skeleton(&new_root)?;
    if !template.mounts.is_empty() {
        let vars = PathExpansionState::without_instance().with_dst_chroot(&new_root);
        apply_mounts(&vars, &template.mounts)?;
    }
    if !template.chmod.is_empty() {
        let vars = PathExpansionState::without_instance().with_dst_chroot(&new_root);
        apply_chmod(&vars, &template.chmod)?;
    }

    info!("pivoting root into {:?}", new_root);
    info!(
        "pivot_root_into(new_root={:?}, put_old={:?})",
        new_root, put_old
    );
    pivot_root_into(&new_root, &put_old)?;
    info!("pivot complete — now inside sandbox root");

    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SandboxState {
    /// Root is the host filesystem — pivot has not been applied.
    NoPivot,
    /// Root matches the persisted sandbox root identity.
    Pivoted,
}

pub fn current_rootfs_id() -> Result<UniqueFile> {
    info!("syscall: stat(/)");
    let stat = nix::sys::stat::stat("/")?;
    Ok(stat.into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxPathStatus {
    pub path: PathBuf,
    pub exists: bool,
    pub kind: Option<String>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMountStatus {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
    pub recursive: bool,
    pub mounted: bool,
    pub target_matches_source: bool,
    pub target_status: SandboxPathStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxStatus {
    pub updated_at_secs: u64,
    pub configured_mode: SandboxMode,
    pub detected_state: SandboxState,
    pub pivot_dir_status: SandboxPathStatus,
    pub mounts: Vec<SandboxMountStatus>,
    pub last_error: Option<String>,
}

fn file_kind(meta: &std::fs::Metadata) -> String {
    let file_type = meta.file_type();
    if file_type.is_dir() {
        "dir".to_string()
    } else if file_type.is_file() {
        "file".to_string()
    } else if file_type.is_symlink() {
        "symlink".to_string()
    } else if file_type.is_block_device() {
        "block".to_string()
    } else if file_type.is_char_device() {
        "char".to_string()
    } else if file_type.is_fifo() {
        "fifo".to_string()
    } else if file_type.is_socket() {
        "socket".to_string()
    } else {
        "unknown".to_string()
    }
}

pub fn inspect_path(path: &Path) -> SandboxPathStatus {
    info!("syscall: symlink_metadata({:?})", path);
    match std::fs::symlink_metadata(path) {
        Ok(meta) => SandboxPathStatus {
            path: path.to_path_buf(),
            exists: true,
            kind: Some(file_kind(&meta)),
            mode: Some(meta.permissions().mode()),
            uid: Some(meta.uid()),
            gid: Some(meta.gid()),
            size: Some(meta.len()),
            error: None,
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => SandboxPathStatus {
            path: path.to_path_buf(),
            exists: false,
            kind: None,
            mode: None,
            uid: None,
            gid: None,
            size: None,
            error: None,
        },
        Err(err) => SandboxPathStatus {
            path: path.to_path_buf(),
            exists: false,
            kind: None,
            mode: None,
            uid: None,
            gid: None,
            size: None,
            error: Some(err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        path.push(format!("nsproxy-sandbox-test-{nanos}-{}", std::process::id()));
        path
    }

    #[test]
    fn apply_chmod_creates_missing_directory_when_mkdir_is_true() {
        let root = unique_temp_dir();
        let target = root.join("nested/dir");
        let vars = PathExpansionState::without_instance().with_dst_chroot(&root);

        let result = apply_chmod(
            &vars,
            &[ProfileChmod {
                path: PathBuf::from("/nested/dir"),
                mode: Some(0o755),
                uid: None,
                gid: None,
                mkdir: true,
            }],
        );

        result.expect("apply_chmod should succeed");
        let meta = std::fs::metadata(&target).expect("target directory should exist");
        assert!(meta.is_dir(), "target should be created as a directory");
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }
}

pub fn collect_sandbox_status(
    configured_mode: SandboxMode,
    detected_state: SandboxState,
    mounts: &[ProfileMount],
    last_error: Option<String>,
) -> Result<SandboxStatus> {
    let mount_info = MountInfo::load()?;
    let mounts = mounts
        .iter()
        .map(|mount| {
            let mounted = mount_info.target_is_mountpoint(&mount.target);
            let target_matches_source = if mounted {
                bind_target_matches_source(&mount.source, &mount.target).unwrap_or(false)
            } else {
                false
            };
            SandboxMountStatus {
                source: mount.source.clone(),
                target: mount.target.clone(),
                read_only: mount.read_only,
                recursive: mount.recursive,
                mounted,
                target_matches_source,
                target_status: inspect_path(&mount.target),
            }
        })
        .collect();

    Ok(SandboxStatus {
        updated_at_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        configured_mode,
        detected_state,
        pivot_dir_status: inspect_path(Path::new("/pivot")),
        mounts,
        last_error,
    })
}

pub fn write_sandbox_status(profile_name: &str, status: &SandboxStatus) -> Result<()> {
    let path = crate::state_paths::sandbox_status(profile_name);
    if let Some(parent) = path.parent() {
        info!("syscall: create_dir_all({:?})", parent);
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_vec_pretty(status)?;
    info!("syscall: write({:?}, {} bytes)", path, content.len());
    std::fs::write(path, content)?;
    Ok(())
}

/// Check whether the current process is in the expected profile mount namespace.
///
/// This avoids relying on `/proc/1`, which is not a stable host reference once
/// PID namespaces are unshared. The expected namespace identity comes from the
/// persisted profile namespace registry.
pub fn assert_mount_ns_matches(expected_mnt: &ExactNS) -> Result<()> {
    let self_mnt = ExactNS::from_source((PidPath::Selfproc, "mnt"))?;

    if self_mnt.unique != expected_mnt.unique {
        bail!(
            "refusing to sandbox: current mount namespace {} does not match expected profile mount namespace {}",
            self_mnt.unique,
            expected_mnt.unique
        );
    }

    // Also verify root is not shared (would propagate mounts to host).
    if is_root_shared()? {
        bail!(
            "refusing to sandbox: the root mount is marked 'shared'. \
             Call mount_bind_root() first to make it private."
        );
    }

    info!(
        "mount namespace validated against profile registry ({})",
        self_mnt.unique
    );
    Ok(())
}

/// Detect whether sandboxing has already been applied by comparing the current
/// root directory identity against the persisted runtime sandbox root id.
pub fn detect_sandbox_state(expected_rootfs: Option<UniqueFile>) -> Result<SandboxState> {
    let Some(expected_rootfs) = expected_rootfs else {
        info!("no persisted rootfs identity found — sandbox not yet applied");
        return Ok(SandboxState::NoPivot);
    };

    let current_rootfs = current_rootfs_id()?;
    if current_rootfs == expected_rootfs {
        info!(
            "current rootfs identity {} matches persisted sandbox root {}",
            current_rootfs, expected_rootfs
        );
        Ok(SandboxState::Pivoted)
    } else {
        info!(
            "current rootfs identity {} does not match persisted sandbox root {}",
            current_rootfs, expected_rootfs
        );
        Ok(SandboxState::NoPivot)
    }
}

/// Check whether the root mount (`/`) has shared propagation.
fn is_root_shared() -> Result<bool> {
    info!("syscall: File::open(/proc/self/mountinfo)");
    let f = std::fs::File::open("/proc/self/mountinfo")?;
    let reader = std::io::BufReader::new(f);

    for line in reader.lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if fields[4] != "/" {
            continue;
        }
        // Optional fields are between fields[6..] and the "-" separator.
        // "shared:N" in any optional field means propagation is on.
        for &f in &fields[6..] {
            if f == "-" {
                break;
            }
            if f.starts_with("shared:") {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    Ok(false)
}
