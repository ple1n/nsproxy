//! Sandboxing: bind-mount overlays, pivot root, profile mounts/chmods.
//!
//! Centralises the rootfs-isolation logic that was previously inlined in
//! the binary's `Run` / `Up` command handlers.

use std::io::BufRead;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use nix::mount::{MsFlags, mount as nix_mount};
use nix::unistd::{Gid, Uid, chown};
use std::os::unix::fs::PermissionsExt;
use tracing::{info, warn};

use crate::{
    PathExpansionState, ProfileChmod, ProfileMount, SandboxMode, TemplateConfig,
    sys::{mount_bind_ro_explicit, mount_bind_rw_explicit, mount_tmpfs, pivot_root_into},
};

/// Apply a list of profile mounts, resolving source/target paths through
/// `vars` (which carries `@`/`~` variable expansion and optional chroot roots).
pub fn apply_mounts(vars: &PathExpansionState, mounts: &[ProfileMount]) -> Result<()> {
    for m in mounts {
        let src = vars.expand_source(&m.source);
        let dst = vars.expand_target(&m.target);
        if m.read_only {
            mount_bind_ro_explicit(&src, &dst, m.recursive)?;
        } else {
            mount_bind_rw_explicit(&src, &dst, m.recursive)?;
        }
    }
    Ok(())
}

/// Apply a list of profile chmods/chowns, resolving paths through `vars`.
pub fn apply_chmod(vars: &PathExpansionState, chmods: &[ProfileChmod]) -> Result<()> {
    for c in chmods {
        let target = vars.expand_target(&c.path);

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

/// Build the minimal filesystem skeleton inside `new_root`.
///
/// This creates stub directories, bind-mounts /usr and /etc read-only,
/// recreates merged-usr symlinks (or bind-mounts them for non-merged distros),
/// bind-mounts /dev read-write, and mounts fresh proc/sys/tmp/run.
pub fn build_skeleton(new_root: &Path) -> Result<()> {
    for d in &["usr", "etc", "dev", "proc", "sys", "tmp", "run", "home", "root"] {
        std::fs::create_dir_all(new_root.join(d))?;
    }

    // Bind-mount /usr and /etc read-only (recursive).
    for dir in &["usr", "etc"] {
        let src = PathBuf::from(format!("/{}", dir));
        if src.exists() {
            mount_bind_ro_explicit(&src, &new_root.join(dir), true)?;
        }
    }

    // Recreate merged-usr symlinks (/bin /lib /lib64 /sbin -> usr/…)
    // if the host uses usr-merge, otherwise bind-mount them.
    for link in &["bin", "lib", "lib64", "lib32", "sbin"] {
        let host_path = PathBuf::from(format!("/{}", link));
        let dst = new_root.join(link);
        if let Ok(target) = std::fs::read_link(&host_path) {
            if !dst.exists() {
                let _ = std::os::unix::fs::symlink(&target, &dst);
            }
        } else if host_path.is_dir() {
            std::fs::create_dir_all(&dst)?;
            mount_bind_ro_explicit(&host_path, &dst, true)?;
        }
    }

    // Bind-mount /dev read-write so ptys / tty work.
    mount_bind_rw_explicit(Path::new("/dev"), &new_root.join("dev"), true)?;

    // Mount fresh proc, sysfs, tmpfs for /proc /sys /tmp /run.
    nix_mount(
        Some("proc"),
        &new_root.join("proc"),
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    nix_mount(
        Some("sysfs"),
        &new_root.join("sys"),
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    nix_mount(
        Some("tmpfs"),
        &new_root.join("tmp"),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=1777"),
    )?;
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
/// 5. Bind the persist root (/nsp3) into the new root
/// 6. `pivot_root` into the new root, old root at `/pivot`
pub fn apply_pivot(template: &TemplateConfig, profile_name: &str) -> Result<()> {
    let new_root = crate::state_paths::pivot_root_dir(profile_name);
    let put_old = new_root.join("pivot");

    // 1. Mount tmpfs as the staging root.
    mount_tmpfs(&new_root)?;

    // 2. Build skeleton.
    build_skeleton(&new_root)?;

    // 3. Apply template mounts.
    if !template.mounts.is_empty() {
        let vars = PathExpansionState::without_instance().with_dst_chroot(&new_root);
        apply_mounts(&vars, &template.mounts)?;
    }

    // 4. Apply chmods.
    if !template.chmod.is_empty() {
        let vars = PathExpansionState::without_instance().with_dst_chroot(&new_root);
        apply_chmod(&vars, &template.chmod)?;
    }

    let persist = crate::state_paths::persist_root();
    if persist.exists() {
        let persist_rel = persist.strip_prefix("/").unwrap_or(&persist);
        let persist_dst = new_root.join(persist_rel);
        std::fs::create_dir_all(&persist_dst)?;
        mount_bind_rw_explicit(&persist, &persist_dst, true)?;
    }

    // 6. Pivot root.
    info!("pivoting root into {:?}", new_root);
    pivot_root_into(&new_root, &put_old)?;
    info!("pivot complete — now inside sandbox root");

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum SandboxState {
    /// Root is the host filesystem — pivot has not been applied.
    Virgin,
    /// Root is already a tmpfs — a previous `apply_pivot` was done.
    AlreadyPivoted,
}

/// Check whether we are in an isolated mount namespace (not the host's).
///
/// Compares the mount-namespace inode of this process against PID 1 (init).
/// Also verifies the root mount is not `shared:`, which would propagate
/// changes back to the host.
///
/// Returns `Ok(())` if isolated, `Err` if we appear to be in the host ns.
pub fn assert_mount_ns_isolated() -> Result<()> {
    let self_mnt = std::fs::metadata("/proc/self/ns/mnt")?;
    let init_mnt = std::fs::metadata("/proc/1/ns/mnt")?;

    // Device + inode uniquely identifies a namespace.
    if self_mnt.dev() == init_mnt.dev() && self_mnt.ino() == init_mnt.ino() {
        bail!(
            "refusing to sandbox: this process shares the host mount namespace \
             (mnt ns inode {} == init mnt ns inode {}). \
             The profile must be brought up with `sp up` first.",
            self_mnt.ino(),
            init_mnt.ino()
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
        "mount namespace isolated (self ino={}, init ino={})",
        self_mnt.ino(),
        init_mnt.ino()
    );
    Ok(())
}

/// Detect whether sandboxing (pivot_root onto tmpfs) has already been applied.
///
/// Parses `/proc/self/mountinfo` and checks if the root mount (`/`) is a tmpfs.
pub fn detect_sandbox_state() -> Result<SandboxState> {
    let f = std::fs::File::open("/proc/self/mountinfo")?;
    let reader = std::io::BufReader::new(f);

    for line in reader.lines() {
        let line = line?;
        // mountinfo format: id parent major:minor root mount_point opts ... - fstype source super_opts
        // We want the line where mount_point is "/"
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let mount_point = fields[4];
        if mount_point != "/" {
            continue;
        }
        // Find the separator "-" then fstype is the next field.
        if let Some(sep_pos) = fields.iter().position(|&f| f == "-") {
            if sep_pos + 1 < fields.len() {
                let fstype = fields[sep_pos + 1];
                if fstype == "tmpfs" {
                    info!("root is tmpfs — sandbox already applied");
                    return Ok(SandboxState::AlreadyPivoted);
                } else {
                    info!("root fstype is '{}' — sandbox not yet applied", fstype);
                    return Ok(SandboxState::Virgin);
                }
            }
        }
    }

    // Couldn't determine — treat as not pivoted, let apply_pivot attempt it.
    warn!("could not determine root fstype from mountinfo, assuming virgin");
    Ok(SandboxState::Virgin)
}

/// Check whether the root mount (`/`) has shared propagation.
fn is_root_shared() -> Result<bool> {
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
