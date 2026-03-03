//! Misc low-level code

use anyhow::{bail, ensure};
use clone3::Clone3;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use libc::{pid_t, stat, syscall, uid_t};
use multimap::MultiMap;
use nix::{
    mount::{MntFlags, MsFlags, mount, umount, umount2},
    sched::{CloneFlags, setns, unshare},
    sys::{
        signal::kill,
        stat::{fstat, makedev},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{
        ForkResult, Gid, Pid, Uid, fork, getresuid, getuid, initgroups, seteuid, setgroups,
        setresgid, setresuid, setuid,
    },
};
use nsproxy_common::{ExactNS, NSFrom, NSSource, PidPath, UID_HINT_VAR, UniqueFile};
use pidfd::PidFd;
use procfs::process::{FDTarget, Process};
use rtnetlink::SELF_NS_PATH;
use std::{
    collections::{HashMap, HashSet},
    env::{set_current_dir, var},
    ffi::{CStr, CString},
    fs::{
        File, FileType, OpenOptions, create_dir, create_dir_all, read_dir, remove_dir_all,
        remove_file,
    },
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{ExitStatus, exit},
    sync::mpsc::sync_channel,
};
use tracing::info;
use tracing::warn;
use uzers::os::unix::UserExt;

use std::{mem::size_of, os::fd::RawFd};
use std::os::unix::fs::PermissionsExt; // for setting file modes


use anyhow::Result;
use nix::{
    NixPath,
    errno::Errno,
    libc::{AT_FDCWD, MS_PRIVATE, SYS_mount_setattr, c_int},
    unistd::pivot_root,
};

use crate::{Paths, PathsBinds, aok};

fn mount_single(pid: &PidPath, bind_at: &Path, dry_run: bool, name: &str) -> Result<()> {
    let path: PathBuf = ["/proc/", pid.to_str().as_ref(), "ns", name]
        .iter()
        .collect();
    let stat = nix::sys::stat::stat(&path)?;
    if !dry_run {
        let _ = File::create(&bind_at)?;
        mount(
            Some(&path),
            bind_at,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
    }

    Ok(())
}

impl NSEnter for NSSource {
    fn enter(&self, f: CloneFlags) -> Result<()> {
        match self {
            Self::Path(p) => {
                let fd = File::open(p)?;
                setns(fd, f)?;
            }
            Self::Pid(p) => {
                let fd = unsafe { pidfd::PidFd::open(*p, 0) }?;
                setns(fd, f)?;
            }
            Self::Unavail(_) => unreachable!(),
        }
        Ok(())
    }
}

impl NSEnter for ExactNS {
    fn enter(&self, f: CloneFlags) -> Result<()> {
        self.source.enter(f)
    }
}

pub trait NSEnter {
    fn enter(&self, f: CloneFlags) -> Result<()>;
}

pub struct UserNS(pub Paths);

#[test]
fn sockpairfork() -> Result<()> {
    let (mut sa, mut sb) = UnixStream::pair()?;

    match unsafe { fork() }? {
        ForkResult::Child => {
            sa.write_all(&[2])?;
        }
        ForkResult::Parent { child } => {
            let mut k: [u8; 1] = [0];
            sb.read_exact(&mut k)?;
            dbg!(k);
        }
    }

    Ok(())
}

impl UserNS {
    fn privmnt(&self) -> PathBuf {
        self.0.mount_private()
    }

    /// A process with euid being owner may enter the user NS without the cap
    fn init(&self, owner: uid_t) -> Result<()> {
        let private = self.privmnt();
        // create_dir_all(&private)?; // doesnt error when dir exists
        self.0.make_mount_point(self.privmnt())?;
        mount(
            // CAP_SYS_ADMIN
            Some(&private),
            &private,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        let mut att = MountAttr::default();
        att.propagation = MS_PRIVATE;
        unsafe { mount_setattr(AT_FDCWD, &private, 0, &att as *const _) }?;

        let (mut sa, mut sb) = UnixStream::pair()?;

        match unsafe { fork() }? {
            ForkResult::Child => {
                let u = Uid::from_raw(owner);
                setresuid(u, u, u)?;
                // After setting EUID, flag dumpable is changed, and perms in /proc get changed too
                capctl::prctl::set_dumpable(true)?;
                info!("unshare, owner uid is {u}");
                unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
                sa.write_all(&[0])?; // unshared

                let mut k: [u8; 1] = [0];
                sa.read_exact(&mut k)?;
                exit(0);
            }
            ForkResult::Parent { child } => {
                let puser: PathBuf = ["/proc", &child.as_raw().to_string(), "ns", "user"]
                    .iter()
                    .collect();
                let pmnt: PathBuf = ["/proc", &child.as_raw().to_string(), "ns", "mnt"]
                    .iter()
                    .collect();
                let mut k: [u8; 1] = [0];

                sb.read_exact(&mut k)?; // unshared
                let mut f = OpenOptions::new()
                    .write(true)
                    .open(format!("/proc/{child}/uid_map"))?;
                // f.write_all(format!("{u} {u} 1").as_bytes())?; // map uid (in user ns) to uid (outside) for range 1
                f.write_all(format!("0 0 4294967295").as_bytes())?;
                let mut f = OpenOptions::new()
                    .write(true)
                    .open(format!("/proc/{child}/gid_map"))?;
                f.write_all(format!("0 0 4294967295").as_bytes())?;

                let ns_user = ExactNS::from_source(puser.clone())?;
                let ns_mnt = ExactNS::from_source(pmnt.clone())?;
                mount(
                    Some(&puser),
                    &self.0.mount(ns_user.clone()),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
                mount(
                    Some(&pmnt),
                    &self.0.mount_user_space(ns_user, ns_mnt),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
                sb.write_all(&[0])?;
                info!("UserNS inited")
            }
        }

        Ok(())
    }
}

#[derive(Default)]
#[repr(C, align(8))]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    unserns_fd: u64,
}

unsafe fn mount_setattr(
    dirfd: RawFd,
    path: &impl NixPath,
    flags: c_int,
    attr: *const MountAttr,
) -> Result<(), Errno> {
    let k = path.with_nix_path(|pa| unsafe {
        syscall(
            SYS_mount_setattr,
            dirfd,
            pa.as_ptr(),
            flags,
            attr,
            size_of::<MountAttr>(),
        )
    })?;

    Errno::result(k).map(drop)
}

/// Automatically removes dst if exists
pub fn mount_ns(source: &Path, dst: &Path) -> Result<()> {
    warn!("bind mounting {:?} onto {:?}", source, dst);
    if dst.exists() {
        let _ = rm_mount(dst);
    }
    File::create(dst)?;
    mount(
        Some(source),
        dst,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;

    Ok(())
}

pub fn mount_bind(source: &Path, dst: &Path) -> Result<()> {
    warn!("bind mounting {:?} onto {:?}", source, dst);
    if !dst.exists() {
        File::create(dst)?;
    }
    mount(
        Some(source),
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    Ok(())
}

pub fn ensure_mount_target(src: &Path, dst: &Path) -> Result<()> {
    info!("ensure_mount_target: src={:?}, dst={:?}", src, dst);

    let meta = std::fs::metadata(src)
        .map_err(|e| anyhow::anyhow!("Failed to stat source {:?}: {}", src, e))?;

    info!(
        "  source exists, is_dir={}, is_file={}",
        meta.is_dir(),
        meta.is_file()
    );

    if meta.is_dir() {
        info!("  creating target directory: {:?}", dst);
        create_dir_all(dst)
            .map_err(|e| anyhow::anyhow!("Failed to create target directory {:?}: {}", dst, e))?;
    } else {
        if let Some(parent) = dst.parent() {
            info!("  checking if parent exists: {:?}", parent);
            match std::fs::metadata(parent) {
                Ok(m) => {
                    info!("  parent exists, is_dir={}", m.is_dir());
                    // Check what filesystem we're on
                    match nix::sys::statfs::statfs(parent) {
                        Ok(fs) => info!("  parent filesystem type: {:?}", fs.filesystem_type()),
                        Err(e) => info!("  couldn't get parent fs type: {}", e),
                    }
                }
                Err(e) => {
                    info!("  parent doesn't exist ({}), creating: {:?}", e, parent);
                    create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!("Failed to create parent directory {:?}: {}", parent, e)
                    })?;
                    // Check the created directory
                    match std::fs::metadata(parent) {
                        Ok(m) => info!("  created parent, is_dir={}", m.is_dir()),
                        Err(e) => info!("  created parent but can't stat: {}", e),
                    }
                }
            }
        } else {
            info!("  no parent directory for {:?}", dst);
        }

        // Check if target already exists
        match std::fs::metadata(dst) {
            Ok(m) => {
                info!(
                    "  target already exists! type={:?}, skipping creation",
                    m.file_type()
                );
                // Target already exists, no need to create it
            }
            Err(_) => {
                info!(
                    "  target doesn't exist yet, creating target file: {:?}",
                    dst
                );
                File::create(dst).map_err(|e| {
                    // Additional context about the error
                    let parent_readable = dst
                        .parent()
                        .and_then(|p| std::fs::read_dir(p).ok())
                        .is_some();
                    anyhow::anyhow!(
                        "Failed to create target file {:?}: {} (errno: {:?}, parent_readable: {})",
                        dst,
                        e,
                        e.raw_os_error(),
                        parent_readable
                    )
                })?;
            }
        }
    }

    info!("  ensure_mount_target succeeded");
    Ok(())
}

pub fn mount_bind_rw_explicit(source: &Path, dst: &Path, recursive: bool) -> Result<()> {
    warn!("bind mounting {:?} onto {:?}", source, dst);
    ensure_mount_target(source, dst).map_err(|e| {
        anyhow::anyhow!(
            "Failed to ensure mount target for {:?} -> {:?}: {}",
            source,
            dst,
            e
        )
    })?;
    let mut flags = MsFlags::MS_BIND;
    if recursive {
        flags |= MsFlags::MS_REC;
    }
    mount(Some(source), dst, None::<&str>, flags, None::<&str>)
        .map_err(|e| anyhow::anyhow!("Failed to bind mount {:?} -> {:?}: {}", source, dst, e))?;

    Ok(())
}

pub fn mount_bind_ro_explicit(source: &Path, dst: &Path, recursive: bool) -> Result<()> {
    mount_bind_rw_explicit(source, dst, recursive)?;
    let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    if recursive {
        flags |= MsFlags::MS_REC;
    }
    mount(Some(source), dst, None::<&str>, flags, None::<&str>)?;

    Ok(())
}

pub fn mount_tmpfs(dst: &Path) -> Result<()> {
    create_dir_all(dst)?;
    mount(
        Some("tmpfs"),
        dst,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    Ok(())
}

pub fn pivot_root_into(new_root: &Path, put_old: &Path) -> Result<()> {
    create_dir_all(new_root)?;
    create_dir_all(put_old)?;
    pivot_root(new_root, put_old)?;
    set_current_dir("/")?;
    // After pivot_root the filesystem root is now `new_root`.  Paths that were
    // absolute before pivot are no longer valid — strip the `new_root` prefix
    // to get the path as seen from inside the new root.
    let rel = put_old
        .strip_prefix(new_root)
        .unwrap_or_else(|_| put_old.strip_prefix("/").unwrap_or(put_old));
    let put_old_inner = PathBuf::from("/").join(rel);
    umount2(&put_old_inner, MntFlags::MNT_DETACH)?;
    remove_dir_all(&put_old_inner)?;

    Ok(())
}

pub fn mount_bind_root() -> Result<()> {
    info!("mount root space");
    mount(
        None as Option<&Path>,
        &PathBuf::from("/"),
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    Ok(())
}

pub fn rm_mount(dst: &Path) -> Result<()> {
    warn!("remove bind-mount {:?}", dst);
    umount(dst)?;
    remove_file(dst)?;
    Ok(())
}

/// Errors if repeated mounted
/// Write content to /tmp and bind mount it to the target path as read-only
pub fn mount_file_content(content: &[u8], target: &Path) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate a unique filename in /tmp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = PathBuf::from(format!("/tmp/nsproxy_mount_{}.tmp", timestamp));

    // Write content to temporary file
    let mut tmp_file = File::create(&tmp_path)?;
    tmp_file.write_all(content)?;
    tmp_file.flush()?;

    // ensure the temp file has sensible permissions (rw-r--r--)
    let perms = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(&tmp_path, perms)?;

    // Ensure the target parent directory exists
    if let Some(parent) = target.parent() {
        create_dir_all(parent)?;
    }

    // Create the target file if it doesn't exist
    if !target.exists() {
        File::create(target)?;
    }

    // Bind mount the temporary file to the target as read-only
    mount_bind_ro_explicit(&tmp_path, target, false)?;

    info!("mounted {:?} to {:?}", tmp_path, target);

    // make sure the target also has appropriate permissions
    let perms = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(target, perms)?;

    Ok(())
}

/// Mount resolv.conf with DNS nameserver configuration
/// Errors if repeated mounted
pub fn mount_resolv_conf(nameserver: &str) -> Result<()> {
    let content = format!("nameserver {}\n", nameserver);
    mount_file_content(content.as_bytes(), Path::new("/etc/resolv.conf"))?;
    info!("mounted resolv.conf with nameserver: {}", nameserver);
    Ok(())
}

/// Mount nsswitch.conf for DNS resolution via glibc's libnss_dns
/// Errors if repeated mounted
pub fn mount_nsswitch_conf() -> Result<()> {
    let content = b"passwd:         files\n
group:          files\n
shadow:         files\n
gshadow:        files\n

hosts:          files dns\n
networks:       files\n

protocols:      files\n
services:       files\n
ethers:         files\n
rpc:            files\n";
    mount_file_content(content, Path::new("/etc/nsswitch.conf"))?;
    info!("mounted nsswitch.conf for DNS resolution");
    Ok(())
}

pub fn check_capsys() -> Result<()> {
    let caps = capctl::CapState::get_current().unwrap();
    if !caps.effective.has(capctl::Cap::SYS_ADMIN) {
        bail!("requires CAP_SYS_ADMIN. Use sproxy");
    }

    Ok(())
}

pub fn your_shell(specify: Option<String>, mut uid: Option<u32>) -> Result<Option<String>> {
    Ok(match specify {
        Some(k) => Some(k),
        None => {
            if uid.is_none() {
                uid = Some(what_uid(uid, false)?);
            }
            let user = uzers::get_user_by_uid(uid.unwrap());
            if let Some(user) = user {
                Some(user.shell().to_string_lossy().into_owned())
            } else {
                None
            }
        }
    })
}

pub fn enable_ping_all() -> Result<()> {
    let mut f = File::options()
        .write(true)
        .open("/proc/sys/net/ipv4/ping_group_range")?;
    f.write_all(b"0 2147483647")?;
    Ok(())
}

pub fn enable_ping_gid(gid: Gid) -> Result<()> {
    let mut f = File::options()
        .write(true)
        .open("/proc/sys/net/ipv4/ping_group_range")?;
    f.write_all(format!("{gid} {gid}").as_bytes())?;
    Ok(())
}

pub fn cmd_uid(uid: Option<u32>, allow_root: bool, change_uid: bool) -> Result<()> {
    let u = Uid::from_raw(what_uid(uid, allow_root)?);
    let user = uzers::get_user_by_uid(u.as_raw()).unwrap();
    let g = user.primary_group_id().into();
    info!("set initgroups");
    // This line failed for a flatpak ns
    let _ = initgroups(&CString::new(user.name().as_bytes())?, g);
    info!("change gid and uid");
    setresgid(g, g, g)?;
    if change_uid {
        setresuid(u, u, u)?;
    }
    Ok(())
}

/// The program keeps a special uid in mind, called the non-root uid.
pub fn what_uid(uid: Option<u32>, allow_root: bool) -> Result<u32> {
    if let Some(u) = uid {
        Ok(u)
    } else {
        if let Ok(id) = var(UID_HINT_VAR) {
            Ok(id.parse()?)
        } else if let Ok(id) = var("SUDO_UID") {
            Ok(id.parse()?)
        } else {
            let res = getresuid()?;
            if !res.real.is_root() {
                Ok(res.real.as_raw())
            } else if let Ok(kde) = var("KDE_SESSION_UID") {
                Ok(kde.parse()?)
            } else {
                if allow_root {
                    Ok(0)
                } else {
                    bail!("unable to find a non-root uid")
                }
            }
        }
    }
}

pub fn check_selfns() -> Result<()> {
    let f = File::open(SELF_NS_PATH)?;
    let stat = fstat(f.as_raw_fd())?;
    info!("self ns {:?}", &stat);

    aok!()
}

/// Unshare the process into a separate userns, rootless
/// Map one single uid, and gid.
pub fn unshare_user_standalone(
    uid: u32,
    gid: Option<u32>,
    mnt: bool,
    uid_out: u32,
    gid_out: Option<u32>,
) -> Result<()> {
    warn!("Unsharing into a new, temporary UserNS. This method currently has limitations.");
    let flg = if mnt {
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS
    } else {
        CloneFlags::CLONE_NEWUSER
    };

    let gid_out = if let Some(g) = gid_out {
        g
    } else {
        let user = uzers::get_user_by_uid(uid).unwrap();
        user.primary_group_id()
    };

    let gid = if let Some(g) = gid {
        g
    } else {
        let user = uzers::get_user_by_uid(uid).unwrap();
        user.primary_group_id()
    };

    unshare(flg)?;
    let mut f = OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/uid_map"))?;
    let uidmap = format!("{uid} {uid_out} 1",);
    info!("uidmap: {}", &uidmap);
    f.write_all(uidmap.as_bytes())?;
    let mut f = OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/setgroups"))?;
    f.write_all(b"deny")?;
    let mut f = OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/gid_map"))?;
    let gidmap = format!("{gid} {gid_out} 1");
    info!("gidmap: {}", &gidmap);
    f.write_all(gidmap.as_bytes())?;

    Ok(())
}

pub fn clone3<const NEW_NET: bool>(mnt: bool, new_pid: bool) -> Result<Clone3Result> {
    let (x, y) = UnixStream::pair()?;
    let mut pidfd = -1;
    let mut syscall = Clone3::default();
    if NEW_NET {
        syscall.flag_newnet();
    }
    if new_pid {
        syscall.flag_newpid();
    }
    if mnt {
        syscall.flag_newns();
    }
    syscall.flag_pidfd(&mut pidfd);
    warn!(
        "Clone3 with NEW_NET={}, NEW_NS={}, NEW_PID={}",
        NEW_NET, mnt, new_pid
    );
    match unsafe { syscall.call() }? {
        0 => Ok(Clone3Result::IsChild { tx: x }),
        id => Ok(Clone3Result::Parent {
            child_pid: id,
            child_pidfd: pidfd,
            tx: y,
        }),
    }
}

pub enum Clone3Result {
    Parent {
        child_pid: i32,
        child_pidfd: i32,
        tx: UnixStream,
    },
    IsChild {
        tx: UnixStream,
    },
}

impl Clone3Result {
    pub async fn wait_for_child(&self) -> Result<ExitStatus> {
        match self {
            Self::Parent {
                child_pid,
                child_pidfd,
                tx,
            } => {
                let fd = unsafe { PidFd::from_raw_fd(*child_pidfd) };
                let k = fd.into_future().await?;
                Ok(k)
            }
            _ => {
                unreachable!()
            }
        }
    }
}

/// Mapping of browser profile and namespace
pub struct ProfileNSMap {
    pub map: HashMap<pid_t, PathBuf>,
}

#[derive(Default)]
pub struct Locks {
    pub pids: MultiMap<pid_t, UniqueFile>,
    pub paths: HashMap<UniqueFile, FDTarget>,
}

pub fn list_locks() -> Result<Locks> {
    let mut resp = Locks::default();
    let locks = procfs::locks()?;
    for lock in locks {
        if let Some(pid) = lock.pid {
            let fds = Process::new(pid)?.fd()?;
            let dev = makedev(lock.devmaj as u64, lock.devmin as u64);
            let lockfile = UniqueFile::new(lock.inode, dev);
            resp.pids.insert(pid, lockfile);
            for fd in fds {
                let fd = fd?;
                let stat = fstat(fd.fd)?;
                let file: UniqueFile = stat.into();
                if file == lockfile {
                    let _ = resp.paths.insert(file, fd.target);
                }
            }
        }
    }

    Ok(resp)
}
