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
    env::var,
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

use anyhow::Result;
use nix::{
    NixPath,
    errno::Errno,
    libc::{AT_FDCWD, MS_PRIVATE, SYS_mount_setattr, c_int},
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
    if dst.exists() {
        let _ = rm_mount(dst);
    }
    File::create(dst)?;
    mount(
        Some(source),
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

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

pub fn clone3<const NEW_NET: bool>(mnt: bool) -> Result<Clone3Result> {
    let (x, y) = UnixStream::pair()?;
    let mut pidfd = -1;
    let mut syscall = Clone3::default();
    if NEW_NET {
        syscall.flag_newnet();
    }
    if mnt {
        syscall.flag_newns();
    }
    syscall.flag_pidfd(&mut pidfd);
    warn!("Clone3 with NEW_NET={}, NEW_NS={}", NEW_NET, mnt);
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
