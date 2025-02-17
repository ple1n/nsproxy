use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::{exit, Command},
};

use anyhow::Result;
use nix::{
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::{signal::kill, stat::fstat},
    unistd::{
        fork, getresuid, getuid, seteuid, setresgid, setresuid, setuid, ForkResult, Gid, Uid,
    },
};
use nsproxy::{paths::PathState, sys::UserNS};

fn main() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    // let _deinit = usern.deinit();
    dbg!(getresuid()?);
    let mut a = std::env::args();
    a.next();
    match a.next().unwrap().as_str() {
        "i" => {
            // Unshare and mount, requires root
            // Weird it doesn't work
            // usern.init()?;
        }
        "s" => {
            usern.procns()?.enter()?;
        }
        "n" => {
            // Requires no root. This works.
            let u = Uid::from_raw(1000);
            setresuid(u, u, u)?;
            capctl::prctl::set_dumpable(true)?; // Oh shit WORKS
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
            let mut f = OpenOptions::new().write(true).open("/proc/self/uid_map")?;
            f.write_all(b"0 1000 1")?; // map 0 (in user ns) to uid 1000 (outside)
                                       // It's only possible to map a single line with this approach
        }
        _ => (),
    }
    bash()?;

    Ok(())
}

fn bash() -> Result<()> {
    let mut cmd = Command::new("/usr/bin/bash");
    let mut sp = cmd.spawn()?;
    sp.wait()?;
    Ok(())
}
