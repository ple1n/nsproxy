use std::{
    env::{current_dir, var},
    ffi::{CStr, CString, OsString},
    os::unix::{process::CommandExt, raw::{gid_t, uid_t}},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, bail};
use nix::unistd::{Gid, execve, getegid, getresuid, setgroups, setresgid, setresuid};
use nsproxy_common::UID_HINT_VAR;
use tracing::{info, warn};
use uzers::{Group, os::unix::UserExt};

use crate::{
    env::CommandEnv,
    prelude::*,
    sys::{Clone3Result, clone3},
};

/// Dedicated to spawning a shell that maximally pleases the user
/// what the user wants the uid of the shell to be, what groups to have

#[derive(Default)]
pub struct ShellPrefs {
    gids: Vec<Group>,
    pub uid: Option<uid_t>,
    /// Main GID
    pub gid: Option<gid_t>,
    /// This can also just be a program despite the struct's name
    pub shell: Option<PathBuf>,
    /// The user wants to drop in a root shell
    /// Defaults to false.
    pub wants_root: bool,
    pub cwd: Option<PathBuf>,
    /// This is different from .shell because this may be late resolved
    /// The PATHS can be different in the user shell
    pub prefer_shell: Option<String>,
    args: Vec<CString>,
    env: Vec<CString>,
}

impl ShellPrefs {
    /// Preferences are fetched from processes up the tree as early as possible, before subsequent operations
    pub fn adjust(&mut self) -> Result<()> {
        if self.uid == None {
            if let Ok(id) = var(UID_HINT_VAR) {
                self.uid = Some(id.parse()?)
            } else if let Ok(id) = var("SUDO_UID") {
                self.uid = Some(id.parse()?)
            } else {
                let res = getresuid()?;
                if !res.real.is_root() {
                    self.uid = res.real.as_raw().into();
                } else if let Ok(kde) = var("KDE_SESSION_UID") {
                    self.uid = Some(kde.parse()?);
                } else {
                    if self.wants_root && res.real.is_root() {
                        self.uid = Some(0);
                    }
                }
            }
        }
        if let Some(user) = self.uid {
            let user = uzers::get_user_by_uid(user).unwrap();
            let gid_in = { user.primary_group_id() };
            let gids = user.groups();
            if self.gids.len() == 0
                && let Some(gids) = gids
            {
                self.gids = gids;
            }
            if self.gid.is_none() {
                self.gid = Some(gid_in);
            } else {
                let egid = getegid();
                if egid.as_raw() != 0 {
                    self.gid = Some(egid.as_raw())
                } else {
                    if !self.wants_root {
                        bail!("can not decide gid to use");
                    }
                }
            }
            let ushell = user.shell().to_owned();
            self.shell = ushell.into();
        }
        if self.cwd.is_none() {
            self.cwd = current_dir()?.into();
        }
        let cmd_env = CommandEnv::default();
        let envs = cmd_env.capture();
        let mut vec: Vec<CString> = Default::default();
        for (k, v) in envs {
            vec.push(CString::new(format!(
                "{}={}",
                k.to_str().unwrap(),
                v.to_str().unwrap()
            ))?);
        }
        self.env = vec;
        aok!()
    }
    pub fn gids_raw(&self) -> Vec<u32> {
        self.gids.iter().map(|k| k.gid()).collect()
    }
    pub fn spawn(mut self) -> Result<Clone3Result> {
        if let Some(name) = &self.prefer_shell {
            self.shell = Some(which::which(name)?);
        }
        if let Some(cmd) = &self.shell {
            let clone = clone3::<false>()?;
            match &clone {
                Clone3Result::IsChild { tx } => {
                    let cmd = CString::new(cmd.to_str().unwrap())?;
                    self.drop_privs()?;

                    execve(cmd.as_c_str(), &self.args, &self.env);
                }
                Clone3Result::Parent {
                    child_pid,
                    child_pidfd,
                    tx,
                } => {}
            }
            Ok(clone)
        } else {
            bail!("no shell or program specified");
        }
    }

    pub async fn spawn_and_block(mut self) -> Result<()> {
        if let Some(name) = &self.prefer_shell {
            self.shell = Some(which::which(name)?);
        }
        if let Some(cmd) = &self.shell {
            let mut cmd = std::process::Command::new(cmd);
            let uid = self.uid.ok_or(anyhow!("can not find suitable uid"))?;
            cmd.uid(uid);
            let gids = self.gids_raw();
            warn!("spawn process with gids {:?}", &gids);
            cmd.groups(&gids);
            if let Some(cwd) = &self.cwd {
                cmd.current_dir(cwd);
            }
            let mut acmd = tokio::process::Command::from(cmd);
            let mut c = acmd.spawn()?;
            c.wait().await;
        } else {
            warn!("no shell or program specified");
        }
        aok!()
    }
    pub fn drop_privs(&self) -> Result<()> {
        info!("drop privs, gids to {:?}", self.gids_raw());
        setgroups(
            &self
                .gids_raw()
                .iter()
                .map(|g| Gid::from_raw(*g))
                .collect::<Vec<_>>(),
        )?;
        let g = self.gid.unwrap().into();
        setresgid(g, g, g);
        if let Some(uid) = self.uid {
            let u = uid.into();
            setresuid(u, u, u)?;
        }

        Ok(())
    }
}
