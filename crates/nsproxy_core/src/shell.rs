use std::{
    env::{current_dir, var},
    os::unix::{process::CommandExt, raw::uid_t},
    path::PathBuf,
};

use anyhow::anyhow;
use nix::unistd::getresuid;
use nsproxy_common::UID_HINT_VAR;
use tracing::warn;
use uzers::{Group, os::unix::UserExt};

use crate::prelude::*;

/// Dedicated to spawning a shell that maximally pleases the user
/// what the user wants the uid of the shell to be, what groups to have

#[derive(Default)]
pub struct ShellPrefs {
    gids: Vec<Group>,
    pub uid: Option<uid_t>,
    /// This can also just be a program despite the struct's name
    pub shell: Option<PathBuf>,
    /// The user wants to drop in a root shell
    /// Defaults to false.
    pub wants_root: bool,
    pub cwd: Option<PathBuf>,
    /// This is different from .shell because this may be late resolved
    /// The PATHS can be different in the user shell
    pub prefer_shell: Option<String>
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
            let ushell = user.shell().to_owned();
            self.shell = ushell.into();
        }
        if self.cwd.is_none() {
            self.cwd = current_dir()?.into();
        }
        aok!()
    }
    pub fn gids_raw(&self) -> Vec<u32> {
        self.gids.iter().map(|k| k.gid()).collect()
    }
    pub async fn spawn_and_block(mut self) -> Result<()> {
        if let Some(name) = &self.prefer_shell {
            self.shell = Some(which::which(name)?);
        }
        if let Some(cmd) = &self.shell {
            let mut cmd = std::process::Command::new(cmd);
            let uid = self.uid.ok_or(anyhow!("can not find suitable uid"))?;
            cmd.uid(uid);
            cmd.groups(&self.gids_raw());
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
}
