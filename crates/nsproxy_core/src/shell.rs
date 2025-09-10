use std::{env::var, os::unix::raw::uid_t, path::PathBuf};

use nix::unistd::{Group, getresuid};
use nsproxy_common::UID_HINT_VAR;

use crate::prelude::*;

/// Dedicated to spawning a shell that maximally pleases the user
/// what the user wants the uid of the shell to be, what groups to have

#[derive(Default)]
struct ShellPrefs {
    gids: Vec<Group>,
    pub uid: Option<uid_t>,
    pub shell: Option<PathBuf>,
    /// The user wants to drop in a root shell
    /// Defaults to false.
    pub wants_root: bool,
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

        aok!()
    }
}
