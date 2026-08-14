use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{env, fmt};

use tracing::warn;

pub type EnvKey = OsString;

/// Stores a set of changes to an environment
#[derive(Clone, Default)]
pub struct CommandEnv {
    clear: bool,
    saw_path: bool,
    vars: BTreeMap<EnvKey, Option<OsString>>,
}

impl fmt::Debug for CommandEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_command_env = f.debug_struct("CommandEnv");
        debug_command_env
            .field("clear", &self.clear)
            .field("vars", &self.vars);
        debug_command_env.finish()
    }
}

impl CommandEnv {
    // Capture the current environment with these changes applied
    pub fn capture(&self) -> BTreeMap<EnvKey, OsString> {
        let mut result = BTreeMap::<EnvKey, OsString>::new();
        if !self.clear {
            for (k, v) in env::vars_os() {
                result.insert(k.into(), v);
            }
        }
        for (k, maybe_v) in &self.vars {
            if let &Some(ref v) = maybe_v {
                result.insert(k.clone(), v.clone());
            } else {
                result.remove(k);
            }
        }
        result
    }

    pub fn is_unchanged(&self) -> bool {
        !self.clear && self.vars.is_empty()
    }

    pub fn capture_if_changed(&self) -> Option<BTreeMap<EnvKey, OsString>> {
        if self.is_unchanged() {
            None
        } else {
            Some(self.capture())
        }
    }

    // The following functions build up changes
    pub fn set(&mut self, key: &OsStr, value: &OsStr) {
        let key = EnvKey::from(key);
        self.maybe_saw_path(&key);
        self.vars.insert(key, Some(value.to_owned()));
    }

    pub fn remove(&mut self, key: &OsStr) {
        let key = EnvKey::from(key);
        self.maybe_saw_path(&key);
        if self.clear {
            self.vars.remove(&key);
        } else {
            self.vars.insert(key, None);
        }
    }

    pub fn clear(&mut self) {
        self.clear = true;
        self.vars.clear();
    }

    pub fn does_clear(&self) -> bool {
        self.clear
    }

    pub fn have_changed_path(&self) -> bool {
        self.saw_path || self.clear
    }

    fn maybe_saw_path(&mut self, key: &EnvKey) {
        if !self.saw_path && key == "PATH" {
            self.saw_path = true;
        }
    }

    pub fn iter(&self) -> CommandEnvs<'_> {
        let iter = self.vars.iter();
        CommandEnvs { iter }
    }
}

#[derive(Debug)]
pub struct CommandEnvs<'a> {
    iter: std::collections::btree_map::Iter<'a, EnvKey, Option<OsString>>,
}

impl<'a> Iterator for CommandEnvs<'a> {
    type Item = (&'a OsStr, Option<&'a OsStr>);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(key, value)| (key.as_ref(), value.as_deref()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for CommandEnvs<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
    fn is_empty(&self) -> bool {
        self.iter.is_empty()
    }
}

pub static ENV_PROFILE: &'static str = "NSPROXY_PROFILE_BROWSER";
pub static ENV_CONTAINER: &'static str = "NSPROXY_PROFILE";
pub static ENV_NSWRAP: &'static str = "NSWRAP";
pub static ENV_DBUS_SESSION_BUS_ADDRESS: &'static str = "DBUS_SESSION_BUS_ADDRESS";
pub static ENV_DBUS_SYSTEM_BUS_ADDRESS: &'static str = "DBUS_SYSTEM_BUS_ADDRESS";

// For mounted paths
pub static ENV_NS: &'static str = "NSROXY_NS";

#[derive(strum::EnumString, strum::IntoStaticStr, strum::Display, strum::AsRefStr)]
pub enum NswrapEnv {
    Confirm,
}

pub fn name_to_mount_path(name: impl AsRef<Path>) -> PathBuf {
    PathBuf::from("/run/").join(name).with_extension("ns")
}

pub fn args_deduce_mount(name: &Option<String>, mount: &Option<PathBuf>) -> Option<PathBuf> {
    if let Some(name) = &name
        && mount.is_none()
    {
        let path = name_to_mount_path(name);
        warn!("Mount path not specified, defaults to {:?}", &path);
        Some(path)
    } else {
        warn!("If you specify a name there is a default mount path");
        None
    }
}
