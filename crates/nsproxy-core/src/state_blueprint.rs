use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use tracing::warn;

use crate::state_paths;

/// Standard persistence contract for global JSON state structs.
pub trait PersistentState: Serialize + DeserializeOwned + Default + Sized {
    const STATE_NAME: &'static str;

    fn path() -> PathBuf;

    fn load_or_default() -> Result<Self> {
        let path = Self::path();
        if path.exists() {
            warn!("load_state_read {:?}", path);
            let content = std::fs::read_to_string(&path)
                .context(format!("Failed to read state from {:?}", path))?;
            let state: Self =
                serde_json::from_str(&content).context("Failed to parse state json")?;
            Ok(state)
        } else {
            warn!("load_state_default {:?}", path);
            Ok(Self::default())
        }
    }

    fn save_atomic(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create state dir")?;
        }

        let tmp = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self).context("Failed to serialize state")?;
        std::fs::write(&tmp, content).context("Failed to write temp state file")?;
        warn!("save_state {:?}", path);
        std::fs::rename(&tmp, &path).context("Failed to replace state file atomically")?;
        Ok(())
    }

    fn node() -> StateNode {
        StateNode::leaf(Self::STATE_NAME, Self::path())
    }
}

#[derive(Debug, Clone)]
pub struct StateNode {
    pub name: &'static str,
    pub path: PathBuf,
    pub children: Vec<StateNode>,
}

impl StateNode {
    pub fn leaf(name: &'static str, path: PathBuf) -> Self {
        Self {
            name,
            path,
            children: Vec::new(),
        }
    }

    pub fn branch(name: &'static str, path: PathBuf, children: Vec<StateNode>) -> Self {
        Self {
            name,
            path,
            children,
        }
    }

    pub fn render_tree(&self) -> String {
        let mut out = Vec::new();
        out.push(format!("{}: {}", self.name, self.path.display()));
        for (index, child) in self.children.iter().enumerate() {
            let is_last = index + 1 == self.children.len();
            child.render_into("", is_last, &mut out);
        }
        out.join("\n")
    }

    fn render_into(&self, prefix: &str, last: bool, out: &mut Vec<String>) {
        let connector = if last {
            "└── "
        } else {
            "├── "
        };

        out.push(format!(
            "{}{}{}: {}",
            prefix,
            connector,
            self.name,
            self.path.display()
        ));

        let child_prefix = if last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        for (index, child) in self.children.iter().enumerate() {
            let is_last = index + 1 == self.children.len();
            child.render_into(&child_prefix, is_last, out);
        }
    }
}

/// Statically-typed blueprint of global state files and directories.
pub fn global_state_tree() -> StateNode {
    StateNode::branch(
        "nsp3",
        state_paths::persist_root(),
        vec![
            StateNode::leaf("namespaces_registry", state_paths::namespaces_registry()),
            StateNode::leaf(
                "wrapped_binaries",
                state_paths::wrapped_binaries_config(),
            ),
            StateNode::branch(
                "profile (template)",
                state_paths::profile_dir("{profile}"),
                vec![
                    StateNode::leaf(
                        "profile_config",
                        state_paths::profile_config("{profile}"),
                    ),
                    StateNode::leaf("hot_config", state_paths::hot_config("{profile}")),
                    StateNode::leaf(
                        "profile_netns_bind",
                        state_paths::profile_netns_bind("{profile}"),
                    ),
                    StateNode::leaf(
                        "profile_ns_meta",
                        state_paths::profile_ns_meta("{profile}"),
                    ),
                ],
            ),
            StateNode::branch(
                "uplink",
                state_paths::uplink_root(),
                vec![
                    <crate::uplink::clash::ClashState as PersistentState>::node(),
                    <crate::uplink::RemoteProxyState as PersistentState>::node(),
                    <crate::uplink::UplinkStatsState as PersistentState>::node(),
                    StateNode::leaf("uplink_kind_dir", state_paths::uplink_dir("{kind}")),
                    StateNode::leaf(
                        "uplink_profile_dir",
                        state_paths::uplink_profile_dir("{kind}", "{profile}"),
                    ),
                ],
            ),
        ],
    )
}
