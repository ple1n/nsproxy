use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::state_blueprint::PersistentState;
use crate::state_paths;

/// Code that is more personal than common.
///
/// The reusable runtime treats these values as hardcoded configuration.
/// Personal workflows should stay concentrated here so UI/runtime code can
/// remain generic.

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum PersonalActionId {
	Llamacpp,
	Cinny,
}

impl PersonalActionId {
	pub fn key(self) -> &'static str {
		match self {
			Self::Llamacpp => "llamacpp",
			Self::Cinny => "cinny",
		}
	}

	pub fn label(self) -> &'static str {
		match self {
			Self::Llamacpp => "llamacpp",
			Self::Cinny => "cinny",
		}
	}
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonalConstants {
	#[serde(default)]
	pub llamacpp_exec: Option<String>,
	#[serde(default)]
	pub cinny_cwd: Option<String>,
}

impl PersistentState for PersonalConstants {
	const STATE_NAME: &'static str = "constants";

	fn path() -> PathBuf {
		state_paths::constants_config()
	}
}

static PERSONAL_CONSTANTS: LazyLock<RwLock<PersonalConstants>> = LazyLock::new(|| {
	RwLock::new(PersonalConstants::load_or_default().unwrap_or_else(|err| {
		tracing::warn!(%err, "failed to load personal constants");
		PersonalConstants::default()
	}))
});

pub fn personal_constants() -> PersonalConstants {
	PERSONAL_CONSTANTS
		.read()
		.expect("personal constants lock poisoned")
		.clone()
}

pub fn reload_personal_constants() -> Result<()> {
	let next = PersonalConstants::load_or_default()?;
	*PERSONAL_CONSTANTS
		.write()
		.expect("personal constants lock poisoned") = next;
	Ok(())
}

pub fn replace_personal_constants(constants: PersonalConstants) {
	*PERSONAL_CONSTANTS
		.write()
		.expect("personal constants lock poisoned") = constants;
}

pub fn replace_personal_constants_from_json(content: &str) -> Result<()> {
	let next: PersonalConstants = serde_json::from_str(content)?;
	replace_personal_constants(next);
	Ok(())
}

#[derive(Debug, Clone)]
pub struct PersonalActionSpec {
	pub id: PersonalActionId,
	pub profile: &'static str,
	pub exec: Option<String>,
	pub args: &'static [&'static str],
	pub cwd: Option<PathBuf>,
	pub ringbuf_size: Option<u32>,
}

impl PersonalActionSpec {
	pub fn is_configured(&self) -> bool {
		self.exec.is_some()
			&& match self.id {
				PersonalActionId::Llamacpp => true,
				PersonalActionId::Cinny => self.cwd.is_some(),
			}
	}
}

const LLAMACPP_ARGS: &[&str] = &[];
const CINNY_ARGS: &[&str] = &["vite", "preview", "--port", "80"];

pub fn personal_action_specs() -> Vec<PersonalActionSpec> {
	[
		PersonalActionId::Llamacpp,
		PersonalActionId::Cinny,
	]
	.into_iter()
	.filter_map(personal_action_spec)
	.collect()
}

pub fn personal_action_spec(id: PersonalActionId) -> Option<PersonalActionSpec> {
	let constants = personal_constants();
	Some(match id {
		PersonalActionId::Llamacpp => PersonalActionSpec {
			id,
			profile: "basic",
			exec: constants.llamacpp_exec.clone(),
			args: LLAMACPP_ARGS,
			cwd: None,
			ringbuf_size: None,
		},
		PersonalActionId::Cinny => PersonalActionSpec {
			id,
			profile: "basic",
			exec: Some("npx".to_string()),
			args: CINNY_ARGS,
			cwd: constants.cinny_cwd.as_ref().map(PathBuf::from),
			ringbuf_size: None,
		},
	})
}

pub fn suspend_restart_action() -> PersonalActionId {
	PersonalActionId::Llamacpp
}