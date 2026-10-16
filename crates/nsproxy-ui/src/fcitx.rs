use anyhow::{Context, Result, bail};
use nsproxy_core::state_paths;
use std::process::Stdio;
use tokio::process::Command;
use zbus::{Proxy, connection::Builder};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputMethodGroup {
    pub name: String,
    pub layout: String,
    pub input_methods: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableInputMethod {
    pub id: String,
    pub name: String,
    pub language: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FcitxState {
    pub status: FcitxStatus,
    pub current_group: String,
    pub current_input_method: String,
    pub groups: Vec<InputMethodGroup>,
    pub available_input_methods: Vec<AvailableInputMethod>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FcitxStatus {
    Disabled,
    Inactive,
    Active,
}

#[derive(Clone, Debug)]
pub enum FcitxAction {
    SetActive(bool),
    SetGroup(String),
    SetInputMethod(String),
    AddInputMethod(String),
    ConfigureInputMethod(String),
}

fn bus_address(profile: &str) -> String {
    format!(
        "unix:path={}",
        state_paths::profile_dir(profile).join("bus/session.sock").display()
    )
}

async fn remote(profile: &str, args: &[&str]) -> Result<String> {
    let address = bus_address(profile);
    let output = Command::new("fcitx5-remote")
        .args(args)
        .env("DBUS_SESSION_BUS_ADDRESS", &address)
        .stdin(Stdio::null())
        .output()
        .await
        .context("failed to run fcitx5-remote")?;
    if !output.status.success() {
        bail!(
            "fcitx5-remote {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn query(profile: &str) -> Result<FcitxState> {
    let address = bus_address(profile);
    let connection = Builder::address(address.as_str())?
        .build()
        .await
        .context("failed to connect to the profile D-Bus session")?;
    let controller = Proxy::new(
        &connection,
        "org.fcitx.Fcitx5",
        "/controller",
        "org.fcitx.Fcitx.Controller1",
    )
    .await
    .context("Fcitx is unavailable on the profile D-Bus session")?;

    let current_group: String = controller
        .call("CurrentInputMethodGroup", &())
        .await
        .context("failed to get the current Fcitx input-method group")?;
    let current_input_method: String = controller
        .call("CurrentInputMethod", &())
        .await
        .context("failed to get the current Fcitx input method")?;
    let group_names: Vec<String> = controller
        .call("InputMethodGroups", &())
        .await
        .context("failed to list Fcitx input-method groups")?;
    let available: Vec<(String, String, String, String, String, String, bool)> = controller
        .call("AvailableInputMethods", &())
        .await
        .context("failed to list available Fcitx input methods")?;

    let mut groups = Vec::with_capacity(group_names.len());
    for name in group_names {
        let (layout, input_methods): (String, Vec<(String, String)>) = controller
            .call("InputMethodGroupInfo", &name)
            .await
            .with_context(|| format!("failed to read Fcitx group {name:?}"))?;
        groups.push(InputMethodGroup {
            name,
            layout,
            input_methods: input_methods.into_iter().map(|(name, _)| name).collect(),
        });
    }
    let available_input_methods = available
        .into_iter()
        .filter(|(_, _, _, _, _, _, available)| *available)
        .map(|(id, name, _, _, language, _, _)| AvailableInputMethod { id, name, language })
        .collect();

    let status = match remote(profile, &[]).await?.as_str() {
        "0" => FcitxStatus::Disabled,
        "1" => FcitxStatus::Inactive,
        "2" => FcitxStatus::Active,
        other => bail!("fcitx5-remote returned an unknown state: {other:?}"),
    };

    Ok(FcitxState {
        status,
        current_group,
        current_input_method,
        groups,
        available_input_methods,
    })
}

pub async fn act(profile: &str, action: FcitxAction) -> Result<FcitxState> {
    match action {
        FcitxAction::SetActive(active) => {
            let address = bus_address(profile);
            let connection = Builder::address(address.as_str())?
                .build()
                .await
                .context("failed to connect to the profile D-Bus session")?;
            let controller = Proxy::new(
                &connection,
                "org.fcitx.Fcitx5",
                "/controller",
                "org.fcitx.Fcitx.Controller1",
            )
            .await
            .context("Fcitx is unavailable on the profile D-Bus session")?;
            let method = if active { "Activate" } else { "Deactivate" };
            controller
                .call::<_, _, ()>(method, &())
                .await
                .with_context(|| format!("Fcitx {method} request failed"))?;
            let state = query(profile).await?;
            if (active && state.status != FcitxStatus::Active)
                || (!active && state.status == FcitxStatus::Active)
            {
                bail!(
                    "Fcitx accepted {method} but its state remains {:?}",
                    state.status,
                );
            }
            return Ok(state);
        }
        FcitxAction::SetGroup(group) => {
            let state = query(profile).await?;
            if !state.groups.iter().any(|candidate| candidate.name == group) {
                bail!("Fcitx input-method group {group:?} is not configured");
            }
            remote(profile, &["-g", &group]).await?;
        }
        FcitxAction::SetInputMethod(input_method) => {
            let state = query(profile).await?;
            let group = state
                .groups
                .iter()
                .find(|group| group.name == state.current_group)
                .context("the current Fcitx input-method group is unavailable")?;
            if !group.input_methods.iter().any(|name| name == &input_method) {
                bail!("Fcitx input method {input_method:?} is not in the current group");
            }
            let address = bus_address(profile);
            let connection = Builder::address(address.as_str())?
                .build()
                .await
                .context("failed to connect to the profile D-Bus session")?;
            let controller = Proxy::new(
                &connection,
                "org.fcitx.Fcitx5",
                "/controller",
                "org.fcitx.Fcitx.Controller1",
            )
            .await
            .context("Fcitx is unavailable on the profile D-Bus session")?;
            controller
                .call::<_, _, ()>("SetCurrentIM", &input_method)
                .await
                .context("failed to select the Fcitx input method")?;
        }
        FcitxAction::AddInputMethod(input_method) => {
            let address = bus_address(profile);
            let connection = Builder::address(address.as_str())?
                .build()
                .await
                .context("failed to connect to the profile D-Bus session")?;
            let controller = Proxy::new(
                &connection,
                "org.fcitx.Fcitx5",
                "/controller",
                "org.fcitx.Fcitx.Controller1",
            )
            .await
            .context("Fcitx is unavailable on the profile D-Bus session")?;
            let state = query(profile).await?;
            let available = state
                .available_input_methods
                .iter()
                .any(|candidate| candidate.id == input_method);
            if !available {
                bail!("Fcitx input method {input_method:?} is not available");
            }
            let group = state
                .groups
                .iter()
                .find(|group| group.name == state.current_group)
                .context("the current Fcitx input-method group is unavailable")?;
            if !group.input_methods.iter().any(|name| name == &input_method) {
                let mut methods: Vec<(String, String)> = group
                    .input_methods
                    .iter()
                    .map(|name| (name.clone(), String::new()))
                    .collect();
                methods.push((input_method.clone(), String::new()));
                controller
                    .call::<_, _, ()>(
                        "SetInputMethodGroupInfo",
                        &(&state.current_group, &group.layout, methods),
                    )
                    .await
                    .context("failed to add the input method to the current group")?;
            }
            controller
                .call::<_, _, ()>("SetCurrentIM", &input_method)
                .await
                .context("failed to select the newly added input method")?;
        }
        FcitxAction::ConfigureInputMethod(input_method) => {
            let state = query(profile).await?;
            let configured = state
                .groups
                .iter()
                .any(|group| group.input_methods.contains(&input_method));
            if !configured {
                bail!("Fcitx input method {input_method:?} is not configured in any group");
            }
            let address = bus_address(profile);
            let connection = Builder::address(address.as_str())?
                .build()
                .await
                .context("failed to connect to the profile D-Bus session")?;
            let controller = Proxy::new(
                &connection,
                "org.fcitx.Fcitx5",
                "/controller",
                "org.fcitx.Fcitx.Controller1",
            )
            .await
            .context("Fcitx is unavailable on the profile D-Bus session")?;
            controller
                .call::<_, _, ()>("ConfigureIM", &input_method)
                .await
                .with_context(|| format!("failed to open configuration for {input_method:?}"))?;
        }
    }
    query(profile).await
}
