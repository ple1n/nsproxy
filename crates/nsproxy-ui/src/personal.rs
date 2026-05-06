use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use diag::{ProcessStatus, SpawnArgs};
use eframe::egui;
use eframe::egui::Color32;
use egui_code_editor::{CodeEditor, ColorTheme};
use futures::StreamExt;
use nsproxy_core::personal::{self, PersonalActionId, PersonalConstants};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::supervisor::{SupervisorCommand, SupervisorHandle, SupervisorSnapshot};

#[derive(Clone, Default)]
pub struct PersonalUiState {
    inner: Arc<Mutex<PersonalState>>,
    cmd_tx: Arc<Mutex<Option<mpsc::UnboundedSender<PersonalCommand>>>>,
}

struct PersonalState {
    llamacpp_task_pgid: Option<u32>,
    cinny_task_pgid: Option<u32>,
    restart_after_resume: bool,
    busy: bool,
    dry_run_suspend: bool,
    message: Option<String>,
    constants_editor_json: String,
    constants_editor_status: Option<String>,
    constants_form: PersonalConstants,
    last_constants_status_token: u64,
    last_loaded_constants_content: Option<String>,
}

impl Default for PersonalState {
    fn default() -> Self {
        let constants_form = PersonalConstants::default();
        Self {
            llamacpp_task_pgid: None,
            cinny_task_pgid: None,
            restart_after_resume: false,
            busy: false,
            dry_run_suspend: false,
            message: None,
            constants_editor_json: default_constants_text(),
            constants_editor_status: None,
            constants_form,
            last_constants_status_token: 0,
            last_loaded_constants_content: None,
        }
    }
}

enum PersonalCommand {
    SaveConstants { content: String },
    ReloadConstants,
    SetRuntimeState(diag::personal::PersonalRuntimeState),
}

impl PersonalUiState {
    fn snapshot(&self) -> PersonalStateSnapshot {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        PersonalStateSnapshot {
            llamacpp_task_pgid: guard.llamacpp_task_pgid,
            cinny_task_pgid: guard.cinny_task_pgid,
            restart_after_resume: guard.restart_after_resume,
            busy: guard.busy,
            dry_run_suspend: guard.dry_run_suspend,
            message: guard.message.clone(),
            constants_editor_json: guard.constants_editor_json.clone(),
            constants_editor_status: guard.constants_editor_status.clone(),
            constants_form: guard.constants_form.clone(),
        }
    }

    fn install_actor(&self, tx: mpsc::UnboundedSender<PersonalCommand>) {
        let mut guard = self.cmd_tx.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(tx);
    }

    fn send_command(&self, command: PersonalCommand) {
        let guard = self.cmd_tx.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(command);
        }
    }

    fn set_dry_run_suspend(&self, enabled: bool) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.dry_run_suspend = enabled;
    }

    fn set_busy(&self, busy: bool, message: impl Into<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.busy = busy;
        guard.message = Some(message.into());
    }

    fn set_llamacpp_task_pgid(&self, task_pgid: Option<u32>, message: impl Into<String>) {
        let next_state = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.llamacpp_task_pgid = task_pgid;
            guard.message = Some(message.into());
            guard.busy = false;
            diag::personal::PersonalRuntimeState {
                llamacpp_task_pgid: guard.llamacpp_task_pgid,
                cinny_task_pgid: guard.cinny_task_pgid,
            }
        };
        self.send_command(PersonalCommand::SetRuntimeState(next_state));
    }

    fn set_cinny_task_pgid(&self, task_pgid: Option<u32>, message: impl Into<String>) {
        let next_state = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.cinny_task_pgid = task_pgid;
            guard.message = Some(message.into());
            guard.busy = false;
            diag::personal::PersonalRuntimeState {
                llamacpp_task_pgid: guard.llamacpp_task_pgid,
                cinny_task_pgid: guard.cinny_task_pgid,
            }
        };
        self.send_command(PersonalCommand::SetRuntimeState(next_state));
    }

    fn finish_busy(&self, message: impl Into<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.busy = false;
        guard.message = Some(message.into());
    }

    fn set_restart_after_resume(&self, restart_after_resume: bool) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.restart_after_resume = restart_after_resume;
    }

    fn take_restart_after_resume(&self) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let restart_after_resume = guard.restart_after_resume;
        guard.restart_after_resume = false;
        restart_after_resume
    }

    fn clear_if_not_running(&self, app: &crate::App) {
        let snapshot = self.snapshot();

        if let Some(task_pgid) = snapshot.llamacpp_task_pgid {
            let active = personal_action_status(app, PersonalActionId::Llamacpp, task_pgid)
                .is_some_and(|status| matches!(status, ProcessStatus::Alive));
            if !active {
                self.set_llamacpp_task_pgid(None, "llamacpp is not running");
            }
        }

        if let Some(task_pgid) = snapshot.cinny_task_pgid {
            let active = personal_action_status(app, PersonalActionId::Cinny, task_pgid)
                .is_some_and(|status| matches!(status, ProcessStatus::Alive));
            if !active {
                self.set_cinny_task_pgid(None, "cinny is not running");
            }
        }
    }

    fn set_constants_json(&self, json: String) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.constants_editor_json = json.clone();
        if let Ok(constants) = serde_json::from_str::<PersonalConstants>(&json) {
            guard.constants_form = constants;
        }
    }

    fn set_constants_field(&self, key: &str, value: String) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let next = if value.trim().is_empty() {
            None
        } else {
            Some(value)
        };
        match key {
            "llamacpp_exec" => guard.constants_form.llamacpp_exec = next,
            "cinny_cwd" => guard.constants_form.cinny_cwd = next,
            _ => return,
        }
        guard.constants_editor_json = serde_json::to_string_pretty(&guard.constants_form)
            .unwrap_or_else(|_| default_constants_text());
    }

    fn request_save_constants(&self) {
        let content = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.constants_editor_json.clone()
        };
        self.send_command(PersonalCommand::SaveConstants { content });
    }

    fn request_reload_constants(&self) {
        self.send_command(PersonalCommand::ReloadConstants);
    }

    fn apply_supervisor_snapshot(&self, snapshot: &SupervisorSnapshot) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.llamacpp_task_pgid = snapshot.personal_runtime_state.llamacpp_task_pgid;
        guard.cinny_task_pgid = snapshot.personal_runtime_state.cinny_task_pgid;
        let Some(status) = snapshot.constants_editor_status.as_ref() else {
            return;
        };
        if status.token == guard.last_constants_status_token {
            return;
        }
        guard.last_constants_status_token = status.token;
        guard.constants_editor_status = Some(status.message.clone());

        if let Some(content) = snapshot.constants_editor_content.as_ref() {
            if guard.last_loaded_constants_content.as_ref() != Some(content) {
                guard.constants_editor_json = content.clone();
                guard.last_loaded_constants_content = Some(content.clone());
                if let Ok(constants) = serde_json::from_str::<PersonalConstants>(content) {
                    guard.constants_form = constants.clone();
                    drop(guard);
                    let _ = personal::replace_personal_constants_from_json(content);
                    return;
                }
            }
        }

        if status.ok {
            let json = guard.constants_editor_json.clone();
            drop(guard);
            if let Err(err) = personal::replace_personal_constants_from_json(&json) {
                let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                guard.constants_editor_status =
                    Some(format!("{}; local reload failed: {err}", status.message));
            }
        }
    }
}

struct PersonalStateSnapshot {
    llamacpp_task_pgid: Option<u32>,
    cinny_task_pgid: Option<u32>,
    restart_after_resume: bool,
    busy: bool,
    dry_run_suspend: bool,
    message: Option<String>,
    constants_editor_json: String,
    constants_editor_status: Option<String>,
    constants_form: PersonalConstants,
}

fn personal_action_status(
    app: &crate::App,
    action_id: PersonalActionId,
    task_pgid: u32,
) -> Option<ProcessStatus> {
    let Some(spec) = personal::personal_action_spec(action_id) else {
        return None;
    };
    app.snapshot
        .profiles
        .get(spec.profile)
        .and_then(|profile| profile.process_list_snapshot.as_ref())
        .and_then(|plist| plist.procs.get(&task_pgid))
        .map(|entry| entry.status.clone())
}

async fn run_llamacpp(supervisor: SupervisorHandle, state: PersonalUiState) -> Result<()> {
    let exec = personal::personal_constants()
        .llamacpp_exec
        .ok_or_else(|| anyhow::anyhow!("llamacpp exec path is not configured"))?;
    let fish_command = exec;
    let mut spawn_args = SpawnArgs {
        uid: None,
        gid: None,
        exec: Some("fish".to_string()),
        cwd: None,
        gids: Vec::new(),
        args: vec!["fish".to_string(), fish_command.clone()],
        ringbuf_size: None,
        ns: diag::NamespaceSpawn::Inside,
    };
    crate::apply_default_spawn_user(&mut spawn_args);
    state.set_busy(true, "starting llamacpp...");
    info!(command = %fish_command, ?spawn_args, "starting llamacpp personal action");
    supervisor.ensure_profile_running("basic").await?;
    let task_pgid = supervisor
        .spawn_managed_process("basic", spawn_args)
        .await?;
    state.set_llamacpp_task_pgid(
        Some(task_pgid),
        format!("llamacpp running as task pgid {}", task_pgid),
    );
    Ok(())
}

async fn run_cinny(supervisor: SupervisorHandle, state: PersonalUiState) -> Result<()> {
    let cinny_cwd = personal::personal_constants()
        .cinny_cwd
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("cinny cwd is not configured"))?;
    let cmd = "vite preview --port 80".to_string();
    let exec = "/usr/bin/npx".to_string();
    let mut spawn_args = SpawnArgs {
        uid: None,
        gid: None,
        exec: Some(exec.clone()),
        cwd: Some(cinny_cwd.clone()),
        gids: Vec::new(),
        args: [exec].into_iter().chain(cmd.split_whitespace().map(|s| s.to_string())).collect(),
        ringbuf_size: None,
        ns: diag::NamespaceSpawn::Inside,
    };
    crate::apply_default_spawn_user(&mut spawn_args);
    state.set_busy(true, "starting cinny...");
    info!(command = %cmd, cwd = %cinny_cwd.display(), ?spawn_args, "starting cinny personal action");
    supervisor.ensure_profile_running("basic").await?;
    let task_pgid = supervisor
        .spawn_managed_process("basic", spawn_args)
        .await?;
    state.set_cinny_task_pgid(Some(task_pgid), format!("cinny running as task pgid {}", task_pgid));
    Ok(())
}

async fn request_suspend(proxy: &zbus::Proxy<'_>) -> Result<()> {
    proxy
        .call_method("Suspend", &(false,))
        .await
        .context("logind suspend request failed")?;
    Ok(())
}

async fn log_nvidia_smi() {
    match tokio::process::Command::new("nvidia-smi").output().await {
        Ok(output) => {
            let mut stdout = io::stdout().lock();
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stdout, "nvidia-smi after resume: {}", output.status);
            let _ = stdout.write_all(&output.stdout);
            if !output.stdout.ends_with(b"\n") {
                let _ = writeln!(stdout);
            }
            let _ = stderr.write_all(&output.stderr);
            if !output.stderr.is_empty() && !output.stderr.ends_with(b"\n") {
                let _ = writeln!(stderr);
            }
        }
        Err(err) => {
            warn!(%err, "failed to run nvidia-smi after resume");
        }
    }
}

async fn acquire_suspend_delay_lock(proxy: &zbus::Proxy<'_>) -> Result<zbus::zvariant::OwnedFd> {
    proxy
        .call(
            "Inhibit",
            &(
                "sleep",
                "nsproxy-ui",
                "nsproxy-ui pre-suspend handler",
                "delay",
            ),
        )
        .await
        .context("failed to acquire logind suspend delay lock")
}

async fn wait_for_sleep_signal(proxy: &zbus::Proxy<'_>) -> Result<()> {
    let mut stream = proxy
        .receive_signal("PrepareForSleep")
        .await
        .context("failed to subscribe to PrepareForSleep")?;

    while let Some(message) = stream.next().await {
        let sleeping = message
            .body()
            .deserialize::<bool>()
            .context("failed to decode PrepareForSleep payload")?;
        if sleeping {
            return Ok(());
        }
    }

    anyhow::bail!("PrepareForSleep signal stream ended before suspend")
}

async fn monitor_systemd_suspend(
    supervisor: SupervisorHandle,
    state: PersonalUiState,
) -> Result<()> {
    let connection = zbus::Connection::system()
        .await
        .context("failed to connect to system bus for sleep hook")?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await
    .context("failed to create logind proxy")?;
    let mut inhibitor = Some(acquire_suspend_delay_lock(&proxy).await?);
    let mut stream = proxy
        .receive_signal("PrepareForSleep")
        .await
        .context("failed to subscribe to PrepareForSleep")?;

    while let Some(message) = stream.next().await {
        let sleeping = message
            .body()
            .deserialize::<bool>()
            .context("failed to decode PrepareForSleep payload")?;

        if sleeping {
            run_pre_suspend(supervisor.clone(), state.clone()).await?;
            inhibitor.take();
        } else {
            run_post_resume(supervisor.clone(), state.clone()).await?;
            inhibitor = Some(acquire_suspend_delay_lock(&proxy).await?);
        }
    }

    anyhow::bail!("PrepareForSleep signal stream ended")
}

pub fn install_systemd_suspend_hook(
    rt: &tokio::runtime::Runtime,
    supervisor: SupervisorHandle,
    state: PersonalUiState,
) {
    info!("starting systemd suspend hook");
    rt.spawn(async move {
        loop {
            if let Err(err) = monitor_systemd_suspend(supervisor.clone(), state.clone()).await {
                warn!(%err, "systemd suspend hook exited; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });
}

pub fn install_personal_actor(
    rt: &tokio::runtime::Runtime,
    supervisor: SupervisorHandle,
    state: PersonalUiState,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    state.install_actor(cmd_tx);
    let Some(mut snapshot_rx) = supervisor.subscribe_snapshots() else {
        return;
    };
    supervisor.send(SupervisorCommand::LoadConstantsPrivileged);
    rt.spawn(async move {
        let snapshot = snapshot_rx.borrow().clone();
        state.apply_supervisor_snapshot(&snapshot);
        loop {
            tokio::select! {
                command = cmd_rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        PersonalCommand::SaveConstants { content } => {
                            supervisor.send(SupervisorCommand::SaveConstantsPrivileged { content });
                        }
                        PersonalCommand::ReloadConstants => {
                            supervisor.send(SupervisorCommand::LoadConstantsPrivileged);
                        }
                        PersonalCommand::SetRuntimeState(state) => {
                            supervisor.send(SupervisorCommand::SetPersonalRuntimeState {
                                profile: "basic".to_string(),
                                state,
                            });
                        }
                    }
                }
                changed = snapshot_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let snapshot = snapshot_rx.borrow().clone();
                    state.apply_supervisor_snapshot(&snapshot);
                }
            }
        }
    });
}

async fn run_pre_suspend(supervisor: SupervisorHandle, state: PersonalUiState) -> Result<()> {
    let snapshot = state.snapshot();
    state.set_busy(true, "preparing suspend...");

    let restart = snapshot.llamacpp_task_pgid.is_some();
    state.set_restart_after_resume(restart);
    if let Some(task_pgid) = snapshot.llamacpp_task_pgid {
        state.set_busy(
            true,
            format!("stopping llamacpp task pgid {}...", task_pgid),
        );
        supervisor.stop_managed_process("basic", task_pgid).await?;
        state.set_llamacpp_task_pgid(None, "llamacpp stopped");
        state.set_busy(true, "waiting for system suspend...");
    }

    log_nvidia_smi().await;

    if !restart {
        state.set_busy(true, "waiting for system suspend...");
    }

    Ok(())
}

async fn run_post_resume(supervisor: SupervisorHandle, state: PersonalUiState) -> Result<()> {
    state.set_busy(true, "resumed; waiting for gpu...");
    tokio::time::sleep(Duration::from_secs(10)).await;

    if state.take_restart_after_resume() {
        run_llamacpp(supervisor, state).await?;
    } else {
        let task_pgid = state.snapshot().llamacpp_task_pgid;
        state.set_llamacpp_task_pgid(task_pgid, "system resumed");
    }

    Ok(())
}

async fn run_suspend(supe: SupervisorHandle, state: PersonalUiState) -> Result<()> {
    let snapshot = state.snapshot();

    if snapshot.dry_run_suspend {
        // Dry run allows for no-suspend tests of process-start-stop
        // Dry run does not disable the hooks for managing llamacpp
        // Llamacpp is only restarted if it was running pre-suspend
        run_pre_suspend(supe.clone(), state.clone()).await?;
        state.set_busy(true, "dry run: suspend");
        state.set_llamacpp_task_pgid(snapshot.llamacpp_task_pgid, "dry run complete");
        run_post_resume(supe.clone(), state.clone()).await?;
        return Ok(());
    }

    state.set_busy(true, "requesting system suspend...");
    let connection = zbus::Connection::system()
        .await
        .context("failed to connect to system bus for suspend request")?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await
    .context("failed to create logind proxy for suspend request")?;

    request_suspend(&proxy).await?;
    wait_for_sleep_signal(&proxy).await?;
    Ok(())
}

fn spawn_action(
    app: &crate::App,
    fut: impl std::future::Future<Output = Result<()>> + Send + 'static,
) {
    let Some(rt) = app.tokio_rt.as_ref() else {
        app.personal_state
            .set_llamacpp_task_pgid(None, "tokio runtime unavailable for actions");
        return;
    };
    let state = app.personal_state.clone();
    rt.spawn(async move {
        if let Err(err) = fut.await {
            let snapshot = state.snapshot();
            if snapshot.llamacpp_task_pgid.is_some() {
                state.set_llamacpp_task_pgid(snapshot.llamacpp_task_pgid, format!("{}", err));
            } else if snapshot.cinny_task_pgid.is_some() {
                state.set_cinny_task_pgid(snapshot.cinny_task_pgid, format!("{}", err));
            } else {
                state.finish_busy(format!("{}", err));
            }
        }
    });
}

pub fn render_actions_tab(app: &mut crate::App, ui: &mut egui::Ui) {
    app.personal_state.clear_if_not_running(app);
    let state = app.personal_state.snapshot();
    let llamacpp_spec = personal::personal_action_spec(PersonalActionId::Llamacpp);
    let cinny_spec = personal::personal_action_spec(PersonalActionId::Cinny);
    let llamacpp_status = state
        .llamacpp_task_pgid
        .and_then(|task_pgid| personal_action_status(app, PersonalActionId::Llamacpp, task_pgid));
    let llamacpp_active = llamacpp_status
        .as_ref()
        .is_some_and(|status| matches!(status, ProcessStatus::Alive));
    let cinny_status = state
        .cinny_task_pgid
        .and_then(|task_pgid| personal_action_status(app, PersonalActionId::Cinny, task_pgid));
    let cinny_active = cinny_status
        .as_ref()
        .is_some_and(|status| matches!(status, ProcessStatus::Alive));

    ui.heading("Actions");
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        let start = ui.add_enabled(
            !state.busy
                && !llamacpp_active
                && llamacpp_spec
                    .as_ref()
                    .is_some_and(|spec| spec.is_configured()),
            egui::Button::new("llamacpp").min_size(egui::vec2(120.0, 34.0)),
        );
        if start.clicked() {
            spawn_action(
                app,
                run_llamacpp(app.supervisor.clone(), app.personal_state.clone()),
            );
        }

        let cinny = ui.add_enabled(
            !state.busy
                && !cinny_active
                && cinny_spec.as_ref().is_some_and(|spec| spec.is_configured()),
            egui::Button::new("cinny").min_size(egui::vec2(120.0, 34.0)),
        );
        if cinny.clicked() {
            spawn_action(
                app,
                run_cinny(app.supervisor.clone(), app.personal_state.clone()),
            );
        }

        let suspend = ui.add_enabled(
            !state.busy,
            egui::Button::new("suspend").min_size(egui::vec2(120.0, 34.0)),
        );
        if suspend.clicked() {
            spawn_action(
                app,
                run_suspend(app.supervisor.clone(), app.personal_state.clone()),
            );
        }

        let mut dry_run_suspend = state.dry_run_suspend;
        if ui.checkbox(&mut dry_run_suspend, "dry run").changed() {
            app.personal_state.set_dry_run_suspend(dry_run_suspend);
        }
    });

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(12.0);

    if let Some(spec) = llamacpp_spec {
        let status = if state.busy {
            ("busy", Color32::from_rgb(220, 180, 90))
        } else if matches!(llamacpp_status, Some(ProcessStatus::Alive)) {
            ("running", Color32::LIGHT_GREEN)
        } else {
            ("idle", Color32::from_rgb(130, 130, 130))
        };
        ui.horizontal(|ui| {
            ui.strong(spec.id.label());
            ui.add_space(12.0);
            ui.colored_label(status.1, status.0);
        });
        ui.label(format!("profile: {}", spec.profile));
        ui.label(format!(
            "exec: {}",
            spec.exec.as_deref().unwrap_or("<unset>")
        ));
        if let Some(task_pgid) = state.llamacpp_task_pgid {
            ui.label(format!("task pgid: {}", task_pgid));
        }
    }

    if let Some(ref spec) = cinny_spec {
        ui.add_space(8.0);
        let status = if state.busy && state.cinny_task_pgid.is_none() {
            ("busy", Color32::from_rgb(220, 180, 90))
        } else if matches!(cinny_status, Some(ProcessStatus::Alive)) {
            ("running", Color32::LIGHT_GREEN)
        } else {
            ("idle", Color32::from_rgb(130, 130, 130))
        };
        ui.horizontal(|ui| {
            ui.strong(spec.id.label());
            ui.add_space(12.0);
            ui.colored_label(status.1, status.0);
        });
        ui.label(format!("profile: {}", spec.profile));
        ui.label(format!(
            "exec: {}",
            spec.exec.as_deref().unwrap_or("<unset>")
        ));
        if let Some(cwd) = spec.cwd.as_ref() {
            ui.label(format!("cwd: {}", cwd.display()));
        }
        if let Some(task_pgid) = state.cinny_task_pgid {
            ui.label(format!("task pgid: {}", task_pgid));
        }
    }

    if cinny_spec
        .as_ref()
        .is_some_and(|spec| !spec.is_configured())
    {
        ui.add_space(8.0);
        ui.colored_label(
            Color32::from_rgb(220, 160, 90),
            "cinny is disabled until constants.json provides cinny_cwd",
        );
    }

    if let Some(message) = state.message.as_deref() {
        ui.add_space(8.0);
        ui.label(message);
    }

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(12.0);

    ui.horizontal(|ui| {
        ui.strong("constants.json");
        if ui.button("Save").clicked() {
            app.personal_state.request_save_constants();
        }
        if ui.button("Reload").clicked() {
            app.personal_state.request_reload_constants();
        }
    });
    ui.small(format!(
        "path: {}",
        nsproxy_core::state_paths::constants_config().display()
    ));

    let mut llamacpp_exec = state
        .constants_form
        .llamacpp_exec
        .clone()
        .unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("llamacpp_exec");
        if ui.text_edit_singleline(&mut llamacpp_exec).changed() {
            app.personal_state
                .set_constants_field("llamacpp_exec", llamacpp_exec.clone());
        }
    });

    let mut cinny_cwd = state.constants_form.cinny_cwd.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("cinny_cwd");
        if ui.text_edit_singleline(&mut cinny_cwd).changed() {
            app.personal_state
                .set_constants_field("cinny_cwd", cinny_cwd.clone());
        }
    });

    ui.add_space(8.0);

    let mut constants_editor_json = state.constants_editor_json.clone();
    let mut editor = CodeEditor::default()
        .id_source("actions-constants-json")
        .with_rows(12)
        .with_theme(ColorTheme::GRUVBOX)
        .with_syntax(crate::json_syntax())
        .with_numlines(true)
        .with_ui_fontsize(ui);
    editor.show(ui, &mut constants_editor_json);
    if constants_editor_json != state.constants_editor_json {
        app.personal_state.set_constants_json(constants_editor_json);
    }

    if let Some(status) = state.constants_editor_status.as_deref() {
        ui.add_space(6.0);
        ui.label(status);
    }
}

fn default_constants_text() -> String {
    serde_json::to_string_pretty(&PersonalConstants::default()).unwrap_or_else(|_| "{}".to_string())
}
