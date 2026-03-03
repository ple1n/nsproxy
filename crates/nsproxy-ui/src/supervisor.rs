use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use diag::summary::DiagAccumulator;
use diag::{ControlCommand, DiagEvent, DiagEventStream};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{execve, fork, ForkResult, Pid};
use nsproxy_common::routing::ProxyID;
use nsproxy_common::stats::ProxyStats;
use nsproxy_common::state_paths;
use nsproxy_common::NsAlive;
use nsproxy_core::cmd_common::{apply_ns_env, read_ns_alive};
use nsproxy_core::shell::{ShellArgs, ShellPrefs};
use nsproxy_core::state_blueprint::PersistentState;
use nsproxy_core::{cli_to_inheritable_fd, to_cstr, Cli, HotConfig, MainCommand, TemplateConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitId(String);

impl UnitId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ProfileName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<String> for ProfileName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ProfileName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Display for ProfileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitKind {
    Up,
    Serve,
    Veth,
    Daemon,
    Custom,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UnitCommand {
    NsproxyCli { cli: Cli },
    Daemon { args: ShellArgs },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitDesiredState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
    Restarting,
    Pending,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnitSpec {
    pub id: UnitId,
    pub profile: ProfileName,
    pub kind: UnitKind,
    pub command: UnitCommand,
    pub restart: RestartPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    pub when: SystemTime,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagSummary {
    pub total_conns: usize,
    pub active_conns: usize,
}

/// Should only contain generic info about a linux process
#[derive(Clone, Serialize, Deserialize)]
pub struct UnitState {
    pub id: UnitId,
    pub kind: UnitKind,
    pub status: UnitStatus,
    pub desired: UnitDesiredState,
    pub pid: Option<i32>,
    pub last_exit: Option<ExitInfo>,
    pub restart_policy: RestartPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileSnapshot {
    pub units: Vec<UnitState>,
    pub hotconfig: HotConfig,
    pub template: TemplateConfig,
    pub routing_state: Option<diag::RoutingState>,
    pub dns_state: Option<diag::DnsState>,
    pub diag_connected: bool,
    pub diag_summary: Option<DiagSummary>,
    pub proxy_stats: HashMap<ProxyID, ProxyStats>,
    #[serde(skip)]
    pub hotconfig_value: serde_json::Value,
    #[serde(skip)]
    pub template_value: serde_json::Value,
    pub ns_alive: Option<NsAlive>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SupervisorSnapshot {
    pub profiles: BTreeMap<ProfileName, ProfileSnapshot>,
    pub generated_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKind {
    Proxies,
    Processes,
    Diagnostics,
    Dns,
    Hotconfig,
    ProfileEditor,
}

#[derive(Debug)]
pub enum SupervisorCommand {
    // Unit management
    EnsureUnit(UnitSpec),
    StartUnit(UnitId),
    StopUnit(UnitId),
    StartDaemon {
        profile: ProfileName,
        args: ShellArgs,
    },
    StartHotconfigDaemons {
        profile: ProfileName,
    },

    // Diag control passthrough (wraps ControlCommand)
    Ctrl {
        unit_id: UnitId,
        cmd: ControlCommand,
    },

    // Profile-level operations
    /// Query hotconfig via diag socket; fall back to disk if needed
    ReloadHotconfig(ProfileName),
    /// Reload profile template from disk
    ReloadProfile(ProfileName),
    /// Load profile from disk: read NsAlive and initialize units
    LoadProfile(ProfileName),
    /// Load multiple profiles in batch (emit single snapshot after all)
    LoadProfiles(Vec<ProfileName>),

    // System events
    /// Initialize supervisor: discover and load all profiles from disk
    Init,

    // UI events
    /// Triggered when a tab is opened in the UI
    OnTabOpen {
        profile: ProfileName,
        tab: TabKind,
    },
}

#[derive(Clone)]
pub struct SupervisorHandle {
    cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
    snapshot_rx: std::sync::Arc<std::sync::Mutex<tokio::sync::watch::Receiver<SupervisorSnapshot>>>,
}

impl SupervisorHandle {
    pub fn new(ectx: egui::Context) -> (Self, SupervisorTask) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(SupervisorSnapshot {
            profiles: BTreeMap::new(),
            generated_at: SystemTime::now(),
        });

        let cmd_tx_for_self = cmd_tx.clone();
        (
            Self {
                cmd_tx: cmd_tx_for_self,
                snapshot_rx: std::sync::Arc::new(std::sync::Mutex::new(snapshot_rx)),
            },
            SupervisorTask {
                cmd_tx,
                cmd_rx,
                snapshot_tx,
                ectx,
            },
        )
    }

    pub fn send(&self, cmd: SupervisorCommand) {
        if self.cmd_tx.send(cmd).is_err() {
            warn!("supervisor command channel dropped");
        }
    }

    pub fn try_recv_snapshot(&self) -> Option<SupervisorSnapshot> {
        let mut rx = self.snapshot_rx.lock().ok()?;
        // Check if value changed, and if so get and mark as seen
        if rx.has_changed().ok()? {
            Some(rx.borrow_and_update().clone())
        } else {
            None
        }
    }
}

pub struct SupervisorTask {
    cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
    cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
    snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
    ectx: egui::Context,
}

impl SupervisorTask {
    pub async fn run(self) {
        let mut supervisor = Supervisor::new(
            self.cmd_tx.clone(),
            self.cmd_rx,
            self.snapshot_tx,
            self.ectx,
        );
        if let Err(err) = supervisor.run().await {
            error!("supervisor stopped: {err:?}");
        }
    }
}

// Backoff/retry removed: supervisor is now purely event-driven.

struct UnitRuntime {
    spec: UnitSpec,
    state: UnitState,
    diag_state: DiagState,
    diag_cmd_tx: Option<mpsc::UnboundedSender<ControlCommand>>,
}

impl UnitRuntime {
    fn new(spec: UnitSpec) -> Self {
        Self {
            state: UnitState {
                id: spec.id.clone(),
                kind: spec.kind,
                status: UnitStatus::Stopped,
                desired: UnitDesiredState::Stopped,
                pid: None,
                last_exit: None,
                restart_policy: spec.restart,
            },
            spec,
            diag_state: DiagState::default(),
            diag_cmd_tx: None,
        }
    }
}

struct DiagState {
    accumulator: DiagAccumulator,
    pub dns_state: Option<diag::DnsState>,
    pub routing_state: Option<diag::RoutingState>,
    pub proxy_stats: HashMap<ProxyID, ProxyStats>,
}

impl Default for DiagState {
    fn default() -> Self {
        Self {
            accumulator: DiagAccumulator::new(512, 256),
            dns_state: None,
            routing_state: None,
            proxy_stats: HashMap::new(),
        }
    }
}

struct Supervisor {
    cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
    cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    event_rx: mpsc::UnboundedReceiver<SupervisorEvent>,
    snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
    ectx: egui::Context,
    units: HashMap<UnitId, UnitRuntime>,
    nsproxy_path: PathBuf,
    persist_state: UiStatsState,
    persist_dirty: bool,
    daemon_catalog: HashMap<ProfileName, Vec<ShellArgs>>,
    spawned_daemons: HashSet<String>,
    ns_alive_status: HashMap<ProfileName, NsAliveStatus>,
    pid_to_unit: HashMap<i32, UnitId>,
}

impl Supervisor {
    fn new(
        cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
        cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
        snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
        ectx: egui::Context,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let persist_state = UiStatsState::load_or_default().unwrap_or_default();
        Self {
            cmd_tx,
            cmd_rx,
            event_tx,
            event_rx,
            snapshot_tx,
            ectx,
            units: HashMap::new(),
            nsproxy_path: default_nsproxy_path(),
            persist_state,
            persist_dirty: false,
            daemon_catalog: HashMap::new(),
            spawned_daemons: HashSet::new(),
            ns_alive_status: HashMap::new(),
            pid_to_unit: HashMap::new(),
        }
    }

    async fn run(&mut self) -> Result<()> {
        self.reconcile().await;
        self.emit_snapshot();

        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd).await;
                    self.reconcile().await;
                    self.emit_snapshot();
                }
                Some(ev) = self.event_rx.recv() => {
                    self.handle_event(ev);
                    self.reconcile().await;
                    self.emit_snapshot();
                }
                else => {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_command(&mut self, cmd: SupervisorCommand) {
        match cmd {
            SupervisorCommand::EnsureUnit(spec) => {
                if let Some(unit) = self.units.get_mut(&spec.id) {
                    unit.spec = spec;
                    unit.state.id = unit.spec.id.clone();
                    unit.state.kind = unit.spec.kind;
                    unit.state.restart_policy = unit.spec.restart;
                    unit.state.desired = UnitDesiredState::Running;
                    unit.state.status = UnitStatus::Pending;
                } else {
                    let mut unit = UnitRuntime::new(spec);
                    unit.state.desired = UnitDesiredState::Running;
                    unit.state.status = UnitStatus::Pending;
                    self.units.insert(unit.spec.id.clone(), unit);
                }
            }
            SupervisorCommand::StartUnit(id) => {
                if let Some(unit) = self.units.get_mut(&id) {
                    unit.state.desired = UnitDesiredState::Running;
                    unit.state.status = UnitStatus::Pending;
                }
            }
            SupervisorCommand::StopUnit(id) => {
                if let Some(unit) = self.units.get_mut(&id) {
                    unit.state.desired = UnitDesiredState::Stopped;
                    if let Some(pid) = unit.state.pid {
                        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                        unit.state.status = UnitStatus::Stopping;
                    }
                }
            }

            SupervisorCommand::Ctrl { unit_id, cmd } => {
                let _ = self.send_diag_cmd(&unit_id, cmd);
            }

            SupervisorCommand::ReloadHotconfig(profile) => {
                // Update daemon catalog from disk
                if let Ok(list) = load_hotconfig_daemons(profile.as_str()) {
                    self.daemon_catalog.insert(profile.clone(), list);
                }
                // Query current hotconfig via diag (snapshot will read disk if diag unavailable)
                let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
                let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryHotConfig);
            }

            SupervisorCommand::ReloadProfile(_profile) => {
                // Template is always read from disk in emit_snapshot
            }

            SupervisorCommand::StartHotconfigDaemons { profile } => {
                self.spawn_hotconfig_daemons(&profile);
            }
            SupervisorCommand::StartDaemon { profile, args } => {
                let spec = build_daemon_unit(&profile, args);
                self.ensure_unit_and_start(spec);
            }

            SupervisorCommand::Init => {
                // Discover all profiles from disk and load them
                if let Ok(profile_infos) = crate::profile_loader::list_profiles() {
                    for info in profile_infos {
                        let profile = ProfileName::new(info.name);
                        let ns_meta = state_paths::profile_ns_meta(profile.as_str());
                        if ns_meta.exists() {
                            if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                                self.init_units_from_ns_alive(&profile, &ns_alive);
                                
                                let child_alive = ns_alive.child_pid.is_some() && {
                                    let proc_path = format!("/proc/{}", ns_alive.child_pid.unwrap());
                                    Path::new(&proc_path).exists()
                                };
                                let serve_alive = ns_alive.serve_pid.is_some() && {
                                    let proc_path = format!("/proc/{}", ns_alive.serve_pid.unwrap());
                                    Path::new(&proc_path).exists()
                                };
                                let status = NsAliveStatus {
                                    profile: profile.clone(),
                                    child_alive,
                                    child_pid: ns_alive.child_pid.map(|p| p as i32),
                                    serve_alive,
                                    serve_pid: ns_alive.serve_pid.map(|p| p as i32),
                                };
                                self.ns_alive_status.insert(profile.clone(), status.clone());
                                let _ = self.event_tx.send(SupervisorEvent::NsAliveUpdated { status });
                            }
                        }
                    }
                }
            }
            SupervisorCommand::LoadProfile(profile) => {
                let ns_meta = state_paths::profile_ns_meta(profile.as_str());
                if ns_meta.exists() {
                    if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                        self.init_units_from_ns_alive(&profile, &ns_alive);
                        
                        // Inline check_ns_alive to avoid duplicate read
                        let child_alive = ns_alive.child_pid.is_some() && {
                            let proc_path = format!("/proc/{}", ns_alive.child_pid.unwrap());
                            Path::new(&proc_path).exists()
                        };
                        let serve_alive = ns_alive.serve_pid.is_some() && {
                            let proc_path = format!("/proc/{}", ns_alive.serve_pid.unwrap());
                            Path::new(&proc_path).exists()
                        };
                        let status = NsAliveStatus {
                            profile: profile.clone(),
                            child_alive,
                            child_pid: ns_alive.child_pid.map(|p| p as i32),
                            serve_alive,
                            serve_pid: ns_alive.serve_pid.map(|p| p as i32),
                        };
                        self.ns_alive_status.insert(profile.clone(), status.clone());
                        let _ = self.event_tx.send(SupervisorEvent::NsAliveUpdated { status });
                    }
                }
            }
            SupervisorCommand::LoadProfiles(profiles) => {
                // Batch process all profiles then emit single snapshot
                for profile in profiles {
                    let ns_meta = state_paths::profile_ns_meta(profile.as_str());
                    if ns_meta.exists() {
                        if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                            self.init_units_from_ns_alive(&profile, &ns_alive);
                            
                            let child_alive = ns_alive.child_pid.is_some() && {
                                let proc_path = format!("/proc/{}", ns_alive.child_pid.unwrap());
                                Path::new(&proc_path).exists()
                            };
                            let serve_alive = ns_alive.serve_pid.is_some() && {
                                let proc_path = format!("/proc/{}", ns_alive.serve_pid.unwrap());
                                Path::new(&proc_path).exists()
                            };
                            let status = NsAliveStatus {
                                profile: profile.clone(),
                                child_alive,
                                child_pid: ns_alive.child_pid.map(|p| p as i32),
                                serve_alive,
                                serve_pid: ns_alive.serve_pid.map(|p| p as i32),
                            };
                            self.ns_alive_status.insert(profile.clone(), status.clone());
                            let _ = self.event_tx.send(SupervisorEvent::NsAliveUpdated { status });
                        }
                    }
                }
            }

            SupervisorCommand::OnTabOpen { profile, tab } => {
                match tab {
                    TabKind::Hotconfig => {
                        // Query current hotconfig via diag
                        let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
                        let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryHotConfig);
                    }
                    TabKind::ProfileEditor => {
                        // Load hotconfig daemons catalog from disk
                        if let Ok(list) = load_hotconfig_daemons(profile.as_str()) {
                            self.daemon_catalog.insert(profile.clone(), list);
                        }
                    }
                    TabKind::Dns => {
                        let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
                        let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryDnsState);
                    }
                    TabKind::Diagnostics => {
                        let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
                        let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryRoutingState);
                    }
                    TabKind::Proxies => {
                        let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
                        let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryUplinkStats);
                        let _ = self.send_diag_cmd(&serve_id, ControlCommand::QueryRoutingState);
                    }
                    _ => {
                        // Other tabs don't need special handling
                    }
                }
            }
        }
    }

    fn ensure_unit_and_start(&mut self, spec: UnitSpec) {
        if let Some(unit) = self.units.get_mut(&spec.id) {
            unit.spec = spec;
            unit.state.id = unit.spec.id.clone();
            unit.state.kind = unit.spec.kind;
            unit.state.restart_policy = unit.spec.restart;
            unit.state.desired = UnitDesiredState::Running;
        } else {
            let mut unit = UnitRuntime::new(spec);
            unit.state.desired = UnitDesiredState::Running;
            self.units.insert(unit.spec.id.clone(), unit);
        }
    }

    fn init_units_from_ns_alive(&mut self, profile: &ProfileName, ns_alive: &NsAlive) {
        // Initialize Up unit if child_pid exists and is alive
        if let Some(child_pid) = ns_alive.child_pid {
            let proc_path = format!("/proc/{}", child_pid);
            if Path::new(&proc_path).exists() {
                let up_id = UnitId::new(format!("{}:up", profile.as_str()));
                let spec = UnitSpec {
                    id: up_id.clone(),
                    profile: profile.clone(),
                    kind: UnitKind::Up,
                    command: UnitCommand::None,
                    restart: RestartPolicy::Never,
                };

                if !self.units.contains_key(&up_id) {
                    let mut unit = UnitRuntime::new(spec);
                    unit.state.status = UnitStatus::Running;
                    unit.state.desired = UnitDesiredState::Running;
                    unit.state.pid = Some(child_pid as i32);
                    let id_for_map = up_id.clone();
                    self.pid_to_unit
                        .insert(child_pid as i32, id_for_map.clone());
                    self.units.insert(id_for_map, unit);
                } else if let Some(unit) = self.units.get_mut(&up_id) {
                    if let Some(prev) = unit.state.pid {
                        self.pid_to_unit.remove(&prev);
                    }
                    unit.state.status = UnitStatus::Running;
                    unit.state.pid = Some(child_pid as i32);
                    self.pid_to_unit.insert(child_pid as i32, up_id.clone());
                }
            } else if let Some(unit_id) = self.pid_to_unit.remove(&(child_pid as i32)) {
                if let Some(unit) = self.units.get_mut(&unit_id) {
                    unit.state.pid = None;
                    unit.state.status = UnitStatus::Stopped;
                }
            }
        }

        // Initialize Serve unit if serve_pid exists and connect diag
        if let Some(serve_pid) = ns_alive.serve_pid {
            let proc_path = format!("/proc/{}", serve_pid);
            if !Path::new(&proc_path).exists() {
                if let Some(unit_id) = self.pid_to_unit.remove(&(serve_pid as i32)) {
                    if let Some(unit) = self.units.get_mut(&unit_id) {
                        unit.state.pid = None;
                        unit.state.status = UnitStatus::Stopped;
                    }
                }
                return;
            }
            let serve_id = UnitId::new(format!("{}:serve", profile.as_str()));
            let spec = UnitSpec {
                id: serve_id.clone(),
                profile: profile.clone(),
                kind: UnitKind::Serve,
                command: UnitCommand::None,
                restart: RestartPolicy::Never,
            };

            if !self.units.contains_key(&serve_id) {
                let mut unit = UnitRuntime::new(spec);
                unit.state.status = UnitStatus::Running;
                unit.state.desired = UnitDesiredState::Running;
                unit.state.pid = Some(serve_pid as i32);
                let id_for_map = serve_id.clone();
                self.pid_to_unit
                    .insert(serve_pid as i32, id_for_map.clone());
                self.units.insert(id_for_map, unit);
            } else {
                // Update existing unit
                if let Some(unit) = self.units.get_mut(&serve_id) {
                    // remove previous mapping if present
                    if let Some(prev) = unit.state.pid {
                        self.pid_to_unit.remove(&prev);
                    }
                    unit.state.status = UnitStatus::Running;
                    unit.state.pid = Some(serve_pid as i32);
                    self.pid_to_unit.insert(serve_pid as i32, serve_id.clone());
                }
            }

            // Connect diag to the serve unit
            if let Some(unit) = self.units.get_mut(&serve_id) {
                if unit.diag_cmd_tx.is_none() {
                    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
                    unit.diag_cmd_tx = Some(cmd_tx);
                    let unit_id = unit.spec.id.clone();
                    let profile_name = profile.clone();
                    let diag_tx = self.event_tx.clone();
                    tokio::spawn(async move {
                        diag_client_loop(unit_id, profile_name, cmd_rx, diag_tx).await;
                    });
                }
            }
        }
    }

    fn check_ns_alive(&mut self, profile: &ProfileName) {
        let ns_meta = state_paths::profile_ns_meta(profile.as_str());
        let (child_alive, child_pid, serve_alive, serve_pid) = if ns_meta.exists() {
            match read_ns_alive(&ns_meta) {
                Ok(ns_alive) => {
                    let child_alive = ns_alive.child_pid.is_some() && {
                        let proc_path = format!("/proc/{}", ns_alive.child_pid.unwrap());
                        Path::new(&proc_path).exists()
                    };
                    let serve_alive = ns_alive.serve_pid.is_some() && {
                        let proc_path = format!("/proc/{}", ns_alive.serve_pid.unwrap());
                        Path::new(&proc_path).exists()
                    };
                    (
                        child_alive,
                        ns_alive.child_pid.map(|p| p as i32),
                        serve_alive,
                        ns_alive.serve_pid.map(|p| p as i32),
                    )
                }
                Err(_) => (false, None, false, None),
            }
        } else {
            (false, None, false, None)
        };

        let status = NsAliveStatus {
            profile: profile.clone(),
            child_alive,
            child_pid,
            serve_alive,
            serve_pid,
        };

        self.ns_alive_status.insert(profile.clone(), status.clone());
        let _ = self
            .event_tx
            .send(SupervisorEvent::NsAliveUpdated { status });
    }

    fn handle_event(&mut self, ev: SupervisorEvent) {
        match ev {
            SupervisorEvent::NsAliveUpdated { status: _ } => {
                self.ectx.request_repaint();
            }
            SupervisorEvent::ChildExit { unit_id, exit } => {
                if let Some(unit) = self.units.get_mut(&unit_id) {
                    if let Some(prev) = unit.state.pid {
                        self.pid_to_unit.remove(&prev);
                    }
                    unit.state.pid = None;
                    unit.state.last_exit = Some(exit.clone());
                    unit.state.status = UnitStatus::Failed;
                    if unit.state.desired == UnitDesiredState::Running {
                        // No automatic retry; mark failed per restart policy
                        match unit.spec.restart {
                            RestartPolicy::Never => {
                                unit.state.status = UnitStatus::Failed;
                            }
                            RestartPolicy::OnFailure | RestartPolicy::Always => {
                                // previously auto-restarted; now we simply mark failed
                                unit.state.status = UnitStatus::Failed;
                            }
                        }
                    }
                }
            }
            SupervisorEvent::DiagEvent { unit_id, event } => {
                if let Some(unit) = self.units.get_mut(&unit_id) {
                    unit.diag_state.accumulator.ingest(&event);
                    match &event {
                        DiagEvent::DnsState { state, .. } => {
                            unit.diag_state.dns_state = Some(state.clone());
                        }
                        DiagEvent::RoutingState { state, .. } => {
                            unit.diag_state.routing_state = Some(state.clone());
                        }
                        DiagEvent::HotConfigSnapshot { ok, content, .. } => {
                            if *ok {
                                if let Some(content) = content.as_ref() {
                                    // Hotconfig snapshot received from diag
                                }
                            }
                        }
                        DiagEvent::UplinkStatsSnapshot { stats, .. } => {
                            unit.diag_state.proxy_stats = stats.clone();
                        }
                        _ => {}
                    }
                    self.persist_dirty = true;
                }
            }
            SupervisorEvent::DiagDisconnected { unit_id } => {
                if let Some(_unit) = self.units.get_mut(&unit_id) {
                    // diag disconnected - connection status tracked in emit_snapshot
                }
            }
        }
    }

    async fn reconcile(&mut self) {
        let mut to_spawn = Vec::new();
        for (id, unit) in self.units.iter_mut() {
            if unit.state.desired == UnitDesiredState::Running {
                if unit.state.pid.is_none() {
                    if unit.state.status == UnitStatus::Pending {
                        to_spawn.push(id.clone());
                    }
                }
            } else if unit.state.desired == UnitDesiredState::Stopped {
                if let Some(pid) = unit.state.pid {
                    let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                    unit.state.status = UnitStatus::Stopping;
                }
            }
        }

        for id in to_spawn {
            if let Some(unit) = self.units.get_mut(&id) {
                if let Err(err) = spawn_unit(unit, &self.nsproxy_path, self.event_tx.clone()).await
                {
                    warn!("spawn failed for {}: {err:?}", unit.spec.id.as_str());
                    unit.state.status = UnitStatus::Failed;
                } else if let Some(pid) = unit.state.pid {
                    self.pid_to_unit.insert(pid, id.clone());
                }
            }
        }
    }

    fn send_diag_cmd(&mut self, unit_id: &UnitId, cmd: ControlCommand) -> bool {
        let Some(unit) = self.units.get_mut(unit_id) else {
            return false;
        };
        let Some(tx) = unit.diag_cmd_tx.as_ref() else {
            return false;
        };
        tx.send(cmd).is_ok()
    }

    fn emit_snapshot(&mut self) {
        let mut profiles: BTreeMap<ProfileName, ProfileSnapshot> = BTreeMap::new();
        for unit in self.units.values_mut() {
            let profile_snapshot = profiles
                .entry(unit.spec.profile.clone())
                .or_insert_with(|| {
                    let hotconfig = HotConfig::default();
                    let template = TemplateConfig::default();
                    let hotconfig_value =
                        serde_json::to_value(&hotconfig).unwrap_or(serde_json::json!({}));
                    let template_value =
                        serde_json::to_value(&template).unwrap_or(serde_json::json!({}));
                    ProfileSnapshot {
                        units: Vec::new(),
                        hotconfig,
                        template,
                        routing_state: None,
                        dns_state: None,
                        diag_connected: false,
                        diag_summary: None,
                        proxy_stats: HashMap::new(),
                        hotconfig_value,
                        template_value,
                        ns_alive: None,
                    }
                });
            profile_snapshot.units.push(unit.state.clone());
        }

        // Aggregate serve unit diag data to profile level
        for (profile_name, snapshot) in profiles.iter_mut() {
            let serve_id = UnitId::new(format!("{}:serve", profile_name.as_str()));
            if let Some(serve_unit) = self.units.get(&serve_id) {
                snapshot.diag_connected = serve_unit.diag_cmd_tx.is_some();
                snapshot.diag_summary = build_diag_summary(&serve_unit.diag_state);
                snapshot.proxy_stats = serve_unit.diag_state.proxy_stats.clone();
                // Aggregate diag events from serve unit
                let dns_state = serve_unit.diag_state.dns_state.clone();
                let routing_state = serve_unit.diag_state.routing_state.clone();
                snapshot.dns_state = dns_state;
                snapshot.routing_state = routing_state;
            }

            // Load hotconfig and template from disk for each profile
            if let Some(hot) = load_hotconfig_from_disk(profile_name) {
                snapshot.hotconfig = hot;
            }
            if let Some(template) = load_template_from_disk(profile_name) {
                snapshot.template = template;
            }

            // Load ns_alive from supervisor's cached status
            if let Some(ns_status) = self.ns_alive_status.get(profile_name) {
                if ns_status.child_alive || ns_status.serve_alive {
                    let ns_meta = state_paths::profile_ns_meta(profile_name.as_str());
                    if let Ok(ns) = read_ns_alive(&ns_meta) {
                        snapshot.ns_alive = Some(ns);
                    }
                }
            }
        }

        // Recompute Value fields for all profiles
        for snapshot in profiles.values_mut() {
            snapshot.hotconfig_value =
                serde_json::to_value(&snapshot.hotconfig).unwrap_or(serde_json::json!({}));
            snapshot.template_value =
                serde_json::to_value(&snapshot.template).unwrap_or(serde_json::json!({}));
        }

        let snapshot = SupervisorSnapshot {
            profiles,
            generated_at: SystemTime::now(),
        };
        // watch::send always succeeds and replaces the previous value
        let _ = self.snapshot_tx.send(snapshot);
        self.ectx.request_repaint();
    }

    fn persist_stats(&mut self) {
        if !self.persist_dirty {
            return;
        }
        self.persist_state.units.clear();
        for unit in self.units.values() {
            if let Some(summary) = build_diag_summary(&unit.diag_state) {
                self.persist_state
                    .units
                    .insert(unit.spec.id.as_str().to_string(), summary);
            }
        }
        if let Err(err) = self.persist_state.save_atomic() {
            warn!("failed to persist ui stats: {err:?}");
        } else {
            self.persist_dirty = false;
        }
    }

    fn spawn_hotconfig_daemons(&mut self, profile: &ProfileName) {
        let list = self
            .daemon_catalog
            .get(profile)
            .cloned()
            .unwrap_or_default();
        if list.is_empty() {
            return;
        }
        let mut pending = Vec::new();
        for args in list.into_iter() {
            let spec = build_daemon_unit(profile, args);
            let key = daemon_key(profile, &spec);
            if self.spawned_daemons.insert(key) {
                pending.push(spec);
            }
        }
        for spec in pending {
            self.ensure_unit_and_start(spec);
        }
    }
}

#[derive(Clone, Debug)]
pub struct NsAliveStatus {
    pub profile: ProfileName,
    pub child_alive: bool,
    pub child_pid: Option<i32>,
    pub serve_alive: bool,
    pub serve_pid: Option<i32>,
}

#[derive(Debug)]
enum SupervisorEvent {
    ChildExit { unit_id: UnitId, exit: ExitInfo },
    DiagEvent { unit_id: UnitId, event: DiagEvent },
    DiagDisconnected { unit_id: UnitId },
    NsAliveUpdated { status: NsAliveStatus },
}

async fn diag_client_loop(
    unit_id: UnitId,
    profile: ProfileName,
    mut cmd_rx: mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    let mut pending: VecDeque<ControlCommand> = VecDeque::new();
    let mut backoff = Duration::from_millis(500);
    loop {
        let sock = diag::diag_sock_path(profile.as_str());
        match diag::connect(&sock).await {
            Ok(mut stream) => {
                info!("diag connected for {}", unit_id.as_str());
                backoff = Duration::from_millis(500);

                // Send initial state queries automatically on connection
                let initial_queries = vec![
                    ControlCommand::QueryDnsState,
                    ControlCommand::QueryRoutingState,
                    ControlCommand::QueryHotConfig,
                    ControlCommand::QueryUplinkStats,
                ];
                let mut query_failed = false;
                for cmd in initial_queries {
                    if stream.send_cmd(&cmd).await.is_err() {
                        query_failed = true;
                        break;
                    }
                }

                if query_failed {
                    let _ = event_tx.send(SupervisorEvent::DiagDisconnected {
                        unit_id: unit_id.clone(),
                    });
                    continue;
                }

                if flush_pending(&mut stream, &mut pending).await.is_err() {
                    let _ = event_tx.send(SupervisorEvent::DiagDisconnected {
                        unit_id: unit_id.clone(),
                    });
                    continue;
                }
                if diag_stream_loop(&unit_id, stream, &mut cmd_rx, &event_tx)
                    .await
                    .is_err()
                {
                    let _ = event_tx.send(SupervisorEvent::DiagDisconnected {
                        unit_id: unit_id.clone(),
                    });
                }
            }
            Err(err) => {
                debug!("diag connect failed for {}: {err:?}", unit_id.as_str());
            }
        }

        while let Ok(cmd) = cmd_rx.try_recv() {
            pending.push_back(cmd);
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

async fn diag_stream_loop(
    unit_id: &UnitId,
    mut stream: DiagEventStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.split();
    // Periodically poll the serve unit for fresh stats every 5 seconds.
    let mut stats_tick = tokio::time::interval(Duration::from_secs(5));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so we don't double-query on connect.
    stats_tick.tick().await;
    loop {
        tokio::select! {
            res = reader.next() => {
                match res? {
                    Some(event) => {
                        let _ = event_tx.send(SupervisorEvent::DiagEvent { unit_id: unit_id.clone(), event });
                    }
                    None => {
                        return Ok(());
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        writer.send_cmd(&cmd).await?;
                    }
                    None => return Ok(()),
                }
            }
            _ = stats_tick.tick() => {
                writer.send_cmd(&ControlCommand::QueryUplinkStats).await?;
            }
        }
    }
}

async fn flush_pending(
    stream: &mut DiagEventStream,
    pending: &mut VecDeque<ControlCommand>,
) -> Result<()> {
    while let Some(cmd) = pending.pop_front() {
        stream.send_cmd(&cmd).await?;
    }
    Ok(())
}

async fn spawn_unit(
    unit: &mut UnitRuntime,
    nsproxy_path: &Path,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) -> Result<()> {
    unit.state.status = UnitStatus::Starting;
    let pid = match &unit.spec.command {
        UnitCommand::NsproxyCli { cli } => spawn_nsproxy(nsproxy_path, cli)?,
        UnitCommand::Daemon { args } => spawn_daemon(unit.spec.profile.as_str(), args)?,
        UnitCommand::None => {
            return Err(anyhow::anyhow!("cannot spawn unit with no command"));
        }
    };

    unit.state.pid = Some(pid.as_raw());
    unit.state.status = UnitStatus::Running;
    // no retry/backoff state — spawn success means running

    let unit_id = unit.spec.id.clone();
    let wait_tx = event_tx.clone();
    tokio::task::spawn_blocking(move || {
        let status = waitpid(pid, None);
        let exit = status_to_exit_info(status);
        let _ = wait_tx.send(SupervisorEvent::ChildExit { unit_id, exit });
    });

    // Start diag client for Serve units
    if unit.spec.kind == UnitKind::Serve {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        unit.diag_cmd_tx = Some(cmd_tx);
        let unit_id = unit.spec.id.clone();
        let profile = unit.spec.profile.clone();
        let diag_tx = event_tx.clone();
        tokio::spawn(async move {
            diag_client_loop(unit_id, profile, cmd_rx, diag_tx).await;
        });
    }

    Ok(())
}

fn build_diag_summary(state: &DiagState) -> Option<DiagSummary> {
    if state.accumulator.conns.is_empty() {
        return None;
    }
    let mut active = 0usize;
    for conn in state.accumulator.conns.values() {
        if conn.finished_ts.is_none() {
            active += 1;
        }
    }
    Some(DiagSummary {
        total_conns: state.accumulator.conns.len(),
        active_conns: active,
    })
}

fn default_nsproxy_path() -> PathBuf {
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            let candidate = parent.join("nsproxy");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("nsproxy")
}

fn spawn_nsproxy(path: &Path, cli: &Cli) -> Result<Pid> {
    let fd = cli_to_inheritable_fd(cli).context("failed to create cli memfd")?;
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            let _ = unsafe { libc::close(fd) };
            Ok(child)
        }
        ForkResult::Child => {
            let fd_str = fd.to_string();
            let argv = [to_cstr(path.to_string_lossy().as_ref()), to_cstr(&fd_str)];
            let envs: Vec<_> = std::env::vars()
                .map(|(k, v)| {
                    let mut s = k;
                    s.push('=');
                    s.push_str(&v);
                    to_cstr(&s)
                })
                .collect();
            let _ = execve(&to_cstr(path.to_string_lossy().as_ref()), &argv, &envs);
            std::process::exit(127);
        }
    }
}

fn spawn_daemon(profile: &str, args: &ShellArgs) -> Result<Pid> {
    let ns_meta = state_paths::profile_ns_meta(profile);
    let bind_mount = state_paths::profile_netns_bind(profile);
    let ns_alive = read_ns_alive(&ns_meta)?;
    let mut prefs = ShellPrefs::default();
    prefs.take_args(args.clone());
    apply_ns_env(&mut prefs, &ns_alive);
    prefs.adjust()?;
    let child = prefs.spawn_in_ns(&ns_alive, &bind_mount)?;
    match child {
        nsproxy_core::sys::Clone3Result::Parent { child_pid, .. } => Ok(Pid::from_raw(child_pid)),
        _ => Err(anyhow::anyhow!("spawn daemon in child context")),
    }
}

fn status_to_exit_info(status: nix::Result<nix::sys::wait::WaitStatus>) -> ExitInfo {
    match status {
        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => ExitInfo {
            when: SystemTime::now(),
            code: Some(code),
            signal: None,
        },
        Ok(nix::sys::wait::WaitStatus::Signaled(_, signal, _)) => ExitInfo {
            when: SystemTime::now(),
            code: None,
            signal: Some(signal as i32),
        },
        _ => ExitInfo {
            when: SystemTime::now(),
            code: None,
            signal: None,
        },
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UiStatsState {
    units: HashMap<String, DiagSummary>,
}

impl PersistentState for UiStatsState {
    const STATE_NAME: &'static str = "ui_stats";

    fn path() -> PathBuf {
        state_paths::persist_root().join("ui").join("stats.json")
    }
}

pub fn build_up_unit(profile: &ProfileName) -> UnitSpec {
    let cli = Cli {
        conf: None,
        root: None,
        no_wrap_check: false,
        cmd: MainCommand::Up {
            profile: profile.to_string(),
        },
    };
    UnitSpec {
        id: UnitId::new(format!("{}:up", profile.as_str())),
        profile: profile.clone(),
        kind: UnitKind::Up,
        command: UnitCommand::NsproxyCli { cli },
        restart: RestartPolicy::OnFailure,
    }
}

pub fn build_serve_unit(profile: &ProfileName) -> UnitSpec {
    let cli = Cli {
        conf: None,
        root: None,
        no_wrap_check: false,
        cmd: MainCommand::Serve {
            profile: profile.to_string(),
            tun_name: None,
            simple: None,
            no_default: false,
            log: None,
            clash: None,
            no_dns_capture: false,
        },
    };
    UnitSpec {
        id: UnitId::new(format!("{}:serve", profile.as_str())),
        profile: profile.clone(),
        kind: UnitKind::Serve,
        command: UnitCommand::NsproxyCli { cli },
        restart: RestartPolicy::OnFailure,
    }
}

pub fn build_daemon_unit(profile: &ProfileName, args: ShellArgs) -> UnitSpec {
    UnitSpec {
        id: daemon_unit_id(profile, &args),
        profile: profile.clone(),
        kind: UnitKind::Daemon,
        command: UnitCommand::Daemon { args },
        restart: RestartPolicy::Never,
    }
}

pub fn daemon_unit_id(profile: &ProfileName, args: &ShellArgs) -> UnitId {
    let payload = serde_json::to_string(args).unwrap_or_default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut hasher);
    let hash = hasher.finish();
    UnitId::new(format!("{}:daemon:{:x}", profile.as_str(), hash))
}

fn daemon_key(profile: &ProfileName, spec: &UnitSpec) -> String {
    format!("{}:{}", profile.as_str(), spec.id.as_str())
}

fn load_hotconfig_daemons(profile: &str) -> Result<Vec<ShellArgs>> {
    let path = state_paths::hot_config(profile);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    let hot: HotConfig = serde_json::from_str(&content)?;
    Ok(hot.daemons)
}

fn load_hotconfig_from_disk(profile: &ProfileName) -> Option<HotConfig> {
    let path = state_paths::hot_config(profile.as_str());
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Some(HotConfig::default()),
    };
    match serde_json::from_str::<HotConfig>(&content) {
        Ok(hot) => Some(hot),
        Err(err) => {
            warn!(
                "invalid hotconfig JSON on disk for {}: {err}",
                profile.as_str()
            );
            Some(HotConfig::default())
        }
    }
}

fn load_template_from_disk(profile: &ProfileName) -> Option<TemplateConfig> {
    let path = state_paths::profile_config(profile.as_str());
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Some(TemplateConfig::default()),
    };
    match serde_json::from_str::<TemplateConfig>(&content) {
        Ok(template) => Some(template),
        Err(err) => {
            warn!(
                "invalid profile JSON on disk for {}: {err}",
                profile.as_str()
            );
            Some(TemplateConfig::default())
        }
    }
}
