use clap::Parser;
use diag::{LogEntry, Timestamp};
use eframe::egui;
use eframe::egui::Color32;
use egui::{Margin, RichText, Vec2};
use egui_code_editor::{CodeEditor, ColorTheme, Syntax};
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular;
use egui_plot::{GridInput, GridMark, Line, LineStyle, PlotPoints};
use nsproxy_common::crdt::CRDT;
use nsproxy_common::normalize_domain;
use nsproxy_common::routing::ProxyID;
use nsproxy_common::stats::{ProxyStats, TransferRateSample};
use nsproxy_core::personal::PersonalConstants;
use nsproxy_core::sandbox::{SandboxState, SandboxStatus};
use nsproxy_core::shell::ShellArgs;
use nsproxy_core::state_blueprint::PersistentState as _;
use nsproxy_core::uplink::clash::{ClashState, GroupId};
use nsproxy_core::uplink::{
    uplink_proxy_default_udp_expected, UplinkHub, UplinkProxy, UplinkStatsState,
};
use nsproxy_core::{
    default_hotconfig, state_paths, DbusMode, HotConfig, HotVeth, LaunchableApp, NsAlive,
    ProfileChmod, ProfileMount, Rootfs, SandboxMode, TemplateConfig, INTERNAL_RESOLV_CONF_DNS,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROCESS_LOG_VIEWER_MAX_BYTES: usize = 64 * 1024;

const LOG_EDITOR_BACKGROUND: Color32 = Color32::from_rgb(12, 13, 16);
const LOG_SYNTAX_RED: Color32 = Color32::from_rgb(224, 108, 117);
const LOG_SYNTAX_GREEN: Color32 = Color32::from_rgb(152, 195, 121);
const LOG_SYNTAX_YELLOW: Color32 = Color32::from_rgb(229, 192, 123);
const LOG_SYNTAX_BLUE: Color32 = Color32::from_rgb(97, 175, 239);
const LOG_SYNTAX_PURPLE: Color32 = Color32::from_rgb(198, 120, 221);
const LOG_SYNTAX_CYAN: Color32 = Color32::from_rgb(86, 182, 194);
const LOG_SYNTAX_FOREGROUND: Color32 = Color32::from_rgb(171, 178, 191);
const LOG_SYNTAX_MUTED: Color32 = Color32::from_rgb(92, 99, 112);
const SPAWN_ARGS_NUMBER_WIDTH: f32 = 220.0;
const SPAWN_ARGS_TEXT_WIDTH: f32 = 480.0;

fn log_level_color(level: &str) -> Color32 {
    match level {
        "ERROR" => LOG_SYNTAX_RED,
        "WARN" => LOG_SYNTAX_YELLOW,
        "INFO" => LOG_SYNTAX_CYAN,
        "DEBUG" => LOG_SYNTAX_GREEN,
        "TRACE" => LOG_SYNTAX_MUTED,
        _ => LOG_SYNTAX_FOREGROUND,
    }
}

fn log_ansi_theme() -> &'static egui_sgr::EguiAnsiTheme {
    static THEME: std::sync::OnceLock<egui_sgr::EguiAnsiTheme> = std::sync::OnceLock::new();
    THEME.get_or_init(|| {
        let mut theme = egui_sgr::EguiAnsiTheme::default();
        theme.default_foreground = LOG_SYNTAX_FOREGROUND;
        theme.default_format.color = LOG_SYNTAX_FOREGROUND;
        theme.default_background = LOG_EDITOR_BACKGROUND;
        theme.palette[..16].copy_from_slice(&[
            LOG_EDITOR_BACKGROUND,
            LOG_SYNTAX_RED,
            LOG_SYNTAX_GREEN,
            LOG_SYNTAX_YELLOW,
            LOG_SYNTAX_BLUE,
            LOG_SYNTAX_PURPLE,
            LOG_SYNTAX_CYAN,
            LOG_SYNTAX_FOREGROUND,
            LOG_SYNTAX_MUTED,
            LOG_SYNTAX_RED,
            LOG_SYNTAX_GREEN,
            LOG_SYNTAX_YELLOW,
            LOG_SYNTAX_BLUE,
            LOG_SYNTAX_PURPLE,
            LOG_SYNTAX_CYAN,
            Color32::WHITE,
        ]);
        theme
    })
}

struct LogEditorPopup {
    title: String,
    text: String,
}

use tokio::runtime::Runtime;
use tracing::info;
use tracing_subscriber::EnvFilter;
use which;

mod alacritty_window;
mod fcitx;
mod personal;
mod profile_loader;
mod supervisor;

use alacritty_window::{run_term_window_process, ExternalTermWindowClient};
use profile_loader::ProfileInfo;
use supervisor::{
    ContainerName, EditorStatus, LogSource, RenderedLogEntry, SupervisorCommand, SupervisorHandle,
};
use term_view::{flush_term_outputs, pump_pty_io, PtyIpc, TermSession, TermView};

#[derive(Debug, Parser)]
#[command(author, version, about = "nsproxy UI dashboard", long_about = None)]
struct UiCli {
    /// Override the advertised build hash for protocol/version handshakes.
    #[arg(long)]
    build_hash: Option<String>,
    /// Allow UI clients to keep running when daemon build hashes differ.
    #[arg(long)]
    lenient: bool,
    #[arg(long, hide = true)]
    term_window_fd: Option<std::os::fd::RawFd>,
}

/// `PtyIpc` implementation that routes through the supervisor for a specific
/// (profile, pid) combination.  Lives in `nsproxy-ui` (debug build) but is
/// only the thin dispatch layer; all data processing is in `term-view`.
struct SupervisorPtyIpc {
    supervisor: SupervisorHandle,
    profile: ContainerName,
    pid: u32,
}

impl PtyIpc for SupervisorPtyIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        self.supervisor.drain_pty(&self.profile, self.pid)
    }
    fn wait_for_incoming(&self, observed_generation: u64) -> u64 {
        self.supervisor
            .wait_for_pty(&self.profile, self.pid, observed_generation)
    }
    fn wake_waiters(&self) {
        self.supervisor.wake_pty_waiters();
    }
    fn send_input(&self, data: Vec<u8>) {
        self.supervisor.send(SupervisorCommand::PtyInput {
            profile: self.profile.clone(),
            pid: self.pid,
            data,
        });
    }
    fn send_resize(&self, cols: u16, rows: u16) {
        self.supervisor.send(SupervisorCommand::PtyResize {
            profile: self.profile.clone(),
            pid: self.pid,
            cols,
            rows,
        });
    }
}

const HOTCONFIG_EXAMPLE: &str = r#"{}"#;

const PROFILE_JSON_EXAMPLE: &str = r#"{}"#;

#[derive(Clone)]
struct ProxyItem {
    id: ProxyID,
    base: UplinkProxy,
    nym: String,
    name: String,
    url: String,
    udp_expected: bool,
    udp_ability: Option<bool>,
    enabled_globally: bool,
    latency_ms: Option<u64>,
    conn_ok: Option<bool>,
    resolved_ips: Vec<IpAddr>,
    groups: HashSet<GroupId>,
}

#[derive(Clone)]
struct TrafficRouteTarget {
    route: nsproxy_common::stats::ObservedRoute,
    key: String,
    summary: String,
    filter_text: String,
}

fn build_traffic_route_targets(proxies: &BTreeMap<ProxyID, ProxyItem>) -> Vec<TrafficRouteTarget> {
    let mut targets = Vec::with_capacity(proxies.len() + 1);
    targets.push(TrafficRouteTarget {
        route: nsproxy_common::stats::ObservedRoute::NoProxy,
        key: "NoProxy".to_string(),
        summary: "Direct connection".to_string(),
        filter_text: "noproxy direct connection".to_string(),
    });
    for (proxy_id, proxy) in proxies {
        targets.push(TrafficRouteTarget {
            route: nsproxy_common::stats::ObservedRoute::Proxy(proxy_id.clone()),
            key: proxy.name.clone(),
            summary: proxy.url.clone(),
            filter_text: format!("{} {} {}", proxy.name, proxy.nym, proxy.url).to_lowercase(),
        });
    }
    targets
}

fn default_clash_group_name(path: &str) -> Option<String> {
    std::path::Path::new(path.trim())
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
}

struct ProxySnapshot {
    proxies: BTreeMap<ProxyID, ProxyItem>,
    nym_to_id: BTreeMap<String, ProxyID>,
    proxy_groups: BTreeMap<ProxyID, HashSet<GroupId>>,
    groups: Vec<GroupId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProxyTableEntry {
    NoProxy,
    Group { id: GroupId, proxy_count: usize },
    Proxy(ProxyID),
}

fn build_proxy_table_entries(
    filtered_proxy_ids: &[ProxyID],
    proxy_groups: &BTreeMap<ProxyID, HashSet<GroupId>>,
    expanded_groups: &[GroupId],
    all_groups: &[GroupId],
) -> Vec<ProxyTableEntry> {
    let mut grouped: BTreeMap<GroupId, Vec<ProxyID>> = BTreeMap::new();
    let mut ungrouped = Vec::new();
    for proxy_id in filtered_proxy_ids {
        let groups = proxy_groups.get(proxy_id);
        if let Some(groups) = groups.filter(|groups| !groups.is_empty()) {
            for group in groups {
                grouped
                    .entry(group.clone())
                    .or_default()
                    .push(proxy_id.clone());
            }
        } else {
            ungrouped.push(proxy_id.clone());
        }
    }
    for group_id in all_groups {
        grouped.entry(group_id.clone()).or_default();
    }

    let mut entries = Vec::with_capacity(filtered_proxy_ids.len() + grouped.len() + 1);
    entries.push(ProxyTableEntry::NoProxy);
    for (id, members) in grouped {
        let is_expanded = expanded_groups.contains(&id);
        entries.push(ProxyTableEntry::Group {
            id,
            proxy_count: members.len(),
        });
        if is_expanded {
            entries.extend(members.into_iter().map(ProxyTableEntry::Proxy));
        }
    }
    entries.extend(ungrouped.into_iter().map(ProxyTableEntry::Proxy));
    entries
}

fn build_proxy_group_controls(entries: &[ProxyTableEntry]) -> Vec<(GroupId, usize)> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            ProxyTableEntry::Group { id, proxy_count } => Some((id.clone(), *proxy_count)),
            ProxyTableEntry::NoProxy | ProxyTableEntry::Proxy(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod proxy_table_entry_tests {
    use super::*;

    #[test]
    fn groups_collapse_into_single_entries_until_expanded() {
        let first = ProxyID([1; 32]);
        let second = ProxyID([2; 32]);
        let ungrouped = ProxyID([3; 32]);
        let group = GroupId("group-a".to_string());
        let filtered = vec![first.clone(), second.clone(), ungrouped.clone()];
        let memberships = BTreeMap::from([
            (first.clone(), HashSet::from([group.clone()])),
            (second.clone(), HashSet::from([group.clone()])),
        ]);

        let collapsed_entries = build_proxy_table_entries(&filtered, &memberships, &[], &[]);
        assert_eq!(
            collapsed_entries,
            vec![
                ProxyTableEntry::NoProxy,
                ProxyTableEntry::Group {
                    id: group.clone(),
                    proxy_count: 2,
                },
                ProxyTableEntry::Proxy(ungrouped),
            ]
        );
        assert_eq!(
            build_proxy_group_controls(&collapsed_entries),
            vec![(group.clone(), 2)]
        );
        assert_eq!(
            build_proxy_table_entries(&filtered, &memberships, &[group.clone()], &[]),
            vec![
                ProxyTableEntry::NoProxy,
                ProxyTableEntry::Group {
                    id: group,
                    proxy_count: 2,
                },
                ProxyTableEntry::Proxy(first),
                ProxyTableEntry::Proxy(second),
                ProxyTableEntry::Proxy(ProxyID([3; 32])),
            ]
        );
    }

    #[test]
    fn empty_user_groups_remain_visible() {
        let group = GroupId("empty-group".to_string());
        assert_eq!(
            build_proxy_table_entries(&[], &BTreeMap::new(), &[], &[group.clone()]),
            vec![
                ProxyTableEntry::NoProxy,
                ProxyTableEntry::Group {
                    id: group,
                    proxy_count: 0,
                },
            ]
        );
    }

    #[test]
    fn clash_group_name_defaults_to_yaml_file_stem() {
        assert_eq!(
            default_clash_group_name("/tmp/fedora-proxies.yaml").as_deref(),
            Some("fedora-proxies")
        );
        assert_eq!(default_clash_group_name(""), None);
    }
}

#[derive(Clone, Debug)]
struct PersistedProcessLogEntry {
    source_label: String,
    log: LogEntry,
}

#[derive(Clone, Debug)]
struct PersistedLogFileInfo {
    path: PathBuf,
    file_name: String,
    process_label: String,
    pid: Option<u32>,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug, Default)]
struct PersistedLogsSnapshot {
    files: Vec<PersistedLogFileInfo>,
    entries_by_pid: HashMap<u32, Vec<PersistedProcessLogEntry>>,
    selected_file_path: Option<PathBuf>,
    selected_file_entries: Vec<PersistedProcessLogEntry>,
}

#[derive(Clone, Debug)]
enum PersistedLogsRequest {
    Refresh {
        selected_file: Option<PathBuf>,
        selected_pid: Option<u32>,
        logs_tab_visible: bool,
        process_logs_visible: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum ProxyType {
    Trojan,
    Remote,
    Geph,
    File,
}

impl ProxyType {
    fn from_uplink_proxy(proxy: &UplinkProxy) -> Self {
        match proxy {
            UplinkProxy::Trojan(_) => ProxyType::Trojan,
            UplinkProxy::Remote(_) => ProxyType::Remote,
            UplinkProxy::Geph => ProxyType::Geph,
            UplinkProxy::File(_) => ProxyType::File,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            ProxyType::Trojan => "Trojan",
            ProxyType::Remote => "Remote",
            ProxyType::Geph => "Geph",
            ProxyType::File => "File",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum RightTab {
    Proxies,
    Daemon,
    Dbus,
    Actions,
    Processes,
    Traffic,
    Hotconfig,
    ProfileEditor,
    State,
    Manage,
    Meta,
}

struct FcitxTabState {
    profile: Option<ContainerName>,
    state: Option<fcitx::FcitxState>,
    pending: bool,
    pending_action: Option<fcitx::FcitxAction>,
    input_method_search: String,
    logs: supervisor::SharedLevelLogRings,
    result_tx: flume::Sender<(ContainerName, Result<fcitx::FcitxState, String>)>,
    result_rx: flume::Receiver<(ContainerName, Result<fcitx::FcitxState, String>)>,
}

impl FcitxTabState {
    fn new() -> Self {
        let (result_tx, result_rx) = flume::unbounded();
        Self {
            profile: None,
            state: None,
            pending: false,
            pending_action: None,
            input_method_search: String::new(),
            logs: Arc::new(RwLock::new(supervisor::LevelLogView::default())),
            result_tx,
            result_rx,
        }
    }

    fn log(&mut self, message: impl Into<String>, is_error: bool) {
        let mut logs = self.logs.write().unwrap_or_else(|e| e.into_inner());
        logs.push_entry(
            LogSource::Fcitx,
            diag::LogEntry {
                ts: Timestamp::now(),
                level: if is_error { "ERROR" } else { "INFO" }.to_string(),
                target: "fcitx".to_string(),
                message: message.into(),
                fields: Vec::new(),
            },
        );
    }

    fn poll(&mut self) {
        while let Ok((profile, result)) = self.result_rx.try_recv() {
            if self.profile.as_ref() != Some(&profile) {
                continue;
            }
            self.pending = false;
            let action = self.pending_action.take();
            match result {
                Ok(state) => {
                    self.log(
                        format!(
                            "{}: {} / {} ({:?})",
                            action
                                .as_ref()
                                .map(fcitx_action_label)
                                .unwrap_or_else(|| "Refreshed".to_string()),
                            state.current_group,
                            state.current_input_method,
                            state.status
                        ),
                        false,
                    );
                    self.state = Some(state);
                }
                Err(error) => {
                    self.log(error.clone(), true);
                }
            }
        }
    }

    fn request(
        &mut self,
        runtime: &Runtime,
        profile: ContainerName,
        action: Option<fcitx::FcitxAction>,
    ) {
        if self.pending {
            return;
        }
        self.profile = Some(profile.clone());
        self.pending = true;
        self.pending_action = action.clone();
        self.log(
            action
                .as_ref()
                .map(fcitx_action_label)
                .unwrap_or_else(|| "Refresh requested".to_string()),
            false,
        );
        let result_tx = self.result_tx.clone();
        runtime.spawn(async move {
            let result = match action {
                Some(action) => fcitx::act(profile.as_str(), action).await,
                None => fcitx::query(profile.as_str()).await,
            }
            .map_err(|error| format!("{error:#}"));
            let _ = result_tx.send((profile, result));
        });
    }
}

fn fcitx_action_label(action: &fcitx::FcitxAction) -> String {
    match action {
        fcitx::FcitxAction::SetActive(true) => "Activate requested".to_string(),
        fcitx::FcitxAction::SetActive(false) => "Deactivate requested".to_string(),
        fcitx::FcitxAction::SetGroup(group) => format!("Group change requested: {group}"),
        fcitx::FcitxAction::SetInputMethod(input_method) => {
            format!("Input method change requested: {input_method}")
        }
        fcitx::FcitxAction::AddInputMethod(input_method) => {
            format!("Add and select input method requested: {input_method}")
        }
        fcitx::FcitxAction::ConfigureInputMethod(input_method) => {
            format!("Configuration window requested for {input_method}")
        }
    }
}

// ── Manage / creation wizard ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Debug, Default)]
enum WizardMode {
    #[default]
    Landing,
    CreateFromTemplate,
    CloneExisting,
}

/// Which top-level sandbox type the user selected.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
enum WizardTemplateKind {
    /// Overlay sandbox, maximum host-compatibility.
    #[default]
    OverlayBasic,
    /// Pivot sandbox; app modules chosen separately on the PivotApps step.
    Pivot,
}

/// App profile module selectable in the Pivot multi-selector.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum PivotAppKind {
    Firefox,
    SignalAppImage,
}

impl PivotAppKind {
    fn label(&self) -> &'static str {
        match self {
            PivotAppKind::Firefox => "Firefox",
            PivotAppKind::SignalAppImage => "Signal AppImage",
        }
    }
    fn description(&self) -> &'static str {
        match self {
            PivotAppKind::Firefox => {
                "Mounts Wayland, PipeWire, PulseAudio, dconf, gvfs and systemd. \
                Firefox profile stored in @/."
            }
            PivotAppKind::SignalAppImage => {
                "Mounts Wayland, PipeWire, PulseAudio, dconf and systemd. \
                Signal data stored in @/.config/Signal AppImage."
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
enum WizardDnsMode {
    /// nsproxy runs an internal DNS server at 127.0.0.1 inside the container;
    /// DNS requests are resolved as SOCKS5 domain queries (hostname passed to proxy).
    #[default]
    InternalServer,
    /// DNS goes through the TUN device and is proxied as regular UDP.
    TunUdp,
    /// No resolv.conf rewriting; inherit host DNS.
    PassThrough,
    /// User-supplied custom nameserver.
    Custom,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
enum WizardStep {
    #[default]
    Landing,
    /// Multi-select app modules for the Pivot sandbox.
    PivotApps,
    DbusMode,
    PortListeners,
    RouteTargets,
    DnsHandling,
    ReviewHotconfig,
    Name,
}

#[derive(Clone, Debug)]
struct ManageWizard {
    mode: WizardMode,
    step: WizardStep,
    /// Template preset chosen by the user.
    template_kind: WizardTemplateKind,
    /// App modules selected for the Pivot sandbox (additive).
    pivot_apps: std::collections::BTreeSet<PivotAppKind>,
    /// D-Bus mode chosen by the user.
    dbus_mode: DbusMode,
    /// The TemplateConfig being built.
    template: TemplateConfig,
    /// The HotConfig being built.
    hot: HotConfig,
    hot_json: String,
    hot_json_error: Option<String>,
    /// DNS strategy chosen.
    dns_mode: WizardDnsMode,
    /// Custom DNS text input.
    dns_custom_text: String,
    /// Port listener input (container_port text).
    local_port_input: String,
    /// Profile to clone from.
    clone_source: String,
    /// New profile name.
    new_name: String,
    /// Path to an existing hot.json to merge into the editor.
    merge_path: String,
    merge_error: Option<String>,
    /// Status message for the final create action.
    status: Option<String>,
}

impl Default for ManageWizard {
    fn default() -> Self {
        let hot = default_hotconfig();
        let hot_json = serde_json::to_string_pretty(&hot).unwrap_or_default();
        Self {
            mode: WizardMode::default(),
            step: WizardStep::default(),
            template_kind: WizardTemplateKind::default(),
            pivot_apps: std::collections::BTreeSet::new(),
            dbus_mode: DbusMode::Container,
            template: TemplateConfig::default(),
            hot,
            hot_json,
            hot_json_error: None,
            dns_mode: WizardDnsMode::default(),
            dns_custom_text: String::new(),
            local_port_input: String::new(),
            clone_source: String::new(),
            new_name: String::new(),
            merge_path: String::new(),
            merge_error: None,
            status: None,
        }
    }
}

/// Sub-view toggle inside the Traffic tab.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
enum TrafficSubview {
    #[default]
    Connections,
    Logs,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LogMinLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogMinLevel {
    fn default() -> Self {
        Self::Warn
    }
}

impl LogMinLevel {
    const ALL: [Self; 5] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Warn,
        Self::Error,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    fn matches(self, level: &str) -> bool {
        Self::rank(level) >= self.rank_value()
    }

    fn rank_value(self) -> u8 {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Warn => 3,
            Self::Error => 4,
        }
    }

    fn rank(level: &str) -> u8 {
        match level.trim().to_ascii_uppercase().as_str() {
            "TRACE" => Self::Trace.rank_value(),
            "DEBUG" => Self::Debug.rank_value(),
            "WARN" => Self::Warn.rank_value(),
            "ERROR" => Self::Error.rank_value(),
            _ => Self::Info.rank_value(),
        }
    }
}

// ── Viewer (ported from nsp-diag viewer.rs) ──────────────────────────────────

static VIEWER_QUERY_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
struct ViewerPingState {
    last_domain: Option<String>,
    last_sent_us: Option<u64>,
    last_accept_delta_us: Option<u64>,
    last_accept_ts: Option<u64>,
    last_conn_id: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Default)]
struct ViewerMassPingState {
    last_batch: Option<u64>,
    started_ts: Option<u64>,
    finished_ts: Option<u64>,
    duration_us: Option<u64>,
    rtt_avg_us: Option<u64>,
    rtt_min_us: Option<u64>,
    rtt_max_us: Option<u64>,
    rtt_samples: u64,
    requested: u64,
    in_flight: u64,
    completed: u64,
    errors: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct ViewerBurstTestResult {
    size: u64,
    requested: u64,
    completed: u64,
    errors: u64,
    failure_rate: f64,
    latency_us_min: u64,
    latency_us_max: u64,
    latency_us_avg: u64,
}

#[derive(Debug)]
struct ViewerBurstTestState {
    running: bool,
    started_ts: Option<u64>,
    finished_ts: Option<u64>,
    results: Vec<ViewerBurstTestResult>,
    threshold_size: Option<u64>,
    last_error: Option<String>,
    max_batch_size: u64,
}

impl Default for ViewerBurstTestState {
    fn default() -> Self {
        Self {
            running: false,
            started_ts: None,
            finished_ts: None,
            results: Vec::new(),
            threshold_size: None,
            last_error: None,
            max_batch_size: 65536,
        }
    }
}

#[derive(Debug)]
struct ViewerBurstTestStats {
    test_count: u64,
    failure_rates: std::collections::VecDeque<f64>,
    durations_ms: std::collections::VecDeque<f64>,
    max_failure_rate: f64,
    threshold_hits: u64,
    max_window: usize,
}

impl ViewerBurstTestStats {
    fn new(window: usize) -> Self {
        Self {
            test_count: 0,
            failure_rates: std::collections::VecDeque::with_capacity(window),
            durations_ms: std::collections::VecDeque::with_capacity(window),
            max_failure_rate: 0.0,
            threshold_hits: 0,
            max_window: window,
        }
    }

    fn add_test(&mut self, failure_rate: f64, duration_ms: f64, hit_threshold: bool) {
        self.test_count += 1;
        if self.failure_rates.len() >= self.max_window {
            self.failure_rates.pop_front();
        }
        if self.durations_ms.len() >= self.max_window {
            self.durations_ms.pop_front();
        }
        self.failure_rates.push_back(failure_rate);
        self.durations_ms.push_back(duration_ms);
        self.max_failure_rate = self.max_failure_rate.max(failure_rate);
        if hit_threshold {
            self.threshold_hits += 1;
        }
    }

    fn avg_failure_rate(&self) -> f64 {
        if self.failure_rates.is_empty() {
            0.0
        } else {
            self.failure_rates.iter().sum::<f64>() / self.failure_rates.len() as f64
        }
    }

    fn avg_duration_ms(&self) -> f64 {
        if self.durations_ms.is_empty() {
            0.0
        } else {
            self.durations_ms.iter().sum::<f64>() / self.durations_ms.len() as f64
        }
    }
}

enum ViewerPingRequest {
    Single(String, String),
    Batch(Vec<String>, String),
    BurstTest(String),
}

fn viewer_now_epoch_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn viewer_build_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    let name = domain.trim_end_matches('.');
    for label in name.split('.') {
        let len = label.len().min(63);
        buf.push(len as u8);
        buf.extend_from_slice(&label.as_bytes()[..len]);
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
}

async fn viewer_send_dns_ping_async(target: &str, domain: String) -> anyhow::Result<u64> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let id = (VIEWER_QUERY_ID_COUNTER.fetch_add(1, Ordering::SeqCst) & 0xFFFF) as u16;
    let query = viewer_build_dns_query(&domain, id);
    let start = tokio::time::Instant::now();
    let _ = sock.send_to(&query, target).await?;
    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(20_000), sock.recv_from(&mut buf)).await??;
    Ok(start.elapsed().as_micros() as u64)
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum SortColumn {
    None,
    Latency,
    FailRate,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum SortFrequency {
    Manual,
    Every1s,
    Every2s,
    Every5s,
}

impl SortFrequency {
    fn duration(&self) -> Option<Duration> {
        match self {
            SortFrequency::Manual => None,
            SortFrequency::Every1s => Some(Duration::from_secs(1)),
            SortFrequency::Every2s => Some(Duration::from_secs(2)),
            SortFrequency::Every5s => Some(Duration::from_secs(5)),
        }
    }
}

#[derive(Clone)]
struct ProxyFilters {
    selected_types: HashSet<ProxyType>,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    sort_frequency: SortFrequency,
}

impl Default for ProxyFilters {
    fn default() -> Self {
        ProxyFilters {
            selected_types: HashSet::new(),
            sort_column: SortColumn::FailRate,
            sort_direction: SortDirection::Ascending,
            sort_frequency: SortFrequency::Manual,
        }
    }
}

struct LoadResult {
    text: String,
    error: Option<String>,
}

#[derive(Clone)]
struct RunCommandDraft {
    command_line: String,
    pending_spawn_args: Option<diag::SpawnArgs>,
    parse_error: Option<String>,
    status: Option<String>,
    spawn_inside_container: bool,
    spawn_as_pty: bool,
}

impl Default for RunCommandDraft {
    fn default() -> Self {
        let mut draft = Self {
            command_line: default_spawn_shell_command_line(),
            pending_spawn_args: None,
            parse_error: None,
            status: None,
            spawn_inside_container: true,
            spawn_as_pty: true,
        };
        refresh_run_command_preview(&mut draft);
        draft
    }
}

#[derive(Clone)]
struct StringMapEditorState {
    pairs: Vec<(String, String)>,
    snapshot: Vec<(String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VirtualDnsTargetKind {
    DnsAnswer,
    TunForward,
    WarpFiles,
}

#[derive(Clone)]
struct VirtualDnsRow {
    domain: String,
    target_kind: VirtualDnsTargetKind,
    target: String,
}

#[derive(Clone)]
struct VirtualDnsEditorState {
    rows: Vec<VirtualDnsRow>,
    snapshot: Vec<(String, VirtualDnsTargetKind, String)>,
}

#[derive(Clone)]
struct U32MapEditorState {
    rows: Vec<(String, String)>,
    snapshot: Vec<(u32, u32)>,
}

struct IntInput {
    texts: HashMap<(egui::Id, usize), String>,
}

impl Default for IntInput {
    fn default() -> Self {
        Self {
            texts: HashMap::new(),
        }
    }
}

impl IntInput {
    fn show<F>(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        value: &mut Option<u32>,
        validate: F,
    ) -> bool
    where
        F: Fn(u32) -> bool,
    {
        let value_addr = value as *mut Option<u32> as usize;
        let text_edit_id = id.with(("text", value_addr));
        let cache_key = (id, value_addr);
        let mut changed = false;

        let input = self
            .texts
            .entry(cache_key)
            .or_insert_with(|| value.map(|parsed| parsed.to_string()).unwrap_or_default());

        let parsed = input.parse::<u32>().ok();
        let is_valid = parsed.is_some_and(&validate);
        let bg_color = if input.is_empty() && value.is_none() {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else if input.is_empty() {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        } else if is_valid {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        };

        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let resp = ui
            .horizontal(|ui| {
                let width = SPAWN_ARGS_NUMBER_WIDTH.min(ui.available_width().max(0.0));
                let resp = ui.add_sized(
                    egui::vec2(width, ui.spacing().interact_size.y),
                    egui::TextEdit::singleline(input).id_source(text_edit_id),
                );
                resp
            })
            .inner;
        ui.visuals_mut().extreme_bg_color = old_bg;

        let next_value = if input.is_empty() {
            None
        } else {
            parsed.filter(|parsed_value| validate(*parsed_value))
        };

        if *value != next_value {
            *value = next_value;
            changed = true;
        }

        changed
    }

    /// Update the internal text cache for an `Option<u32>` so the UI reflects
    /// an external programmatic change to the `value` (value -> UI sync).
    fn sync_from_value(&mut self, ui: &mut egui::Ui, label: &str, value: &Option<u32>) {
        let id = ui.make_persistent_id(("optional-u32", label));
        let value_addr = value as *const Option<u32> as usize;
        let cache_key = (id, value_addr);
        let text = value.map(|v| v.to_string()).unwrap_or_default();
        self.texts.insert(cache_key, text);
    }
}

struct App {
    selected_profile: Option<ContainerName>,
    remove_containers_armed: bool,
    right_tab: RightTab,
    /// UI-only presentation mode for screenshots and demonstrations.
    /// This never changes the profile names, paths, or data sent to the supervisor.
    demo_mode: bool,
    proxies: BTreeMap<ProxyID, ProxyItem>,
    nym_to_id: BTreeMap<String, ProxyID>,
    proxy_groups: BTreeMap<ProxyID, HashSet<GroupId>>,
    user_groups: Vec<GroupId>,
    clash_import_path: String,
    clash_import_group_name: String,
    clash_import_default_group_name: String,
    clash_replace_group: Option<GroupId>,
    clash_import_status: Option<String>,
    clash_import_pending: bool,
    clash_import_result_rx: Option<flume::Receiver<supervisor::ClashGroupImportCompletion>>,
    filtered_proxy_ids: Vec<ProxyID>,
    proxy_table_entries: Vec<ProxyTableEntry>,
    proxy_group_controls: Vec<(GroupId, usize)>,
    expanded_proxy_groups: Vec<GroupId>,
    proxy_table_entries_dirty: bool,
    filters_dirty: bool,
    hovered_proxy: Option<usize>,
    reload_tx: flume::Sender<()>,
    proxy_rx: flume::Receiver<ProxySnapshot>,
    persisted_logs_tx: flume::Sender<PersistedLogsRequest>,
    persisted_logs_rx: flume::Receiver<PersistedLogsSnapshot>,
    proxy_filters: ProxyFilters,
    supervisor: SupervisorHandle,
    personal_state: personal::PersonalUiState,
    snapshot: supervisor::SupervisorSnapshot,
    run_command: RunCommandDraft,
    int_input: IntInput,
    hide_secret: bool,
    cover_text: String,
    tokio_rt: Option<Runtime>,
    fcitx_tab: FcitxTabState,
    detail_proxy_id: Option<ProxyID>,
    expanded_ip_rows: HashSet<ProxyID>,
    last_sort_time: Instant,
    /// Number of upcoming frames that should force-fit/reset detail plots.
    detail_fit_frames_left: u8,
    profile_editor_target: Option<ContainerName>,
    profile_editor_template: TemplateConfig,
    profile_editor_json: String,
    profile_editor_json_error: Option<String>,
    profile_editor_hot_init_json: String,
    profile_editor_hot_init_error: Option<String>,
    profile_editor_create_name: String,
    profile_editor_status: Option<String>,
    hotconfig_editor_target: Option<ContainerName>,
    hotconfig_editor_value: HotConfig,
    hotconfig_editor_json: String,
    hotconfig_editor_error: Option<String>,
    hotconfig_editor_status: Option<String>,
    hotconfig_veth_drafts: HashMap<ContainerName, Vec<VethDraft>>,
    selected_traffic_conn: Option<diag::ConnId>,
    traffic_subview: TrafficSubview,
    traffic_route_target: nsproxy_common::stats::ObservedRoute,
    traffic_route_target_index: usize,
    traffic_route_targets: Vec<TrafficRouteTarget>,
    traffic_route_filter: String,
    traffic_route_filter_applied: String,
    filtered_traffic_route_target_indices: Vec<usize>,
    traffic_subscription_profile: Option<ContainerName>,
    /// Whether newly started `sp up` and `sp serve` processes should capture backtraces.
    rust_backtrace: bool,
    /// Which process's raw logs are currently being inspected (profile, slot-pid).
    selected_process_logs: Option<(ContainerName, u32)>,
    process_log_editor_target: Option<(ContainerName, u32)>,
    process_log_editor_next_seq: Option<u64>,
    process_log_rows: VecDeque<String>,
    process_log_rows_bytes: usize,
    selected_persisted_log_file: Option<PathBuf>,
    persisted_logs_snapshot: PersistedLogsSnapshot,
    last_persisted_logs_refresh: Instant,
    /// State for the special swap terminal child process, if any.
    swap_term_window: ExternalTermWindowClient,
    /// Dedicated PTY windows keyed by their owning (profile, slot-pid).
    dedicated_term_windows: HashMap<(ContainerName, u32), ExternalTermWindowClient>,
    /// Last consumed auto-open token from supervisor snapshots.
    last_auto_open_logs_token: u64,
    /// Which process's SpawnArgs are currently being inspected (profile, slot-pid).
    selected_process_spawn_args: Option<(ContainerName, u32)>,
    pty_sessions: HashMap<(ContainerName, u32), TermSession>,
    // Viewer sub-view state (ported from nsp-diag viewer.rs)
    viewer_ping_tx: flume::Sender<ViewerPingRequest>,
    viewer_dns_config: Arc<Mutex<String>>,
    viewer_ping_state: Arc<Mutex<ViewerPingState>>,
    viewer_mass_ping_state: Arc<Mutex<ViewerMassPingState>>,
    viewer_burst_test_state: Arc<Mutex<ViewerBurstTestState>>,
    viewer_burst_test_stats: Arc<Mutex<ViewerBurstTestStats>>,
    viewer_selected_conn: Option<diag::ConnId>,
    ui_frame_seq: u64,
    last_frame_progress_log: Instant,
    last_frame_elapsed_ms: u128,
    fps_window_start: Instant,
    fps_window_count: u32,
    last_fps: f32,
    log_panel_min_level: LogMinLevel,
    log_editor_popup: Option<LogEditorPopup>,
    /// State for the Manage (creation wizard) tab.
    manage_wizard: ManageWizard,
    /// Applications with an in-flight lifecycle launch request, keyed by profile and app name.
    action_launching: Arc<Mutex<HashSet<(ContainerName, String)>>>,
    action_status: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Debug)]
struct VethDraft {
    peer: String,
    basis_namespace: bool,
    name: String,
    src_ip4: String,
    dst_ip4: String,
    prefix_len: String,
    add_on_start: bool,
    submitted: bool,
}

impl Default for VethDraft {
    fn default() -> Self {
        Self {
            peer: String::new(),
            basis_namespace: false,
            name: String::new(),
            src_ip4: String::new(),
            dst_ip4: String::new(),
            prefix_len: "30".to_owned(),
            add_on_start: false,
            submitted: false,
        }
    }
}

fn load_proxies_from_persisted() -> ProxySnapshot {
    use nsproxy_core::uplink::UplinkProxy;

    let stats_state = UplinkStatsState::load_or_default().unwrap_or_default();
    let clash_state = ClashState::load_or_default().unwrap_or_default();
    let mut hub = UplinkHub::new();
    if hub.hydrate_from_persisted().is_err() {
        return ProxySnapshot {
            proxies: BTreeMap::new(),
            nym_to_id: BTreeMap::new(),
            proxy_groups: BTreeMap::new(),
            groups: clash_state.groups.keys().cloned().collect(),
        };
    }
    let proxy_groups = clash_state.proxy_group_memberships();
    let groups = clash_state.groups.keys().cloned().collect();

    let mut nym_to_id = BTreeMap::new();
    let mut proxies: BTreeMap<ProxyID, ProxyItem> = BTreeMap::new();

    for (id, proxy) in hub.all_proxies().iter() {
        let nym = id.nym().to_string();
        nym_to_id.insert(nym.clone(), id.clone());

        let (latency_ms, conn_ok) = if let Some(s) = stats_state.stats.get(id) {
            let h = s.past_hour();
            let lat = h.avg_latency_ms().map(|ms| ms as u64);
            let ok = h.success_rate().map(|p| p >= 0.5);
            (lat, ok)
        } else {
            (None, None)
        };

        let (name, url, proxy_domain) = match proxy {
            UplinkProxy::Trojan(t) => (
                t.name.clone(),
                format!("trojan://{}:{}", t.server_name, t.server_addr.port()),
                Some(t.server_name.as_str()),
            ),
            UplinkProxy::Remote(a) => (nym.clone(), format!("{}://{}", a.proxy_type, a.addr), None),
            UplinkProxy::Geph => (nym.clone(), "geph://".into(), None),
            UplinkProxy::File(p) => (nym.clone(), format!("file://{}", p.display()), None),
        };

        let (udp_expected, udp_ability) = if let Some(s) = stats_state.stats.get(id) {
            (
                s.expected_udp
                    .unwrap_or(uplink_proxy_default_udp_expected(proxy)),
                s.udp_ability,
            )
        } else {
            (uplink_proxy_default_udp_expected(proxy), None)
        };

        // Get resolved proxy-domain IPs from clash state if available.
        let resolved_ips: Vec<IpAddr> = proxy_domain
            .and_then(|domain| clash_state.get_latest_proxy_ips(domain))
            .map(|ips| ips.iter().copied().collect())
            .unwrap_or_default();

        // Get groups for this proxy from clash state
        let groups: HashSet<GroupId> = proxy_groups
            .get(id)
            .map(|g| g.clone())
            .unwrap_or_default();

        proxies.insert(
            id.clone(),
            ProxyItem {
                id: id.clone(),
                base: proxy.clone(),
                nym,
                name,
                url,
                udp_expected,
                udp_ability,
                enabled_globally: false,
                latency_ms,
                conn_ok,
                resolved_ips,
                groups,
            },
        );
    }

    ProxySnapshot {
        proxies,
        nym_to_id,
        proxy_groups,
        groups,
    }
}

fn load_hotconfig_daemons(profile: &str) -> anyhow::Result<Vec<ShellArgs>> {
    let path = state_paths::hot_config(profile);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    let hot: HotConfig = serde_json::from_str(&content)?;
    Ok(hot.daemons)
}

fn format_shell_args(args: &ShellArgs) -> String {
    let mut parts = Vec::new();
    if let Some(shell) = &args.shell {
        parts.push(shell.clone());
    }
    for arg in &args.args {
        parts.push(arg.clone());
    }
    if let Some(cwd) = &args.cwd {
        parts.push(format!("(cwd: {})", cwd.display()));
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(" ")
    }
}

fn default_spawn_identity() -> (Option<u32>, Option<u32>, Vec<u32>) {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let gids = nix::unistd::getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(|g: nix::unistd::Gid| g.as_raw())
        .collect();
    (Some(uid), Some(gid), gids)
}

fn apply_default_spawn_user(args: &mut diag::SpawnArgs) {
    let (uid, gid, gids) = default_spawn_identity();
    args.uid = uid;
    args.gid = gid;
    args.gids = gids;
}

fn default_spawn_shell_command_line() -> String {
    nsproxy_core::sys::your_shell(None, nix::unistd::getuid().as_raw().into())
        .ok()
        .flatten()
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .filter(|shell| !shell.trim().is_empty())
        })
        .unwrap_or_else(|| "/bin/sh".to_string())
}

fn parse_command_line_to_spawn_args(
    command_line: &str,
    spawn_inside_container: bool,
) -> Result<diag::SpawnArgs, String> {
    let trimmed = command_line.trim();
    if trimmed.is_empty() {
        return Err("command line is empty".to_string());
    }
    let tokens = shlex::split(trimmed)
        .ok_or_else(|| "failed to parse command line (check quoting/escaping)".to_string())?;
    if tokens.is_empty() {
        return Err("command line did not produce any argv entries".to_string());
    }
    // Resolve exec using standard PATH lookup if not an absolute path
    let exec_str = &tokens[0];
    let exec_resolved = if std::path::Path::new(exec_str).is_absolute() {
        exec_str.clone()
    } else {
        match which::which(exec_str) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => exec_str.clone(), // Fall back to original if not found in PATH
        }
    };
    let mut args = diag::SpawnArgs {
        uid: None,
        gid: None,
        exec: Some(exec_resolved),
        cwd: None,
        gids: Vec::new(),
        args: tokens,
        ringbuf_size: None,
        application: None,
        ns: if spawn_inside_container {
            diag::NamespaceSpawn::Inside
        } else {
            diag::NamespaceSpawn::Outside
        },
    };
    apply_default_spawn_user(&mut args);
    Ok(args)
}

fn refresh_run_command_preview(run_command: &mut RunCommandDraft) {
    match parse_command_line_to_spawn_args(
        &run_command.command_line,
        run_command.spawn_inside_container,
    ) {
        Ok(args) => {
            run_command.pending_spawn_args = Some(args);
            run_command.parse_error = None;
        }
        Err(err) => {
            run_command.pending_spawn_args = None;
            run_command.parse_error = Some(err);
        }
    }
}

impl App {
    fn request_persisted_logs_refresh(&mut self) {
        let _ = self
            .persisted_logs_tx
            .try_send(PersistedLogsRequest::Refresh {
                selected_file: self.selected_persisted_log_file.clone(),
                selected_pid: self
                    .selected_process_logs
                    .as_ref()
                    .and_then(|(_, pid)| (!self.selected_process_is_pty()).then_some(*pid)),
                logs_tab_visible: false,
                process_logs_visible: false,
            });
        self.last_persisted_logs_refresh = Instant::now();
    }

    fn desired_traffic_subscription(&self) -> Option<ContainerName> {
        if self.right_tab == RightTab::Traffic {
            self.selected_profile.clone()
        } else {
            None
        }
    }

    fn sync_traffic_subscription(&mut self) {
        let desired = self.desired_traffic_subscription();
        if self.traffic_subscription_profile == desired {
            return;
        }

        self.traffic_subscription_profile = desired.clone();
        self.supervisor
            .send(SupervisorCommand::SetTrafficSubscription { profile: desired });
    }

    fn refresh_traffic_route_target_filter(&mut self) {
        let filter = self.traffic_route_filter.trim().to_lowercase();
        self.filtered_traffic_route_target_indices = self
            .traffic_route_targets
            .iter()
            .enumerate()
            .filter_map(|(index, target)| {
                (filter.is_empty() || target.filter_text.contains(&filter)).then_some(index)
            })
            .collect();
        self.traffic_route_filter_applied = self.traffic_route_filter.clone();
    }

    pub fn new(ectx: egui::Context) -> Self {
        info!("initializing nsproxy-ui app state");
        let snapshot = load_proxies_from_persisted();
        let proxies = snapshot.proxies.clone();
        let nym_to_id = snapshot.nym_to_id.clone();
        let proxy_groups = snapshot.proxy_groups.clone();
        let user_groups = snapshot.groups.clone();

        let filtered_proxy_ids: Vec<ProxyID> = snapshot.proxies.keys().cloned().collect();
        let proxy_table_entries = build_proxy_table_entries(
            &filtered_proxy_ids,
            &snapshot.proxy_groups,
            &[],
            &user_groups,
        );
        let proxy_group_controls = build_proxy_group_controls(&proxy_table_entries);

        // Background reload: caller sends () to trigger a reload on a worker thread.
        let (reload_tx, reload_rx) = flume::bounded::<()>(1);
        let (proxy_tx, proxy_rx) = flume::bounded::<ProxySnapshot>(1);
        let (persisted_logs_tx, persisted_logs_req_rx) = flume::bounded::<PersistedLogsRequest>(1);
        let (persisted_logs_snapshot_tx, persisted_logs_rx) =
            flume::bounded::<PersistedLogsSnapshot>(1);
        thread::spawn(move || {
            info!("proxy reload worker started");
            while reload_rx.recv().is_ok() {
                let started = Instant::now();
                info!("proxy reload requested");
                let updated = load_proxies_from_persisted();
                info!(
                    proxies = updated.proxies.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "proxy reload completed"
                );
                let _ = proxy_tx.send(updated); // drop error if GUI has exited
            }
            info!("proxy reload worker exiting");
        });
        thread::spawn(move || {
            info!("persisted logs worker started");
            while let Ok(request) = persisted_logs_req_rx.recv() {
                match request {
                    PersistedLogsRequest::Refresh {
                        selected_file,
                        selected_pid,
                        logs_tab_visible,
                        process_logs_visible,
                    } => {
                        let snapshot = build_persisted_logs_snapshot(
                            selected_file.as_deref(),
                            selected_pid,
                            logs_tab_visible,
                            process_logs_visible,
                        );
                        let _ = persisted_logs_snapshot_tx.send(snapshot);
                    }
                }
            }
            info!("persisted logs worker exiting");
        });

        let tokio_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for ui supervisor");
        let (supervisor, supervisor_task) = SupervisorHandle::new(ectx.clone());
        let personal_state = personal::PersonalUiState::default();
        tokio_rt.spawn(supervisor_task.run());
        personal::install_personal_actor(&tokio_rt, supervisor.clone(), personal_state.clone());
        personal::install_systemd_suspend_hook(
            &tokio_rt,
            supervisor.clone(),
            personal_state.clone(),
        );

        // Initialize supervisor: discover and load all profiles
        supervisor.send(supervisor::SupervisorCommand::Init);

        // Viewer DNS ping background task
        let (viewer_ping_tx, viewer_ping_rx) = flume::unbounded::<ViewerPingRequest>();
        let viewer_dns_config = Arc::new(Mutex::new("8.8.8.8:53".to_string()));
        let viewer_ping_state = Arc::new(Mutex::new(ViewerPingState::default()));
        let viewer_mass_ping_state = Arc::new(Mutex::new(ViewerMassPingState::default()));
        let viewer_burst_test_state = Arc::new(Mutex::new(ViewerBurstTestState::default()));
        let viewer_burst_test_stats = Arc::new(Mutex::new(ViewerBurstTestStats::new(50)));
        {
            use futures::stream::FuturesUnordered;
            use futures::StreamExt as FuturesStreamExt;
            let ping_state_bg = viewer_ping_state.clone();
            let mass_state_bg = viewer_mass_ping_state.clone();
            let burst_state_bg = viewer_burst_test_state.clone();
            tokio_rt.spawn(async move {
                while let Ok(req) = viewer_ping_rx.recv_async().await {
                    match req {
                        ViewerPingRequest::Single(domain, dns_addr) => {
                            if let Err(err) = viewer_send_dns_ping_async(&dns_addr, domain).await {
                                ping_state_bg.lock().unwrap().last_error =
                                    Some(format!("dns ping error: {}", err));
                            }
                        }
                        ViewerPingRequest::BurstTest(dns_addr) => {
                            let started = viewer_now_epoch_us();
                            let max_batch_size = {
                                let mut burst = burst_state_bg.lock().unwrap();
                                burst.running = true;
                                burst.started_ts = Some(started);
                                burst.finished_ts = None;
                                burst.results.clear();
                                burst.threshold_size = None;
                                burst.last_error = None;
                                burst.max_batch_size
                            };
                            let mut test_sizes = Vec::new();
                            let mut power = 4u32;
                            loop {
                                let size = 1u64 << power;
                                if size > max_batch_size {
                                    break;
                                }
                                test_sizes.push(size);
                                power += 1;
                            }
                            if test_sizes.is_empty()
                                || *test_sizes.last().unwrap() != max_batch_size
                            {
                                test_sizes.push(max_batch_size);
                            }
                            let mut threshold_found = false;
                            for size in test_sizes {
                                let now_us = viewer_now_epoch_us();
                                let domains: Vec<String> = (0..size)
                                    .map(|i| format!("burst-{}-{}.diag", now_us, i))
                                    .collect();
                                let mut tasks: FuturesUnordered<_> = domains
                                    .into_iter()
                                    .map(|d| {
                                        let dns = dns_addr.clone();
                                        async move { viewer_send_dns_ping_async(&dns, d).await }
                                    })
                                    .collect();
                                let mut errs = 0u64;
                                let mut done = 0u64;
                                let mut lat_sum_us = 0u64;
                                let mut lat_min_us = u64::MAX;
                                let mut lat_max_us = 0u64;
                                while let Some(res) = tasks.next().await {
                                    done += 1;
                                    match res {
                                        Ok(lat) => {
                                            lat_sum_us = lat_sum_us.saturating_add(lat);
                                            lat_min_us = lat_min_us.min(lat);
                                            lat_max_us = lat_max_us.max(lat);
                                        }
                                        Err(_) => errs += 1,
                                    }
                                }
                                let failure_rate = if done > 0 {
                                    errs as f64 / done as f64 * 100.0
                                } else {
                                    0.0
                                };
                                let ok = done.saturating_sub(errs);
                                let lat_avg_us = if ok > 0 { lat_sum_us / ok } else { 0 };
                                let result = ViewerBurstTestResult {
                                    size,
                                    requested: size,
                                    completed: done,
                                    errors: errs,
                                    failure_rate,
                                    latency_us_min: if ok > 0 { lat_min_us } else { 0 },
                                    latency_us_max: lat_max_us,
                                    latency_us_avg: lat_avg_us,
                                };
                                {
                                    let mut burst = burst_state_bg.lock().unwrap();
                                    burst.results.push(result);
                                    if !threshold_found && failure_rate > 5.0 {
                                        burst.threshold_size = Some(size);
                                        threshold_found = true;
                                    }
                                }
                                if threshold_found {
                                    break;
                                }
                            }
                            let finished = viewer_now_epoch_us();
                            let mut burst = burst_state_bg.lock().unwrap();
                            burst.running = false;
                            burst.finished_ts = Some(finished);
                        }
                        ViewerPingRequest::Batch(domains, dns_addr) => {
                            let batch_started = viewer_now_epoch_us();
                            let mut tasks: FuturesUnordered<_> = domains
                                .into_iter()
                                .map(|d| {
                                    let dns = dns_addr.clone();
                                    async move { viewer_send_dns_ping_async(&dns, d).await }
                                })
                                .collect();
                            let mut errs = 0u64;
                            let mut done = 0u64;
                            let mut rtt_sum_us = 0u64;
                            let mut rtt_min_us = u64::MAX;
                            let mut rtt_max_us = 0u64;
                            let mut rtt_samples = 0u64;
                            while let Some(res) = tasks.next().await {
                                done += 1;
                                match res {
                                    Ok(rtt) => {
                                        rtt_samples += 1;
                                        rtt_sum_us = rtt_sum_us.saturating_add(rtt);
                                        rtt_min_us = rtt_min_us.min(rtt);
                                        rtt_max_us = rtt_max_us.max(rtt);
                                    }
                                    Err(_) => errs += 1,
                                }
                            }
                            let batch_finished = viewer_now_epoch_us();
                            let mut mass = mass_state_bg.lock().unwrap();
                            mass.completed = done;
                            mass.errors = errs;
                            mass.in_flight = 0;
                            mass.finished_ts = Some(batch_finished);
                            mass.duration_us = Some(batch_finished.saturating_sub(batch_started));
                            if rtt_samples > 0 {
                                mass.rtt_avg_us = Some(rtt_sum_us / rtt_samples);
                                mass.rtt_min_us = Some(rtt_min_us);
                                mass.rtt_max_us = Some(rtt_max_us);
                                mass.rtt_samples = rtt_samples;
                            } else {
                                mass.rtt_avg_us = None;
                                mass.rtt_min_us = None;
                                mass.rtt_max_us = None;
                                mass.rtt_samples = 0;
                            }
                            mass.last_error = if errs > 0 {
                                Some(format!("{} errors", errs))
                            } else {
                                None
                            };
                        }
                    }
                }
            });
        }

        info!(
            initial_proxy_count = proxies.len(),
            "nsproxy-ui app initialized"
        );
        let traffic_route_targets = build_traffic_route_targets(&proxies);
        let filtered_traffic_route_target_indices = (0..traffic_route_targets.len()).collect();
        Self {
            selected_profile: None,
            remove_containers_armed: false,
            right_tab: RightTab::Proxies,
            demo_mode: false,
            proxies,
            nym_to_id,
            proxy_groups,
            clash_replace_group: user_groups.first().cloned(),
            clash_import_path: String::new(),
            clash_import_group_name: String::new(),
            clash_import_default_group_name: String::new(),
            clash_import_status: None,
            clash_import_pending: false,
            clash_import_result_rx: None,
            user_groups,
            filtered_proxy_ids,
            proxy_table_entries,
            proxy_group_controls,
            expanded_proxy_groups: Vec::new(),
            proxy_table_entries_dirty: false,
            filters_dirty: false,
            hovered_proxy: None,
            reload_tx,
            proxy_rx,
            persisted_logs_tx,
            persisted_logs_rx,
            proxy_filters: ProxyFilters::default(),
            supervisor,
            personal_state,
            snapshot: supervisor::SupervisorSnapshot {
                profiles: BTreeMap::new(),
                ui_ns: supervisor::NamespaceIndicator::default(),
                namespace_warning: None,
                root_daemon_connection: supervisor::ConnectionState::Disconnected,
                root_daemon_error: None,
                hotconfig_editor_status: None,
                profile_editor_status: None,
                constants_editor_status: None,
                constants_editor_content: None,
                personal_runtime_state: diag::personal::PersonalRuntimeState::default(),
                root_daemon_logs: Arc::new(RwLock::new(supervisor::LevelLogView::default())),
                auto_open_logs_target: None,
                generated_at: SystemTime::now(),
            },
            run_command: RunCommandDraft::default(),
            int_input: IntInput::default(),
            hide_secret: false,
            cover_text: "redacted".to_string(),
            tokio_rt: Some(tokio_rt),
            fcitx_tab: FcitxTabState::new(),
            detail_proxy_id: None,
            expanded_ip_rows: HashSet::new(),
            last_sort_time: Instant::now(),
            detail_fit_frames_left: 0,
            profile_editor_target: None,
            profile_editor_template: TemplateConfig::default(),
            profile_editor_json: default_profile_text(),
            profile_editor_json_error: None,
            profile_editor_hot_init_json: default_hotconfig_text(),
            profile_editor_hot_init_error: None,
            profile_editor_create_name: String::new(),
            profile_editor_status: None,
            hotconfig_editor_target: None,
            hotconfig_editor_value: default_hotconfig(),
            hotconfig_editor_json: default_hotconfig_text(),
            hotconfig_editor_error: None,
            hotconfig_editor_status: None,
            hotconfig_veth_drafts: HashMap::new(),
            selected_traffic_conn: None,
            traffic_subview: TrafficSubview::default(),
            traffic_route_target: nsproxy_common::stats::ObservedRoute::NoProxy,
            traffic_route_target_index: 0,
            traffic_route_targets,
            traffic_route_filter: String::new(),
            traffic_route_filter_applied: String::new(),
            filtered_traffic_route_target_indices,
            traffic_subscription_profile: None,
            rust_backtrace: false,
            selected_process_logs: None,
            process_log_editor_target: None,
            process_log_editor_next_seq: None,
            process_log_rows: VecDeque::new(),
            process_log_rows_bytes: 0,
            selected_persisted_log_file: None,
            persisted_logs_snapshot: PersistedLogsSnapshot::default(),
            last_persisted_logs_refresh: Instant::now() - Duration::from_secs(60),
            swap_term_window: ExternalTermWindowClient::default(),
            dedicated_term_windows: HashMap::new(),
            last_auto_open_logs_token: 0,
            selected_process_spawn_args: None,
            pty_sessions: HashMap::new(),
            viewer_ping_tx,
            viewer_dns_config,
            viewer_ping_state,
            viewer_mass_ping_state,
            viewer_burst_test_state,
            viewer_burst_test_stats,
            viewer_selected_conn: None,
            ui_frame_seq: 0,
            last_frame_progress_log: Instant::now(),
            last_frame_elapsed_ms: 0,
            fps_window_start: Instant::now(),
            fps_window_count: 0,
            last_fps: 0.0,
            log_panel_min_level: LogMinLevel::default(),
            log_editor_popup: None,
            manage_wizard: ManageWizard::default(),
            action_launching: Arc::new(Mutex::new(HashSet::new())),
            action_status: Arc::new(Mutex::new(None)),
        }
    }

    fn right_tab_label(&self) -> &'static str {
        match self.right_tab {
            RightTab::Proxies => "Proxies",
            RightTab::Daemon => "Daemon",
            RightTab::Dbus => "Dbus",
            RightTab::Actions => "Actions",
            RightTab::Processes => "Processes",
            RightTab::Traffic => "Traffic",
            RightTab::Hotconfig => "Hotconfig",
            RightTab::ProfileEditor => "ProfileEditor",
            RightTab::State => "State",
            RightTab::Manage => "Manage",
            RightTab::Meta => "Meta",
        }
    }

    /// Returns text suitable for rendering. In demonstration mode this removes
    /// profile names and the local home-directory prefix without touching the
    /// underlying state or any value used for an action.
    fn display_text(&self, text: impl AsRef<str>) -> String {
        let mut displayed = text.as_ref().to_owned();
        if !self.demo_mode {
            return displayed;
        }

        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home).display().to_string();
            if !home.is_empty() {
                displayed = displayed.replace(&home, "/home/demo-user");
            }
        }

        let mut profiles: Vec<_> = self.snapshot.profiles.keys().collect();
        profiles.sort_by(|a, b| {
            b.as_str()
                .len()
                .cmp(&a.as_str().len())
                .then_with(|| a.as_str().cmp(b.as_str()))
        });
        for profile_name in profiles {
            let ordinal = self
                .snapshot
                .profiles
                .keys()
                .enumerate()
                .find_map(|(index, name)| (name == profile_name).then_some(index + 1))
                .expect("profile name was obtained from the profile map");
            displayed = displayed.replace(profile_name.as_str(), &format!("container-{ordinal}"));
        }

        displayed
    }

    fn display_path(&self, path: &Path) -> String {
        self.display_text(path.display().to_string())
    }

    fn display_hotconfig(&self, hot: &HotConfig) -> HotConfig {
        if !self.demo_mode {
            return hot.clone();
        }

        serde_json::to_string(hot)
            .ok()
            .map(|json| self.display_text(json))
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(|| hot.clone())
    }

    fn render_meta_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Meta");
        ui.add_space(8.0);
        ui.label("Presentation controls that only affect text rendered by this UI.");
        ui.add_space(8.0);

        let button_text = if self.demo_mode {
            "demo mode enabled (replace personal information)"
        } else {
            "demo mode (replace personal information)"
        };
        if ui.button(button_text).clicked() {
            self.demo_mode = !self.demo_mode;
        }

        ui.add_space(6.0);
        if self.demo_mode {
            ui.colored_label(
                Color32::LIGHT_GREEN,
                "Enabled: container names are replaced with generic labels and home paths use /home/demo-user.",
            );
        } else {
            ui.colored_label(
                Color32::from_gray(150),
                "Disabled: the UI shows the original values.",
            );
        }
        ui.small("This mode does not modify persisted configuration, runtime state, or commands sent to containers.");

        ui.add_space(18.0);
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Namespaces");
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if Self::refresh_button(ui, "Refresh namespace view").clicked() {
                            self.supervisor
                                .send(SupervisorCommand::RefreshNamespaces);
                        }
                    },
                );
            });
            ui.add_space(3.0);
            ui.small("Namespace IDs for the UI and the selected container.");

            if let Some(warning) = &self.snapshot.namespace_warning {
                ui.add_space(8.0);
                ui.colored_label(
                    Color32::from_rgb(220, 170, 70),
                    RichText::new(warning).small(),
                );
            }

            ui.add_space(10.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                render_namespace_indicator_row(
                    ui,
                    "UI",
                    Some(std::process::id() as i32),
                    Some(&self.snapshot.ui_ns),
                    Color32::from_rgb(100, 150, 240),
                );
            });

            if let Some(profile_name) = &self.selected_profile {
                if let Some(profile_snapshot) = self.snapshot.profiles.get(profile_name) {
                    let up_pid = profile_snapshot
                        .ns_alive
                        .as_ref()
                        .and_then(|ns| ns.up_pid)
                        .map(|pid| pid as i32);
                    let child_pid = profile_snapshot
                        .ns_alive
                        .as_ref()
                        .and_then(|ns| ns.child_pid)
                        .map(|pid| pid as i32);

                    if let Some(pid) = up_pid {
                        ui.add_space(6.0);
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            render_namespace_indicator_row(
                                ui,
                                "up",
                                Some(pid),
                                profile_snapshot.up_ns.as_ref(),
                                Color32::from_rgb(120, 200, 140),
                            );
                        });
                    }
                    if let Some(pid) = child_pid {
                        ui.add_space(6.0);
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            render_namespace_indicator_row(
                                ui,
                                "keeper",
                                Some(pid),
                                profile_snapshot.keeper_ns.as_ref(),
                                Color32::from_rgb(220, 180, 90),
                            );
                        });
                    }
                    if up_pid.is_none() && child_pid.is_none() {
                        ui.add_space(8.0);
                        ui.colored_label(
                            Color32::GRAY,
                            "Selected profile has no live pid yet",
                        );
                    }
                }
            } else {
                ui.add_space(8.0);
                ui.colored_label(
                    Color32::GRAY,
                    "Select a profile to compare its namespace state",
                );
            }
        });
    }

    fn is_valid_path(path: &str) -> bool {
        if path.is_empty() {
            return false;
        }

        let path_buf = std::path::PathBuf::from(path);

        if path == "@" || path.starts_with("@/") || path.starts_with('@') {
            return true;
        }

        if path == "~" || path.starts_with("~/") {
            return true;
        }

        if path.starts_with('/') {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = std::path::PathBuf::from(home);
                let expanded = if path.starts_with("~/") {
                    home_path.join(&path[2..])
                } else {
                    path_buf.clone()
                };
                return expanded.exists();
            }
            return path_buf.exists();
        }

        false
    }

    fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        if !domain.ends_with('.') {
            return false;
        }

        !domain.contains(char::is_whitespace)
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }

    fn is_valid_ipv4(ip: &str) -> bool {
        ip.parse::<std::net::Ipv4Addr>().is_ok()
    }

    fn is_valid_port(port: u32) -> bool {
        port > 0 && port <= 65535
    }

    fn is_valid_mode(mode: u32) -> bool {
        mode <= 0o7777
    }

    fn snapshot_string_map(map: &HashMap<String, String>) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> =
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    fn snapshot_virtual_dns(hot: &HotConfig) -> Vec<(String, VirtualDnsTargetKind, String)> {
        let mut entries: BTreeMap<String, (VirtualDnsTargetKind, String)> = hot
            .dns
            .iter()
            .map(|(domain, address)| {
                (
                    domain.clone(),
                    (VirtualDnsTargetKind::DnsAnswer, address.clone()),
                )
            })
            .collect();

        // `derive_desired_state` applies `tun` after `dns`, so preserve that
        // precedence when a legacy configuration contains the same domain in both.
        for (domain, target) in &hot.tun {
            let (target_kind, target) = match target {
                Value::Number(port) => (
                    VirtualDnsTargetKind::TunForward,
                    port.as_u64()
                        .map(|port| format!("127.0.0.1:{port}"))
                        .unwrap_or_else(|| target.to_string()),
                ),
                Value::String(target) if target.parse::<std::net::SocketAddr>().is_ok() => {
                    (VirtualDnsTargetKind::TunForward, target.clone())
                }
                Value::String(target) => (VirtualDnsTargetKind::WarpFiles, target.clone()),
                _ => (VirtualDnsTargetKind::WarpFiles, target.to_string()),
            };
            entries.insert(domain.clone(), (target_kind, target));
        }

        entries
            .into_iter()
            .map(|(domain, (target_kind, target))| (domain, target_kind, target))
            .collect()
    }

    fn snapshot_u32_map(map: &HashMap<u32, u32>) -> Vec<(u32, u32)> {
        let mut pairs: Vec<(u32, u32)> = map.iter().map(|(k, v)| (*k, *v)).collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    fn snapshot_path_map(
        map: &HashMap<std::path::PathBuf, std::path::PathBuf>,
    ) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = map
            .iter()
            .map(|(k, v)| (k.display().to_string(), v.display().to_string()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    fn path_text_edit_with_validation(ui: &mut egui::Ui, value: &mut String) -> egui::Response {
        let is_valid = Self::is_valid_path(value);
        let bg_color = if is_valid {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        };

        let mut text_edit = egui::TextEdit::singleline(value);
        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let response = ui.add(text_edit);
        ui.visuals_mut().extreme_bg_color = old_bg;
        response
    }

    fn domain_text_edit_with_validation(ui: &mut egui::Ui, value: &mut String) -> egui::Response {
        let is_valid = {
            if Self::is_valid_domain(value) {
                true
            } else {
                let mut normalized = value.clone();
                normalize_domain(&mut normalized);
                Self::is_valid_domain(&normalized)
            }
        };
        let bg_color = if is_valid {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        };

        let mut text_edit = egui::TextEdit::singleline(value);
        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let mut response = ui.add(text_edit);
        ui.visuals_mut().extreme_bg_color = old_bg;
        if response.lost_focus() {
            let before = value.clone();
            normalize_domain(value);
            if *value != before {
                response.mark_changed();
            }
        }
        response
    }

    fn ip_text_edit_with_validation(ui: &mut egui::Ui, value: &mut String) -> egui::Response {
        let is_valid = Self::is_valid_ipv4(value);
        let bg_color = if is_valid {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        };

        let mut text_edit = egui::TextEdit::singleline(value);
        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let response = ui.add(text_edit);
        ui.visuals_mut().extreme_bg_color = old_bg;
        response
    }

    fn socket_addr_text_edit_with_validation(
        ui: &mut egui::Ui,
        value: &mut String,
    ) -> egui::Response {
        let bg_color = if value.parse::<std::net::SocketAddr>().is_ok() {
            egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
        } else {
            egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
        };

        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let response = ui.add(egui::TextEdit::singleline(value));
        ui.visuals_mut().extreme_bg_color = old_bg;
        response
    }

    fn refresh_hotconfig_editor_target(&mut self) {
        if self.hotconfig_editor_target == self.selected_profile {
            return;
        }

        self.hotconfig_editor_target = self.selected_profile.clone();
        self.hotconfig_editor_status = None;
        self.hotconfig_editor_error = None;

        if let Some(profile_name) = self.selected_profile.as_ref() {
            if let Some(snapshot) = self.snapshot.profiles.get(profile_name) {
                self.hotconfig_editor_value = snapshot.hotconfig.clone();
            } else {
                self.hotconfig_editor_value = default_hotconfig();
            }
        } else {
            self.hotconfig_editor_value = default_hotconfig();
        }
        self.hotconfig_veth_drafts.insert(
            self.selected_profile.clone().unwrap_or_default(),
            self.hotconfig_editor_value
                .veth
                .iter()
                .map(|veth| VethDraft {
                    peer: if veth.dst == "this" {
                        String::new()
                    } else {
                        veth.dst.clone()
                    },
                    basis_namespace: veth.dst == "basis",
                    name: veth.veth_name.clone().unwrap_or_default(),
                    src_ip4: veth.src_ip4.map(|ip| ip.to_string()).unwrap_or_default(),
                    dst_ip4: veth.dst_ip4.map(|ip| ip.to_string()).unwrap_or_default(),
                    prefix_len: veth.prefix_len.to_string(),
                    add_on_start: true,
                    submitted: false,
                })
                .collect(),
        );
        self.hotconfig_editor_json = serde_json::to_string_pretty(&self.hotconfig_editor_value)
            .unwrap_or_else(|_| "{}".to_string());
    }

    /// Returns the latest route reported by the profile's serve process.
    /// `Some(HotRoute::None)` is a known live state, while `None` means no
    /// routing state has been received yet.
    fn live_route_for_profile(
        &self,
        profile_name: &ContainerName,
    ) -> Option<nsproxy_core::HotRoute> {
        self.snapshot
            .profiles
            .get(profile_name)
            .and_then(|profile| profile.routing_state.as_ref())
            .map(|routing| {
                if routing.no_proxy {
                    nsproxy_core::HotRoute::NoProxy
                } else if let Some(group_id) = &routing.selected_group {
                    nsproxy_core::HotRoute::Group {
                        group_id: group_id.clone(),
                    }
                } else if let Some(proxy_id) = &routing.selected_proxy {
                    nsproxy_core::HotRoute::SimpleProxy {
                        proxy_id: proxy_id.clone(),
                    }
                } else {
                    nsproxy_core::HotRoute::None
                }
            })
    }

    fn save_hotconfig_editor(&mut self) {
        let Some(profile_name) = self.selected_profile.clone() else {
            self.hotconfig_editor_status = Some("Select a profile to save hotconfig.".to_string());
            return;
        };

        // The proxy selector updates the running serve process immediately.
        // Preserve that newer route when saving unrelated HotConfig edits.
        if let Some(route) = self.live_route_for_profile(&profile_name) {
            self.hotconfig_editor_value.default_route = route;
            self.hotconfig_editor_json = serde_json::to_string_pretty(&self.hotconfig_editor_value)
                .unwrap_or_else(|_| "{}".to_string());
        }

        let content = match serde_json::to_string_pretty(&self.hotconfig_editor_value) {
            Ok(content) => content,
            Err(err) => {
                self.hotconfig_editor_status = Some(format!("Serialize failed: {err}"));
                return;
            }
        };

        self.hotconfig_editor_status = Some("Saving hotconfig via sp daemon...".to_string());
        self.supervisor
            .send(SupervisorCommand::SaveHotconfigPrivileged {
                profile: profile_name,
                content,
            });
    }

    fn refresh_profile_editor_target(&mut self) {
        if self.profile_editor_target == self.selected_profile {
            return;
        }

        self.profile_editor_target = self.selected_profile.clone();
        self.profile_editor_status = None;
        self.profile_editor_json_error = None;
        self.profile_editor_hot_init_error = None;

        if let Some(profile_name) = self.selected_profile.as_ref() {
            if let Some(snapshot) = self.snapshot.profiles.get(profile_name) {
                self.profile_editor_template = snapshot.template.clone();
                self.profile_editor_create_name = profile_name.clone();
            } else {
                self.profile_editor_template = TemplateConfig::default();
            }
        } else {
            self.profile_editor_template = TemplateConfig::default();
        }
        self.refresh_profile_editor_json_from_template();
        self.refresh_hot_init_json_from_template();
    }

    fn refresh_profile_editor_json_from_template(&mut self) {
        self.profile_editor_json = serde_json::to_string_pretty(&self.profile_editor_template)
            .unwrap_or_else(|_| "{}".to_string());
    }

    fn refresh_hot_init_json_from_template(&mut self) {
        if let Some(hot) = self.profile_editor_template.hot_init.as_ref() {
            self.profile_editor_hot_init_json =
                serde_json::to_string_pretty(hot).unwrap_or_else(|_| "{}".to_string());
        } else {
            self.profile_editor_hot_init_json = default_hotconfig_text();
        }
    }

    fn save_profile_editor(&mut self) {
        let Some(profile_name) = self.selected_profile.clone() else {
            self.profile_editor_status = Some("Select a profile to save.".to_string());
            return;
        };

        if self.profile_editor_json_error.is_some() || self.profile_editor_hot_init_error.is_some()
        {
            self.profile_editor_status = Some("Fix JSON errors before saving.".to_string());
            return;
        }

        let content = match serde_json::to_string_pretty(&self.profile_editor_template) {
            Ok(content) => content,
            Err(err) => {
                self.profile_editor_status = Some(format!("Serialize failed: {err}"));
                return;
            }
        };

        self.profile_editor_status = Some("Saving profile via sp daemon...".to_string());
        self.supervisor
            .send(SupervisorCommand::SaveProfilePrivileged {
                profile: profile_name,
                content,
            });
    }

    fn create_profile_from_editor(&mut self) {
        let name = self.profile_editor_create_name.trim().to_string();
        if name.is_empty() {
            self.profile_editor_status = Some("Enter a profile name first.".to_string());
            return;
        }
        if name.contains('/') {
            self.profile_editor_status = Some("Profile name must not contain '/'.".to_string());
            return;
        }
        if self.profile_editor_json_error.is_some() || self.profile_editor_hot_init_error.is_some()
        {
            self.profile_editor_status = Some("Fix JSON errors before creating.".to_string());
            return;
        }

        let profile_content = match serde_json::to_string_pretty(&self.profile_editor_template) {
            Ok(content) => content,
            Err(err) => {
                self.profile_editor_status = Some(format!("Serialize failed: {err}"));
                return;
            }
        };
        let hot_content = self
            .profile_editor_template
            .hot_init
            .as_ref()
            .and_then(|hot| serde_json::to_string_pretty(hot).ok());

        self.profile_editor_status = Some("Creating profile via sp daemon...".to_string());
        self.supervisor
            .send(SupervisorCommand::CreateProfilePrivileged {
                name,
                profile_content,
                hot_content,
            });
    }

    fn render_optional_u32(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        label: &str,
        value: &mut Option<u32>,
        value_changed: bool,
    ) -> bool {
        Self::render_optional_u32_with_default(ui, int_input, label, value, value_changed, 0)
    }

    fn render_optional_u32_with_default(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        label: &str,
        value: &mut Option<u32>,
        value_changed: bool,
        default_value: u32,
    ) -> bool {
        let mut changed = false;
        ui.horizontal(|ui| {
            let state_id = ui.make_persistent_id(("optional-u32-enabled", label));
            let mut enabled = ui
                .data_mut(|d| d.get_temp::<bool>(state_id))
                .unwrap_or(value.is_some());

            if ui.checkbox(&mut enabled, label).changed() {
                changed = true;
                if enabled && value.is_none() {
                    *value = Some(default_value);
                }
                if !enabled {
                    *value = None;
                }
                ui.data_mut(|d| d.insert_temp(state_id, enabled));
            }

            // If an external change set the value to Some(...), ensure the
            // persisted enabled state follows so the input doesn't get hidden.
            if value.is_some() && !enabled {
                enabled = true;
                ui.data_mut(|d| d.insert_temp(state_id, enabled));
            }

            if enabled {
                let id = ui.make_persistent_id(("optional-u32", label));
                if value_changed {
                    int_input.sync_from_value(ui, label, &*value);
                }
                if label == "mode" {
                    if int_input.show(ui, id, value, Self::is_valid_mode) {
                        changed = true;
                    }
                } else if int_input.show(ui, id, value, |_| true) {
                    changed = true;
                }
            }
        });
        changed
    }

    fn render_optional_text(ui: &mut egui::Ui, label: &str, value: &mut Option<String>) -> bool {
        Self::render_optional_text_with_width(ui, label, value, ui.available_width())
    }

    fn render_optional_text_with_width(
        ui: &mut egui::Ui,
        label: &str,
        value: &mut Option<String>,
        width: f32,
    ) -> bool {
        let mut changed = false;
        ui.horizontal(|ui| {
            let mut enabled = value.is_some();
            if ui.checkbox(&mut enabled, label).changed() {
                changed = true;
                if enabled && value.is_none() {
                    *value = Some(String::new());
                }
                if !enabled {
                    *value = None;
                }
            }
            if let Some(text) = value.as_mut() {
                let width = width.min(ui.available_width().max(0.0));
                if ui
                    .add_sized(
                        egui::vec2(width, ui.spacing().interact_size.y),
                        egui::TextEdit::singleline(text),
                    )
                    .changed()
                {
                    changed = true;
                }
            }
        });
        changed
    }

    fn render_path_field(
        ui: &mut egui::Ui,
        label: &str,
        path: &mut std::path::PathBuf,
        id_salt: impl std::hash::Hash + std::fmt::Debug,
    ) -> bool {
        let mut changed = false;
        let mut value = path.display().to_string();
        ui.horizontal(|ui| {
            ui.push_id(("path-field", label, &id_salt), |ui| {
                ui.label(label);
                if Self::path_text_edit_with_validation(ui, &mut value).changed() {
                    *path = value.clone().into();
                    changed = true;
                }
            });
        });
        changed
    }

    fn refresh_button(ui: &mut egui::Ui, tooltip: &str) -> egui::Response {
        // small clickable area with 1px padding around the glyph
        let size = egui::vec2(16.0, 16.0);
        let id = ui.make_persistent_id(("refresh_button", tooltip));
        let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());

        let base = egui::Color32::from_rgba_unmultiplied(200, 200, 200, 140);
        let hover_col = egui::Color32::from_rgba_unmultiplied(240, 240, 240, 200);
        let col = if resp.hovered() { hover_col } else { base };

        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "⟳",
            egui::FontId::proportional(14.0),
            col,
        );

        // keep usual tooltip/response behavior
        resp.on_hover_text(tooltip)
    }

    fn remove_armed_button(ui: &mut egui::Ui, armed: bool) -> egui::Response {
        let size = egui::vec2(16.0, 16.0);
        let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());

        let armed_col = egui::Color32::from_rgba_unmultiplied(220, 100, 100, 200);
        let base = egui::Color32::from_rgba_unmultiplied(200, 200, 200, 140);
        let hover_col = egui::Color32::from_rgba_unmultiplied(240, 240, 240, 200);
        let col = if armed {
            armed_col
        } else if resp.hovered() {
            hover_col
        } else {
            base
        };

        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            regular::TRASH,
            egui::FontId::proportional(14.0),
            col,
        );

        resp.on_hover_text("Enable Ctrl+D to remove the selected container")
    }

    fn remove_icon_button(ui: &mut egui::Ui, tooltip: &str) -> egui::Response {
        let (rect, response) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
        let color = if response.hovered() {
            Color32::from_rgb(255, 135, 135)
        } else {
            Color32::from_rgb(190, 115, 115)
        };

        if response.hovered() {
            ui.painter()
                .rect_filled(rect, 3.0, Color32::from_rgba_unmultiplied(220, 75, 75, 65));
        }
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            regular::X,
            egui::FontId::proportional(11.0),
            color,
        );

        response.on_hover_text(tooltip)
    }

    fn validation_icon(ui: &mut egui::Ui, valid: bool, tooltip: &str) -> egui::Response {
        let (rect, response) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        let color = if valid {
            if response.hovered() {
                Color32::from_rgb(155, 255, 175)
            } else {
                Color32::LIGHT_GREEN
            }
        } else {
            if response.hovered() {
                Color32::from_rgb(255, 140, 140)
            } else {
                Color32::LIGHT_RED
            }
        };
        if response.hovered() {
            ui.painter().rect_filled(
                rect,
                3.0,
                if valid {
                    Color32::from_rgba_unmultiplied(65, 205, 105, 55)
                } else {
                    Color32::from_rgba_unmultiplied(220, 75, 75, 65)
                },
            );
        }
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            if valid { regular::CHECK } else { regular::X },
            egui::FontId::proportional(12.0),
            color,
        );
        response.on_hover_text(tooltip)
    }

    fn render_mount_list(ui: &mut egui::Ui, mounts: &mut Vec<ProfileMount>, title: &str) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(title);
                if ui.button("+ Add").clicked() {
                    mounts.push(ProfileMount {
                        source: "/".into(),
                        target: "/".into(),
                        read_only: false,
                        recursive: true,
                        skip_missing: false,
                    });
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, mount) in mounts.iter_mut().enumerate() {
                ui.push_id(("mount-row", i), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", i + 1));
                    });
                    if Self::render_path_field(ui, "source", &mut mount.source, i * 2) {
                        changed = true;
                    }
                    if Self::render_path_field(ui, "target", &mut mount.target, i * 2 + 1) {
                        changed = true;
                    }
                    if ui.checkbox(&mut mount.read_only, "read_only").changed() {
                        changed = true;
                    }
                    if ui.checkbox(&mut mount.recursive, "recursive").changed() {
                        changed = true;
                    }
                    if mount.source.to_string_lossy().is_empty()
                        || mount.target.to_string_lossy().is_empty()
                    {
                        remove_ixs.push(i);
                    }
                });
            }
            for &ix in remove_ixs.iter().rev() {
                mounts.remove(ix);
                changed = true;
            }
        });
        changed
    }

    fn render_chmod_list(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        chmod: &mut Vec<ProfileChmod>,
    ) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("chmod");
                if ui.button("+ Add").clicked() {
                    chmod.push(ProfileChmod {
                        path: "/".into(),
                        mode: None,
                        uid: None,
                        gid: None,
                        mkdir: false,
                    });
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, op) in chmod.iter_mut().enumerate() {
                ui.push_id(("chmod-row", i), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", i + 1));
                    });
                    if Self::render_path_field(ui, "path", &mut op.path, i) {
                        changed = true;
                    }
                    if Self::render_optional_u32(ui, int_input, "mode", &mut op.mode, false) {
                        changed = true;
                    }
                    if Self::render_optional_u32(ui, int_input, "uid", &mut op.uid, false) {
                        changed = true;
                    }
                    if Self::render_optional_u32(ui, int_input, "gid", &mut op.gid, false) {
                        changed = true;
                    }
                    if op.path.to_string_lossy().is_empty() {
                        remove_ixs.push(i);
                    }
                });
            }
            for &ix in remove_ixs.iter().rev() {
                chmod.remove(ix);
                changed = true;
            }
        });
        changed
    }

    fn render_env_map(ui: &mut egui::Ui, env: &mut HashMap<String, String>) -> bool {
        let mut changed = false;
        let state_id = ui.make_persistent_id("env-map-editor-state");
        let snapshot = Self::snapshot_string_map(env);
        let mut state = ui
            .data_mut(|d| d.get_temp::<StringMapEditorState>(state_id))
            .unwrap_or_else(|| StringMapEditorState {
                pairs: snapshot.clone(),
                snapshot: snapshot.clone(),
            });
        if state.snapshot != snapshot {
            state.pairs = snapshot.clone();
            state.snapshot = snapshot.clone();
        }
        let mut pairs = state.pairs;

        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("env");
                if ui.button("+ Add").clicked() {
                    pairs.push(("KEY".to_string(), "value".to_string()));
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, (k, v)) in pairs.iter_mut().enumerate() {
                ui.push_id(("env-row", i), |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        if ui.text_edit_singleline(k).changed() {
                            changed = true;
                        }
                        if ui.text_edit_singleline(v).changed() {
                            changed = true;
                        }
                    });
                    if k.is_empty() || v.is_empty() {
                        remove_ixs.push(i);
                    }
                });
            }
            for &ix in remove_ixs.iter().rev() {
                pairs.remove(ix);
                changed = true;
            }
        });

        if changed {
            env.clear();
            let mut ordered_pairs = Vec::new();
            for (k, v) in pairs {
                if !k.trim().is_empty() {
                    ordered_pairs.push((k.clone(), v.clone()));
                    env.insert(k, v);
                }
            }
            state.snapshot = Self::snapshot_string_map(env);
            state.pairs = ordered_pairs;
        } else {
            state.pairs = pairs;
        }
        ui.data_mut(|d| d.insert_temp(state_id, state));
        changed
    }

    fn render_string_map(
        ui: &mut egui::Ui,
        title: &str,
        map: &mut HashMap<String, String>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;
        let state_id = ui.make_persistent_id((id_prefix, title, "string-map-editor-state"));
        let snapshot = Self::snapshot_string_map(map);
        let mut state = ui
            .data_mut(|d| d.get_temp::<StringMapEditorState>(state_id))
            .unwrap_or_else(|| StringMapEditorState {
                pairs: snapshot.clone(),
                snapshot: snapshot.clone(),
            });
        if state.snapshot != snapshot {
            state.pairs = snapshot.clone();
            state.snapshot = snapshot.clone();
        }
        let mut pairs = state.pairs;

        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(title);
                if ui.button("+ Add").clicked() {
                    pairs.push(("key".to_string(), "value".to_string()));
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, (k, v)) in pairs.iter_mut().enumerate() {
                ui.push_id((id_prefix, title, i), |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        if title == "dns" {
                            if Self::domain_text_edit_with_validation(ui, k).changed() {
                                changed = true;
                            }
                            if Self::ip_text_edit_with_validation(ui, v).changed() {
                                changed = true;
                            }
                        } else {
                            if ui.text_edit_singleline(k).changed() {
                                changed = true;
                            }
                            if ui.text_edit_singleline(v).changed() {
                                changed = true;
                            }
                        }
                    });
                    if k.is_empty() || v.is_empty() {
                        remove_ixs.push(i);
                    }
                });
            }
            for &ix in remove_ixs.iter().rev() {
                pairs.remove(ix);
                changed = true;
            }
        });

        if changed {
            map.clear();
            let mut ordered_pairs = Vec::new();
            for (k, v) in pairs {
                if !k.trim().is_empty() {
                    ordered_pairs.push((k.clone(), v.clone()));
                    map.insert(k, v);
                }
            }
            state.snapshot = Self::snapshot_string_map(map);
            state.pairs = ordered_pairs;
        } else {
            state.pairs = pairs;
        }
        ui.data_mut(|d| d.insert_temp(state_id, state));
        changed
    }

    fn render_virtual_dns_table(ui: &mut egui::Ui, hot: &mut HotConfig, id_prefix: &str) -> bool {
        let mut changed = false;
        let state_id = ui.make_persistent_id((id_prefix, "virtual-dns-editor-state"));
        let snapshot = Self::snapshot_virtual_dns(hot);
        let mut state = ui
            .data_mut(|d| d.get_temp::<VirtualDnsEditorState>(state_id))
            .unwrap_or_else(|| VirtualDnsEditorState {
                rows: snapshot
                    .iter()
                    .map(|(domain, target_kind, target)| VirtualDnsRow {
                        domain: domain.clone(),
                        target_kind: *target_kind,
                        target: target.clone(),
                    })
                    .collect(),
                snapshot: snapshot.clone(),
            });
        if state.snapshot != snapshot {
            state.rows = snapshot
                .iter()
                .map(|(domain, target_kind, target)| VirtualDnsRow {
                    domain: domain.clone(),
                    target_kind: *target_kind,
                    target: target.clone(),
                })
                .collect();
            state.snapshot = snapshot;
        }

        section_frame(ui, |ui| {
            // Keep this header wrapped so the helper text does not push the action button off-screen in narrow panes.
            ui.horizontal_wrapped(|ui| {
                ui.strong("virtual dns");
                ui.weak("Route a domain to an address, TUN endpoint, or Warp file server.");
                if ui.button("+ Add").clicked() {
                    state.rows.push(VirtualDnsRow {
                        domain: "example.test.".to_string(),
                        target_kind: VirtualDnsTargetKind::DnsAnswer,
                        target: "127.0.0.1".to_string(),
                    });
                    changed = true;
                }
            });

            let mut remove_ix = None;
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::remainder())
                .column(Column::exact(112.0))
                .column(Column::remainder())
                .column(Column::exact(30.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Domain");
                    });
                    header.col(|ui| {
                        ui.strong("Route");
                    });
                    header.col(|ui| {
                        ui.strong("Target");
                    });
                    header.col(|_| {});
                })
                .body(|mut body| {
                    for (index, row) in state.rows.iter_mut().enumerate() {
                        body.row(26.0, |mut table_row| {
                            table_row.col(|ui| {
                                if Self::domain_text_edit_with_validation(ui, &mut row.domain)
                                    .changed()
                                {
                                    changed = true;
                                }
                            });
                            table_row.col(|ui| {
                                let before = row.target_kind;
                                egui::ComboBox::from_id_salt((
                                    id_prefix,
                                    "virtual-dns-kind",
                                    index,
                                ))
                                .selected_text(match row.target_kind {
                                    VirtualDnsTargetKind::DnsAnswer => "DNS answer",
                                    VirtualDnsTargetKind::TunForward => "TUN forward",
                                    VirtualDnsTargetKind::WarpFiles => "Warp files",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut row.target_kind,
                                        VirtualDnsTargetKind::DnsAnswer,
                                        "DNS answer",
                                    );
                                    ui.selectable_value(
                                        &mut row.target_kind,
                                        VirtualDnsTargetKind::TunForward,
                                        "TUN forward",
                                    );
                                    ui.selectable_value(
                                        &mut row.target_kind,
                                        VirtualDnsTargetKind::WarpFiles,
                                        "Warp files",
                                    );
                                });
                                if row.target_kind != before {
                                    row.target = match row.target_kind {
                                        VirtualDnsTargetKind::DnsAnswer => "127.0.0.1".to_string(),
                                        VirtualDnsTargetKind::TunForward => {
                                            "127.0.0.1:8080".to_string()
                                        }
                                        VirtualDnsTargetKind::WarpFiles => {
                                            "/path/to/files".to_string()
                                        }
                                    };
                                    changed = true;
                                }
                            });
                            table_row.col(|ui| {
                                let response = match row.target_kind {
                                    VirtualDnsTargetKind::DnsAnswer => {
                                        Self::ip_text_edit_with_validation(ui, &mut row.target)
                                    }
                                    VirtualDnsTargetKind::TunForward => {
                                        Self::socket_addr_text_edit_with_validation(
                                            ui,
                                            &mut row.target,
                                        )
                                    }
                                    VirtualDnsTargetKind::WarpFiles => {
                                        Self::path_text_edit_with_validation(ui, &mut row.target)
                                    }
                                };
                                if response.changed() {
                                    changed = true;
                                }
                            });
                            table_row.col(|ui| {
                                if Self::remove_icon_button(ui, "Remove virtual DNS route")
                                    .clicked()
                                {
                                    remove_ix = Some(index);
                                }
                            });
                        });
                    }
                });

            if let Some(index) = remove_ix {
                state.rows.remove(index);
                changed = true;
            }
            ui.small("DNS answer returns an IPv4 address. TUN forward expects host:port. Warp files serves the selected directory over the intercepted domain.");
        });

        if changed {
            hot.dns.clear();
            hot.tun.clear();
            for row in &state.rows {
                if row.domain.trim().is_empty() || row.target.trim().is_empty() {
                    continue;
                }
                match row.target_kind {
                    VirtualDnsTargetKind::DnsAnswer => {
                        hot.dns.insert(row.domain.clone(), row.target.clone());
                    }
                    VirtualDnsTargetKind::TunForward | VirtualDnsTargetKind::WarpFiles => {
                        hot.tun
                            .insert(row.domain.clone(), Value::String(row.target.clone()));
                    }
                }
            }
            state.snapshot = Self::snapshot_virtual_dns(hot);
        }
        ui.data_mut(|d| d.insert_temp(state_id, state));
        changed
    }

    fn render_u32_map(
        ui: &mut egui::Ui,
        title: &str,
        map: &mut HashMap<u32, u32>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;
        let state_id = ui.make_persistent_id((id_prefix, title, "u32-map-editor-state"));
        let snapshot = Self::snapshot_u32_map(map);
        let mut state = ui
            .data_mut(|d| d.get_temp::<U32MapEditorState>(state_id))
            .unwrap_or_else(|| U32MapEditorState {
                rows: snapshot
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                snapshot: snapshot.clone(),
            });
        if state.snapshot != snapshot {
            state.rows = snapshot
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            state.snapshot = snapshot.clone();
        }
        let mut rows = state.rows;

        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(title);
                if ui.button("+ Add").clicked() {
                    if !rows
                        .iter()
                        .any(|(key_text, value_text)| key_text.is_empty() && value_text.is_empty())
                    {
                        rows.push((String::new(), String::new()));
                    }
                }
            });

            let mut remove_ixs = Vec::new();
            let mut empty_row_seen = false;
            egui::Grid::new(format!("{id_prefix}-{title}-u32-map-grid"))
                .num_columns(2)
                .spacing([4.0, 4.0])
                .striped(false)
                .show(ui, |ui| {
                    if title == "locals" {
                        ui.label("container port");
                        ui.label("host port");
                    } else {
                        ui.label("key");
                        ui.label("value");
                    }
                    ui.end_row();

                    for (i, (k_str, v_str)) in rows.iter_mut().enumerate() {
                        ui.push_id((id_prefix, title, i, "key"), |ui| {
                            if title == "locals" {
                                let k_valid =
                                    k_str.parse::<u32>().ok().is_some_and(Self::is_valid_port);
                                let k_bg_color = if k_str.is_empty() {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                } else if k_valid {
                                    egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
                                } else {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                };
                                let visuals = ui.visuals_mut();
                                let old_k_bg = visuals.extreme_bg_color;
                                visuals.extreme_bg_color = k_bg_color;
                                ui.text_edit_singleline(k_str);
                                ui.visuals_mut().extreme_bg_color = old_k_bg;
                            } else {
                                let k_bg_color = if k_str.is_empty() {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                } else if k_str.parse::<u32>().is_ok() {
                                    egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
                                } else {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                };
                                let visuals = ui.visuals_mut();
                                let old_k_bg = visuals.extreme_bg_color;
                                visuals.extreme_bg_color = k_bg_color;
                                ui.text_edit_singleline(k_str);
                                ui.visuals_mut().extreme_bg_color = old_k_bg;
                            }
                        });

                        ui.push_id((id_prefix, title, i, "value"), |ui| {
                            if title == "locals" {
                                let v_valid =
                                    v_str.parse::<u32>().ok().is_some_and(Self::is_valid_port);
                                let v_bg_color = if v_str.is_empty() {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                } else if v_valid {
                                    egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
                                } else {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                };
                                let visuals = ui.visuals_mut();
                                let old_v_bg = visuals.extreme_bg_color;
                                visuals.extreme_bg_color = v_bg_color;
                                ui.text_edit_singleline(v_str);
                                ui.visuals_mut().extreme_bg_color = old_v_bg;
                            } else {
                                let v_bg_color = if v_str.is_empty() {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                } else if v_str.parse::<u32>().is_ok() {
                                    egui::Color32::from_rgba_unmultiplied(100, 200, 100, 25)
                                } else {
                                    egui::Color32::from_rgba_unmultiplied(200, 100, 100, 25)
                                };
                                let visuals = ui.visuals_mut();
                                let old_v_bg = visuals.extreme_bg_color;
                                visuals.extreme_bg_color = v_bg_color;
                                ui.text_edit_singleline(v_str);
                                ui.visuals_mut().extreme_bg_color = old_v_bg;
                            }
                        });

                        if k_str.is_empty() && v_str.is_empty() {
                            if empty_row_seen {
                                remove_ixs.push(i);
                            } else {
                                empty_row_seen = true;
                            }
                        }
                        if !(k_str.is_empty() && v_str.is_empty()) {
                            // Invalid non-empty rows stay visible so the user can fix them.
                        }
                        ui.end_row();
                    }
                });

            for &ix in remove_ixs.iter().rev() {
                rows.remove(ix);
            }
        });

        let mut next_map = HashMap::new();
        for (k_str, v_str) in &rows {
            let (Ok(k), Ok(v)) = (k_str.parse::<u32>(), v_str.parse::<u32>()) else {
                continue;
            };
            if title == "locals" && (!Self::is_valid_port(k) || !Self::is_valid_port(v)) {
                continue;
            }
            next_map.insert(k, v);
        }

        let next_snapshot = Self::snapshot_u32_map(&next_map);
        if next_snapshot != snapshot {
            *map = next_map;
            changed = true;
        }

        state.snapshot = next_snapshot;
        state.rows = rows;
        ui.data_mut(|d| d.insert_temp(state_id, state));
        changed
    }

    fn render_path_map(
        ui: &mut egui::Ui,
        title: &str,
        map: &mut HashMap<std::path::PathBuf, std::path::PathBuf>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;
        let state_id = ui.make_persistent_id((id_prefix, title, "path-map-editor-state"));
        let snapshot = Self::snapshot_path_map(map);
        let mut state = ui
            .data_mut(|d| d.get_temp::<StringMapEditorState>(state_id))
            .unwrap_or_else(|| StringMapEditorState {
                pairs: snapshot.clone(),
                snapshot: snapshot.clone(),
            });
        if state.snapshot != snapshot {
            state.pairs = snapshot.clone();
            state.snapshot = snapshot.clone();
        }
        let mut pairs = state.pairs;

        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(title);
                if ui.button("+ Add").clicked() {
                    pairs.push(("/source".to_string(), "/target".to_string()));
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, (src, dst)) in pairs.iter_mut().enumerate() {
                ui.push_id((id_prefix, title, i), |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        if Self::path_text_edit_with_validation(ui, src).changed() {
                            changed = true;
                        }
                        if Self::path_text_edit_with_validation(ui, dst).changed() {
                            changed = true;
                        }
                    });
                    if src.is_empty() || dst.is_empty() {
                        remove_ixs.push(i);
                    }
                });
            }
            for &ix in remove_ixs.iter().rev() {
                pairs.remove(ix);
                changed = true;
            }
        });

        if changed {
            map.clear();
            let mut ordered_pairs = Vec::new();
            for (src, dst) in pairs {
                if !src.trim().is_empty() {
                    ordered_pairs.push((src.clone(), dst.clone()));
                    map.insert(src.into(), dst.into());
                }
            }
            state.snapshot = Self::snapshot_path_map(map);
            state.pairs = ordered_pairs;
        } else {
            state.pairs = pairs;
        }
        ui.data_mut(|d| d.insert_temp(state_id, state));
        changed
    }

    fn render_shell_args_list(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        list: &mut Vec<ShellArgs>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("daemons");
                if ui.button("+ Add").clicked() {
                    list.push(ShellArgs::default());
                    changed = true;
                }
            });

            let mut remove_ix = None;
            for (i, args) in list.iter_mut().enumerate() {
                ui.push_id((id_prefix, "daemon", i), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", i + 1));
                        if Self::remove_icon_button(ui, "Remove daemon").clicked() {
                            remove_ix = Some(i);
                        }
                    });
                    if Self::render_shell_args(ui, int_input, args, "shell args") {
                        changed = true;
                    }
                });
            }
            if let Some(ix) = remove_ix {
                list.remove(ix);
                changed = true;
            }
        });
        changed
    }

    fn render_launchable_apps_list(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        apps: &mut Vec<LaunchableApp>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("applications");
                if ui.button("+ Add").clicked() {
                    apps.push(LaunchableApp::default());
                    changed = true;
                }
            });

            let mut remove_ix = None;
            for (i, app) in apps.iter_mut().enumerate() {
                ui.push_id((id_prefix, "application", i), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", i + 1));
                        ui.label("name");
                        if ui.text_edit_singleline(&mut app.name).changed() {
                            changed = true;
                        }
                        if Self::remove_icon_button(ui, "Remove application").clicked() {
                            remove_ix = Some(i);
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("description");
                        if ui.text_edit_singleline(&mut app.description).changed() {
                            changed = true;
                        }
                    });
                    if Self::render_shell_args(ui, int_input, &mut app.command, "command") {
                        changed = true;
                    }
                });
            }
            if let Some(i) = remove_ix {
                apps.remove(i);
                changed = true;
            }
        });
        changed
    }

    fn render_hotconfig_form(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        id_prefix: &str,
        hot: &mut HotConfig,
    ) -> bool {
        let mut changed = false;

        if Self::render_virtual_dns_table(ui, hot, id_prefix) {
            changed = true;
        }
        if Self::render_string_map(ui, "devs", &mut hot.devs, id_prefix) {
            changed = true;
        }
        if Self::render_u32_map(ui, "locals", &mut hot.locals, id_prefix) {
            changed = true;
        }
        if Self::render_path_map(ui, "mnt", &mut hot.mnt, id_prefix) {
            changed = true;
        }
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("display backends");
                ui.weak("mount host display sockets into the sandbox");
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .toggle_value(&mut hot.x11, "X11")
                    .on_hover_text("Mount /tmp/.X11-unix and XAUTHORITY")
                    .changed()
                {
                    changed = true;
                }
                if ui
                    .toggle_value(&mut hot.wayland, "Wayland")
                    .on_hover_text("Mount the host Wayland display socket")
                    .changed()
                {
                    changed = true;
                }
            });
        });
        if Self::render_mount_list(ui, &mut hot.mounts, "mounts") {
            changed = true;
        }
        if Self::render_shell_args_list(ui, int_input, &mut hot.daemons, id_prefix) {
            changed = true;
        }
        if Self::render_launchable_apps_list(ui, int_input, &mut hot.applications, id_prefix) {
            changed = true;
        }

        section_frame(ui, |ui| {
            ui.strong("dns runtime");
            let captured_resolv_conf_dns = "100.68.0.1";
            let mut use_internal_dns = hot.resolv_conf_dns
                == nsproxy_core::INTERNAL_RESOLV_CONF_DNS
                && !hot.dns_capture_enabled();
            let mut dns_capture_enabled = hot.dns_capture_enabled();
            let dns_capture_label = if dns_capture_enabled {
                "capture all dns"
            } else {
                "no dns capture"
            };
            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut use_internal_dns, "route to local dns")
                    .changed()
                {
                    if use_internal_dns {
                        hot.resolv_conf_dns = nsproxy_core::INTERNAL_RESOLV_CONF_DNS.to_string();
                        hot.set_dns_capture_enabled(false);
                    } else {
                        if hot.resolv_conf_dns == nsproxy_core::INTERNAL_RESOLV_CONF_DNS {
                            hot.resolv_conf_dns =
                                nsproxy_core::CAPTURED_RESOLV_CONF_DNS.to_string();
                        }
                        hot.set_dns_capture_enabled(true);
                    }
                    changed = true;
                }

                if ui
                    .toggle_value(&mut dns_capture_enabled, dns_capture_label)
                    .changed()
                {
                    hot.set_dns_capture_enabled(dns_capture_enabled);
                    if dns_capture_enabled {
                        hot.resolv_conf_dns = captured_resolv_conf_dns.to_string();
                    }
                    changed = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("resolv_conf_dns");
                let mut resolv_conf_dns = hot.resolv_conf_dns.clone();
                if ui.text_edit_singleline(&mut resolv_conf_dns).changed() {
                    hot.resolv_conf_dns = resolv_conf_dns;
                    changed = true;
                }
            });

            ui.horizontal_wrapped(|ui| {
                if ui.button("127.0.0.1").clicked() {
                    hot.resolv_conf_dns = "127.0.0.1".to_string();
                    changed = true;
                }
                if ui.button("100.68.0.1").clicked() {
                    hot.resolv_conf_dns = captured_resolv_conf_dns.to_string();
                    changed = true;
                }
            });
            ui.small("DNS edits stay local until Save.");
        });

        section_frame(ui, |ui| {
            ui.strong("traffic diagnostics");
            ui.horizontal(|ui| {
                ui.label("finished connection retention");
                if ui
                    .add(
                        egui::Slider::new(&mut hot.diag_conn_persist_secs, 0..=3600)
                            .suffix(" s"),
                    )
                    .on_hover_text(
                        "Keep completed TCP/UDP activity visible for this many seconds; active connections are retained.",
                    )
                    .changed()
                {
                    changed = true;
                }
            });
        });

        changed
    }

    fn render_hotconfig_editor_split(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        id_prefix: &str,
        hot: &mut HotConfig,
        json_text: &mut String,
        json_error: &mut Option<String>,
        demo_display: Option<(HotConfig, String)>,
    ) -> bool {
        if let Some((mut display_hot, mut display_json)) = demo_display {
            ui.columns(2, |columns| {
                columns[0].heading("Form");
                egui::ScrollArea::vertical()
                    .id_salt(format!("{}-form-scroll", id_prefix))
                    .min_scrolled_height(560.0)
                    .show(&mut columns[0], |ui| {
                        ui.add_enabled_ui(false, |ui| {
                            Self::render_hotconfig_form(ui, int_input, id_prefix, &mut display_hot);
                        });
                    });

                columns[1].heading("Formatted JSON");
                egui::ScrollArea::vertical()
                    .id_salt(format!("{}-json-scroll", id_prefix))
                    .min_scrolled_height(560.0)
                    .show(&mut columns[1], |ui| {
                        ui.add_enabled_ui(false, |ui| {
                            CodeEditor::default()
                                .id_source(format!("{}-json-editor", id_prefix))
                                .with_rows(40)
                                .with_theme(ColorTheme::GRUVBOX)
                                .with_numlines(true)
                                .with_ui_fontsize(ui)
                                .show(ui, &mut display_json, &json_syntax());
                        });
                    });
            });
            return false;
        }

        let mut changed = false;
        ui.columns(2, |columns| {
            columns[0].heading("Form");
            egui::ScrollArea::vertical()
                .id_salt(format!("{}-form-scroll", id_prefix))
                .min_scrolled_height(560.0)
                .show(&mut columns[0], |ui| {
                    if Self::render_hotconfig_form(ui, int_input, id_prefix, hot) {
                        *json_text =
                            serde_json::to_string_pretty(hot).unwrap_or_else(|_| "{}".to_string());
                        *json_error = None;
                        changed = true;
                    }
                });

            columns[1].heading("Formatted JSON");
            egui::ScrollArea::vertical()
                .id_salt(format!("{}-json-scroll", id_prefix))
                .min_scrolled_height(560.0)
                .show(&mut columns[1], |ui| {
                    let mut editor = CodeEditor::default()
                        .id_source(format!("{}-json-editor", id_prefix))
                        .with_rows(40)
                        .with_theme(ColorTheme::GRUVBOX)
                        .with_numlines(true)
                        .with_ui_fontsize(ui);
                    let (output, _) = editor.show(ui, json_text, &json_syntax());
                    if output.response.changed() {
                        match serde_json::from_str::<HotConfig>(json_text) {
                            Ok(parsed) => {
                                *hot = parsed;
                                *json_error = None;
                                changed = true;
                            }
                            Err(err) => {
                                *json_error = Some(format!("JSON error: {err}"));
                            }
                        }
                    }
                    if let Some(err) = json_error.as_ref() {
                        ui.colored_label(egui::Color32::LIGHT_RED, err);
                    }
                });
        });
        changed
    }

    fn render_shell_args(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        sargs: &mut ShellArgs,
        title: &str,
    ) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.strong(title);
            if Self::render_optional_u32(ui, int_input, "uid", &mut sargs.uid, false) {
                changed = true;
            }
            if Self::render_optional_u32(ui, int_input, "gid", &mut sargs.gid, false) {
                changed = true;
            }
            if Self::render_optional_text(ui, "shell", &mut sargs.shell) {
                changed = true;
            }

            let mut cwd_string = sargs
                .cwd
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            ui.horizontal(|ui| {
                let mut enabled = sargs.cwd.is_some();
                if ui.checkbox(&mut enabled, "cwd").changed() {
                    changed = true;
                    if enabled && sargs.cwd.is_none() {
                        sargs.cwd = Some("/".into());
                        cwd_string = "/".to_string();
                    }
                    if !enabled {
                        sargs.cwd = None;
                    }
                }
                if enabled && ui.text_edit_singleline(&mut cwd_string).changed() {
                    sargs.cwd = Some(cwd_string.clone().into());
                    changed = true;
                }
            });

            let mut gids_csv = sargs
                .gids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            ui.horizontal(|ui| {
                ui.label("gids csv");
                if ui.text_edit_singleline(&mut gids_csv).changed() {
                    let parsed = gids_csv
                        .split(',')
                        .filter_map(|s| {
                            let t = s.trim();
                            if t.is_empty() {
                                None
                            } else {
                                t.parse::<u32>().ok()
                            }
                        })
                        .collect::<Vec<_>>();
                    sargs.gids = parsed;
                    changed = true;
                }
            });

            if Self::render_args_array_editor(ui, &mut sargs.args, "shell-args") {
                changed = true;
            }
        });
        changed
    }

    /// Renders `args` as an argv array rather than a shell-parsed string.
    /// This preserves empty arguments and arguments containing whitespace.
    fn render_args_array_editor(
        ui: &mut egui::Ui,
        args: &mut Vec<String>,
        id_prefix: &str,
    ) -> bool {
        let mut changed = false;

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong("arguments");
            ui.weak("argv array; one item per field");
        });

        let mut remove_ix = None;
        for (index, arg) in args.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("[{index}]"))
                        .monospace()
                        .weak()
                        .size(11.0),
                );
                if ui
                    .add_sized(
                        egui::vec2(
                            (ui.available_width() - 24.0)
                                .clamp(0.0, SPAWN_ARGS_TEXT_WIDTH),
                            ui.spacing().interact_size.y,
                        ),
                        egui::TextEdit::singleline(arg),
                    )
                    .changed()
                {
                    changed = true;
                }
                if Self::remove_icon_button(ui, "Remove argument").clicked() {
                    remove_ix = Some(index);
                }
            });
        }

        if let Some(index) = remove_ix {
            args.remove(index);
            changed = true;
        }

        ui.push_id((id_prefix, "add-arg"), |ui| {
            if ui
                .add(egui::Button::new("+ Add argument").small())
                .clicked()
            {
                args.push(String::new());
                changed = true;
            }
        });

        if args.is_empty() {
            ui.colored_label(Color32::from_rgb(220, 170, 90), "No arguments configured.");
        }

        changed
    }

    fn render_spawn_args_gadget(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        args: &mut diag::SpawnArgs,
        id_prefix: &str,
        read_only: bool,
    ) -> bool {
        let mut changed = false;
        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Spawn arguments");
                    ui.weak("Process identity, execution context, and argv.");
                });
                if !read_only {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mut uid_gid_value_changed = false;
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("Root").monospace().size(11.0),
                                )
                                .small(),
                            )
                            .on_hover_text("uid=0, gid=0, clear gids")
                            .clicked()
                        {
                            args.uid = Some(0);
                            args.gid = Some(0);
                            args.gids = vec![];
                            changed = true;
                            uid_gid_value_changed = true;
                        }
                        ui.add_space(4.0);
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("Current user").size(11.0))
                                    .small(),
                            )
                            .on_hover_text("Reset uid/gid to current user")
                            .clicked()
                        {
                            apply_default_spawn_user(args);
                            changed = true;
                            uid_gid_value_changed = true;
                        }
                        // stash so field renders below can pick it up
                        ui.data_mut(|d| {
                            d.insert_temp(
                                egui::Id::new((id_prefix, "uid_gid_changed")),
                                uid_gid_value_changed,
                            )
                        });
                    });
                }
            });

            if read_only {
                egui::Grid::new((id_prefix, "ro-grid"))
                    .num_columns(2)
                    .spacing([8.0, 2.0])
                    .show(ui, |ui| {
                        let pairs = [
                            ("uid", format!("{:?}", args.uid)),
                            ("gid", format!("{:?}", args.gid)),
                            ("exec", format!("{:?}", args.exec)),
                            ("cwd", format!("{:?}", args.cwd)),
                            ("gids", format!("{:?}", args.gids)),
                            ("ringbuf_size", format!("{:?}", args.ringbuf_size)),
                        ];
                        for (k, v) in &pairs {
                            ui.weak(*k);
                            ui.monospace(v);
                            ui.end_row();
                        }
                    });
                if !args.args.is_empty() {
                    ui.add_space(2.0);
                    ui.weak("argv");
                    for (i, arg) in args.args.iter().enumerate() {
                        ui.monospace(format!("  [{i}]  {arg}"));
                    }
                }
                return;
            }

            let uid_gid_value_changed = ui
                .data_mut(|d| d.remove_temp::<bool>(egui::Id::new((id_prefix, "uid_gid_changed"))))
                .unwrap_or(false);

            ui.add_space(6.0);
            ui.weak("Identity");
            if Self::render_optional_u32(
                ui,
                int_input,
                "uid",
                &mut args.uid,
                uid_gid_value_changed,
            ) {
                changed = true;
            }
            if Self::render_optional_u32(
                ui,
                int_input,
                "gid",
                &mut args.gid,
                uid_gid_value_changed,
            ) {
                changed = true;
            }
            if Self::render_optional_text_with_width(
                ui,
                "exec",
                &mut args.exec,
                SPAWN_ARGS_TEXT_WIDTH,
            ) {
                changed = true;
            }

            ui.add_space(6.0);
            ui.separator();
            ui.weak("Execution context");
            let mut cwd_text = args
                .cwd
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            ui.horizontal(|ui| {
                let mut enabled = args.cwd.is_some();
                if ui.checkbox(&mut enabled, "cwd").changed() {
                    changed = true;
                    if enabled && args.cwd.is_none() {
                        args.cwd = Some(std::path::PathBuf::from("/"));
                        cwd_text = "/".to_string();
                    }
                    if !enabled {
                        args.cwd = None;
                    }
                }
                if enabled {
                    if ui
                        .add_sized(
                            egui::vec2(
                                SPAWN_ARGS_TEXT_WIDTH.min(ui.available_width().max(0.0)),
                                ui.spacing().interact_size.y,
                            ),
                            egui::TextEdit::singleline(&mut cwd_text)
                        )
                        .changed()
                    {
                        args.cwd = Some(std::path::PathBuf::from(cwd_text.clone()));
                        changed = true;
                    }
                }
            });

            let mut gids_csv = args
                .gids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            ui.horizontal(|ui| {
                ui.weak("gids");
                if ui
                    .add_sized(
                        egui::vec2(
                            SPAWN_ARGS_TEXT_WIDTH.min(ui.available_width().max(0.0)),
                            ui.spacing().interact_size.y,
                        ),
                        egui::TextEdit::singleline(&mut gids_csv)
                            .hint_text("comma-separated, e.g. 10,104"),
                    )
                    .changed()
                {
                    args.gids = gids_csv
                        .split(',')
                        .filter_map(|s| {
                            let t = s.trim();
                            if t.is_empty() {
                                None
                            } else {
                                t.parse::<u32>().ok()
                            }
                        })
                        .collect();
                    changed = true;
                }
            });

            if Self::render_optional_u32_with_default(
                ui,
                int_input,
                "ringbuf_size",
                &mut args.ringbuf_size,
                false,
                diag::RAW_LOG_RING_CAP as u32,
            ) {
                changed = true;
            }

            if Self::render_args_array_editor(ui, &mut args.args, id_prefix) {
                changed = true;
            }

            ui.push_id((id_prefix, "spawnargs-json"), |ui| {
                if let Ok(json) = serde_json::to_string_pretty(args) {
                    ui.collapsing("Raw JSON", |ui| {
                        ui.monospace(json);
                    });
                }
            });
        });
        changed
    }

    fn render_template_form(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;

        ui.horizontal(|ui| {
            ui.label("schema");
            if ui
                .add(
                    egui::DragValue::new(&mut self.profile_editor_template.schema)
                        .range(1..=u32::MAX),
                )
                .changed()
            {
                changed = true;
            }
        });

        ui.horizontal(|ui| {
            ui.label("sandbox_mode");
            if ui
                .radio_value(
                    &mut self.profile_editor_template.sandbox_mode,
                    SandboxMode::Overlay,
                    "Overlay",
                )
                .changed()
            {
                changed = true;
            }
            if ui
                .radio_value(
                    &mut self.profile_editor_template.sandbox_mode,
                    SandboxMode::Pivot,
                    "Pivot",
                )
                .changed()
            {
                changed = true;
            }
        });

        if Self::render_mount_list(ui, &mut self.profile_editor_template.mounts, "mounts") {
            changed = true;
        }
        if Self::render_chmod_list(
            ui,
            &mut self.int_input,
            &mut self.profile_editor_template.chmod,
        ) {
            changed = true;
        }
        if Self::render_env_map(ui, &mut self.profile_editor_template.env) {
            changed = true;
        }

        if ui
            .checkbox(&mut self.profile_editor_template.inherit_env, "inherit_env")
            .changed()
        {
            changed = true;
        }
        if Self::render_path_field(ui, "hot", &mut self.profile_editor_template.hot, "hot") {
            changed = true;
        }

        let mut refresh_hot_init_json = false;
        section_frame(ui, |ui| {
            let mut enabled = self.profile_editor_template.hot_init.is_some();
            if ui.checkbox(&mut enabled, "hot_init").changed() {
                changed = true;
                if enabled && self.profile_editor_template.hot_init.is_none() {
                    self.profile_editor_template.hot_init = Some(default_hotconfig());
                    refresh_hot_init_json = true;
                }
                if !enabled {
                    self.profile_editor_template.hot_init = None;
                    self.profile_editor_hot_init_error = None;
                }
            }

            if enabled {
                ui.label("hot_init (same form as Hotconfig tab)");
                let mut hot_init = self
                    .profile_editor_template
                    .hot_init
                    .clone()
                    .unwrap_or_default();
                if Self::render_hotconfig_form(
                    ui,
                    &mut self.int_input,
                    "profile-hot-init",
                    &mut hot_init,
                ) {
                    self.profile_editor_template.hot_init = Some(hot_init);
                    self.profile_editor_hot_init_json = self
                        .profile_editor_template
                        .hot_init
                        .as_ref()
                        .and_then(|h| serde_json::to_string_pretty(h).ok())
                        .unwrap_or_else(|| default_hotconfig_text());
                    self.profile_editor_hot_init_error = None;
                    changed = true;
                }
                if let Some(err) = &self.profile_editor_hot_init_error {
                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                }
            }
        });
        if refresh_hot_init_json {
            self.refresh_hot_init_json_from_template();
        }

        if Self::render_shell_args(
            ui,
            &mut self.int_input,
            &mut self.profile_editor_template.sargs,
            "sargs",
        ) {
            changed = true;
        }
        if Self::render_optional_text(
            ui,
            "browser_profile",
            &mut self.profile_editor_template.browser_profile,
        ) {
            changed = true;
        }

        changed
    }

    fn get_selected_profile(&self) -> Option<&supervisor::ContainerState> {
        self.selected_profile
            .as_ref()
            .and_then(|name| self.snapshot.profiles.get(name))
    }

    fn get_selected_profile_mut(&mut self) -> Option<&mut supervisor::ContainerState> {
        if let Some(name) = self.selected_profile.clone() {
            self.snapshot.profiles.get_mut(&name)
        } else {
            None
        }
    }

    fn reload_all_ns_alive(&self) {
        info!("requesting authoritative profile rescan from disk");
        self.supervisor.send(supervisor::SupervisorCommand::Init);
    }

    fn apply_filters(&mut self) {
        let now = Instant::now();

        // First, filter proxies
        self.filtered_proxy_ids = self
            .proxies
            .iter()
            .filter(|(_, item)| {
                // Filter by type if any types are selected
                if !self.proxy_filters.selected_types.is_empty() {
                    let proxy_type = ProxyType::from_uplink_proxy(&item.base);
                    if !self.proxy_filters.selected_types.contains(&proxy_type) {
                        return false;
                    }
                }

                true
            })
            .map(|(id, _)| id.clone())
            .collect();

        // Then, apply sorting if interval has elapsed or sort mode changed
        let should_resort =
            if let Some(freq_duration) = self.proxy_filters.sort_frequency.duration() {
                now.elapsed() >= freq_duration
            } else {
                false
            };

        if should_resort || self.proxy_filters.sort_column != SortColumn::None {
            self.sort_filtered_proxies();
            self.last_sort_time = now;
        }
        self.proxy_table_entries = build_proxy_table_entries(
            &self.filtered_proxy_ids,
            &self.proxy_groups,
            &self.expanded_proxy_groups,
            &self.user_groups,
        );
        self.proxy_group_controls = build_proxy_group_controls(&self.proxy_table_entries);
        self.proxy_table_entries_dirty = false;
    }

    fn sort_filtered_proxies(&mut self) {
        let proxies = &self.proxies;
        let sort_column = self.proxy_filters.sort_column;
        let sort_direction = self.proxy_filters.sort_direction;

        let live_stats: HashMap<ProxyID, ProxyStats> = self
            .selected_profile
            .as_ref()
            .and_then(|p| self.snapshot.profiles.get(p))
            .map(|p| p.proxy_stats.clone())
            .unwrap_or_default();

        self.filtered_proxy_ids.sort_by(|a, b| {
            let item_a = match proxies.get(a) {
                Some(item) => item,
                None => return std::cmp::Ordering::Equal,
            };
            let item_b = match proxies.get(b) {
                Some(item) => item,
                None => return std::cmp::Ordering::Equal,
            };

            let order = match sort_column {
                SortColumn::None => std::cmp::Ordering::Equal,
                SortColumn::Latency => {
                    let lat_a = item_a.latency_ms.unwrap_or(u64::MAX);
                    let lat_b = item_b.latency_ms.unwrap_or(u64::MAX);
                    lat_a.cmp(&lat_b)
                }
                SortColumn::FailRate => {
                    let success_a = live_stats
                        .get(a)
                        .and_then(|s| s.past_hour().success_rate())
                        .unwrap_or(1.);
                    let success_b = live_stats
                        .get(b)
                        .and_then(|s| s.past_hour().success_rate())
                        .unwrap_or(1.);
                    success_a
                        .partial_cmp(&success_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }
            };

            if sort_direction == SortDirection::Descending {
                order.reverse()
            } else {
                order
            }
        });
    }

    fn on_sort_column_clicked(&mut self, column: SortColumn) {
        if self.proxy_filters.sort_column == column {
            // Clicking the same column toggles direction
            self.proxy_filters.sort_direction = match self.proxy_filters.sort_direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            // Clicking a new column switches to that column with ascending order
            self.proxy_filters.sort_column = column;
            self.proxy_filters.sort_direction = SortDirection::Ascending;
        }
        // Always sort immediately on header click
        self.sort_filtered_proxies();
        self.last_sort_time = Instant::now();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.close_swap_pty_window();
        self.close_dedicated_pty_windows();
        info!("app drop started; shutting down tokio runtime in background");
        if let Some(rt) = self.tokio_rt.take() {
            rt.shutdown_background();
        }
        info!("app drop finished");
    }
}

fn default_hotconfig_text() -> String {
    serde_json::to_string_pretty(&default_hotconfig()).unwrap_or_else(|_| "{}".to_string())
}

fn default_profile_text() -> String {
    serde_json::to_string_pretty(&TemplateConfig::default()).unwrap_or_else(|_| "{}".to_string())
}

// ── Wizard template factories ─────────────────────────────────────────────────

/// Build a (TemplateConfig, HotConfig) pair for the given wizard template kind.
/// All values are constructed from Rust native types — no JSON strings.
fn wizard_build_template(
    kind: WizardTemplateKind,
    pivot_apps: &std::collections::BTreeSet<PivotAppKind>,
) -> (TemplateConfig, HotConfig) {
    match kind {
        WizardTemplateKind::OverlayBasic => wizard_template_overlay_basic(),
        WizardTemplateKind::Pivot => wizard_build_pivot_template(pivot_apps),
    }
}

/// Overlay sandbox — maximum host-compatibility (mirrors /nsp3/config/basic).
///
/// Pre-configures:
/// - Port 9909 (Geph SOCKS5) forwarded into the container
/// - Internal DNS server at 127.0.0.1 (nsproxy resolves hostnames via the proxy)
fn wizard_template_overlay_basic() -> (TemplateConfig, HotConfig) {
    let hot = HotConfig {
        locals: [(9909u32, 9909u32)].into_iter().collect(),
        resolv_conf_dns: "127.0.0.1".to_string(),
        ..HotConfig::default()
    };
    let template = TemplateConfig {
        schema: TemplateConfig::VERSION, // [schema-bump:wizard]
        sandbox_mode: SandboxMode::Overlay,
        mounts: vec![],
        chmod: vec![],
        env: HashMap::new(),
        inherit_env: true,
        hot: PathBuf::from("@/hot.json"),
        hot_init: Some(hot.clone()),
        sargs: nsproxy_core::shell::ShellArgs::default(),
        browser_profile: None,
        dbus: DbusMode::Container,
        rootfs: Rootfs::Default,
        fcitx_default_input_method: None,
    };
    (template, hot)
}

/// Pivot sandbox with selected app modules merged additively.
///
/// Shared graphical infrastructure (Wayland, PipeWire, PulseAudio, dconf,
/// systemd, cgroups) is included once whenever any graphical app is selected.
/// Mount targets are deduplicated so running Firefox + Signal doesn't double-mount sockets.
fn wizard_build_pivot_template(
    apps: &std::collections::BTreeSet<PivotAppKind>,
) -> (TemplateConfig, HotConfig) {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let run_user = format!("/run/user/{}", uid);

    let mut mounts: Vec<ProfileMount> = Vec::new();
    let mut chmod: Vec<ProfileChmod> = vec![
        ProfileChmod {
            path: PathBuf::from("/home"),
            mode: None,
            uid: Some(uid),
            gid: Some(gid),
            mkdir: true,
        },
        ProfileChmod {
            path: PathBuf::from(&run_user),
            mode: None,
            uid: Some(uid),
            gid: Some(gid),
            mkdir: false,
        },
    ];
    let mut env: HashMap<String, String> = HashMap::new();
    let has_graphical = !apps.is_empty();

    if apps.contains(&PivotAppKind::Firefox) {
        mounts.extend([
            ProfileMount {
                source: PathBuf::from("@/.mozilla/firefox"),
                target: PathBuf::from("~/.mozilla/firefox"),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from("@/.cache/mozilla/firefox"),
                target: PathBuf::from("~/.cache/mozilla/firefox"),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from("@/.mozilla/native-messaging-hosts"),
                target: PathBuf::from("~/.mozilla/native-messaging-hosts"),
                read_only: false,
                recursive: true,
                skip_missing: true,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/gvfs", run_user)),
                target: PathBuf::from(format!("{}/gvfs", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
        ]);
        chmod.extend([
            ProfileChmod {
                path: PathBuf::from("~/.mozilla"),
                mode: None,
                uid: Some(uid),
                gid: Some(gid),
                mkdir: true,
            },
            ProfileChmod {
                path: PathBuf::from("~/.cache"),
                mode: None,
                uid: Some(uid),
                gid: Some(gid),
                mkdir: true,
            },
        ]);
    }

    if apps.contains(&PivotAppKind::SignalAppImage) {
        mounts.push(ProfileMount {
            source: PathBuf::from("@/.config/Signal AppImage"),
            target: PathBuf::from("~/.config/Signal AppImage"),
            read_only: false,
            recursive: true,
            skip_missing: false,
        });
        chmod.push(ProfileChmod {
            path: PathBuf::from("~/.config"),
            mode: None,
            uid: Some(uid),
            gid: Some(gid),
            mkdir: true,
        });
    }

    if has_graphical {
        // Shared graphical/audio infrastructure — added once regardless of which apps are selected
        mounts.extend([
            ProfileMount {
                source: PathBuf::from(format!("{}/wayland-0", run_user)),
                target: PathBuf::from(format!("{}/wayland-0", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: true,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/wayland-1", run_user)),
                target: PathBuf::from(format!("{}/wayland-1", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: true,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/pipewire-0", run_user)),
                target: PathBuf::from(format!("{}/pipewire-0", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/pipewire-0-manager", run_user)),
                target: PathBuf::from(format!("{}/pipewire-0-manager", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/pulse", run_user)),
                target: PathBuf::from(format!("{}/pulse", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/dconf", run_user)),
                target: PathBuf::from(format!("{}/dconf", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from(format!("{}/systemd", run_user)),
                target: PathBuf::from(format!("{}/systemd", run_user)),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from("/run/systemd"),
                target: PathBuf::from("/run/systemd"),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
            ProfileMount {
                source: PathBuf::from("/sys/fs/cgroup"),
                target: PathBuf::from("/sys/fs/cgroup"),
                read_only: false,
                recursive: true,
                skip_missing: false,
            },
        ]);
        env.extend([
            ("NO_AT_BRIDGE".to_string(), "1".to_string()),
            ("GIO_USE_VFS".to_string(), "local".to_string()),
        ]);
    }

    // Deduplicate mounts by target so combining multiple apps doesn't double-mount shared sockets.
    let mut seen_targets = std::collections::HashSet::new();
    let mounts: Vec<ProfileMount> = mounts
        .into_iter()
        .filter(|m| seen_targets.insert(m.target.clone()))
        .collect();

    let dbus = DbusMode::Container;
    let browser_profile = if apps.contains(&PivotAppKind::Firefox) {
        Some("firefox".to_string())
    } else {
        None
    };

    let hot = default_hotconfig();
    let template = TemplateConfig {
        schema: TemplateConfig::VERSION, // [schema-bump:wizard]
        sandbox_mode: SandboxMode::Pivot,
        mounts,
        chmod,
        env,
        inherit_env: true,
        hot: PathBuf::from("@/hot.json"),
        hot_init: Some(hot.clone()),
        sargs: nsproxy_core::shell::ShellArgs::default(),
        browser_profile,
        dbus,
        rootfs: Rootfs::Default,
        fcitx_default_input_method: None,
    };
    (template, hot)
}

fn default_constants_text() -> String {
    serde_json::to_string_pretty(&PersonalConstants::default()).unwrap_or_else(|_| "{}".to_string())
}

fn json_syntax() -> Syntax {
    Syntax::new("json")
        .with_case_sensitive(true)
        .with_comment("//")
        .with_keywords(["true", "false", "null"])
}

fn load_constants_json<F: FnOnce() -> String>(fallback: Option<F>) -> LoadResult {
    let path = state_paths::constants_config();
    match std::fs::read_to_string(path) {
        Ok(content) => LoadResult {
            text: content,
            error: None,
        },
        Err(_) => LoadResult {
            text: fallback.map_or_else(|| default_constants_text(), |f| f()),
            error: None,
        },
    }
}

fn load_profile_json<F: FnOnce() -> String>(profile: &str, fallback: Option<F>) -> LoadResult {
    let path = state_paths::profile_config(profile);
    if !path.exists() {
        return LoadResult {
            text: fallback.map_or_else(|| default_profile_text(), |f| f()),
            error: None,
        };
    }
    match nsproxy_core::TemplateConfig::load(&path) {
        Ok(parsed) => LoadResult {
            text: serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| default_profile_text()),
            error: None,
        },
        Err(err) => LoadResult {
            text: default_profile_text(),
            error: Some(format!("Invalid profile JSON on disk: {err}")),
        },
    }
}

fn load_hotconfig_json<F: FnOnce() -> String>(profile: &str, fallback: Option<F>) -> LoadResult {
    let path = state_paths::hot_config(profile);
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => {
            return LoadResult {
                text: fallback.map_or_else(|| default_hotconfig_text(), |f| f()),
                error: None,
            };
        }
    };
    match serde_json::from_str::<HotConfig>(&content) {
        Ok(parsed) => LoadResult {
            text: serde_json::to_string_pretty(&parsed).unwrap_or(content),
            error: None,
        },
        Err(err) => LoadResult {
            text: default_hotconfig_text(),
            error: Some(format!("Invalid hotconfig JSON on disk: {err}")),
        },
    }
}

fn load_scope_from_disk<FH, FP>(
    profile: &ContainerName,
    fallback_hot: Option<FH>,
    fallback_profile: Option<FP>,
) -> (String, String, Option<String>, Option<String>)
where
    FH: FnOnce() -> String,
    FP: FnOnce() -> String,
{
    let hot = load_hotconfig_json(profile.as_str(), None::<FH>);
    let profile_json = load_profile_json(profile.as_str(), None::<FP>);
    (hot.text, profile_json.text, hot.error, profile_json.error)
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        use egui::Color32;

        let ctx = ui.ctx().clone();
        let frame_started = Instant::now();
        self.ui_frame_seq = self.ui_frame_seq.wrapping_add(1);
        if self.last_frame_progress_log.elapsed() >= Duration::from_secs(5) {
            info!(
                frame = self.ui_frame_seq,
                tab = self.right_tab_label(),
                profile = self.selected_profile.as_deref().unwrap_or("<global>"),
                profiles = self.snapshot.profiles.len(),
                proxies = self.proxies.len(),
                "ui frame heartbeat"
            );
            self.last_frame_progress_log = Instant::now();
        }

        // Drain any reload results pushed by the background thread.
        if let Ok(updated) = self.proxy_rx.try_recv() {
            info!(
                frame = self.ui_frame_seq,
                proxies = updated.proxies.len(),
                "applying proxy reload snapshot"
            );
            self.proxies = updated.proxies.clone();
            self.traffic_route_targets = build_traffic_route_targets(&self.proxies);
            self.refresh_traffic_route_target_filter();
            self.traffic_route_target_index = self
                .traffic_route_targets
                .iter()
                .position(|target| target.route == self.traffic_route_target)
                .unwrap_or(0);
            if let Some(target) = self
                .traffic_route_targets
                .get(self.traffic_route_target_index)
            {
                self.traffic_route_target = target.route.clone();
            }
            self.nym_to_id = updated.nym_to_id.clone();
            self.proxy_groups = updated.proxy_groups.clone();
            self.user_groups = updated.groups.clone();
            if !self
                .clash_replace_group
                .as_ref()
                .is_some_and(|group| self.user_groups.contains(group))
            {
                self.clash_replace_group = self.user_groups.first().cloned();
            }

            // Reapply filters with new data
            self.apply_filters();
        }

        if self.traffic_route_filter_applied != self.traffic_route_filter {
            self.refresh_traffic_route_target_filter();
        }

        while let Ok(snapshot) = self.persisted_logs_rx.try_recv() {
            self.persisted_logs_snapshot = snapshot;
        }

        if self
            .selected_persisted_log_file
            .as_ref()
            .is_some_and(|selected| {
                !self
                    .persisted_logs_snapshot
                    .files
                    .iter()
                    .any(|file| file.path == *selected)
            })
        {
            self.selected_persisted_log_file = None;
        }
        // Update snapshot from supervisor (single source of truth)
        let mut drained_snapshots = 0usize;
        while let Some(snapshot) = self.supervisor.try_recv_snapshot() {
            drained_snapshots += 1;
            self.snapshot = snapshot;
        }

        while let Some(update) = self.supervisor.try_recv_process_raw_log() {
            let target = (update.profile, update.task_pgid);
            if self.process_log_editor_target.as_ref() != Some(&target) {
                continue;
            }

            let current_seq = self.process_log_editor_next_seq.unwrap_or_default();
            if update.reset {
                self.process_log_rows.clear();
                self.process_log_rows_bytes = 0;
            }
            let first_new = if update.reset {
                0
            } else {
                current_seq.saturating_sub(update.start_seq) as usize
            };
            for entry in update.logs.into_iter().skip(first_new) {
                let content = entry.content.trim_end_matches(['\r', '\n']);
                let mut line_start = content.len().saturating_sub(PROCESS_LOG_VIEWER_MAX_BYTES);
                while !content.is_char_boundary(line_start) {
                    line_start += 1;
                }
                let line = content[line_start..].to_string();
                self.process_log_rows_bytes += line.len();
                self.process_log_rows.push_back(line);
                while self.process_log_rows_bytes > PROCESS_LOG_VIEWER_MAX_BYTES {
                    let Some(removed) = self.process_log_rows.pop_front() else {
                        break;
                    };
                    self.process_log_rows_bytes =
                        self.process_log_rows_bytes.saturating_sub(removed.len());
                }
            }
            self.process_log_editor_next_seq = Some(update.next_seq);
        }
        if drained_snapshots > 0 {
            if let Some(target) = self.snapshot.auto_open_logs_target.as_ref() {
                if target.token > self.last_auto_open_logs_token {
                    self.selected_process_logs = Some((target.profile.clone(), target.pid));
                    self.last_auto_open_logs_token = target.token;
                }
            }
            if self
                .selected_profile
                .as_ref()
                .is_some_and(|profile| !self.snapshot.profiles.contains_key(profile))
            {
                self.selected_profile = None;
            }
            if self
                .selected_process_logs
                .as_ref()
                .is_some_and(|(profile, _)| !self.snapshot.profiles.contains_key(profile))
            {
                if let Some((profile, pid)) = self.selected_process_logs.take() {
                    self.supervisor
                        .send(SupervisorCommand::StopQueryRawLogs { profile, pid });
                }
            }
            info!(
                frame = self.ui_frame_seq,
                drained_snapshots,
                profiles = self.snapshot.profiles.len(),
                "applied supervisor snapshot updates"
            );
        }

        let delete_shortcut = egui::KeyboardShortcut::new(egui::Modifiers::CTRL, egui::Key::D);
        let delete_requested = self.remove_containers_armed
            && self.selected_profile.is_some()
            && !ctx.egui_wants_keyboard_input()
            && ctx.input_mut(|i| i.consume_shortcut(&delete_shortcut));
        if delete_requested {
            if let Some(profile_name) = self.selected_profile.clone() {
                info!(
                    profile = profile_name.as_str(),
                    "ui shortcut requested container delete"
                );
                self.supervisor.send(SupervisorCommand::DeleteContainer {
                    profile: profile_name,
                });
            }
        }

        egui::Panel::left("left_sidebar")
            .resizable(false)
            .default_size(280.0)
            .frame(
                egui::Frame::new()
                    .fill(ui.style().visuals.panel_fill)
                    .inner_margin(Margin::same(8)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("left_sidebar_content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.heading("Containers");
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                        ui.add_space(5.);
                                    if Self::refresh_button(ui, "Reload all container status")
                                        .clicked()
                                    {
                            self.reload_all_ns_alive();
                        }
                                    if Self::remove_armed_button(ui, self.remove_containers_armed)
                                        .clicked()
                                    {
                                        self.remove_containers_armed =
                                            !self.remove_containers_armed;
                        }
                                },
                            );
                });

                ui.add_space(6.0);

                // Global configuration box at the top
                let global_selected = self.selected_profile.is_none();
                let global_status_color = egui::Color32::from_rgb(100, 150, 240);
                        if sidebar_box(ui, "all", "", global_selected, global_status_color)
                            .clicked()
                        {
                    self.selected_profile = None;
                }

                ui.add_space(6.0);
                // Profiles
                if self.snapshot.profiles.is_empty() {
                            ui.label(
                                egui::RichText::new("No profiles found").color(egui::Color32::GRAY),
                            );
                    ui.small(format!(
                        "Create profiles in {}",
                        self.display_path(&state_paths::persist_root())
                    ));
                } else {
                    for (profile_name, profile_snapshot) in &self.snapshot.profiles {
                                let is_selected =
                                    self.selected_profile.as_ref() == Some(profile_name);

                        let running = profile_snapshot.container_lifecycle.is_active()
                            || profile_snapshot.serve_alive;

                        let unpivoted_warning = running
                            && profile_snapshot.template.sandbox_mode == SandboxMode::Pivot
                                    && profile_snapshot.sandbox_status.as_ref().map_or(true, |s| {
                                        s.detected_state == SandboxState::NoPivot
                                    });

                        let status_color = if unpivoted_warning {
                            Color32::from_rgb(255, 185, 0)
                        } else if running {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::LIGHT_RED
                        };
                        let status_text = if unpivoted_warning {
                            "unpivoted"
                        } else {
                            match profile_snapshot.container_lifecycle {
                                supervisor::ContainerLifecycleState::Stopped => "stopped",
                                supervisor::ContainerLifecycleState::Starting => "starting",
                                supervisor::ContainerLifecycleState::Running => "running",
                                        supervisor::ContainerLifecycleState::Stopping {
                                            ..
                                        } => "stopping",
                                        supervisor::ContainerLifecycleState::Killing { .. } => {
                                            "killing"
                                        }
                            }
                        };

                        let box_resp = sidebar_box(
                            ui,
                            &self.display_text(profile_name.as_str()),
                            status_text,
                            is_selected,
                            status_color,
                        );
                        if box_resp.clicked() {
                            self.selected_profile = Some(profile_name.clone());
                                    self.supervisor.send(
                                        supervisor::SupervisorCommand::LoadProfile(
                                    profile_name.clone(),
                                        ),
                                    );
                        }
                        ui.add_space(6.0);
                    }
                }

            });
            });

        let tab_fill = {
            let base = ui.style().visuals.panel_fill;
            Color32::from_rgb(
                base.r().saturating_add(15),
                base.g().saturating_add(15),
                base.b().saturating_add(15),
            )
        };
        egui::Panel::top("tab_bar")
            .show_separator_line(false)
            .frame(
                egui::Frame::NONE
                    .fill(tab_fill)
                    .inner_margin(egui::Margin {
                        left: 8,
                        right: 8,
                        top: 10,
                        bottom: 10,
                    }),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.right_tab == RightTab::Proxies, "Proxies")
                        .clicked()
                    {
                        self.right_tab = RightTab::Proxies;
                        if let Some(profile_name) = &self.selected_profile {
                            self.supervisor
                                .send(supervisor::SupervisorCommand::OnTabOpen {
                                    profile: profile_name.clone(),
                                    tab: supervisor::TabKind::Proxies,
                                });
                        }
                    }

                    self.sync_traffic_subscription();
                    if ui
                        .selectable_label(self.right_tab == RightTab::Daemon, "Daemon")
                        .clicked()
                    {
                        self.right_tab = RightTab::Daemon;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Dbus, "Dbus")
                        .clicked()
                    {
                        self.right_tab = RightTab::Dbus;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Actions, "Actions")
                        .clicked()
                    {
                        self.right_tab = RightTab::Actions;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Processes, "Processes")
                        .clicked()
                    {
                        self.right_tab = RightTab::Processes;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Traffic, "Traffic")
                        .clicked()
                    {
                        self.right_tab = RightTab::Traffic;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Hotconfig, "Hotconfig")
                        .clicked()
                    {
                        self.right_tab = RightTab::Hotconfig;
                        if let Some(profile_name) = &self.selected_profile {
                            self.supervisor
                                .send(supervisor::SupervisorCommand::OnTabOpen {
                                    profile: profile_name.clone(),
                                    tab: supervisor::TabKind::Hotconfig,
                                });
                        }
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::ProfileEditor, "Profile")
                        .clicked()
                    {
                        self.right_tab = RightTab::ProfileEditor;
                        if let Some(profile_name) = &self.selected_profile {
                            self.supervisor
                                .send(supervisor::SupervisorCommand::OnTabOpen {
                                    profile: profile_name.clone(),
                                    tab: supervisor::TabKind::ProfileEditor,
                                });
                        }
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::State, "State")
                        .clicked()
                    {
                        self.right_tab = RightTab::State;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Manage, "Manage")
                        .clicked()
                    {
                        self.right_tab = RightTab::Manage;
                    }
                    if ui
                        .selectable_label(self.right_tab == RightTab::Meta, "Meta")
                        .clicked()
                    {
                        self.right_tab = RightTab::Meta;
                    }

                    let profile_state = self
                        .selected_profile
                        .as_ref()
                        .and_then(|profile| self.snapshot.profiles.get(profile));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(ps) = profile_state {
                            let mut hover_text = None;
                            let (label, color) = if ps.template_error.is_some() {
                                ("misconfigured", Color32::from_rgb(220, 120, 60))
                            } else if ps.up_connection == supervisor::ConnectionState::Connecting
                                || ps.diag_connection == supervisor::ConnectionState::Connecting
                            {
                                ("connecting", Color32::from_rgb(220, 180, 90))
                            } else if ps.child_alive && !ps.up_connected {
                                hover_text = ps.up_error.clone();
                                ("container disconnected", Color32::from_rgb(220, 120, 60))
                            } else if ps.serve_alive && !ps.diag_connected {
                                hover_text = ps.diag_error.clone();
                                ("serve disconnected", Color32::from_rgb(220, 120, 60))
                            } else if ps.diag_connected {
                                ("connected", Color32::LIGHT_GREEN)
                            } else {
                                ("disconnected", Color32::LIGHT_RED)
                            };
                            let mut resp = ui.colored_label(color, label);
                            if let Some(text) = hover_text {
                                resp = resp.on_hover_text(text);
                            }
                            let _ = resp;
                        }
                    });
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.right_tab == RightTab::Manage {
                // Manage tab manages its own scroll + bottom panel
                self.render_manage_tab(ui);
            } else {
                let scroll_id = format!("right_tab_panel_scroll_{}", self.right_tab_label());
                egui::ScrollArea::vertical()
                    .id_salt(scroll_id)
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.right_tab {
                        RightTab::Proxies => self.render_proxies_tab(ui),
                        RightTab::Daemon => self.render_daemon_tab(ui),
                        RightTab::Dbus => self.render_dbus_tab(ui),
                        RightTab::Actions => self.render_actions_tab(ui),
                        RightTab::Processes => self.render_processes_tab(ui),
                        RightTab::Traffic => self.render_traffic_tab(ui),
                        RightTab::Hotconfig => self.render_hotconfig_tab(ui),
                        RightTab::ProfileEditor => self.render_profile_editor_tab(ui),
                        RightTab::State => self.render_state_tab(ui),
                        RightTab::Manage => unreachable!(),
                        RightTab::Meta => self.render_meta_tab(ui),
                    });
            }
        });

        self.render_external_pty_window(&ctx);
        self.render_proxy_detail_window(&ctx);
        self.render_log_editor_popup(&ctx);

        // Minimal dev-only watermark at bottom-left: non-intrusive, low-contrast
        egui::Area::new(egui::Id::new("dev_frame_watermark"))
            .anchor(egui::Align2::LEFT_BOTTOM, egui::Vec2::new(8.0, -8.0))
            .movable(false)
            .show(&ctx, |ui| {
                ui.horizontal(|ui| {
                    let ms = self.last_frame_elapsed_ms as f32;
                    let fps = self.last_fps;

                    let indicator_color = if ms <= 16.0 {
                        Color32::from_rgba_unmultiplied(120, 220, 120, 120)
                    } else if ms <= 33.0 {
                        Color32::from_rgba_unmultiplied(240, 200, 120, 120)
                    } else {
                        Color32::from_rgba_unmultiplied(220, 100, 100, 120)
                    };

                    ui.colored_label(indicator_color, "●");

                    ui.add_space(6.0);

                    ui.label(
                        egui::RichText::new(format!(
                            "{}ms  {:.1}fps",
                            self.last_frame_elapsed_ms, fps
                        ))
                        .small()
                        .color(Color32::from_rgba_unmultiplied(200, 200, 200, 120)),
                    );
                });
            });

        let frame_elapsed = frame_started.elapsed();
        self.last_frame_elapsed_ms = frame_elapsed.as_millis();
        self.fps_window_count += 1;
        let fps_elapsed = self.fps_window_start.elapsed();
        if fps_elapsed >= Duration::from_secs(1) {
            self.last_fps = self.fps_window_count as f32 / fps_elapsed.as_secs_f32();
            self.fps_window_count = 0;
            self.fps_window_start = Instant::now();
        }
        if frame_elapsed >= Duration::from_millis(100) {
            info!(
                frame = self.ui_frame_seq,
                elapsed_ms = frame_elapsed.as_millis(),
                tab = self.right_tab_label(),
                profile = self.selected_profile.as_deref().unwrap_or("<global>"),
                "slow ui frame"
            );
        }
    }
}

impl App {
    fn render_actions_tab(&mut self, ui: &mut egui::Ui) {
        let apps: Vec<(ContainerName, LaunchableApp)> = self
            .snapshot
            .profiles
            .iter()
            .flat_map(|(container, profile)| {
                profile
                    .hotconfig
                    .applications
                    .iter()
                    .cloned()
                    .map(|app| (container.clone(), app))
                    .collect::<Vec<_>>()
            })
            .collect();

        ui.heading("Actions");
        ui.label(
            "Launch configured applications and manage their live processes across containers.",
        );
        ui.add_space(8.0);

        if apps.is_empty() {
            ui.colored_label(
                Color32::from_gray(150),
                "No launchable applications are configured. Add applications in a profile's Hotconfig tab.",
            );
        }

        let mut launch_request: Option<(ContainerName, LaunchableApp)> = None;
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
            for (container, app) in &apps {
                let running = self
                    .snapshot
                    .profiles
                    .get(container)
                    .and_then(|profile| profile.process_list_snapshot.as_ref())
                    .is_some_and(|list| {
                        list.procs.values().any(|entry| {
                            matches!(entry.status, diag::ProcessStatus::Alive)
                                && matches!(
                                    &entry.meta,
                                    diag::SpawnedEntry::Args(args)
                                        | diag::SpawnedEntry::Pty(args)
                                        if args.application.as_deref() == Some(app.name.as_str())
                                )
                        })
                    });
                let launching = self
                    .action_launching
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&(container.clone(), app.name.clone()));
                let configured = !app.name.trim().is_empty()
                    && app
                        .command
                        .shell
                        .as_ref()
                        .is_some_and(|shell| !shell.trim().is_empty());
                // Only lifecycle state disables an Actions card. Configuration
                // errors are reported after a click, so an unlaunched app is
                // always actionable as promised by the Actions workflow.
                let enabled = !running && !launching;
                let status = if running {
                    "Already launched"
                } else if launching {
                    "Launching"
                } else if !configured {
                    "Configure a command shell in Hotconfig"
                } else if app.description.trim().is_empty() {
                    "Launch application"
                } else {
                    app.description.as_str()
                };
                if action_app_card(ui, &app.name, container, enabled, running)
                    .on_hover_text(status)
                    .clicked()
                {
                    launch_request = Some((container.clone(), app.clone()));
                }
            }
        });

        if let Some((container, app)) = launch_request {
            self.launch_hotconfig_application(container, app);
        }
        if let Some(status) = self
            .action_status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            ui.add_space(6.0);
            ui.label(status);
        }

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(8.0);
        ui.heading("Launched processes");
        self.render_units_table(ui, &None);
    }

    fn launch_hotconfig_application(&mut self, profile: ContainerName, app: LaunchableApp) {
        let name = app.name.trim().to_owned();
        let shell = app.command.shell.clone().unwrap_or_default();
        if name.is_empty() || shell.trim().is_empty() {
            *self.action_status.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("Application requires both a name and command shell.".to_string());
            return;
        }

        let key = (profile.clone(), name.clone());
        self.action_launching
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone());
        let exec = which::which(&shell)
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or(shell.clone());
        let mut args = Vec::with_capacity(app.command.args.len() + 1);
        args.push(shell.clone());
        args.extend(app.command.args.clone());
        let mut spawn_args = diag::SpawnArgs {
            uid: app.command.uid,
            gid: app.command.gid,
            exec: Some(exec),
            cwd: app.command.cwd,
            gids: app.command.gids,
            args,
            ringbuf_size: None,
            application: Some(name.clone()),
            ns: diag::NamespaceSpawn::Inside,
        };
        apply_default_spawn_user(&mut spawn_args);

        let supervisor = self.supervisor.clone();
        let launching = self.action_launching.clone();
        let status = self.action_status.clone();
        let Some(runtime) = self.tokio_rt.as_ref() else {
            launching
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            *status.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("Tokio runtime is unavailable.".to_string());
            return;
        };
        runtime.spawn(async move {
            let result: anyhow::Result<u32> = async {
                supervisor.ensure_profile_running(profile.as_str()).await?;
                let task_pgid = supervisor
                    .spawn_managed_process(profile.as_str(), spawn_args)
                    .await?;
                Ok(task_pgid)
            }
            .await;
            launching
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            *status.lock().unwrap_or_else(|e| e.into_inner()) = Some(match result {
                Ok(task_pgid) => format!(
                    "{} launched in {} (task PGID {}).",
                    name, profile, task_pgid
                ),
                Err(err) => format!("{} failed to launch in {}: {}", name, profile, err),
            });
        });
    }

    fn render_proxies_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Reload").clicked() {
                let _ = self.reload_tx.try_send(());
            }
            if ui.button("Clear Stats").clicked() {
                if let Some(profile_name) = self.selected_profile.clone() {
                    self.supervisor.send(SupervisorCommand::Ctrl {
                        profile: profile_name,
                        cmd: diag::ControlCommand::ClearStats,
                    });
                }
            }
        });
        ui.add_space(8.0);

        self.render_clash_group_import(ui);
        ui.add_space(8.0);

        if !self.expanded_proxy_groups.is_empty() {
            ui.horizontal(|ui| {
                if ui.button("Collapse all groups").clicked() {
                    self.expanded_proxy_groups.clear();
                    self.proxy_table_entries_dirty = true;
                }
            });
        }

        self.render_selected_proxy_summary(ui);
        ui.add_space(6.0);

        self.render_proxy_filters(ui);
        if self.filters_dirty {
            self.apply_filters();
            self.filters_dirty = false;
        }

        ui.add_space(6.0);

        self.render_proxies_table(ui);
        ui.add_space(8.0);
    }

    fn request_clash_group_import(&mut self, replace: bool) {
        if self.clash_import_pending {
            return;
        }

        let path = std::path::PathBuf::from(self.clash_import_path.trim());
        if !path.is_absolute() {
            self.clash_import_status =
                Some("Enter an absolute path to the Clash YAML file.".to_string());
            return;
        }

        let group_id = if replace {
            self.clash_replace_group
                .as_ref()
                .map(|group| group.as_str().to_string())
        } else {
            let name = self.clash_import_group_name.trim();
            (!name.is_empty()).then(|| name.to_string())
        };
        let Some(group_id) = group_id else {
            self.clash_import_status = Some(if replace {
                "Select a group to replace.".to_string()
            } else {
                "Enter a name for the new group.".to_string()
            });
            return;
        };

        let (result_tx, result_rx) = flume::bounded(1);
            self.clash_import_result_rx = Some(result_rx);
            self.supervisor.send(SupervisorCommand::ImportClashGroup {
                group_id: group_id.clone(),
                path,
                replace,
                result_tx,
            });
        self.clash_import_pending = true;
        self.clash_import_status = Some(format!("Importing into '{group_id}'…"));
    }

    fn render_clash_group_import(&mut self, ui: &mut egui::Ui) {
        if let Some(receiver) = self.clash_import_result_rx.take() {
            if let Some(runtime) = self.tokio_rt.as_ref() {
                let ctx = ui.ctx().clone();
                runtime.spawn(async move {
                    let completion = receiver.recv_async().await.unwrap_or_else(|error| {
                        supervisor::ClashGroupImportCompletion {
                            result: Some(Err(format!(
                                "Supervisor closed before returning the import result: {error}"
                            ))),
                            ..Default::default()
                        }
                    });
                    ctx.data_mut(|data| {
                        data.insert_temp(
                            egui::Id::new("clash_group_import_completion"),
                            completion,
                        )
                    });
                    ctx.request_repaint();
                });
            } else {
                self.clash_import_pending = false;
                self.clash_import_status =
                    Some("Import failed: the UI runtime is unavailable".to_owned());
            }
        }

        let completion = ui.ctx().data_mut(|data| {
            data.remove_temp::<supervisor::ClashGroupImportCompletion>(egui::Id::new(
                "clash_group_import_completion",
            ))
        });
        if let Some(completion) = completion {
            self.clash_import_pending = false;
            match completion.result.unwrap_or_else(|| {
                Err("Supervisor returned an empty Clash import result".to_owned())
            }) {
                Ok(message) => {
                    self.clash_import_status = Some(message.clone());
                    match self.reload_tx.try_send(()) {
                        Ok(()) | Err(flume::TrySendError::Full(())) => {}
                        Err(flume::TrySendError::Disconnected(())) => {
                            self.clash_import_status = Some(format!(
                                "{message}; failed to refresh the proxy group list"
                            ));
                        }
                    }
                    for (profile, state) in &self.snapshot.profiles {
                        if state.serve_alive {
                            self.supervisor.send(SupervisorCommand::Ctrl {
                                profile: profile.clone(),
                                cmd: diag::ControlCommand::ReloadUplink,
                            });
                        }
                    }
                }
                Err(error) => {
                    self.clash_import_status =
                        Some(format!("Clash group import failed: {error}"));
                }
            }
        }
        egui::CollapsingHeader::new("Import Clash group")
            .id_salt("clash_group_import")
            .default_open(true)
            .show(ui, |ui| {
                ui.label("Add a Clash YAML file as a new group, or replace all data in an existing group.");
                ui.weak("Run `sp uplink clash resolve` to resolve imported proxy servers before routing through them.");
                let path_changed = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.clash_import_path)
                            .hint_text("Absolute path to Clash YAML"),
                    )
                    .changed();
                if path_changed {
                    let default_name =
                        default_clash_group_name(&self.clash_import_path).unwrap_or_default();
                    if self.clash_import_group_name.trim().is_empty()
                        || self.clash_import_group_name == self.clash_import_default_group_name
                    {
                        self.clash_import_group_name = default_name.clone();
                    }
                    self.clash_import_default_group_name = default_name;
                }

                ui.horizontal(|ui| {
                    ui.label("New group name");
                    ui.text_edit_singleline(&mut self.clash_import_group_name);
                    if ui
                        .add_enabled(
                            !self.clash_import_pending,
                            egui::Button::new("Add as new group"),
                        )
                        .clicked()
                    {
                        self.request_clash_group_import(false);
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Replace existing");
                    let selected_text = self
                        .clash_replace_group
                        .as_ref()
                        .map(GroupId::as_str)
                        .unwrap_or("Select group");
                    egui::ComboBox::from_id_salt("clash_replace_group")
                        .selected_text(selected_text)
                        .show_ui(ui, |ui| {
                            for group in &self.user_groups {
                                ui.selectable_value(
                                    &mut self.clash_replace_group,
                                    Some(group.clone()),
                                    group.as_str(),
                                );
                            }
                        });
                    if ui
                        .add_enabled(
                            !self.clash_import_pending && !self.user_groups.is_empty(),
                            egui::Button::new("Replace group"),
                        )
                        .clicked()
                    {
                        self.request_clash_group_import(true);
                    }
                });

                if let Some(status) = &self.clash_import_status {
                    ui.label(status);
                }
            });
    }

    fn render_selected_proxy_summary(&self, ui: &mut egui::Ui) {
        if let Some(profile_name) = &self.selected_profile {
            if let Some(profile) = self.snapshot.profiles.get(profile_name) {
                ui.horizontal(|ui| {
                    ui.label("Selected:");
                    if let Some(routing) = &profile.routing_state {
                        if routing.no_proxy {
                            ui.label(egui::RichText::new("NoProxy").color(Color32::LIGHT_GREEN));
                        } else if let Some(group_id) = &routing.selected_group {
                            ui.label(
                                egui::RichText::new(format!("Group: {group_id}"))
                                    .strong()
                                    .color(Color32::LIGHT_GREEN),
                            );
                        } else if let Some(proxy_id) = &routing.selected_proxy {
                            let proxy_nym_str = proxy_id.nym().to_string();
                            if let Some(proxy_item) = self.proxies.get(proxy_id) {
                                ui.label(
                                    egui::RichText::new(&proxy_item.name)
                                        .strong()
                                        .color(Color32::LIGHT_GREEN),
                                );
                                let displayed_url = if self.hide_secret {
                                    self.cover_text.as_str()
                                } else {
                                    &proxy_item.url
                                };
                                ui.label(format!("({})", displayed_url));
                            } else {
                                ui.label(
                                    egui::RichText::new(&proxy_nym_str).color(Color32::LIGHT_GREEN),
                                );
                            }
                        } else {
                            ui.label(egui::RichText::new("None").color(Color32::GRAY));
                        }
                    } else {
                        ui.label(egui::RichText::new("None").color(Color32::GRAY));
                    }
                });
            }
        } else {
            ui.horizontal(|ui| {
                ui.label("Selected:");
                ui.label(egui::RichText::new("(Select a profile)").color(Color32::GRAY));
            });
        }
    }

    fn render_proxy_filters(&mut self, ui: &mut egui::Ui) {
        ui.label("Proxy Type Filter:");
        ui.horizontal(|ui| {
            for proxy_type in &[
                ProxyType::Remote,
                ProxyType::Trojan,
                ProxyType::Geph,
                ProxyType::File,
            ] {
                let is_selected = self.proxy_filters.selected_types.contains(proxy_type);
                if ui
                    .selectable_label(is_selected, proxy_type.label())
                    .clicked()
                {
                    if is_selected {
                        self.proxy_filters.selected_types.remove(proxy_type);
                    } else {
                        self.proxy_filters.selected_types.insert(*proxy_type);
                    }
                    self.filters_dirty = true;
                }
            }
            if !self.proxy_filters.selected_types.is_empty() {
                if ui.button("Clear Filters").clicked() {
                    self.proxy_filters.selected_types.clear();
                    self.filters_dirty = true;
                }
            }
        });

        ui.add_space(6.0);
        ui.label("Sort Frequency:");
        ui.horizontal(|ui| {
            let freq_options = [
                ("Manual", SortFrequency::Manual),
                ("Every 1s", SortFrequency::Every1s),
                ("Every 2s", SortFrequency::Every2s),
                ("Every 5s", SortFrequency::Every5s),
            ];

            for (label, freq) in &freq_options {
                let is_selected = self.proxy_filters.sort_frequency == *freq;
                if ui.selectable_label(is_selected, *label).clicked() {
                    self.proxy_filters.sort_frequency = *freq;
                    self.last_sort_time = Instant::now();
                }
            }
        });

        ui.add_space(6.0);
        if self.proxy_filters.sort_column != SortColumn::None {
            ui.label(format!(
                "Current sort: {:?} ({:?})",
                self.proxy_filters.sort_column, self.proxy_filters.sort_direction
            ));
        }

        ui.label("Expanded groups:");
        if self.proxy_group_controls.is_empty() {
            ui.weak("No groups");
        } else {
            ui.horizontal_wrapped(|ui| {
                for (group, proxy_count) in &self.proxy_group_controls {
                    let expanded = self.expanded_proxy_groups.contains(group);
                    if ui
                        .selectable_label(expanded, format!("{} ({proxy_count})", group.as_str()))
                        .clicked()
                    {
                        if expanded {
                            self.expanded_proxy_groups
                                .retain(|expanded_group| expanded_group != group);
                        } else {
                            self.expanded_proxy_groups.push(group.clone());
                        }
                        self.proxy_table_entries_dirty = true;
                    }
                }
            });
        }

    }

    fn render_proxies_table(&mut self, ui: &mut egui::Ui) {
        if self.proxy_table_entries_dirty {
            self.proxy_table_entries = build_proxy_table_entries(
                &self.filtered_proxy_ids,
                &self.proxy_groups,
                &self.expanded_proxy_groups,
                &self.user_groups,
            );
            self.proxy_group_controls = build_proxy_group_controls(&self.proxy_table_entries);
            self.proxy_table_entries_dirty = false;
        }

        let header_h = 28.0;
        let row_h = if self.expanded_ip_rows.is_empty() {
            96.0
        } else {
            132.0
        };
        let mut next_hovered_proxy: Option<usize> = None;

        ui.ctx()
            .options_mut(|options| options.input_options.line_scroll_speed = 150.);

        let selected_proxy_id = self.selected_profile.as_ref().and_then(|profile_name| {
            self.snapshot
                .profiles
                .get(profile_name)
                .and_then(|profile| profile.routing_state.as_ref())
                .and_then(|routing| routing.selected_proxy.as_ref().cloned())
        });
        let selected_group_id = self.selected_profile.as_ref().and_then(|profile_name| {
            self.snapshot
                .profiles
                .get(profile_name)
                .and_then(|profile| profile.routing_state.as_ref())
                .and_then(|routing| {
                    routing
                        .selected_group
                        .as_deref()
                        .map(GroupId::from)
                })
        });
        let no_proxy_route_selected = self.selected_profile.as_ref().is_some_and(|profile_name| {
            self.snapshot
                .profiles
                .get(profile_name)
                .and_then(|profile| profile.routing_state.as_ref())
                .is_some_and(|routing| routing.no_proxy)
        });

        let live_stats: HashMap<ProxyID, ProxyStats> = self
            .selected_profile
            .as_ref()
            .and_then(|p| self.snapshot.profiles.get(p))
            .map(|p| p.proxy_stats.clone())
            .unwrap_or_default();

        egui::ScrollArea::vertical()
            .wheel_scroll_multiplier(Vec2::new(15., 15.))
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .striped(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    // name width, proxy URL made modest (not using remainder)
                    .column(Column::exact(160.0))
                    .column(Column::exact(200.0))
                    .column(Column::exact(100.0))
                    .column(Column::exact(140.0))
                    // let status column expand to fill remaining width
                    .column(Column::remainder())
                    .header(header_h, |mut header| {
                        header.col(|ui| {
                            ui.strong("Name");
                        });
                        header.col(|ui| {
                            ui.strong("Proxy URL");
                        });
                        header.col(|ui| {
                            let latency_sorted =
                                self.proxy_filters.sort_column == SortColumn::Latency;
                            let mut label = "Latency".to_string();
                            if latency_sorted {
                                label.push(
                                    if self.proxy_filters.sort_direction == SortDirection::Ascending
                                    {
                                        ' '
                                    } else {
                                        ' '
                                    },
                                );
                                label.push(
                                    if self.proxy_filters.sort_direction == SortDirection::Ascending
                                    {
                                        '▲'
                                    } else {
                                        '▼'
                                    },
                                );
                            }
                            if ui.button(&label).clicked() {
                                self.on_sort_column_clicked(SortColumn::Latency);
                            }
                        });
                        header.col(|ui| {
                            let stats_sorted =
                                self.proxy_filters.sort_column == SortColumn::FailRate;
                            let mut label = "Fails".to_string();
                            if stats_sorted {
                                label.push(
                                    if self.proxy_filters.sort_direction == SortDirection::Ascending
                                    {
                                        ' '
                                    } else {
                                        ' '
                                    },
                                );
                                label.push(
                                    if self.proxy_filters.sort_direction == SortDirection::Ascending
                                    {
                                        '▲'
                                    } else {
                                        '▼'
                                    },
                                );
                            }
                            if ui.button(&label).clicked() {
                                self.on_sort_column_clicked(SortColumn::FailRate);
                            }
                        });
                        header.col(|ui| {
                            ui.strong("Status");
                        });
                    })
                    .body(|mut body| {
                        let widths = body.widths().to_vec();
                        let spacing_x = body.ui_mut().spacing().item_spacing.x;
                        let row_width = widths.iter().sum::<f32>()
                            + spacing_x * (widths.len().saturating_sub(1) as f32);

                        body.rows(row_h, self.proxy_table_entries.len(), |mut row| {
                            let i = row.index();
                            match self.proxy_table_entries.get(i).cloned() {
                                Some(ProxyTableEntry::NoProxy) => {
                                    self.render_no_proxy_row(
                                        &mut row,
                                        row_width,
                                        no_proxy_route_selected,
                                    );
                                }
                                Some(ProxyTableEntry::Group { id, proxy_count }) => {
                                    self.render_proxy_group_row(
                                        &mut row,
                                        &id,
                                        proxy_count,
                                        selected_group_id.as_ref(),
                                    );
                                }
                                Some(ProxyTableEntry::Proxy(proxy_id)) => {
                                    self.render_proxy_row(
                                        &mut row,
                                        &proxy_id,
                                        i,
                                        row_width,
                                        selected_proxy_id.as_ref(),
                                        &live_stats,
                                        &mut next_hovered_proxy,
                                    );
                                }
                                None => {}
                            }
                        });
                    });
            });

        self.hovered_proxy = next_hovered_proxy;
    }

    fn render_no_proxy_row(
        &mut self,
        row: &mut egui_extras::TableRow,
        row_width: f32,
        is_selected: bool,
    ) {
        let mut is_hover = false;

        row.col(|ui| {
            if is_selected {
                let row_rect = ui.available_rect_before_wrap();
                ui.painter().rect_filled(
                    row_rect,
                    0.0,
                    Color32::from_rgba_unmultiplied(100, 180, 100, 40),
                );
            }
            ui.vertical(|ui| {
                let response = ui.label(egui::RichText::new("NoProxy").strong());
                let row_rect =
                    egui::Rect::from_min_size(response.rect.min, egui::vec2(row_width, 96.0));
                let pointer_pos = ui
                    .ctx()
                    .input(|input| input.pointer.interact_pos().or(input.pointer.hover_pos()));
                is_hover = pointer_pos.is_some_and(|pos| row_rect.contains(pos));
                ui.small("No proxy");
                if is_hover {
                    if let Some(profile_name) = self.selected_profile.clone() {
                        if ui.button("Select NoProxy").clicked() {
                            self.supervisor.send(SupervisorCommand::Ctrl {
                                profile: profile_name,
                                cmd: diag::ControlCommand::SetNoProxyRouting,
                            });
                        }
                    }
                }
            });
        });
        row.col(|ui| {
            ui.label("NoProxy connection");
        });
        row.col(|ui| {
            ui.label(egui::RichText::new("—").color(Color32::from_gray(120)));
        });
        row.col(|ui| {
            ui.label(egui::RichText::new("—").color(Color32::from_gray(120)));
        });
        row.col(|ui| {
            ui.vertical(|ui| {
                ui.colored_label(
                    if is_selected {
                        Color32::LIGHT_GREEN
                    } else {
                        Color32::from_gray(160)
                    },
                    if is_selected { "active" } else { "no proxy" },
                );
            });
        });
    }

    fn render_proxy_group_row(
        &mut self,
        row: &mut egui_extras::TableRow,
        group: &GroupId,
        proxy_count: usize,
        selected_group_id: Option<&GroupId>,
    ) {
        let expanded = self.expanded_proxy_groups.contains(group);
        let is_selected = selected_group_id == Some(group);
        row.col(|ui| {
            if ui.small_button(if expanded { "▾" } else { "▸" }).clicked() {
                if expanded {
                    self.expanded_proxy_groups
                        .retain(|expanded_group| expanded_group != group);
                } else {
                    self.expanded_proxy_groups.push(group.clone());
                }
                self.proxy_table_entries_dirty = true;
            }
            ui.label(
                egui::RichText::new(group.as_str())
                    .strong()
                    .color(if is_selected {
                        Color32::LIGHT_GREEN
                    } else {
                        ui.visuals().text_color()
                    }),
            );
        });
        row.col(|ui| {
            ui.label(format!("{proxy_count} proxies"));
        });
        row.col(|ui| {
            ui.label(egui::RichText::new("—").color(Color32::from_gray(120)));
        });
        row.col(|ui| {
            ui.label(egui::RichText::new("—").color(Color32::from_gray(120)));
        });
        row.col(|ui| {
            if let Some(profile_name) = self.selected_profile.clone() {
                if ui
                    .small_button(if is_selected {
                        "Selected group"
                    } else {
                        "Route via group"
                    })
                    .clicked()
                {
                    self.supervisor.send(SupervisorCommand::Ctrl {
                        profile: profile_name,
                        cmd: diag::ControlCommand::SetGroupRouting {
                            group_id: group.as_str().to_string(),
                        },
                    });
                }
            } else {
            ui.label("Group");
            }
        });
    }

    fn render_proxy_row(
        &mut self,
        row: &mut egui_extras::TableRow,
        proxy_id: &ProxyID,
        i: usize,
        row_width: f32,
        selected_proxy_id: Option<&ProxyID>,
        live_stats: &HashMap<ProxyID, ProxyStats>,
        next_hovered: &mut Option<usize>,
    ) {
        let proxy_item = match self.proxies.get(proxy_id) {
            Some(item) => item.clone(),
            None => return,
        };

        let stats = live_stats.get(proxy_id);

        let live_latency_ms = stats.and_then(|s| {
            let h = s.past_hour();
            h.avg_latency_ms().map(|ms| ms as u64)
        });
        let live_success_rate = stats.and_then(|s| {
            let h = s.past_hour();
            h.success_rate()
        });

        let display_latency = live_latency_ms.or(proxy_item.latency_ms);
        let display_conn_ok = if let Some(rate) = live_success_rate {
            Some(rate >= 0.5)
        } else {
            proxy_item.conn_ok
        };

        let mut row_hot = false;
        let mut is_hover = false;
        let is_selected = selected_proxy_id.map(|id| id == proxy_id).unwrap_or(false);

        row.col(|ui| {
            if is_selected {
                let row_rect = ui.available_rect_before_wrap();
                ui.painter().rect_filled(
                    row_rect,
                    0.0,
                    Color32::from_rgba_unmultiplied(100, 180, 100, 40),
                );
            }

            ui.vertical(|ui| {
                let resp = ui.label(egui::RichText::new(&proxy_item.name).strong());
                let row_rect =
                    egui::Rect::from_min_size(resp.rect.min, egui::vec2(row_width, 96.0));
                let pointer_pos = ui
                    .ctx()
                    .input(|i| i.pointer.interact_pos().or(i.pointer.hover_pos()));
                row_hot = pointer_pos.is_some_and(|pos| row_rect.contains(pos));
                is_hover = row_hot || self.hovered_proxy == Some(i);

                if is_hover {
                } else {
                    let udp_label = match proxy_item.udp_ability {
                        Some(true) => "UDP ok + TCP",
                        Some(false) => "UDP fail + TCP",
                        None if proxy_item.udp_expected => "UDP + TCP",
                        None => "TCP only",
                    };
                    ui.small(udp_label);
                }

                if !proxy_item.groups.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        for group in &proxy_item.groups {
                            ui.label(egui::RichText::new(format!("◉ {}", group.as_str())).small());
                        }
                    });
                }
            });
        });

        row.col(|ui| {
            ui.vertical(|ui| {
                let displayed_url = if self.hide_secret {
                    self.cover_text.as_str()
                } else {
                    &proxy_item.url
                };
                ui.label(displayed_url);

                if let Some(first_ip) = proxy_item.resolved_ips.first() {
                    let has_more_ips = proxy_item.resolved_ips.len() > 1;
                    let trunc = if has_more_ips { "…" } else { "" };
                    ui.small(format!("{}{}", first_ip, trunc));

                    if has_more_ips {
                        let expanded = self.expanded_ip_rows.contains(proxy_id);
                        let toggle = if expanded { "IPs ▾" } else { "IPs ▸" };
                        if ui.small_button(toggle).clicked() {
                            if expanded {
                                self.expanded_ip_rows.remove(proxy_id);
                            } else {
                                self.expanded_ip_rows.insert(proxy_id.clone());
                            }
                        }
                        if expanded {
                            for ip in proxy_item.resolved_ips.iter().skip(1) {
                                ui.small(format!("  {}", ip));
                            }
                        }
                    }
                }

                if is_hover {
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Select proxy").clicked() {
                            if let Some(profile_name) = self.selected_profile.clone() {
                                self.supervisor.send(SupervisorCommand::Ctrl {
                                    profile: profile_name,
                                    cmd: diag::ControlCommand::SetSimpleRouting {
                                        proxy_id: proxy_id.clone(),
                                    },
                                });
                            }
                        }
                        if ui.button("📈 Detail").clicked() {
                            self.detail_proxy_id = Some(proxy_id.clone());
                            self.detail_fit_frames_left = 3;
                            // Immediately request fresh stats from the running serve unit.
                            if let Some(profile_name) = self.selected_profile.clone() {
                                self.supervisor.send(SupervisorCommand::Ctrl {
                                    profile: profile_name,
                                    cmd: diag::ControlCommand::QueryUplinkStats,
                                });
                            }
                        }
                    });
                } else {
                    // when not hovered.
                }
            });
        });

        row.col(|ui| {
            ui.vertical(|ui| {
                match display_latency {
                    Some(ms) => {
                        let color = if ms < 100 {
                            egui::Color32::LIGHT_GREEN
                        } else if ms < 400 {
                            egui::Color32::YELLOW
                        } else {
                            egui::Color32::LIGHT_RED
                        };
                        ui.colored_label(color, format!("{}ms", ms));
                    }
                    None => {
                        ui.label(egui::RichText::new("—").color(egui::Color32::from_gray(120)));
                    }
                }
                if let Some(rate) = live_success_rate {
                    ui.label(format!("{:.0}%", rate * 100.0));
                }
            });
        });

        // Mini sparkline chart column
        row.col(|ui| {
            if let Some(proxy_stats) = stats {
                render_mini_sparkline(ui, proxy_stats, proxy_id);
            } else {
                ui.label(egui::RichText::new("—").color(egui::Color32::from_gray(120)));
            }
        });

        row.col(|ui| {
            let (status_color, status_text) = match display_conn_ok {
                Some(true) => (egui::Color32::LIGHT_GREEN, "ok".to_owned()),
                Some(false) => (egui::Color32::LIGHT_RED, "fail".to_owned()),
                None => (egui::Color32::from_gray(160), "".to_owned()),
            };
            ui.vertical(|ui| {
                ui.colored_label(status_color, &status_text);
                if let Some(s) = stats {
                    let h = s.past_hour();
                    let up = format_bytes(h.bytes_up);
                    let down = format_bytes(h.bytes_down);
                    ui.small(format!("↑{} ↓{}", up, down));
                }
                if is_hover {
                    let enabled = if proxy_item.enabled_globally {
                        "on"
                    } else {
                        "off"
                    };
                }
            });
        });

        if row_hot {
            *next_hovered = Some(i);
        }
    }

    fn render_processes_tab(&mut self, ui: &mut egui::Ui) {
        let profile_name = self.selected_profile.clone();

        if let Some(profile_name) = profile_name.as_ref() {
            egui::CollapsingHeader::new(
                RichText::new(format!(
                    "Processes - {}",
                    self.display_text(profile_name.as_str())
                ))
                .strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                let rust_backtrace_label =
                    format!("RUST_BACKTRACE={}", if self.rust_backtrace { 1 } else { 0 });
                ui.checkbox(&mut self.rust_backtrace, rust_backtrace_label)
                    .on_hover_text(
                        "Set RUST_BACKTRACE for the next sp up and sp serve launches.",
                    );
            });
            ui.add_space(6.0);
            self.render_process_controls(ui, profile_name);
        } else {
            ui.heading("Global Processes");
            ui.label("Select a profile to manage its units.");
        }

        ui.add_space(8.0);

        self.render_units_table(ui, &profile_name);

        if self.selected_process_spawn_args.is_some() {
            self.render_process_spawn_args_panel(ui);
        }
        if let Some(profile) = &profile_name {
            ui.add_space(12.0);
            self.render_run_command_section(ui, profile);
        }

        if self.selected_process_logs.is_some() {
            if self.selected_process_is_pty() {
                self.render_process_pty_panel(ui);
            } else {
                self.render_process_raw_logs_panel(ui);
            }
        }
    }

    fn render_structured_log_panel(
        ui: &mut egui::Ui,
        panel_id: &str,
        empty_message: &str,
        no_level_message: String,
        log_panel_min_level: &mut LogMinLevel,
        entries: &VecDeque<Arc<RenderedLogEntry>>,
        total_entries: usize,
    ) -> Option<String> {
        let mut open_editor = false;
        egui::Frame::NONE
            .fill(LOG_EDITOR_BACKGROUND)
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_size(egui::Vec2::new(ui.available_width(), 160.0));
                let total = entries.len();

                ui.horizontal(|ui| {
                    ui.label("Min level");
                    egui::ComboBox::from_id_salt(("log_panel_min_level", panel_id))
                        .selected_text(log_panel_min_level.label())
                        .show_ui(ui, |ui| {
                            for level in LogMinLevel::ALL {
                                ui.selectable_value(log_panel_min_level, level, level.label());
                            }
                        });
                    ui.add_space(8.0);
                    ui.colored_label(
                        Color32::from_gray(130),
                        format!("showing {} / {}", total, total_entries),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        open_editor = ui
                            .small_button("Open editor")
                            .on_hover_text(
                                "Open this filtered log view in a selectable, scrollable editor",
                            )
                            .clicked();
                    });
                });

                ui.add_space(6.0);
                if total_entries == 0 {
                    ui.colored_label(Color32::from_gray(110), empty_message);
                    return;
                }

                if entries.is_empty() {
                    ui.colored_label(Color32::from_gray(110), no_level_message);
                    return;
                }

                let row_h = ui.text_style_height(&egui::TextStyle::Body);

                egui_log_viewer::LogViewer::show_rows(
                    ui,
                    (
                        "log_panel",
                        panel_id,
                        log_panel_min_level.label(),
                        entries.front().map(|entry| entry.entry.hash),
                    ),
                    entries,
                    row_h,
                    500.0,
                    |entry| {
                        let source = match &entry.entry.src {
                            LogSource::Serve => "serve".to_owned(),
                            LogSource::Up => "up".to_owned(),
                            LogSource::RootDaemon => "daemon".to_owned(),
                            LogSource::Fcitx => "fcitx".to_owned(),
                            LogSource::Pid(_) => "pid".to_owned(),
                        };
                        let log = &entry.entry.log;
                        let mut text = format!(
                            "{source} {} [{}] {}",
                            log.level, log.target, log.message
                        );
                        for field in &log.fields {
                            text.push_str(&format!("\n{}={}", field.name, field.value));
                        }
                        text
                    },
                    |ui, _row_index, entry, _selected| {
                        let (badge_text, badge_color) = match entry.entry.src {
                            LogSource::Serve => ("serve", LOG_SYNTAX_GREEN),
                            LogSource::Up => ("up", LOG_SYNTAX_BLUE),
                            LogSource::RootDaemon => ("daemon", LOG_SYNTAX_PURPLE),
                            LogSource::Fcitx => ("fcitx", LOG_SYNTAX_CYAN),
                            LogSource::Pid(_) => ("pid", LOG_SYNTAX_YELLOW),
                        };
                        ui.style_mut().interaction.selectable_labels = false;
                        ui.horizontal(|ui| {
                            ui.colored_label(badge_color, badge_text);

                            ui.colored_label(
                                log_level_color(&entry.entry.log.level),
                                &entry.entry.log.level,
                            );

                            ui.colored_label(
                                LOG_SYNTAX_BLUE,
                                format!("[{}]", entry.entry.log.target),
                            );

                            ui.label(entry.ansi_parts.as_ref().clone());
                            for field in &entry.entry.log.fields {
                                ui.add_space(6.0);
                                ui.colored_label(
                                    LOG_SYNTAX_CYAN,
                                    format!("{}=", field.name),
                                );
                                ui.label(
                                    RichText::new(&field.value)
                                        .monospace()
                                        .color(LOG_SYNTAX_GREEN),
                                );
                            }
                        });
                    },
                );
            });
        open_editor.then(|| {
            let mut text = String::new();
            for entry in entries {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&format!(
                    "{} {} [{}] {}",
                    match entry.entry.src {
                        LogSource::Serve => "serve",
                        LogSource::Up => "up",
                        LogSource::RootDaemon => "daemon",
                        LogSource::Fcitx => "fcitx",
                        LogSource::Pid(_) => "pid",
                    },
                    entry.entry.log.level,
                    entry.entry.log.target,
                    entry.entry.log.message,
                ));
                for field in &entry.entry.log.fields {
                    text.push_str(&format!("\n{}={}", field.name, field.value));
                }
            }
            text
        })
    }

    fn render_dbus_tab(&mut self, ui: &mut egui::Ui) {
        let Some(profile) = self.selected_profile.clone() else {
            ui.heading("Input Methods");
            ui.label("Select a profile to control its private Fcitx session.");
            return;
        };
        if self.fcitx_tab.profile.as_ref() != Some(&profile) {
            self.fcitx_tab.profile = Some(profile.clone());
            self.fcitx_tab.state = None;
            self.fcitx_tab.pending = false;
            if let Some(runtime) = self.tokio_rt.as_ref() {
                self.fcitx_tab.request(runtime, profile.clone(), None);
            }
        }
        let uses_private_bus = self
            .snapshot
            .profiles
            .get(&profile)
            .is_some_and(|state| state.template.dbus == DbusMode::Container);
        if !uses_private_bus {
            ui.heading("Input Methods");
            ui.label("Input-method controls require this profile's private D-Bus session.");
            return;
        }

        self.fcitx_tab.poll();
        ui.horizontal(|ui| {
            ui.heading("Input Methods");
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    if ui
                        .add_enabled(!self.fcitx_tab.pending, egui::Button::new("Refresh"))
                        .clicked()
                    {
                        if let Some(runtime) = self.tokio_rt.as_ref() {
                            self.fcitx_tab.request(runtime, profile.clone(), None);
                        }
                    }
                },
            );
        });
        let Some(state) = self.fcitx_tab.state.clone() else {
            self.render_fcitx_log_panel(ui);
            return;
        };

        egui::Frame::NONE
            .fill(Color32::from_gray(30))
            .stroke(egui::Stroke::NONE)
            .inner_margin(egui::Margin::same(8))
            .corner_radius(egui::CornerRadius::same(4))
            .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (status, color) = match state.status {
                    fcitx::FcitxStatus::Disabled => ("Disabled", Color32::GRAY),
                    fcitx::FcitxStatus::Inactive => {
                        ("Inactive (ready to activate)", Color32::LIGHT_YELLOW)
                    }
                    fcitx::FcitxStatus::Active => ("Active", Color32::LIGHT_GREEN),
                };
                ui.add_sized(
                    egui::vec2(270.0, 20.0),
                    egui::Label::new(
                        egui::RichText::new(format!("Fcitx: {status}")).color(color),
                    ),
                );
                let button = match state.status {
                    fcitx::FcitxStatus::Active => "Deactivate",
                    fcitx::FcitxStatus::Disabled | fcitx::FcitxStatus::Inactive => "Activate",
                };
                if ui
                    .add_enabled(!self.fcitx_tab.pending, egui::Button::new(button))
                    .clicked()
                {
                    if let Some(runtime) = self.tokio_rt.as_ref() {
                        self.fcitx_tab.request(
                            runtime,
                            profile.clone(),
                            Some(fcitx::FcitxAction::SetActive(
                                state.status != fcitx::FcitxStatus::Active,
                            )),
                        );
                    }
                }
                });
            ui.horizontal(|ui| {
                ui.label("Input-method group");
                let mut selected_group = state.current_group.clone();
                egui::ComboBox::from_id_salt("fcitx_input_method_group")
                    .selected_text(&state.current_group)
                    .show_ui(ui, |ui| {
                        for group in &state.groups {
                            let label = if group.layout.is_empty() {
                                group.name.clone()
                            } else {
                                format!("{} ({})", group.name, group.layout)
                            };
                            ui.selectable_value(&mut selected_group, group.name.clone(), label);
                        }
                    });
                if selected_group != state.current_group {
                    if let Some(runtime) = self.tokio_rt.as_ref() {
                        self.fcitx_tab.request(
                            runtime,
                            profile.clone(),
                            Some(fcitx::FcitxAction::SetGroup(selected_group)),
                        );
                    }
                }
            });
        });

        let current_group = state
            .groups
            .iter()
            .find(|group| group.name == state.current_group);
        let pending = self.fcitx_tab.pending;
        let mut requested_action = None;
        ui.add_space(8.0);
        ui.columns(2, |columns| {
            egui::Frame::NONE
                .fill(Color32::from_gray(22))
                .stroke(egui::Stroke::NONE)
                .inner_margin(egui::Margin::same(10))
                .corner_radius(egui::CornerRadius::same(4))
                .show(&mut columns[0], |ui| {
                ui.heading("Configured methods");
                ui.small("Select a method to switch. Configure opens its options window.");
                ui.small("The current marker appears only while a container app has an input context.");
                if let Some(group) = current_group {
                    egui::ScrollArea::vertical()
                        .id_salt("fcitx_configured_methods")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            for input_method in &group.input_methods {
                                ui.horizontal(|ui| {
                                    if ui
                                        .add_enabled(
                                            !pending,
                                            egui::Button::selectable(
                                                state.status == fcitx::FcitxStatus::Active
                                                    && state.current_input_method == *input_method,
                                                input_method,
                                            ),
                                        )
                                        .clicked()
                                    {
                                        requested_action = Some(
                                            fcitx::FcitxAction::SetInputMethod(
                                                input_method.clone(),
                                            ),
                                        );
                                    }
                                    if ui
                                        .add_enabled(
                                            !pending,
                                            egui::Button::new("Configure"),
                                        )
                                        .on_hover_text(format!(
                                            "Open {}'s configuration window",
                                            input_method
                                        ))
                                        .clicked()
                                    {
                                        requested_action = Some(
                                            fcitx::FcitxAction::ConfigureInputMethod(
                                                input_method.clone(),
                                            ),
                                        );
                                    }
                                });
                            }
                        });
                } else {
                    ui.weak("This group has no configured methods.");
                }
                });

            egui::Frame::NONE
                .fill(Color32::from_gray(22))
                .stroke(egui::Stroke::NONE)
                .inner_margin(egui::Margin::same(10))
                .corner_radius(egui::CornerRadius::same(4))
                .show(&mut columns[1], |ui| {
                ui.heading("Add installed method");
                ui.add(
                    egui::TextEdit::singleline(&mut self.fcitx_tab.input_method_search)
                        .hint_text("Search by name, language, or ID")
                        .desired_width(f32::INFINITY),
                );
                let search = self.fcitx_tab.input_method_search.trim().to_lowercase();
                if search.is_empty() {
                    ui.weak("Type to search available methods.");
                } else if let Some(group) = current_group {
                    let candidates: Vec<_> = state
                        .available_input_methods
                        .iter()
                        .filter(|method| {
                            !group.input_methods.contains(&method.id)
                                && (method.id.to_lowercase().contains(&search)
                                    || method.name.to_lowercase().contains(&search)
                                    || method.language.to_lowercase().contains(&search))
                        })
                        .take(20)
                        .cloned()
                        .collect();
                    if candidates.is_empty() {
                        ui.weak("No matching unconfigured methods.");
                    } else {
                        egui::ScrollArea::vertical()
                            .id_salt("fcitx_available_input_methods")
                            .max_height(180.0)
                            .show(ui, |ui| {
                                for method in candidates {
                                    let label = if method.language.is_empty() {
                                        format!("{} ({})", method.name, method.id)
                                    } else {
                                        format!(
                                            "{} ({}, {})",
                                            method.name, method.id, method.language
                                        )
                                    };
                                    if ui
                                        .add_enabled(!pending, egui::Button::new(label))
                                        .clicked()
                                    {
                                        requested_action = Some(
                                            fcitx::FcitxAction::AddInputMethod(method.id),
                                        );
                                    }
                                }
                                });
                    }
                }
            });
        });
        if let (Some(action), Some(runtime)) = (requested_action, self.tokio_rt.as_ref()) {
            self.fcitx_tab
                .request(runtime, profile.clone(), Some(action));
        }
        self.render_fcitx_log_panel(ui);
    }

    fn render_fcitx_log_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.separator();
        ui.heading("Fcitx logs");
        let logs = self
            .fcitx_tab
            .logs
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let entries = logs.entries_for_min_level(self.log_panel_min_level.rank_value());
        let total_entries = logs.total_entries();
        let mut min_level = self.log_panel_min_level;
        if let Some(text) = Self::render_structured_log_panel(
            ui,
            "fcitx",
            "No Fcitx activity yet.",
            format!("No Fcitx logs at or above {}", min_level.label()),
            &mut min_level,
            entries,
            total_entries,
        ) {
            self.log_editor_popup = Some(LogEditorPopup {
                title: format!("{} Fcitx logs", self.selected_profile.as_deref().unwrap_or("")),
                text,
            });
        }
    }

    fn render_daemon_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("sp daemon");
        ui.add_space(6.0);

        let guard = self
            .snapshot
            .root_daemon_logs
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let entries = guard.entries_for_min_level(self.log_panel_min_level.rank_value());
        let total_entries = guard.total_entries();

        if let Some(text) = Self::render_structured_log_panel(
            ui,
            "root_daemon",
            "no daemon logs yet",
            format!(
                "no daemon logs at or above {}",
                self.log_panel_min_level.label()
            ),
            &mut self.log_panel_min_level,
            entries,
            total_entries,
        ) {
            self.log_editor_popup = Some(LogEditorPopup {
                title: "sp daemon logs".to_string(),
                text,
            });
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);

        let daemon_error = self.snapshot.root_daemon_error.as_deref();
        let version_mismatch =
            daemon_error.is_some_and(|err| err.to_ascii_lowercase().contains("version mismatch"));
        let (status_text, detail_text, detail_color) = if version_mismatch {
            (
                "version mismatch",
                daemon_error.unwrap_or("sp daemon version mismatch"),
                Color32::from_rgb(220, 120, 90),
            )
        } else if let Some(error) = daemon_error {
            let status = if error
                .to_ascii_lowercase()
                .contains("failed to restart sp daemon")
                || error
                    .to_ascii_lowercase()
                    .contains("root daemon channel unavailable")
                || error
                    .to_ascii_lowercase()
                    .contains("root daemon command channel dropped")
            {
                "error starting daemon"
            } else if self.snapshot.root_daemon_connection
                == supervisor::ConnectionState::Connecting
            {
                "connecting"
            } else {
                "error"
            };
            (status, error, Color32::from_rgb(220, 120, 90))
        } else {
            match self.snapshot.root_daemon_connection {
                supervisor::ConnectionState::Connected => (
                    "running",
                    "UI is connected to the sp daemon socket.",
                    Color32::from_rgb(120, 200, 140),
                ),
                supervisor::ConnectionState::Connecting => (
                    "connecting",
                    "UI is connecting to the sp daemon socket.",
                    Color32::from_rgb(220, 180, 90),
                ),
                supervisor::ConnectionState::Disconnected => (
                    "stopped",
                    "sp daemon socket is not connected.",
                    Color32::from_gray(140),
                ),
                supervisor::ConnectionState::NoRetry => (
                    "error",
                    "sp daemon is in a terminal error state.",
                    Color32::from_rgb(220, 120, 90),
                ),
            }
        };

        ui.label(RichText::new(format!("status: {status_text}")).strong());
        ui.colored_label(detail_color, detail_text);
    }

    fn effective_hotconfig_status<'a>(&'a self, profile_name: &ContainerName) -> Option<&'a str> {
        if let Some(status) = &self.hotconfig_editor_status {
            if status != "Saving hotconfig via sp daemon..." {
                return Some(status.as_str());
            }
        }
        if let Some(EditorStatus {
            profile: Some(status_profile),
            message,
            ..
        }) = self.snapshot.hotconfig_editor_status.as_ref()
        {
            if status_profile == profile_name {
                return Some(message.as_str());
            }
        }
        self.hotconfig_editor_status.as_deref()
    }

    fn effective_profile_editor_status(&self) -> Option<&str> {
        if let Some(status) = &self.profile_editor_status {
            if status != "Saving profile via sp daemon..."
                && status != "Creating profile via sp daemon..."
            {
                return Some(status.as_str());
            }
        }
        if let Some(status) = self.snapshot.profile_editor_status.as_ref() {
            return Some(status.message.as_str());
        }
        self.profile_editor_status.as_deref()
    }

    fn render_process_controls(&mut self, ui: &mut egui::Ui, profile_name: &ContainerName) {
        let (
            container_lifecycle,
            up_running,
            serve_running,
            template_error,
            child_pid,
            up_connected,
            up_connection,
            up_error,
            serve_diag_connected,
            diag_connection,
            diag_error,
            sandbox_status,
            sandbox_mode,
        ) = self
            .snapshot
            .profiles
            .get(profile_name)
            .map(|p| {
                (
                    p.container_lifecycle,
                    p.child_alive,
                    p.serve_alive,
                    p.template_error.clone(),
                    p.child_pid,
                    p.up_connected,
                    p.up_connection,
                    p.up_error.clone(),
                    p.diag_connected,
                    p.diag_connection,
                    p.diag_error.clone(),
                    p.sandbox_status.clone(),
                    p.template.sandbox_mode.clone(),
                )
            })
            .unwrap_or((
                supervisor::ContainerLifecycleState::Stopped,
                false,
                false,
                None,
                None,
                false,
                supervisor::ConnectionState::Disconnected,
                None,
                false,
                supervisor::ConnectionState::Disconnected,
                None,
                None,
                SandboxMode::Overlay,
            ));

        // True when the container is up but pivot-root sandbox has not been applied yet.
        let unpivoted = up_running
            && matches!(
                container_lifecycle,
                supervisor::ContainerLifecycleState::Running
            )
            && sandbox_mode == SandboxMode::Pivot
            && sandbox_status
                .as_ref()
                .map_or(true, |s| s.detected_state == SandboxState::NoPivot);

        ui.horizontal(|ui| {
            let spacing = ui.spacing().item_spacing.x;
            let width_each = (ui.available_width() - spacing).max(0.0) / 2.0;

            let up_disabled = !up_running && template_error.is_some();
            let up_subtitle = if up_disabled {
                template_error.as_deref().unwrap_or("invalid").to_string()
            } else if unpivoted {
                child_pid.map_or("no sandbox — click to apply".to_string(), |p| {
                    format!("no sandbox  pid={p}")
                })
            } else {
                match container_lifecycle {
                    supervisor::ContainerLifecycleState::Stopped => "down".to_string(),
                    supervisor::ContainerLifecycleState::Starting => {
                        child_pid.map_or("starting".to_string(), |p| format!("starting  pid={p}"))
                    }
                    supervisor::ContainerLifecycleState::Running => {
                        if up_connection == supervisor::ConnectionState::Connecting {
                            child_pid.map_or("connecting".to_string(), |p| {
                                format!("connecting  pid={p}")
                            })
                        } else if up_connected {
                            child_pid
                                .map_or("connected".to_string(), |p| format!("connected  pid={p}"))
                        } else {
                            child_pid.map_or("disconnected".to_string(), |p| {
                                format!("disconnected  pid={p}")
                            })
                        }
                    }
                    supervisor::ContainerLifecycleState::Stopping { attempt } => child_pid
                        .map_or(format!("stop attempt {attempt}"), |p| {
                            format!("stop attempt {attempt}  pid={p}")
                        }),
                    supervisor::ContainerLifecycleState::Killing { attempt } => child_pid
                        .map_or(format!("kill attempt {attempt}"), |p| {
                            format!("kill attempt {attempt}  pid={p}")
                        }),
                }
            };
            let up_title = if unpivoted {
                "Apply Sandbox"
            } else {
                match container_lifecycle {
                    supervisor::ContainerLifecycleState::Stopped => "Start Container",
                    supervisor::ContainerLifecycleState::Starting
                    | supervisor::ContainerLifecycleState::Running => "Restart Container",
                    supervisor::ContainerLifecycleState::Stopping { .. }
                    | supervisor::ContainerLifecycleState::Killing { .. } => "Kill Container",
                }
            };
            let up_color = if up_disabled {
                egui::Color32::from_rgb(160, 80, 80)
            } else if unpivoted {
                egui::Color32::from_rgb(255, 185, 0)
            } else if matches!(
                container_lifecycle,
                supervisor::ContainerLifecycleState::Starting
            ) {
                egui::Color32::from_rgb(200, 165, 90)
            } else if up_running && up_connection == supervisor::ConnectionState::Connecting {
                egui::Color32::from_rgb(200, 165, 90)
            } else if matches!(
                container_lifecycle,
                supervisor::ContainerLifecycleState::Stopping { .. }
            ) {
                egui::Color32::from_rgb(190, 110, 90)
            } else if matches!(
                container_lifecycle,
                supervisor::ContainerLifecycleState::Killing { .. }
            ) {
                egui::Color32::from_rgb(200, 70, 70)
            } else if up_running && up_connected {
                egui::Color32::from_rgb(80, 160, 220)
            } else if up_running {
                egui::Color32::from_rgb(190, 110, 90)
            } else {
                egui::Color32::from_rgb(180, 180, 180)
            };

            let mut up_resp = sidebar_box_width(
                ui,
                up_title,
                &up_subtitle,
                up_running,
                up_color,
                Some(width_each),
            );
            if up_disabled {
                if let Some(ref err) = template_error {
                    up_resp =
                        up_resp.on_hover_text(format!("TemplateConfig invalid or missing: {err}"));
                }
            } else if let Some(ref err) = up_error {
                up_resp = up_resp.on_hover_text(format!("sp up: {err}"));
            }

            if !up_disabled && up_resp.clicked() {
                if unpivoted {
                    info!(
                        profile = profile_name.as_str(),
                        "ui clicked Apply Sandbox (unpivoted state)"
                    );
                    self.supervisor.send(SupervisorCommand::RunSandbox {
                        profile: profile_name.clone(),
                        reason: "apply sandbox from process controls (unpivoted)".to_string(),
                    });
                } else {
                    match container_lifecycle {
                        supervisor::ContainerLifecycleState::Stopped => {
                            info!(
                                profile = profile_name.as_str(),
                                "ui clicked Start Container"
                            );
                            self.supervisor.send(SupervisorCommand::StartUp {
                                profile: profile_name.clone(),
                                rust_backtrace: self.rust_backtrace,
                            });
                        }
                        supervisor::ContainerLifecycleState::Starting
                        | supervisor::ContainerLifecycleState::Running => {
                            info!(
                                profile = profile_name.as_str(),
                                child_pid, "ui clicked Restart Container"
                            );
                            self.supervisor.send(SupervisorCommand::StartUp {
                                profile: profile_name.clone(),
                                rust_backtrace: self.rust_backtrace,
                            });
                        }
                        supervisor::ContainerLifecycleState::Stopping { .. }
                        | supervisor::ContainerLifecycleState::Killing { .. } => {
                            info!(
                                profile = profile_name.as_str(),
                                child_pid, "ui clicked Kill Container"
                            );
                            self.supervisor.send(SupervisorCommand::KillContainer {
                                profile: profile_name.clone(),
                            });
                        }
                    }
                } // end else !unpivoted
            }

            let serve_enabled = up_running
                && matches!(
                    container_lifecycle,
                    supervisor::ContainerLifecycleState::Running
                );

            let serve_subtitle = if !serve_enabled {
                "requires container up"
            } else if serve_running && diag_connection == supervisor::ConnectionState::Connecting {
                "connecting"
            } else if serve_running && serve_diag_connected {
                "connected"
            } else if serve_running {
                "disconnected"
            } else {
                "down"
            };
            let serve_title = if serve_running {
                "Stop TUN"
            } else {
                "Start TUN"
            };
            let serve_color = if !serve_enabled {
                egui::Color32::from_rgb(160, 80, 80)
            } else if serve_running && diag_connection == supervisor::ConnectionState::Connecting {
                egui::Color32::from_rgb(200, 165, 90)
            } else if serve_running && serve_diag_connected {
                egui::Color32::from_rgb(120, 200, 140)
            } else if serve_running {
                egui::Color32::from_rgb(190, 110, 90)
            } else {
                egui::Color32::from_rgb(180, 180, 180)
            };

            let mut serve_resp = sidebar_box_width(
                ui,
                serve_title,
                serve_subtitle,
                serve_running,
                serve_color,
                Some(width_each),
            );
            if let Some(ref err) = diag_error {
                serve_resp = serve_resp.on_hover_text(format!("diag: {err}"));
            } else if !serve_enabled {
                serve_resp = serve_resp.on_hover_text("Start Container first");
            }
            if serve_enabled && serve_resp.clicked() {
                if serve_running {
                    info!(profile = profile_name.as_str(), "ui clicked Stop TUN");
                    self.supervisor.send(SupervisorCommand::StopServe {
                        profile: profile_name.clone(),
                    });
                } else {
                    info!(profile = profile_name.as_str(), "ui clicked Start TUN");
                    self.supervisor.send(SupervisorCommand::StartServe {
                        profile: profile_name.clone(),
                        rust_backtrace: self.rust_backtrace,
                    });
                }
            }
        });

        ui.add_space(6.0);
        let snapshot = &self.snapshot;
        let mut log_panel_min_level = self.log_panel_min_level;
        let profile = snapshot.profiles.get(profile_name);
        let logs_guard = match profile {
            Some(profile) => Some(
                profile
                    .logs_by_level
                    .read()
                    .unwrap_or_else(|e| e.into_inner()),
            ),
            None => None,
        };

        if let Some(guard) = logs_guard.as_ref() {
            let entries = guard.entries_for_min_level(log_panel_min_level.rank_value());
            let total_entries = guard.total_entries();
            if let Some(text) = Self::render_structured_log_panel(
                ui,
                profile_name,
                "no logs yet — start the container to see output",
                format!(
                    "no logs at or above {} for this profile",
                    log_panel_min_level.label()
                ),
                &mut log_panel_min_level,
                entries,
                total_entries,
            ) {
                self.log_editor_popup = Some(LogEditorPopup {
                    title: format!("{} logs", self.display_text(profile_name)),
                    text,
                });
            }
        } else {
            if let Some(text) = Self::render_structured_log_panel(
                ui,
                profile_name,
                "no logs yet — start the container to see output",
                format!(
                    "no logs at or above {} for this profile",
                    log_panel_min_level.label()
                ),
                &mut log_panel_min_level,
                &VecDeque::new(),
                0,
            ) {
                self.log_editor_popup = Some(LogEditorPopup {
                    title: format!("{} logs", self.display_text(profile_name)),
                    text,
                });
            }
        }

        self.log_panel_min_level = log_panel_min_level;
    }

    fn render_log_editor_popup(&mut self, ctx: &egui::Context) {
        let Some(popup) = self.log_editor_popup.as_mut() else {
            return;
        };

        let mut open = true;
        egui::Window::new(&popup.title)
            .id(egui::Id::new("structured_log_editor_popup"))
            .default_size(egui::vec2(900.0, 640.0))
            .min_size(egui::vec2(500.0, 320.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label("Editable local snapshot of the currently filtered log view");
                ui.add_space(6.0);
                let mut editor = CodeEditor::default()
                    .id_source("structured_log_editor")
                    .with_rows(32)
                    .with_theme(ColorTheme::GRUVBOX)
                    .with_numlines(true)
                    .with_ui_fontsize(ui);
                let syntax =
                    Syntax::new("log").with_keywords(["ERROR", "WARN", "INFO", "DEBUG", "TRACE"]);
                let _ = editor.show(ui, &mut popup.text, &syntax);
            });

        if !open {
            self.log_editor_popup = None;
        }
    }

    fn render_process_spawn_args_panel(&mut self, ui: &mut egui::Ui) {
        let Some((profile, slot_pid)) = self.selected_process_spawn_args.clone() else {
            return;
        };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading(format!("SpawnArgs — PID {slot_pid}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    self.selected_process_spawn_args = None;
                }
            });
        });

        let maybe_entry = self
            .snapshot
            .profiles
            .get(&profile)
            .and_then(|p| p.process_list_snapshot.as_ref())
            .and_then(|snap| snap.procs.get(&slot_pid))
            .cloned();

        egui::Frame::NONE
            .fill(Color32::from_gray(16))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| match maybe_entry {
                Some(entry) => match entry.meta {
                    diag::SpawnedEntry::Args(mut args) => {
                        Self::render_spawn_args_gadget(
                            ui,
                            &mut self.int_input,
                            &mut args,
                            "process-inspect-spawnargs",
                            true,
                        );
                    }
                    diag::SpawnedEntry::Pty(mut args) => {
                        ui.colored_label(
                            Color32::from_rgb(100, 180, 240),
                            "PTY process (interactive terminal)",
                        );
                        Self::render_spawn_args_gadget(
                            ui,
                            &mut self.int_input,
                            &mut args,
                            "process-inspect-spawnargs-pty",
                            true,
                        );
                    }
                    diag::SpawnedEntry::Cli(cli_meta) => {
                        ui.colored_label(
                            Color32::from_rgb(220, 170, 90),
                            "This unit was launched via SpawnCli payload.",
                        );
                        ui.label(format!(
                            "cli_bincode bytes: {}  mode: {}",
                            cli_meta.cli_bincode.len(),
                            match cli_meta.kind {
                                diag::SpawnCliKind::Serve => "serve",
                                diag::SpawnCliKind::Dbus => "dbus",
                                diag::SpawnCliKind::Other => "spawncli",
                            }
                        ));
                    }
                },
                None => {
                    ui.colored_label(Color32::from_gray(120), "process entry not found");
                }
            });
    }

    fn render_units_table(&mut self, ui: &mut egui::Ui, profile_name: &Option<ContainerName>) {
        self.poll_term_windows();

        // Collect owned rows so we don't borrow self.snapshot across the mutable send below.
        let rows: Vec<(ContainerName, u32, diag::ProcessEntry)> = {
            let mut v = Vec::new();
            if let Some(profile) = profile_name {
                if let Some(profile_snapshot) = self.snapshot.profiles.get(profile) {
                    if let Some(diag::ProcessListSnapshot { procs, .. }) =
                        profile_snapshot.process_list_snapshot.as_ref()
                    {
                        v.extend(
                            procs
                                .iter()
                                .map(|(pid, entry)| (profile.clone(), *pid, entry.clone())),
                        );
                    }
                }
            } else {
                for (pname, profile_snapshot) in &self.snapshot.profiles {
                    if let Some(diag::ProcessListSnapshot { procs, .. }) =
                        profile_snapshot.process_list_snapshot.as_ref()
                    {
                        v.extend(
                            procs
                                .iter()
                                .map(|(pid, entry)| (pname.clone(), *pid, entry.clone())),
                        );
                    }
                }
            }
            v
        };

        if rows.is_empty() {
            ui.label("No managed apps running");
            return;
        }

        let now = std::time::SystemTime::now();
        let mut kill_request: Option<(ContainerName, u32)> = None;
        let mut inspect_request: Option<(ContainerName, u32)> = None;
        let mut logs_request: Option<(ContainerName, u32)> = None;
        let mut swap_external_pty_request: Option<(ContainerName, u32, String)> = None;
        let mut open_dedicated_pty_request: Option<(ContainerName, u32, String)> = None;
        let mut close_dedicated_pty_request: Option<(ContainerName, u32)> = None;

        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto()) // Container
            .column(Column::exact(58.0)) // PGID
            .column(Column::exact(80.0)) // State
            .column(Column::auto()) // Program
            .column(Column::exact(42.0)) // UID
            .column(Column::auto()) // Spawned
            .column(Column::exact(46.0)) // Kill
            .column(Column::exact(64.0)) // Inspect
            .column(Column::exact(60.0)) // Logs
            .column(Column::exact(50.0)) // Swap
            .column(Column::exact(54.0)) // Open/Close
            .column(Column::remainder()) // Fill remaining width
            .header(22.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Container");
                });
                header.col(|ui| {
                    ui.strong("PGID");
                });
                header.col(|ui| {
                    ui.strong("State");
                });
                header.col(|ui| {
                    ui.strong("Program");
                });
                header.col(|ui| {
                    ui.strong("UID");
                });
                header.col(|ui| {
                    ui.strong("Spawned");
                });
                header.col(|ui| { /* Kill */ });
                header.col(|ui| { /* Inspect */ });
                header.col(|ui| { /* Logs */ });
                header.col(|ui| {
                    ui.strong("Swap");
                });
                header.col(|ui| {
                    ui.strong("Open");
                });
                header.col(|ui| { /* Fill */ });
            })
            .body(|mut body| {
                for (row_profile, slot_pid, entry) in &rows {
                    body.row(22.0, |mut row| {
                        // Profile
                        row.col(|ui| {
                            ui.label(self.display_text(row_profile.as_str()));
                        });

                        // Managed task identity is the process-group id.
                        let task_pgid = *slot_pid;
                        row.col(|ui| {
                            ui.label(task_pgid.to_string());
                        });

                        // State — colored
                        row.col(|ui| {
                            let (label, color) = match &entry.status {
                                diag::ProcessStatus::Alive => ("running", Color32::LIGHT_GREEN),
                                diag::ProcessStatus::Terminating => {
                                    ("stopping", Color32::from_rgb(220, 165, 60))
                                }
                                diag::ProcessStatus::Killed => {
                                    ("dead", Color32::from_rgb(200, 80, 80))
                                }
                                diag::ProcessStatus::Vacant => ("vacant", Color32::from_gray(130)),
                            };
                            ui.colored_label(color, label);
                        });

                        // Program + UID extraction
                        let (prog, uid_str) = match &entry.meta {
                            diag::SpawnedEntry::Args(a) => {
                                let prog = a.exec_program_hint().unwrap_or_else(|| "-".to_string());
                                let uid = a
                                    .uid
                                    .map(|u| u.to_string())
                                    .unwrap_or_else(|| "-".to_string());
                                (format!("[output] {}", prog), uid)
                            }
                            diag::SpawnedEntry::Pty(a) => {
                                let prog = a.exec_program_hint().unwrap_or_else(|| "-".to_string());
                                let uid = a
                                    .uid
                                    .map(|u| u.to_string())
                                    .unwrap_or_else(|| "-".to_string());
                                (format!("[PTY] {}", prog), uid)
                            }
                            diag::SpawnedEntry::Cli(cli_meta) => {
                                let prog = match cli_meta.kind {
                                    diag::SpawnCliKind::Serve => "sp serve".to_string(),
                                    diag::SpawnCliKind::Dbus => "sp dbus".to_string(),
                                    diag::SpawnCliKind::Other => "sp spawncli".to_string(),
                                };
                                (format!("[output] {}", prog), "-".to_string())
                            }
                        };

                        row.col(|ui| {
                            ui.label(self.display_text(&prog));
                        });
                        row.col(|ui| {
                            ui.label(&uid_str);
                        });

                        let external_title =
                            Self::format_external_terminal_title(row_profile, entry);
                        let swap_title = Self::format_swap_terminal_title(row_profile, entry);
                        let is_swap_target = self.is_same_swap_pty(row_profile, *slot_pid);
                        let is_dedicated_open = self.is_dedicated_pty_open(row_profile, *slot_pid);

                        // Spawned — relative age
                        row.col(|ui| {
                            let age = now.duration_since(entry.spawned_at).unwrap_or_default();
                            let age_str = if age.as_secs() < 60 {
                                format!("{}s ago", age.as_secs())
                            } else if age.as_secs() < 3600 {
                                format!("{}m ago", age.as_secs() / 60)
                            } else {
                                format!("{}h ago", age.as_secs() / 3600)
                            };
                            ui.label(age_str);
                        });

                        // Kill button — only for alive/terminating processes
                        row.col(|ui| {
                            if matches!(
                                &entry.status,
                                diag::ProcessStatus::Alive | diag::ProcessStatus::Terminating
                            ) {
                                if ui.small_button("Kill").clicked() {
                                    kill_request = Some((row_profile.clone(), task_pgid));
                                }
                            }
                        });

                        // Inspect button (SpawnArgs gadget)
                        row.col(|ui| {
                            let is_selected = self
                                .selected_process_spawn_args
                                .as_ref()
                                .map(|(p, pid)| p == row_profile && *pid == *slot_pid)
                                .unwrap_or(false);
                            let btn_text = if is_selected { "Close" } else { "Inspect" };
                            if ui.small_button(btn_text).clicked() {
                                if is_selected {
                                    self.selected_process_spawn_args = None;
                                } else {
                                    inspect_request = Some((row_profile.clone(), *slot_pid));
                                }
                            }
                        });

                        // Raw logs are available only for stdout/stderr processes.
                        row.col(|ui| {
                            if !matches!(&entry.meta, diag::SpawnedEntry::Pty(_)) {
                                let is_selected = self
                                    .selected_process_logs
                                    .as_ref()
                                    .map(|(p, pid)| p == row_profile && *pid == *slot_pid)
                                    .unwrap_or(false);
                                let btn_text = if is_selected { "Close" } else { "Logs" };
                                if ui.small_button(btn_text).clicked() {
                                    if is_selected {
                                        self.selected_process_logs = None;
                                    } else {
                                        logs_request = Some((row_profile.clone(), *slot_pid));
                                    }
                                }
                            }
                        });

                        // Swap PTY into the special second terminal window.
                        row.col(|ui| {
                            if matches!(&entry.meta, diag::SpawnedEntry::Pty(_)) {
                                if ui
                                    .add_enabled(
                                        !is_dedicated_open && !is_swap_target,
                                        egui::Button::new("swap").small(),
                                    )
                                    .on_hover_text(
                                        "Swap this PTY into the special second terminal window",
                                    )
                                    .clicked()
                                {
                                    swap_external_pty_request =
                                        Some((row_profile.clone(), *slot_pid, swap_title.clone()));
                                }
                            }
                        });

                        // Open/Close dedicated PTY window.
                        row.col(|ui| {
                            if matches!(&entry.meta, diag::SpawnedEntry::Pty(_)) {
                                if is_dedicated_open {
                                    if ui
                                        .small_button("close")
                                        .on_hover_text("Close the dedicated PTY window")
                                        .clicked()
                                    {
                                        close_dedicated_pty_request =
                                            Some((row_profile.clone(), *slot_pid));
                                    }
                                } else {
                                    if ui
                                        .add_enabled(
                                            !is_swap_target,
                                            egui::Button::new("open").small(),
                                        )
                                        .on_hover_text(
                                            "Open a dedicated terminal window for this PTY",
                                        )
                                        .clicked()
                                    {
                                        open_dedicated_pty_request =
                                            Some((row_profile.clone(), *slot_pid, external_title));
                                    }
                                }
                            }
                        });

                        row.col(|_ui| {});
                    });
                }
            });

        if let Some((profile, task_pgid)) = kill_request {
            self.supervisor
                .send(SupervisorCommand::KillManagedProcess { profile, task_pgid });
        }
        if let Some((profile, pid)) = inspect_request {
            self.selected_process_spawn_args = Some((profile, pid));
        }
        if let Some((profile, pid)) = logs_request {
            self.selected_process_logs = Some((profile, pid));
        }
        if let Some((profile, pid, title)) = open_dedicated_pty_request {
            self.open_dedicated_pty_window(profile, pid, title);
        }
        if let Some((profile, pid)) = close_dedicated_pty_request {
            self.close_dedicated_pty_window(&profile, pid);
        }
        if let Some((profile, pid, title)) = swap_external_pty_request {
            if !self.is_same_swap_pty(&profile, pid) {
                self.attach_swap_pty_window(profile, pid, title);
            } else if let Err(err) = self.swap_term_window.focus() {
                tracing::warn!(%err, "failed to focus terminal child window");
            }
        }
    }

    fn format_external_terminal_title(
        profile: &ContainerName,
        entry: &diag::ProcessEntry,
    ) -> String {
        let profile = profile.to_string();
        let (program, uid) = match &entry.meta {
            diag::SpawnedEntry::Pty(args) | diag::SpawnedEntry::Args(args) => {
                let raw_program = args
                    .exec_program_hint()
                    .or_else(|| args.args.first().cloned())
                    .unwrap_or_else(|| "-".to_string());
                let program = Path::new(raw_program.as_str())
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(raw_program.as_str())
                    .to_string();
                let uid = args
                    .uid
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string());
                (program, uid)
            }
            diag::SpawnedEntry::Cli(cli_meta) => {
                let program = match cli_meta.kind {
                    diag::SpawnCliKind::Serve => "sp-serve".to_string(),
                    diag::SpawnCliKind::Dbus => "sp-dbus".to_string(),
                    diag::SpawnCliKind::Other => "sp-spawncli".to_string(),
                };
                (program, "-".to_string())
            }
        };

        Self::join_title_parts([
            Some(profile.as_str()),
            Some(program.as_str()),
            Some(uid.as_str()),
        ])
    }

    fn format_swap_terminal_title(profile: &ContainerName, entry: &diag::ProcessEntry) -> String {
        let title = Self::format_external_terminal_title(profile, entry);
        Self::join_title_parts([Some("swap"), Some(title.as_str()), None])
    }

    fn join_title_parts(parts: [Option<&str>; 3]) -> String {
        let mut title = String::new();

        for part in parts
            .into_iter()
            .flatten()
            .map(str::trim)
            .filter(|part| !part.is_empty() && *part != "-")
        {
            if !title.is_empty() {
                title.push_str(" - ");
            }
            title.push_str(part);
        }

        title
    }

    fn is_pty_process(&self, profile: &ContainerName, slot_pid: u32) -> bool {
        self.snapshot
            .profiles
            .get(profile)
            .and_then(|p| p.process_list_snapshot.as_ref())
            .and_then(|snap| snap.procs.get(&slot_pid))
            .map(|entry| matches!(entry.meta, diag::SpawnedEntry::Pty(_)))
            .unwrap_or(false)
    }

    fn process_ringbuf_limit(&self, profile: &ContainerName, slot_pid: u32) -> usize {
        self.snapshot
            .profiles
            .get(profile)
            .and_then(|p| p.process_list_snapshot.as_ref())
            .and_then(|snap| snap.procs.get(&slot_pid))
            .and_then(|entry| match &entry.meta {
                diag::SpawnedEntry::Args(args) | diag::SpawnedEntry::Pty(args) => {
                    args.ringbuf_size.map(|size| size as usize)
                }
                diag::SpawnedEntry::Cli(_) => None,
            })
            .unwrap_or(diag::RAW_LOG_RING_CAP)
    }

    fn request_process_logs(&self, profile: &ContainerName, pid: u32) {
        if self.is_pty_process(profile, pid) {
            self.supervisor.send(SupervisorCommand::AttachPty {
                profile: profile.clone(),
                pid,
            });
        } else {
            self.supervisor.send(SupervisorCommand::QueryRawLogs {
                profile: profile.clone(),
                pid,
                limit: self.process_ringbuf_limit(profile, pid),
                after_seq: self
                    .process_log_editor_target
                    .as_ref()
                    .filter(|target| target.0 == *profile && target.1 == pid)
                    .and(self.process_log_editor_next_seq),
            });
        }
    }

    fn selected_process_is_pty(&self) -> bool {
        self.selected_process_logs
            .as_ref()
            .is_some_and(|(profile, pid)| self.is_pty_process(profile, *pid))
    }

    fn is_same_swap_pty(&self, profile: &ContainerName, pid: u32) -> bool {
        self.swap_term_window
            .current_target()
            .is_some_and(|target| target.profile == *profile && target.pid == pid)
            || self
                .swap_term_window
                .pending_target()
                .is_some_and(|target| target.profile == *profile && target.pid == pid)
    }

    fn is_dedicated_pty_open(&self, profile: &ContainerName, pid: u32) -> bool {
        self.dedicated_term_windows
            .get(&(profile.clone(), pid))
            .is_some_and(|window| window.is_open() || window.pending_target().is_some())
    }

    fn attach_swap_pty_window(&mut self, profile: ContainerName, pid: u32, title: String) {
        let Some(rt) = self.tokio_rt.as_ref() else {
            tracing::warn!("tokio runtime unavailable for swap terminal spawn");
            return;
        };
        if let Err(err) = self.swap_term_window.attach(rt, profile, pid, title) {
            tracing::warn!(%err, "failed to attach swap terminal child window");
        }
    }

    fn close_swap_pty_window(&mut self) {
        self.swap_term_window.shutdown();
    }

    fn open_dedicated_pty_window(&mut self, profile: ContainerName, pid: u32, title: String) {
        let Some(rt) = self.tokio_rt.as_ref() else {
            tracing::warn!("tokio runtime unavailable for dedicated terminal spawn");
            return;
        };
        let key = (profile.clone(), pid);
        let window = self.dedicated_term_windows.entry(key).or_default();
        if let Err(err) = window.attach(rt, profile, pid, title) {
            tracing::warn!(%err, "failed to attach dedicated terminal child window");
        }
    }

    fn close_dedicated_pty_window(&mut self, profile: &ContainerName, pid: u32) {
        if let Some(mut window) = self.dedicated_term_windows.remove(&(profile.clone(), pid)) {
            window.shutdown();
        }
    }

    fn close_dedicated_pty_windows(&mut self) {
        for (_, mut window) in self.dedicated_term_windows.drain() {
            window.shutdown();
        }
    }

    fn poll_term_windows(&mut self) {
        self.swap_term_window.poll();
        self.dedicated_term_windows.retain(|_, window| {
            window.poll();
            window.is_open() || window.pending_target().is_some()
        });
    }

    fn render_process_pty_panel(&mut self, ui: &mut egui::Ui) {
        let Some((selected_profile, selected_slot_pid)) = self.selected_process_logs.as_ref()
        else {
            return;
        };
        let profile = selected_profile.clone();
        let slot_pid = *selected_slot_pid;
        let key = (profile.clone(), slot_pid);

        ui.add_space(8.0);
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.heading(format!("Terminal — PID {slot_pid}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    if !self.is_same_swap_pty(&profile, slot_pid) {
                        self.supervisor.send(SupervisorCommand::DetachPty {
                            profile: profile.clone(),
                            pid: slot_pid,
                        });
                        self.pty_sessions.remove(&key);
                    }
                    self.selected_process_logs = None;
                }
            });
        });

        self.render_process_pty_terminal(ui, &profile, slot_pid);
    }

    fn render_process_pty_terminal(
        &mut self,
        ui: &mut egui::Ui,
        profile: &ContainerName,
        slot_pid: u32,
    ) {
        let key = (profile.clone(), slot_pid);

        let ipc = SupervisorPtyIpc {
            supervisor: self.supervisor.clone(),
            profile: profile.clone(),
            pid: slot_pid,
        };

        let session = self
            .pty_sessions
            .entry(key)
            .or_insert_with(|| TermSession::new(slot_pid));
        pump_pty_io(&ipc, session);

        let mut input_frames: Vec<Vec<u8>> = Vec::new();
        let mut resize_evt: Option<(u16, u16)> = None;
        ui.add(
            TermView::new(session, &mut input_frames, &mut resize_evt)
                .set_size(ui.available_size()),
        );

        flush_term_outputs(&ipc, input_frames, resize_evt);
    }

    fn render_external_pty_window(&mut self, ctx: &egui::Context) {
        let _ = ctx;
        self.poll_term_windows();
    }

    fn render_process_raw_logs_panel(&mut self, ui: &mut egui::Ui) {
        let Some((selected_profile, selected_slot_pid)) = self.selected_process_logs.as_ref()
        else {
            return;
        };
        let profile = selected_profile.clone();
        let slot_pid = *selected_slot_pid;
        let target = (profile.clone(), slot_pid);
        if self.process_log_editor_target.as_ref() != Some(&target) {
            self.process_log_editor_target = Some(target);
            self.process_log_editor_next_seq = None;
            self.process_log_rows.clear();
            self.process_log_rows_bytes = 0;
            self.request_process_logs(&profile, slot_pid);
        }
        ui.add_space(8.0);
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.heading(format!("Output — PID {slot_pid}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    self.supervisor.send(SupervisorCommand::StopQueryRawLogs {
                        profile: profile.clone(),
                        pid: slot_pid,
                    });
                    self.selected_process_logs = None;
                    return;
                }
                if Self::refresh_button(ui, "Refresh").clicked() {
                    self.request_process_logs(&profile, slot_pid);
                }
            });
        });

        egui::Frame::NONE
            .fill(LOG_EDITOR_BACKGROUND)
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_size(egui::vec2(ui.available_width(), 400.0));
                if self.process_log_rows.is_empty() {
                    ui.colored_label(Color32::from_gray(110), "no output yet");
                    return;
                }
                let row_h = ui.text_style_height(&egui::TextStyle::Body);
                egui_log_viewer::LogViewer::show_rows(
                    ui,
                    ("process_raw_logs", &profile, slot_pid),
                    &self.process_log_rows,
                    row_h,
                    388.0,
                    |line| line.clone(),
                    |ui, _row_index, line, _selected| {
                        ui.label(egui_sgr::ansi_to_layout_job(line, log_ansi_theme()));
                    },
                );
            });
    }

    fn render_logs_tab(&mut self, ui: &mut egui::Ui) {
        let files = self.persisted_logs_snapshot.files.clone();

        if self
            .selected_persisted_log_file
            .as_ref()
            .is_some_and(|selected| !files.iter().any(|file| file.path == *selected))
        {
            self.selected_persisted_log_file = None;
        }
        if self.selected_persisted_log_file.is_none() {
            self.selected_persisted_log_file = files.first().map(|file| file.path.clone());
        }

        ui.heading("Logs");
        ui.add_space(6.0);
        ui.colored_label(
            Color32::from_gray(130),
            format!(
                "live file view over {}",
                self.display_path(&state_paths::logs_root())
            ),
        );
        ui.add_space(8.0);

        let sidebar_width = (ui.available_width() * 0.28).clamp(220.0, 300.0);
        let viewer_width = (ui.available_width() - sidebar_width - 12.0).max(320.0);

        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(sidebar_width, ui.available_height()),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.heading("Files");
                    ui.add_space(6.0);

                    egui::ScrollArea::vertical()
                        .id_salt("persisted_logs_file_list")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            if files.is_empty() {
                                ui.colored_label(
                                    Color32::from_gray(110),
                                    "no persisted log files yet",
                                );
                                return;
                            }

                            for file in &files {
                                let is_selected = self
                                    .selected_persisted_log_file
                                    .as_ref()
                                    .is_some_and(|selected| *selected == file.path);
                                let subtitle = match (file.pid, file.modified) {
                                    (Some(pid), Some(modified)) => {
                                        let modified_secs = modified
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        format!("pid {}  updated {}", pid, modified_secs)
                                    }
                                    (Some(pid), None) => format!("pid {}", pid),
                                    (None, Some(modified)) => {
                                        let modified_secs = modified
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        format!("updated {}", modified_secs)
                                    }
                                    (None, None) => String::new(),
                                };
                                if sidebar_box_width(
                                    ui,
                                    &file.process_label,
                                    &subtitle,
                                    is_selected,
                                    Color32::from_rgb(140, 140, 220),
                                    Some(sidebar_width - 8.0),
                                )
                                .clicked()
                                {
                                    self.selected_persisted_log_file = Some(file.path.clone());
                                    self.request_persisted_logs_refresh();
                                }
                                ui.add_space(4.0);
                            }
                        });
                },
            );

            ui.add_space(12.0);

            ui.allocate_ui_with_layout(
                egui::vec2(viewer_width, ui.available_height()),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.heading("Viewer");
                    ui.add_space(6.0);

                    if let Some(selected_path) = self.selected_persisted_log_file.clone() {
                        let selected_file = files.iter().find(|file| file.path == selected_path);
                        let entries = if self.persisted_logs_snapshot.selected_file_path.as_ref()
                            == Some(&selected_path)
                        {
                            self.persisted_logs_snapshot.selected_file_entries.clone()
                        } else {
                            Vec::new()
                        };
                        let visible_entries = entries
                            .iter()
                            .filter(|entry| self.log_panel_min_level.matches(&entry.log.level))
                            .collect::<Vec<_>>();

                        ui.horizontal(|ui| {
                            let label = selected_file
                                .map(|file| file.file_name.as_str())
                                .unwrap_or("selected file");
                            ui.label(RichText::new(label).strong());
                            ui.add_space(8.0);
                            ui.label("Min level");
                            egui::ComboBox::from_id_salt((
                                "persisted_logs_min_level",
                                &selected_path,
                            ))
                            .selected_text(self.log_panel_min_level.label())
                            .show_ui(ui, |ui| {
                                for level in LogMinLevel::ALL {
                                    ui.selectable_value(
                                        &mut self.log_panel_min_level,
                                        level,
                                        level.label(),
                                    );
                                }
                            });
                            ui.add_space(8.0);
                            ui.colored_label(
                                Color32::from_gray(130),
                                format!("showing {} / {}", visible_entries.len(), entries.len()),
                            );
                        });
                        ui.add_space(6.0);

                        if visible_entries.is_empty() {
                            let message = if entries.is_empty() {
                                "selected log file is empty".to_string()
                            } else {
                                format!(
                                    "no saved logs at or above {}",
                                    self.log_panel_min_level.label()
                                )
                            };
                            ui.colored_label(Color32::from_gray(110), message);
                        } else {
                            egui::Frame::NONE
                                .fill(LOG_EDITOR_BACKGROUND)
                                .inner_margin(egui::Margin::same(6))
                                .show(ui, |ui| {
                                    ui.set_min_size(egui::Vec2::new(ui.available_width(), 220.0));
                                    let row_h = ui.text_style_height(&egui::TextStyle::Body);
                                    egui::ScrollArea::vertical()
                                        .id_salt(("persisted_logs_view", &selected_path))
                                        .auto_shrink([false, false])
                                        .stick_to_bottom(true)
                                        .show_rows(
                                            ui,
                                            row_h,
                                            visible_entries.len(),
                                            |ui, row_range| {
                                                for row_index in row_range {
                                                    let Some(entry) =
                                                        visible_entries.get(row_index)
                                                    else {
                                                        continue;
                                                    };
                                                    ui.horizontal(|ui| {
                                                        ui.colored_label(
                                                            LOG_SYNTAX_BLUE,
                                                            "saved",
                                                        );
                                                        ui.colored_label(
                                                            log_level_color(&entry.log.level),
                                                            &entry.log.level,
                                                        );
                                                        ui.colored_label(
                                                            LOG_SYNTAX_MUTED,
                                                            format_timestamp_age(entry.log.ts),
                                                        );
                                                        ui.colored_label(
                                                            LOG_SYNTAX_BLUE,
                                                            format!("[{}]", entry.log.target),
                                                        );
                                                        ui.label(egui_sgr::ansi_to_layout_job(
                                                            &entry.log.message,
                                                            log_ansi_theme(),
                                                        ));
                                                        for field in &entry.log.fields {
                                                            ui.add_space(6.0);
                                                            ui.colored_label(
                                                                LOG_SYNTAX_CYAN,
                                                                format!("{}=", field.name),
                                                            );
                                                            ui.label(
                                                                RichText::new(&field.value)
                                                                    .monospace()
                                                                    .color(LOG_SYNTAX_GREEN),
                                                            );
                                                        }
                                                    });
                                                }
                                            },
                                        );
                                });
                        }
                    } else {
                        ui.colored_label(
                            Color32::from_gray(110),
                            "select a log file from the sidebar",
                        );
                    }
                },
            );
        });
    }

    fn render_run_command_section(&mut self, ui: &mut egui::Ui, profile: &ContainerName) {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        egui::Frame::NONE
            .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, 8))
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                // Title row
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Run Command").strong().size(14.0));
                    ui.weak("POSIX compatible command line");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let can_run = self.run_command.pending_spawn_args.is_some();
                        let run_btn = ui.add_enabled(
                            can_run,
                            egui::Button::new(egui::RichText::new("  Run  ").strong()),
                        );
                        if run_btn.clicked() {
                            if let Some(args) = self.run_command.pending_spawn_args.clone() {
                                if self.run_command.spawn_as_pty {
                                    self.supervisor.send(SupervisorCommand::SpawnPty {
                                        profile: profile.clone(),
                                        args,
                                    });
                                    self.run_command.status =
                                        Some("PTY spawn request sent".to_string());
                                } else {
                                    self.supervisor.send(SupervisorCommand::StartDaemon {
                                        profile: profile.clone(),
                                        args,
                                    });
                                    self.run_command.status =
                                        Some("Output-mode spawn request sent".to_string());
                                }
                                self.run_command.parse_error = None;
                            }
                        }
                    });
                });

                ui.add_space(4.0);

                // Command input
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.run_command.command_line)
                        .hint_text("e.g. /usr/bin/fish  or  curl https://example.com")
                        .desired_width(f32::INFINITY),
                );
                let edited = response.changed();

                let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));

                if enter_pressed {
                    if let Some(args) = self.run_command.pending_spawn_args.clone() {
                        if self.run_command.spawn_as_pty {
                            self.supervisor.send(SupervisorCommand::SpawnPty {
                                profile: profile.clone(),
                                args,
                            });
                            self.run_command.status = Some("PTY spawn request sent".to_string());
                        } else {
                            self.supervisor.send(SupervisorCommand::StartDaemon {
                                profile: profile.clone(),
                                args,
                            });
                            self.run_command.status =
                                Some("Output-mode spawn request sent".to_string());
                        }
                        self.run_command.parse_error = None;
                    } else if response.lost_focus() {
                        refresh_run_command_preview(&mut self.run_command);
                        self.run_command.status = None;
                    }
                }

                ui.add_space(4.0);

                // Checkboxes side-by-side
                ui.horizontal(|ui| {
                    let ns_toggled = ui
                        .checkbox(
                            &mut self.run_command.spawn_inside_container,
                            "Spawn inside container namespace",
                        )
                        .changed();
                    ui.add_space(16.0);
                    let mode_toggled = ui
                        .checkbox(
                            &mut self.run_command.spawn_as_pty,
                            "Spawn as PTY (interactive terminal)",
                        )
                        .changed();
                    if edited || ns_toggled || mode_toggled {
                        self.run_command.status = None;
                        refresh_run_command_preview(&mut self.run_command);
                    }
                });

                // Status / error feedback
                if let Some(err) = self.run_command.parse_error.as_ref() {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            Color32::LIGHT_RED,
                            egui::RichText::new(regular::WARNING)
                                .size(12.0)
                                .color(Color32::LIGHT_RED),
                        );
                        ui.colored_label(Color32::LIGHT_RED, err);
                    });
                }
                if let Some(status) = self.run_command.status.as_ref() {
                    ui.add_space(2.0);
                    ui.colored_label(Color32::from_rgb(140, 190, 240), status);
                }

                if let Some(args) = self.run_command.pending_spawn_args.as_mut() {
                    ui.add_space(8.0);
                    Self::render_spawn_args_gadget(
                        ui,
                        &mut self.int_input,
                        args,
                        "run-command-confirm-spawnargs",
                        false,
                    );
                }
            });
    }

    fn render_host_route_action_popup(
        supervisor: &SupervisorHandle,
        proxies: &BTreeMap<ProxyID, ProxyItem>,
        hide_secret: bool,
        cover_text: &str,
        response: egui::Response,
        profile_name: &str,
        metric: &nsproxy_common::stats::HostRouteMetric,
        selected_route: &nsproxy_common::stats::ObservedRoute,
        diag_connected: bool,
    ) {
        let mut tooltip = egui::Tooltip::for_enabled(&response);
        tooltip.popup = tooltip.popup.align(egui::RectAlign::RIGHT_START).gap(6.0);
        tooltip.show(|popup_ui| {
            let host = nsproxy_common::stats::HostRouteHost::from_wire_address(&metric.key.target);
            popup_ui.strong(host.display_host());
            popup_ui.weak(format!(
                "Last observed {}",
                format_timestamp_age(metric.last_observed.unwrap_or(metric.observed_at))
            ));
            if let nsproxy_common::stats::ObservedRoute::Proxy(proxy_id) = &metric.key.route {
                Self::render_proxy_summary(popup_ui, proxy_id, proxies, hide_secret, cover_text);
            }
            popup_ui.horizontal(|ui| {
                if ui
                    .add_enabled(diag_connected, egui::Button::new("Kill"))
                    .clicked()
                {
                    supervisor.send(SupervisorCommand::Ctrl {
                        profile: profile_name.to_string(),
                        cmd: diag::ControlCommand::KillHostConnections { host: host.clone() },
                    });
                }
                if ui
                    .add_enabled(diag_connected, egui::Button::new("Route"))
                    .clicked()
                {
                    let key = match &metric.key.target {
                        nsproxy_common::routing::WireAddress::SocketAddress(address) => {
                            nsproxy_common::routing::RoutingKey::Addr(
                                nsproxy_common::routing::TargetKey::for_final_destination(*address),
                            )
                        }
                        nsproxy_common::routing::WireAddress::DomainAddress(host, port) => {
                            nsproxy_common::routing::RoutingKey::host(host, Some(*port))
                        }
                    };
                    let decision = match selected_route {
                        nsproxy_common::stats::ObservedRoute::NoProxy => {
                            match &metric.key.target {
                                nsproxy_common::routing::WireAddress::SocketAddress(address) => {
                                    nsproxy_common::routing::RoutingResovled::NoProxy(*address)
                                }
                                nsproxy_common::routing::WireAddress::DomainAddress(host, port) => {
                                    nsproxy_common::routing::RoutingResovled::NoProxyDomain {
                                        host: host.clone(),
                                        port: *port,
                                    }
                                }
                            }
                        }
                        nsproxy_common::stats::ObservedRoute::Proxy(proxy_id) => {
                            nsproxy_common::routing::RoutingResovled::ProxyResovled {
                                target: metric.key.target.clone(),
                                id: proxy_id.clone(),
                            }
                        }
                    };
                    supervisor.send(SupervisorCommand::Ctrl {
                        profile: profile_name.to_string(),
                        cmd: diag::ControlCommand::SetHostRoute {
                            key,
                            decision,
                        },
                    });
                }
            });
        });
    }

    fn render_proxy_summary(
        ui: &mut egui::Ui,
        proxy_id: &ProxyID,
        proxies: &BTreeMap<ProxyID, ProxyItem>,
        hide_secret: bool,
        cover_text: &str,
    ) {
        ui.separator();
        if let Some(proxy) = proxies.get(proxy_id) {
            ui.strong(format!("Proxy: {}", proxy.name));
            let url = if hide_secret { cover_text } else { &proxy.url };
            ui.label(egui::RichText::new(url).monospace());
            ui.horizontal_wrapped(|ui| {
                if let Some(latency_ms) = proxy.latency_ms {
                    ui.label(format!("{} ms", latency_ms));
                }
                if let Some(conn_ok) = proxy.conn_ok {
                    ui.label(if conn_ok {
                        "Connection OK"
                    } else {
                        "Connection failed"
                    });
                }
                ui.label(match proxy.udp_ability {
                    Some(true) => "UDP supported",
                    Some(false) => "UDP failed",
                    None if proxy.udp_expected => "UDP expected",
                    None => "TCP only",
                });
            });
        } else {
            ui.weak(format!("Proxy {}", proxy_id.nym()));
        }
    }

    fn render_traffic_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let original_style = (**ui.style()).clone();
        let mut immediate_tooltip_style = original_style.clone();
        immediate_tooltip_style.interaction.tooltip_delay = 0.0;
        immediate_tooltip_style
            .interaction
            .show_tooltips_only_when_still = false;
        *ui.style_mut() = immediate_tooltip_style;
        self.render_traffic_tab_contents(ui);
        *ui.style_mut() = original_style;
    }

    fn render_traffic_tab_contents(&mut self, ui: &mut egui::Ui) {
        if self.selected_profile.is_none() {
            ui.heading("Traffic — Global");
            ui.label(format!("Profiles: {}", self.snapshot.profiles.len()));
            let running = self
                .snapshot
                .profiles
                .values()
                .map(|p| {
                    let daemon_count = match p.process_list_snapshot.as_ref() {
                        Some(diag::ProcessListSnapshot { procs, .. }) => procs.len(),
                        _ => 0,
                    };
                    (p.child_alive as usize) + (p.serve_alive as usize) + daemon_count
                })
                .sum::<usize>();
            ui.label(format!("Running: {}", running));
            return;
        }

        let profile_name = match self.selected_profile.as_ref() {
            Some(p) => p.clone(),
            None => return,
        };
        let profile = match self.snapshot.profiles.get(&profile_name) {
            Some(p) => p,
            None => return,
        };

        let traffic = &profile.traffic;

        // Header: connection status + loop stats
        ui.horizontal(|ui| {
            ui.heading(format!("Traffic — {}", self.display_text(&profile_name)));
            ui.separator();
            if profile.diag_connected {
                ui.colored_label(Color32::GREEN, "connected");
            } else {
                ui.colored_label(Color32::LIGHT_RED, "disconnected");
                if let Some(err) = &profile.diag_error {
                    ui.label(err.as_str());
                }
            }
        });

        ui.horizontal(|ui| {
            use diag::summary::format_duration_us;
            ui.label(format!(
                "loop body — avg: {}  max: {}  min: {}  samples: {}",
                format_duration_us(traffic.loop_avg_us),
                format_duration_us(traffic.loop_max_us as f64),
                format_duration_us(traffic.loop_min_us as f64),
                traffic.loop_samples,
            ));
            ui.separator();
            ui.label(format!("connections tracked: {}", traffic.conns.len()));
        });

        if let Some(err) = &profile.up_error {
            ui.colored_label(Color32::from_rgb(220, 120, 60), format!("sp up: {err}"));
        }
        if let Some(dns) = &profile.dns_state {
            ui.label(format!(
                "DNS: domains={}, v4={}, v6={}, aaaa_only={}",
                dns.domain_count, dns.ip4_count, dns.ip6_count, dns.aaaa_only
            ));
        }
        if let Some(routing) = &profile.routing_state {
            if routing.no_proxy {
                ui.label("Routing: NoProxy");
            } else if let Some(group_id) = &routing.selected_group {
                ui.label(format!("Routing: selected group '{group_id}'"));
            } else if let Some(proxy_id) = &routing.selected_proxy {
                ui.label(format!("Routing: selected proxy {}", proxy_id));
            } else {
                ui.label("Routing: no route selected");
            }
        }

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        // Sub-view toggle: Connections | Logs
        ui.horizontal(|ui| {
            if ui
                .selectable_label(
                    self.traffic_subview == TrafficSubview::Connections,
                    "Connections",
                )
                .clicked()
            {
                self.traffic_subview = TrafficSubview::Connections;
            }
            if ui
                .selectable_label(self.traffic_subview == TrafficSubview::Logs, "Logs")
                .clicked()
            {
                self.traffic_subview = TrafficSubview::Logs;
            }
        });
        ui.add_space(4.0);

        // ── Logs sub-view (ported from nsp-diag viewer.rs) ───────────────────
        if self.traffic_subview == TrafficSubview::Logs {
            // DNS server + ping toolbar
            ui.horizontal(|ui| {
                ui.label("DNS Server:");
                {
                    let mut dns_addr = self.viewer_dns_config.lock().unwrap();
                    ui.text_edit_singleline(&mut *dns_addr);
                }
                if ui.button("Random IP").clicked() {
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    let ip = format!(
                        "{}.{}.{}.{}:53",
                        rng.gen_range(1u8..=254),
                        rng.gen_range(0u8..=255),
                        rng.gen_range(0u8..=255),
                        rng.gen_range(1u8..=254)
                    );
                    *self.viewer_dns_config.lock().unwrap() = ip;
                }
            });

            ui.horizontal(|ui| {
                if ui.button("DNS ping").clicked() {
                    let now_us = viewer_now_epoch_us();
                    let domain = format!("ping-{}.diag", now_us);
                    let dns_addr = self.viewer_dns_config.lock().unwrap().clone();
                    {
                        let mut ping = self.viewer_ping_state.lock().unwrap();
                        ping.last_domain = Some(domain.clone());
                        ping.last_sent_us = Some(now_us);
                        ping.last_accept_delta_us = None;
                        ping.last_accept_ts = None;
                        ping.last_conn_id = None;
                        ping.last_error = None;
                    }
                    let _ = self
                        .viewer_ping_tx
                        .send(ViewerPingRequest::Single(domain, dns_addr));
                }

                let burst_running = self.viewer_burst_test_state.lock().unwrap().running;
                ui.add_enabled_ui(!burst_running, |ui| {
                    ui.label("Max batch:");
                    let mut burst = self.viewer_burst_test_state.lock().unwrap();
                    let mut log_value = (burst.max_batch_size as f64).log2();
                    if ui
                        .add(
                            egui::Slider::new(&mut log_value, 4.0..=20.0)
                                .custom_formatter(|n, _| {
                                    let val = 2_f64.powf(n).round() as u64;
                                    if val >= 1_048_576 {
                                        format!("{}M", val / 1_048_576)
                                    } else if val >= 1_024 {
                                        format!("{}k", val / 1_024)
                                    } else {
                                        format!("{}", val)
                                    }
                                })
                                .custom_parser(|s| {
                                    let s = s.trim().to_lowercase();
                                    if let Some(s) = s.strip_suffix('m') {
                                        s.parse::<f64>().ok().map(|v| (v * 1_048_576.0).log2())
                                    } else if let Some(s) = s.strip_suffix('k') {
                                        s.parse::<f64>().ok().map(|v| (v * 1_024.0).log2())
                                    } else {
                                        s.parse::<f64>().ok().map(|v| v.log2())
                                    }
                                }),
                        )
                        .changed()
                    {
                        burst.max_batch_size = 2_f64.powf(log_value).round() as u64;
                    }
                    let max_batch = burst.max_batch_size;
                    drop(burst);
                    if ui
                        .button("Burst Test")
                        .on_hover_text(format!(
                            "Test burst sizes (log scale up to {}) to find >5% failure rate",
                            max_batch
                        ))
                        .clicked()
                    {
                        let dns_addr = self.viewer_dns_config.lock().unwrap().clone();
                        let _ = self
                            .viewer_ping_tx
                            .send(ViewerPingRequest::BurstTest(dns_addr));
                    }
                });

                if ui.button("DNS ping x100").clicked() {
                    let now_us = viewer_now_epoch_us();
                    let domains: Vec<String> = (0..100u64)
                        .map(|i| format!("ping-{}-{}.diag", now_us, i))
                        .collect();
                    let dns_addr = self.viewer_dns_config.lock().unwrap().clone();
                    {
                        let mut mass = self.viewer_mass_ping_state.lock().unwrap();
                        mass.last_batch = Some(now_us);
                        mass.started_ts = Some(now_us);
                        mass.finished_ts = None;
                        mass.duration_us = None;
                        mass.rtt_avg_us = None;
                        mass.rtt_min_us = None;
                        mass.rtt_max_us = None;
                        mass.rtt_samples = 0;
                        mass.requested = 100;
                        mass.in_flight = 100;
                        mass.completed = 0;
                        mass.errors = 0;
                        mass.last_error = None;
                    }
                    let _ = self
                        .viewer_ping_tx
                        .send(ViewerPingRequest::Batch(domains, dns_addr));
                }

                let ping = self.viewer_ping_state.lock().unwrap();
                if let Some(ref domain) = ping.last_domain {
                    ui.label(format!("last: {}", domain));
                }
                if let Some(delta) = ping.last_accept_delta_us {
                    use diag::summary::format_duration_us;
                    ui.label(format!("accept Δ: {}", format_duration_us(delta as f64)));
                } else if ping.last_domain.is_some() {
                    ui.label("accept Δ: …");
                }
                if let Some(err) = ping.last_error.as_ref() {
                    ui.colored_label(Color32::RED, err);
                }
            });

            // Mass ping / batch results
            ui.horizontal(|ui| {
                let mass = self.viewer_mass_ping_state.lock().unwrap();
                if let Some(ts) = mass.last_batch {
                    ui.label(format!("batch: {}", ts));
                }
                ui.label(format!(
                    "requested: {}  in_flight: {}  completed: {}",
                    mass.requested, mass.in_flight, mass.completed
                ));
                if let Some(dur) = mass.duration_us {
                    use diag::summary::format_duration_us;
                    ui.label(format!("duration: {}", format_duration_us(dur as f64)));
                    if mass.completed > 0 {
                        let rps = (mass.completed as f64) / (dur as f64 / 1_000_000.0);
                        ui.label(format!("rate: {:.1}/s", rps));
                    }
                } else if mass.in_flight > 0 {
                    if let Some(started) = mass.started_ts {
                        use diag::summary::format_duration_us;
                        ui.label(format!(
                            "elapsed: {}",
                            format_duration_us(viewer_now_epoch_us().saturating_sub(started) as f64)
                        ));
                    }
                }
                if let Some(avg) = mass.rtt_avg_us {
                    use diag::summary::format_duration_us;
                    ui.label(format!(
                        "rtt avg/min/max: {} / {} / {} (n={})",
                        format_duration_us(avg as f64),
                        format_duration_us(mass.rtt_min_us.unwrap_or(avg) as f64),
                        format_duration_us(mass.rtt_max_us.unwrap_or(avg) as f64),
                        mass.rtt_samples
                    ));
                }
                if mass.errors > 0 {
                    ui.colored_label(Color32::RED, format!("errors: {}", mass.errors));
                }
                if let Some(err) = mass.last_error.as_ref() {
                    ui.colored_label(Color32::RED, err);
                }
            });

            // Burst test results
            {
                let burst = self.viewer_burst_test_state.lock().unwrap();
                let is_running = burst.running;
                let has_results = !burst.results.is_empty();
                let last_error = burst.last_error.clone();
                let results = burst.results.clone();
                let threshold_size = burst.threshold_size;
                let started_ts = burst.started_ts;
                let finished_ts = burst.finished_ts;
                drop(burst);

                if is_running {
                    ui.horizontal(|ui| {
                        ui.label("⏳ Burst test running...");
                        if let Some(started) = started_ts {
                            use diag::summary::format_duration_us;
                            ui.label(format!(
                                "elapsed: {}",
                                format_duration_us(
                                    viewer_now_epoch_us().saturating_sub(started) as f64
                                )
                            ));
                        }
                    });
                } else if has_results {
                    let finished = finished_ts.unwrap_or(0);
                    let started = started_ts.unwrap_or(0);
                    let duration_ms = finished.saturating_sub(started) as f64 / 1000.0;
                    let overall_fr =
                        results.iter().map(|r| r.failure_rate).sum::<f64>() / results.len() as f64;
                    let hit_threshold = threshold_size.is_some();

                    egui::ScrollArea::horizontal()
                        .id_salt(format!("burst_results_{}", profile_name))
                        .show(ui, |ui| {
                            egui::Grid::new(format!("burst_grid_{}", profile_name))
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label("Batch");
                                    ui.label("Success/Req");
                                    ui.label("Failure %");
                                    ui.label("Min RTT");
                                    ui.label("Avg RTT");
                                    ui.label("Max RTT");
                                    ui.end_row();
                                    for r in &results {
                                        ui.label(format!("n={}", r.size));
                                        ui.label(format!(
                                            "{}/{}",
                                            r.completed.saturating_sub(r.errors),
                                            r.requested
                                        ));
                                        let color = if r.failure_rate > 5.0 {
                                            Color32::RED
                                        } else if r.failure_rate > 1.0 {
                                            Color32::YELLOW
                                        } else {
                                            Color32::GREEN
                                        };
                                        ui.colored_label(color, format!("{:.1}%", r.failure_rate));
                                        use diag::summary::format_duration_us;
                                        ui.label(format_duration_us(r.latency_us_min as f64));
                                        ui.label(format_duration_us(r.latency_us_avg as f64));
                                        ui.label(format_duration_us(r.latency_us_max as f64));
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.horizontal(|ui| {
                        if let Some(threshold) = threshold_size {
                            ui.colored_label(
                                Color32::RED,
                                format!("⚠ Threshold: >5% failures at n={}", threshold),
                            );
                        } else {
                            ui.colored_label(Color32::GREEN, "✓ All tests passed (<5% failures)");
                        }
                        {
                            let mut stats = self.viewer_burst_test_stats.lock().unwrap();
                            if stats.test_count < results.len() as u64 {
                                stats.add_test(overall_fr, duration_ms, hit_threshold);
                            }
                        }
                        if let Some(err) = last_error.as_ref() {
                            ui.colored_label(Color32::RED, err);
                        }
                    });
                } else if let Some(err) = last_error {
                    ui.colored_label(Color32::RED, &err);
                }
            }

            // ── Selected connection details ────────────────────────────────
            ui.separator();
            let selected = self.viewer_selected_conn;
            if let Some(id) = selected {
                if let Some(c) = profile.traffic.conns.get(&id) {
                    ui.horizontal(|ui| {
                        ui.strong(format!("Conn {}", c.id.0));
                        ui.label(format!("kind: {}  src: {}  dst: {}", c.kind, c.src, c.dst));
                        if !c.route.is_empty() {
                            ui.label(format!("route: {}", c.route));
                        }
                        if let Some(ref q) = c.dns_query {
                            if let Some(ref r) = c.dns_response {
                                ui.label(format!("dns: {} → {}", q, r));
                            } else {
                                ui.label(format!("dns: {} → …", q));
                            }
                        }
                        ui.label(format!(
                            "dispatch: {}µs  ↑{:.0}B ↓{:.0}B",
                            c.dispatch_us, c.bytes_up, c.bytes_down
                        ));
                        if let Some(ref err) = c.error {
                            ui.colored_label(Color32::RED, format!("err: {}", err));
                        }
                    });
                } else {
                    ui.colored_label(
                        Color32::from_gray(120),
                        "selected connection no longer tracked",
                    );
                }
            } else {
                ui.colored_label(
                    Color32::from_gray(100),
                    "click a row to see connection details",
                );
            }

            // ── Connection table ───────────────────────────────────────────
            let conn_order: Vec<diag::ConnId> =
                profile.traffic.conn_order.iter().cloned().collect();
            let conns = profile.traffic.conns.clone();
            let selected_cell = std::cell::Cell::new(self.viewer_selected_conn);
            let row_height = 18.0_f32;

            egui::ScrollArea::horizontal()
                .id_salt(format!("viewer_conns_{}", profile_name))
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::auto().at_least(60.0))
                        .column(Column::auto().at_least(80.0))
                        .column(Column::auto().at_least(120.0))
                        .column(Column::remainder().at_least(160.0))
                        .column(Column::remainder().at_least(140.0))
                        .column(Column::auto().at_least(90.0))
                        .column(Column::auto().at_least(90.0))
                        .column(Column::auto().at_least(90.0))
                        .column(Column::auto().at_least(80.0))
                        .column(Column::exact(12.0))
                        .header(row_height, |mut header| {
                            header.col(|ui| {
                                ui.strong("ID");
                            });
                            header.col(|ui| {
                                ui.strong("Kind");
                            });
                            header.col(|ui| {
                                ui.strong("Src");
                            });
                            header.col(|ui| {
                                ui.strong("Dst / Route");
                            });
                            header.col(|ui| {
                                ui.strong("DNS");
                            });
                            header.col(|ui| {
                                ui.strong("Dispatch");
                            });
                            header.col(|ui| {
                                ui.strong("Connect").on_hover_text("Accepted to Connected");
                            });
                            header.col(|ui| {
                                ui.strong("Duration");
                            });
                            header.col(|ui| {
                                ui.strong("Status");
                            });
                            header.col(|_ui| {});
                        })
                        .body(|mut body| {
                            body.rows(row_height, conn_order.len(), |mut row| {
                                let cid = conn_order[row.index()];
                                if let Some(c) = conns.get(&cid) {
                                    let is_sel = selected_cell.get() == Some(c.id);
                                    row.col(|ui| {
                                        if ui
                                            .selectable_label(is_sel, format!("{}", c.id.0))
                                            .clicked()
                                        {
                                            selected_cell.set(Some(c.id));
                                        }
                                    });
                                    row.col(|ui| {
                                        ui.label(&c.kind);
                                    });
                                    row.col(|ui| {
                                        ui.label(&c.src);
                                    });
                                    row.col(|ui| {
                                        ui.label(if c.route.is_empty() {
                                            &c.dst
                                        } else {
                                            &c.route
                                        });
                                    });
                                    row.col(|ui| match (&c.dns_query, &c.dns_response) {
                                        (Some(q), Some(r)) => {
                                            ui.label(format!(
                                                "{} {} {}",
                                                q,
                                                regular::ARROW_RIGHT,
                                                r
                                            ));
                                        }
                                        (Some(q), None) => {
                                            ui.label(format!("{} {} …", q, regular::ARROW_RIGHT));
                                        }
                                        _ => {}
                                    });
                                    row.col(|ui| {
                                        use diag::summary::format_duration_us;
                                        let color = if c.kind == "Wait" {
                                            Color32::LIGHT_BLUE
                                        } else if c.dispatch_us > 1000 {
                                            Color32::RED
                                        } else if c.dispatch_us > 100 {
                                            Color32::YELLOW
                                        } else {
                                            Color32::GREEN
                                        };
                                        ui.colored_label(
                                            color,
                                            format_duration_us(c.dispatch_us as f64),
                                        );
                                    });
                                    row.col(|ui| {
                                        use diag::summary::format_duration_us;
                                        let lat = if c.is_dns() {
                                            c.dns_resolve_latency()
                                        } else {
                                            c.connect_latency()
                                        };
                                        if let Some(d) = lat {
                                            let us = d.as_secs_f64() * 1_000_000.0;
                                            let color = if us > 500_000.0 {
                                                Color32::RED
                                            } else if us > 100_000.0 {
                                                Color32::YELLOW
                                            } else {
                                                Color32::GREEN
                                            };
                                            ui.colored_label(color, format_duration_us(us));
                                        }
                                    });
                                    row.col(|ui| {
                                        if !c.is_dns() {
                                            if let Some(dur) = c.total_duration() {
                                                use diag::summary::format_duration_us;
                                                ui.label(format_duration_us(
                                                    dur.as_secs_f64() * 1_000_000.0,
                                                ));
                                            } else {
                                                ui.label("active");
                                            }
                                        }
                                    });
                                    row.col(|ui| {
                                        if let Some(ref err) = c.error {
                                            if err == "killed by user" {
                                                ui.colored_label(Color32::from_gray(150), "killed");
                                            } else {
                                                ui.colored_label(
                                                    Color32::RED,
                                                    format!("{}", &err[..err.len().min(40)]),
                                                );
                                            }
                                        } else if c.is_dns() {
                                            if let Some(ref resp) = c.dns_response {
                                                if resp.starts_with("err:") {
                                                    ui.colored_label(Color32::RED, "error");
                                                } else {
                                                    ui.colored_label(Color32::GREEN, "resolved");
                                                }
                                            }
                                        } else if c.finished_ts.is_some() {
                                            ui.colored_label(Color32::GREEN, "OK");
                                        }
                                    });
                                    row.col(|_ui| {});
                                }
                            });
                        });
                });

            self.viewer_selected_conn = selected_cell.get();
            return;
        }

        // ── Connections sub-view ──────────────────────────────────────────────
        let conns = &profile.conns_state;
        let row_height = 18.0_f32;
        let proxies = &self.proxies;
        let hide_secret = self.hide_secret;
        let cover_text = self.cover_text.as_str();
        if conns.conns.is_empty() {
            ui.colored_label(Color32::from_gray(110), "no tracked connections");
        }

        let render_conn_table = |ui: &mut egui::Ui, id_salt: String, ids: &[diag::ConnId]| {
            egui::ScrollArea::horizontal()
                .id_salt(id_salt.clone())
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .id_salt(format!("{}_tbl", id_salt))
                        .striped(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::auto().at_least(70.0)) // ID
                        .column(Column::auto().at_least(105.0)) // State
                        .column(Column::remainder().at_least(140.0)) // Route
                        .column(Column::remainder().at_least(160.0)) // Destination
                        .column(Column::auto().at_least(70.0)) // Duration
                        .header(row_height, |mut header| {
                            header.col(|ui| {
                                ui.strong("ID");
                            });
                            header.col(|ui| {
                                ui.strong("State");
                            });
                            header.col(|ui| {
                                ui.strong("Route");
                            });
                            header.col(|ui| {
                                ui.strong("Destination");
                            });
                            header.col(|ui| {
                                ui.strong("Duration");
                            });
                        })
                        .body(|mut body| {
                            body.rows(row_height, ids.len(), |mut row| {
                                let id = ids[row.index()];
                                let Some(entry) = conns.conns.get(&id) else {
                                    return;
                                };
                                row.col(|ui| {
                                    ui.colored_label(Color32::LIGHT_BLUE, format!("{}", id.0));
                                });
                                row.col(|ui| {
                                    ui.colored_label(
                                        conn_phase_color(entry.phase),
                                        conn_phase_label(entry.phase),
                                    );
                                });
                                row.col(|ui| {
                                    let response = ui.label(conn_route_label(entry.route.as_ref()));
                                    response.on_hover_ui(|ui| {
                                        ui.strong(format!(
                                            "Connection #{} — {}",
                                            id.0, entry.dst
                                        ));
                                        ui.label(format!(
                                            "Final state: {}",
                                            conn_phase_label(entry.phase)
                                        ));
                                        if let Some(
                                            nsproxy_common::routing::RoutingResovled::ProxyResovled {
                                                id,
                                                ..
                                            },
                                        ) = entry.route.as_ref()
                                        {
                                            Self::render_proxy_summary(
                                                ui,
                                                id,
                                                proxies,
                                                hide_secret,
                                                cover_text,
                                            );
                                        }
                                        if let Some(error) = &entry.error {
                                            ui.colored_label(Color32::LIGHT_RED, error);
                                        }
                                        if entry.history_truncated {
                                            ui.weak("Earlier transitions were trimmed.");
                                        }
                                        egui::ScrollArea::vertical()
                                            .max_height(280.0)
                                            .show(ui, |ui| {
                                                egui::Grid::new(("conn_history", id.0))
                                                    .striped(true)
                                                    .show(ui, |ui| {
                                                        for transition in &entry.history {
                                                            ui.label(format_conn_timestamp(
                                                                transition.ts,
                                                            ));
                                                            ui.label(conn_transition_label(
                                                                &transition.kind,
                                                            ));
                                                            ui.end_row();
                                                        }
                                                    });
                                            });
                                    });
                                });
                                row.col(|ui| {
                                    ui.label(format!("{}", entry.dst));
                                });
                                row.col(|ui| {
                                    let end = entry
                                        .finished_at
                                        .unwrap_or_else(diag::Timestamp::now);
                                    let duration = end.elapsed_since(entry.accepted_at);
                                    ui.label(diag::summary::format_duration_us(
                                        duration.as_secs_f64() * 1_000_000.0,
                                    ));
                                });
                            });
                        });
                });
        };

        if !profile.recent_conn_ids.is_empty() {
            ui.label(egui::RichText::new("Recent connections").strong());
            render_conn_table(
                ui,
                format!("conns_recent_{}", profile_name),
                &profile.recent_conn_ids,
            );
        }

        ui.add_space(6.0);
        egui::CollapsingHeader::new(format!(
            "Recent host / route performance ({})",
            profile.recent_host_routes.len()
        ))
        .default_open(true)
        .show(ui, |ui| {
            let supervisor = &self.supervisor;
            let route_targets = &self.traffic_route_targets;
            let route_target_index = &mut self.traffic_route_target_index;
            let route_target = &mut self.traffic_route_target;
            let route_filter = &mut self.traffic_route_filter;
            let filtered_route_target_indices = &self.filtered_traffic_route_target_indices;
            ui.weak("Showing up to 512 recent TCP and UDP target/routes, including routes before measurements are available.");
            ui.horizontal(|ui| {
                ui.label("Click button to route to");
                egui::ComboBox::from_id_salt("traffic_host_route_target")
                    .selected_text(
                        route_targets
                            .get(*route_target_index)
                            .map(|target| target.key.as_str())
                            .unwrap_or("NoProxy"),
                    )
                    .width(360.0)
                    .height(360.0)
                    .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                    .show_ui(ui, |ui| {
                        ui.set_min_width(420.0);
                        ui.set_min_height(340.0);
                        ui.add(
                            egui::TextEdit::singleline(route_filter)
                                .hint_text("Filter by proxy name or address")
                                .desired_width(400.0),
                        );
                        ui.separator();
                        if filtered_route_target_indices.is_empty() {
                            ui.weak("No matching routes.");
                        } else {
                            egui::ScrollArea::vertical()
                                .max_height(280.0)
                                .min_scrolled_height(220.0)
                                .show_rows(
                                    ui,
                                    24.0,
                                    filtered_route_target_indices.len(),
                                    |ui, rows| {
                                        for row in rows {
                                            let target_index = filtered_route_target_indices[row];
                                            let target = &route_targets[target_index];
                                            ui.horizontal(|ui| {
                                                let selected = *route_target_index == target_index;
                                                let clicked = ui
                                                    .selectable_label(selected, &target.key)
                                                    .clicked();
                                                let summary = if hide_secret
                                                    && matches!(
                                                        &target.route,
                                                        nsproxy_common::stats::ObservedRoute::Proxy(
                                                            _
                                                    )
                                                    ) {
                                                    cover_text
                                                } else {
                                                    target.summary.as_str()
                                                };
                                                ui.add_sized(
                                                    [260.0, 20.0],
                                                    egui::Label::new(
                                                        egui::RichText::new(summary).monospace(),
                                                    ),
                                                );
                                                if clicked {
                                                    *route_target_index = target_index;
                                                    *route_target = target.route.clone();
                                                    ui.close();
                                                }
                                            });
                                        }
                                    },
                                );
                        }
                    });
                if let Some(target) = route_targets.get(*route_target_index) {
                    *route_target = target.route.clone();
                }
            });
            if profile.recent_host_routes.is_empty() {
                ui.weak("No recent host / route activity yet.");
                return;
            }
            let selected_route = route_target.clone();
            let diag_connected = profile.diag_connected;
            TableBuilder::new(ui)
                .id_salt("host_route_performance")
                .max_scroll_height(360.0)
                .animate_scrolling(false)
                .striped(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder().at_least(180.0))
                .column(Column::remainder().at_least(130.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::auto().at_least(70.0))
                .column(Column::auto().at_least(85.0))
                .column(Column::auto().at_least(85.0))
                .column(Column::auto().at_least(85.0))
                .column(Column::auto().at_least(85.0))
                .header(row_height, |mut header| {
                    header.col(|ui| {
                        ui.strong("Target");
                    });
                    header.col(|ui| {
                        ui.strong("Route");
                    });
                    header.col(|ui| {
                        ui.strong("Connect");
                    });
                    header.col(|ui| {
                        ui.strong("Success");
                    });
                    header.col(|ui| {
                        ui.strong("TCP up");
                    });
                    header.col(|ui| {
                        ui.strong("TCP down");
                    });
                    header.col(|ui| {
                        ui.strong("UDP up");
                    });
                    header.col(|ui| {
                        ui.strong("UDP down");
                    });
                })
                .body(|mut body| {
                    body.rows(row_height, profile.recent_host_routes.len(), |mut row| {
                        let metric = &profile.recent_host_routes[row.index()];
                        row.col(|ui| {
                            ui.label(metric.key.target.to_string());
                        });
                        row.col(|ui| {
                            let response = ui.label(format!("{:?}", metric.key.route));
                            Self::render_host_route_action_popup(
                                supervisor,
                                proxies,
                                hide_secret,
                                cover_text,
                                response,
                                &profile_name,
                                metric,
                                &selected_route,
                                diag_connected,
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                metric
                                    .connect_latency_ms
                                    .map(|ms| format!("{ms:.0} ms"))
                                    .unwrap_or_else(|| "—".to_string()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                metric
                                    .connect_success_rate
                                    .map(|rate| format!("{:.0}%", rate * 100.0))
                                    .unwrap_or_else(|| "—".to_string()),
                            );
                        });
                        row.col(|ui| {
                            render_transfer_rate_cell(
                                ui,
                                metric.upload_bytes_per_sec,
                                metric.upload_rate_summary,
                                metric.upload_sample,
                            );
                        });
                        row.col(|ui| {
                            render_transfer_rate_cell(
                                ui,
                                metric.download_bytes_per_sec,
                                metric.download_rate_summary,
                                metric.download_sample,
                            );
                        });
                        row.col(|ui| {
                            render_transfer_rate_cell(
                                ui,
                                metric.udp_upload_bytes_per_sec,
                                metric.udp_upload_rate_summary,
                                metric.udp_upload_sample,
                            );
                        });
                        row.col(|ui| {
                            render_transfer_rate_cell(
                                ui,
                                metric.udp_download_bytes_per_sec,
                                metric.udp_download_rate_summary,
                                metric.udp_download_sample,
                            );
                        });
                    });
                });
        });
    }

    // ── Manage tab ────────────────────────────────────────────────────────────

    fn wizard_do_create(&mut self) {
        let name = self.manage_wizard.new_name.trim().to_string();
        self.manage_wizard.template.dbus = self.manage_wizard.dbus_mode.clone();
        self.manage_wizard.template.hot = PathBuf::from("@/hot.json");
        self.manage_wizard.template.hot_init = Some(self.manage_wizard.hot.clone());
        let profile_content = match serde_json::to_string_pretty(&self.manage_wizard.template) {
            Ok(s) => s,
            Err(e) => {
                self.manage_wizard.status = Some(format!("Serialize error: {e}"));
                return;
            }
        };
        let hot_content = serde_json::to_string_pretty(&self.manage_wizard.hot).ok();
        self.manage_wizard.status = Some(format!("Creating '{}'...", name));
        self.supervisor
            .send(SupervisorCommand::CreateProfilePrivileged {
                name,
                profile_content,
                hot_content,
            });
    }

    fn render_manage_tab(&mut self, ui: &mut egui::Ui) {
        let step = self.manage_wizard.step.clone();
        let mode = self.manage_wizard.mode.clone();

        // Read keyboard shortcuts before any mutable borrow of ui
        let key_back = !ui.ctx().egui_wants_keyboard_input()
            && ui.ctx().input(|i| i.key_pressed(egui::Key::ArrowLeft));
        let key_next = !ui.ctx().egui_wants_keyboard_input()
            && ui.ctx().input(|i| i.key_pressed(egui::Key::ArrowRight));

        // Compute back/next step for this step
        let back_step: Option<WizardStep> = match step {
            WizardStep::Landing => None,
            WizardStep::PivotApps => Some(WizardStep::Landing),
            WizardStep::DbusMode => Some(
                if self.manage_wizard.template_kind == WizardTemplateKind::Pivot {
                    WizardStep::PivotApps
                } else {
                    WizardStep::Landing
                },
            ),
            WizardStep::PortListeners => Some(WizardStep::DbusMode),
            WizardStep::RouteTargets => Some(WizardStep::PortListeners),
            WizardStep::DnsHandling => Some(WizardStep::RouteTargets),
            WizardStep::ReviewHotconfig => Some(WizardStep::DnsHandling),
            WizardStep::Name => Some(WizardStep::ReviewHotconfig),
        };

        let next_step: Option<(WizardStep, &str)> = match step {
            WizardStep::Landing | WizardStep::Name => None,
            WizardStep::PivotApps => Some((WizardStep::DbusMode, "Next: D-Bus")),
            WizardStep::DbusMode => Some((WizardStep::PortListeners, "Next: Port Listeners")),
            WizardStep::PortListeners => Some((WizardStep::RouteTargets, "Next: Route Targets")),
            WizardStep::RouteTargets => Some((WizardStep::DnsHandling, "Next: DNS")),
            WizardStep::DnsHandling => Some((WizardStep::ReviewHotconfig, "Next: Review")),
            WizardStep::ReviewHotconfig => Some((WizardStep::Name, "Next: Create")),
        };

        let name_ok = step == WizardStep::Name && {
            let n = self.manage_wizard.new_name.trim();
            !n.is_empty() && !n.contains('/')
        };

        // ── Bottom nav bar (must be declared before content area) ──────────
        let mut do_back = false;
        let mut do_next: Option<WizardStep> = None;
        let mut do_create = false;

        if back_step.is_some() || step == WizardStep::Name {
            egui::Panel::bottom("wizard_bottom_nav")
                .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(8, 8)))
                .show_separator_line(false)
                .show(ui, |ui| {
                    // Draw top border
                    let border_color = ui.visuals().widgets.noninteractive.bg_stroke.color;
                    let r = ui.max_rect();
                    ui.painter()
                        .hline(r.x_range(), r.top(), egui::Stroke::new(1.0, border_color));
                    ui.add_space(4.0);

                    ui.horizontal(|ui| {
                        // Back card
                        if let Some(ref bstep) = back_step {
                            if wizard_nav_card(ui, "← Back", "Left Arrow", true).clicked()
                                || key_back
                            {
                                do_back = true;
                                let _ = bstep; // used below
                            }
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if step == WizardStep::Name {
                                // Create card
                                if wizard_nav_card(ui, "✓ Create Profile", "Right Arrow", name_ok)
                                    .clicked()
                                    || (key_next && name_ok)
                                {
                                    do_create = true;
                                }
                            } else if let Some((ref nstep, label)) = next_step {
                                if wizard_nav_card(ui, &format!("{} →", label), "Right Arrow", true)
                                    .clicked()
                                    || key_next
                                {
                                    do_next = Some(nstep.clone());
                                }
                            }
                        });
                    });
                });
        }

        // Apply nav actions
        if do_back {
            if let Some(s) = back_step {
                self.manage_wizard.step = s;
            }
        }
        if let Some(s) = do_next {
            self.manage_wizard.step = s;
        }
        if do_create {
            self.wizard_do_create();
        }

        // ── Step content ───────────────────────────────────────────────────
        egui::ScrollArea::vertical()
            .id_salt("wizard_content_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Manage Containers");
                ui.add_space(6.0);
                match step {
                    WizardStep::Landing => self.render_wizard_landing(ui),
                    WizardStep::PivotApps => self.render_wizard_pivot_apps(ui),
                    WizardStep::DbusMode => self.render_wizard_dbus_mode(ui),
                    WizardStep::PortListeners => self.render_wizard_port_listeners(ui),
                    WizardStep::RouteTargets => self.render_wizard_route_targets(ui),
                    WizardStep::DnsHandling => self.render_wizard_dns_handling(ui),
                    WizardStep::ReviewHotconfig => self.render_wizard_review_hotconfig(ui),
                    WizardStep::Name => self.render_wizard_name(ui),
                }
            });
    }

    fn wizard_step_label(step: &WizardStep) -> &'static str {
        match step {
            WizardStep::Landing => "Start",
            WizardStep::PivotApps => "1 / Apps",
            WizardStep::DbusMode => "2 / D-Bus",
            WizardStep::PortListeners => "3 / Port Listeners",
            WizardStep::RouteTargets => "4 / Route Targets",
            WizardStep::DnsHandling => "5 / DNS Handling",
            WizardStep::ReviewHotconfig => "6 / Review",
            WizardStep::Name => "7 / Create",
        }
    }

    fn render_wizard_breadcrumb(&mut self, ui: &mut egui::Ui) {
        let is_pivot = self.manage_wizard.template_kind == WizardTemplateKind::Pivot;
        let steps: &[WizardStep] = if is_pivot {
            &[
                WizardStep::PivotApps,
                WizardStep::DbusMode,
                WizardStep::PortListeners,
                WizardStep::RouteTargets,
                WizardStep::DnsHandling,
                WizardStep::ReviewHotconfig,
                WizardStep::Name,
            ]
        } else {
            &[
                WizardStep::DbusMode,
                WizardStep::PortListeners,
                WizardStep::RouteTargets,
                WizardStep::DnsHandling,
                WizardStep::ReviewHotconfig,
                WizardStep::Name,
            ]
        };
        let current_idx = steps
            .iter()
            .position(|s| s == &self.manage_wizard.step)
            .unwrap_or(usize::MAX);
        let mut jump_to: Option<WizardStep> = None;

        ui.horizontal_wrapped(|ui| {
            for (i, step) in steps.iter().enumerate() {
                let label = Self::wizard_step_label(step);
                if i == current_idx {
                    // Current step — highlighted, not interactive
                    ui.label(RichText::new(label).color(Color32::LIGHT_BLUE).strong());
                } else {
                    // Any other step — all independent, all jumpable; dim, no text selection
                    let resp = ui
                        .add(
                            egui::Label::new(RichText::new(label).color(Color32::from_gray(100)))
                                .selectable(false)
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        jump_to = Some(step.clone());
                    }
                }
                ui.colored_label(Color32::from_gray(50), "›");
            }
        });

        if let Some(step) = jump_to {
            self.manage_wizard.step = step;
        }
        ui.add_space(8.0);
    }

    fn render_wizard_landing(&mut self, ui: &mut egui::Ui) {
        ui.label("What would you like to do?");
        ui.add_space(12.0);

        let overlay_fill = Color32::from_rgb(38, 30, 14);
        let overlay_hover = Color32::from_rgba_unmultiplied(200, 150, 60, 28);
        let pivot_fill = Color32::from_rgb(14, 24, 40);
        let pivot_hover = Color32::from_rgba_unmultiplied(80, 130, 200, 28);

        let mut go_overlay = false;
        let mut go_pivot = false;

        section_frame(ui, |ui| {
            ui.heading("Create from Template");
            ui.add_space(6.0);

            // ── Overlay — Basic ───────────────────────────────────
            let resp = egui::Frame::NONE
                .fill(overlay_fill)
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("Overlay — Basic").strong());
                    ui.label(
                        "Host root filesystem visible inside the container. Maximum compatibility \
                        for most desktop software. Pre-configures port 9909 (Geph) and internal DNS.",
                    );
                })
                .response
                .interact(egui::Sense::click());
            if resp.hovered() {
                ui.painter().rect_filled(resp.rect, 0.0, overlay_hover);
            }
            if resp.clicked() {
                go_overlay = true;
            }

            ui.add_space(4.0);

            // ── Pivot ─────────────────────────────────────────────────
            let resp = egui::Frame::NONE
                .fill(pivot_fill)
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Pivot").strong());
                        ui.label(
                            RichText::new(" best isolation ")
                                .background_color(Color32::from_rgb(28, 52, 88))
                                .color(Color32::from_rgb(130, 175, 220))
                                .small(),
                        );
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Replaces the root filesystem entirely. Best method to prevent");
                        ui.label(
                            RichText::new(" accidental IP leaks ")
                                .background_color(Color32::from_rgb(66, 54, 0))
                                .color(Color32::from_rgb(255, 230, 150))
                                .strong(),
                        );
                        ui.label("by app launches in the wrong namespace. Choose which apps run inside on the next step. 
In a state-based identity model, programs launched outside the container can not access the state associated with an identity; therefore you can not accidentally correlate IPs with a particular identity.
Pivot-enabled containers have URL opening handled right within the container, which is a trouble for Dbus available overlay-type container.");
                    });
                })
                .response
                .interact(egui::Sense::click());
            if resp.hovered() {
                ui.painter().rect_filled(resp.rect, 0.0, pivot_hover);
            }
            if resp.clicked() {
                go_pivot = true;
            }
        });

        if go_overlay {
            self.manage_wizard.mode = WizardMode::CreateFromTemplate;
            self.manage_wizard.template_kind = WizardTemplateKind::OverlayBasic;
            let (mut tmpl, hot) = wizard_build_template(
                WizardTemplateKind::OverlayBasic,
                &std::collections::BTreeSet::new(),
            );
            tmpl.dbus = self.manage_wizard.dbus_mode.clone();
            self.manage_wizard.template = tmpl;
            self.manage_wizard.hot = hot;
            self.manage_wizard.hot_json =
                serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
            self.manage_wizard.step = WizardStep::DbusMode;
        }
        if go_pivot {
            self.manage_wizard.mode = WizardMode::CreateFromTemplate;
            self.manage_wizard.template_kind = WizardTemplateKind::Pivot;
            self.manage_wizard.pivot_apps.clear();
            self.manage_wizard.step = WizardStep::PivotApps;
        }

        ui.add_space(8.0);

        section_frame(ui, |ui| {
            ui.heading("Clone Existing Container");
            ui.label("Copy the configuration of an existing profile as a starting point.");
            ui.add_space(8.0);

            let profiles: Vec<(String, String)> = self
                .snapshot
                .profiles
                .iter()
                .map(|(name, snap)| {
                    let subtitle = if snap.child_alive {
                        "running".to_string()
                    } else {
                        format!("{:?}", snap.template.sandbox_mode)
                    };
                    (name.clone(), subtitle)
                })
                .collect();

            if profiles.is_empty() {
                ui.colored_label(
                    Color32::from_gray(120),
                    "No existing profiles found. Create one from a template first.",
                );
            } else {
                let mut clone_src: Option<String> = None;
                for (name, subtitle) in &profiles {
                    let selected = self.manage_wizard.clone_source == *name;
                    let status_color = if self
                        .snapshot
                        .profiles
                        .get(name)
                        .map(|s| s.child_alive)
                        .unwrap_or(false)
                    {
                        Color32::LIGHT_GREEN
                    } else {
                        Color32::from_gray(100)
                    };
                    if sidebar_box(
                        ui,
                        &self.display_text(name),
                        subtitle,
                        selected,
                        status_color,
                    )
                    .clicked()
                    {
                        clone_src = Some(name.clone());
                    }
                    ui.add_space(2.0);
                }

                if let Some(src) = clone_src {
                    let profile_path = state_paths::profile_config(&src);
                    let hot_path = state_paths::hot_config(&src);
                    match TemplateConfig::load(&profile_path) {
                        Ok(tmpl) => {
                            self.manage_wizard.template = tmpl;
                            let mut hot: HotConfig = std::fs::read_to_string(&hot_path)
                                .ok()
                                .and_then(|s| serde_json::from_str(&s).ok())
                                .unwrap_or_default();
                            if let Some(route) = self.live_route_for_profile(&src) {
                                hot.default_route = route;
                            }
                            self.manage_wizard.template.hot_init = Some(hot.clone());
                            self.manage_wizard.hot = hot;
                            self.manage_wizard.hot_json =
                                serde_json::to_string_pretty(&self.manage_wizard.hot)
                                    .unwrap_or_default();
                            self.manage_wizard.clone_source = src;
                            self.manage_wizard.mode = WizardMode::CloneExisting;
                            self.manage_wizard.step = WizardStep::DbusMode;
                            self.manage_wizard.status = None;
                        }
                        Err(e) => {
                            self.manage_wizard.status =
                                Some(format!("Could not load profile: {}", e));
                        }
                    }
                }
            }

            if let Some(err) = &self.manage_wizard.status {
                ui.add_space(4.0);
                ui.colored_label(Color32::LIGHT_RED, err);
            }
        });
    }

    // render_wizard_template_kind removed — template selection merged into render_wizard_landing

    fn render_wizard_pivot_apps(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("Choose Apps");
        ui.add_space(4.0);
        ui.label(
            "Select the apps that will run inside this container. \
            Each adds its profile data and required sockets. \
            Multiple apps share the same network namespace — they are additive.",
        );
        ui.add_space(8.0);

        let pivot_fill = Color32::from_rgb(14, 24, 40);
        let pivot_active_fill = Color32::from_rgb(22, 38, 62);
        let pivot_hover = Color32::from_rgba_unmultiplied(80, 130, 200, 28);
        let badge_bg = Color32::from_rgb(28, 52, 88);
        let badge_fg = Color32::from_rgb(130, 175, 220);

        let all_apps = [PivotAppKind::Firefox, PivotAppKind::SignalAppImage];
        let mut changed = false;

        for app in &all_apps {
            let is_active = self.manage_wizard.pivot_apps.contains(app);
            let fill = if is_active {
                pivot_active_fill
            } else {
                pivot_fill
            };
            let resp = egui::Frame::NONE
                .fill(fill)
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(app.label()).strong());
                        if is_active {
                            ui.label(
                                RichText::new(" added ")
                                    .background_color(badge_bg)
                                    .color(badge_fg)
                                    .small(),
                            );
                        }
                    });
                    ui.label(app.description());
                })
                .response
                .interact(egui::Sense::click());
            if resp.hovered() {
                ui.painter().rect_filled(resp.rect, 0.0, pivot_hover);
            }
            if resp.clicked() {
                if is_active {
                    self.manage_wizard.pivot_apps.remove(app);
                } else {
                    self.manage_wizard.pivot_apps.insert(app.clone());
                }
                changed = true;
            }
            ui.add_space(4.0);
        }

        if self.manage_wizard.pivot_apps.is_empty() {
            ui.colored_label(
                Color32::from_gray(120),
                "No apps selected — creates a bare pivot sandbox with no pre-configured mounts.",
            );
        }

        if changed {
            let (mut tmpl, hot) = wizard_build_pivot_template(&self.manage_wizard.pivot_apps);
            tmpl.dbus = self.manage_wizard.dbus_mode.clone();
            self.manage_wizard.template = tmpl;
            self.manage_wizard.hot = hot;
            self.manage_wizard.hot_json =
                serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
        }
    }

    fn render_wizard_dbus_mode(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("D-Bus Mode");
        ui.add_space(4.0);
        ui.label("Controls whether and how the session D-Bus is exposed inside the container.");
        ui.add_space(10.0);

        let mut changed = false;

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dbus_mode == DbusMode::Block;
            if ui
                .selectable_label(sel, "Block  (no session bus)")
                .clicked()
            {
                self.manage_wizard.dbus_mode = DbusMode::Block;
                changed = true;
            }
            ui.label("No session D-Bus inside the container. DBUS_SESSION_BUS_ADDRESS is unset.");
        });
        ui.add_space(6.0);

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dbus_mode == DbusMode::Container;
            if ui
                .selectable_label(sel, "Container  (default, private bus)")
                .clicked()
            {
                self.manage_wizard.dbus_mode = DbusMode::Container;
                changed = true;
            }
            ui.label(
                "nsproxy runs one private dbus-daemon session bus inside the container. \
                Apps can communicate with each other but cannot reach host services.",
            );
        });
        ui.add_space(6.0);

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dbus_mode == DbusMode::Pass;
            if ui
                .selectable_label(sel, "Pass  (host session bus)")
                .clicked()
            {
                self.manage_wizard.dbus_mode = DbusMode::Pass;
                changed = true;
            }
            if self.manage_wizard.dbus_mode == DbusMode::Pass {
                ui.label(
                    RichText::new(
                        "⚠  The container can reach ALL host D-Bus services. \
                        Suitable only for trusted software.",
                    )
                    .color(Color32::from_rgb(236, 168, 52)),
                );
            } else {
                ui.label("Passes the host DBUS_SESSION_BUS_ADDRESS through. Risky — only for trusted apps.");
            }
        });

        if changed {
            self.manage_wizard.template.dbus = self.manage_wizard.dbus_mode.clone();
        }
    }

    fn render_wizard_port_listeners(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("Port Listeners");
        ui.add_space(4.0);
        ui.label(
            "Map host localhost ports into the container. \
            Processes inside the container will reach host:port as localhost:port.",
        );
        ui.add_space(8.0);

        // Preset buttons
        ui.horizontal_wrapped(|ui| {
            ui.label("Presets:");
            if ui.button("Geph  (9909)").clicked() {
                self.manage_wizard.hot.locals.insert(9909, 9909);
                self.manage_wizard.hot_json =
                    serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
            }
            if ui.button("Chrome DevTools  (9222)").clicked() {
                self.manage_wizard.hot.locals.insert(9222, 9222);
                self.manage_wizard.hot_json =
                    serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
            }
        });
        ui.add_space(6.0);

        // Custom port input
        ui.horizontal(|ui| {
            ui.label("Custom port:");
            ui.text_edit_singleline(&mut self.manage_wizard.local_port_input);
            if ui.button("Add").clicked() {
                let trimmed = self.manage_wizard.local_port_input.trim();
                if let Ok(port) = trimmed.parse::<u32>() {
                    self.manage_wizard.hot.locals.insert(port, port);
                    self.manage_wizard.hot_json =
                        serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
                    self.manage_wizard.local_port_input.clear();
                }
            }
        });
        ui.add_space(8.0);

        // Show current locals
        let locals: Vec<(u32, u32)> = self
            .manage_wizard
            .hot
            .locals
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        if locals.is_empty() {
            ui.colored_label(Color32::from_gray(120), "No port listeners configured.");
        } else {
            ui.label("Configured:");
            let mut to_remove = None;
            for (container_port, host_port) in &locals {
                ui.horizontal(|ui| {
                    ui.label(format!("container:{} → host:{}", container_port, host_port));
                    if Self::remove_icon_button(ui, "Remove port mapping").clicked() {
                        to_remove = Some(*container_port);
                    }
                });
            }
            if let Some(port) = to_remove {
                self.manage_wizard.hot.locals.remove(&port);
                self.manage_wizard.hot_json =
                    serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
            }
        }
    }

    fn render_wizard_route_targets(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("Route Targets");
        ui.add_space(4.0);
        ui.label(
            "Select which uplink proxy routes traffic from this container. \
            The proxy must be reachable via a configured port listener.",
        );
        ui.add_space(8.0);

        let current_route = self.manage_wizard.hot.default_route.clone();
        let mut new_route = current_route.clone();

        ui.strong("Proxy groups");
        for group_id in &self.user_groups {
            let is_selected = matches!(
                &current_route,
                nsproxy_core::HotRoute::Group { group_id: selected } if selected.as_str() == group_id.as_str()
            );
            if ui
                .selectable_label(is_selected, format!("Group: {}", group_id.as_str()))
                .clicked()
            {
                new_route = nsproxy_core::HotRoute::Group {
                    group_id: group_id.as_str().to_string(),
                };
            }
        }

        ui.add_space(6.0);
        ui.strong("Individual proxies");
        // Show available proxies
        if self.proxies.is_empty() {
            ui.colored_label(
                Color32::from_gray(130),
                "No uplink proxies configured yet. Add proxies in the Proxies tab first.",
            );
        } else {
            for (proxy_id, item) in &self.proxies {
                let is_selected = matches!(&current_route, nsproxy_core::HotRoute::SimpleProxy { proxy_id: pid } if pid == proxy_id);
                ui.horizontal(|ui| {
                    if ui.selectable_label(is_selected, &item.name).clicked() {
                        new_route = nsproxy_core::HotRoute::SimpleProxy {
                            proxy_id: proxy_id.clone(),
                        };
                    }
                    ui.colored_label(Color32::from_gray(140), &item.url);
                });
            }
        }

        let is_no_proxy = matches!(&current_route, nsproxy_core::HotRoute::NoProxy);
        if ui.selectable_label(is_no_proxy, "NoProxy").clicked() {
            new_route = nsproxy_core::HotRoute::NoProxy;
        }

        let is_none = matches!(&current_route, nsproxy_core::HotRoute::None);
        if ui.selectable_label(is_none, "None  (no route)").clicked() {
            new_route = nsproxy_core::HotRoute::None;
        }

        if new_route != current_route {
            self.manage_wizard.hot.default_route = new_route;
            self.manage_wizard.template.hot_init = Some(self.manage_wizard.hot.clone());
            self.manage_wizard.hot_json =
                serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
        }

        ui.add_space(8.0);
        ui.label(RichText::new("Note").strong());
        ui.label(
            "Geph (port 9909) is a popular choice. Add '9909' in Port Listeners if not already done, \
            then configure a Geph proxy in the Proxies tab.",
        );
    }

    fn render_wizard_dns_handling(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("DNS Handling");
        ui.add_space(4.0);
        ui.label("Controls how DNS queries are resolved inside the container.");
        ui.add_space(10.0);

        let mut changed = false;

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dns_mode == WizardDnsMode::InternalServer;
            if ui
                .selectable_label(sel, "Internal DNS server  (127.0.0.1)  — recommended")
                .clicked()
            {
                self.manage_wizard.dns_mode = WizardDnsMode::InternalServer;
                changed = true;
            }
            ui.label(
                "nsproxy spins up an internal DNS resolver at 127.0.0.1:53 inside the container. \
                DNS requests are forwarded to the SOCKS5 proxy as domain-name queries — \
                the proxy resolves hostnames, preventing DNS leaks.",
            );
        });
        ui.add_space(6.0);

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dns_mode == WizardDnsMode::TunUdp;
            if ui
                .selectable_label(sel, "TUN UDP DNS  (100.68.0.1)")
                .clicked()
            {
                self.manage_wizard.dns_mode = WizardDnsMode::TunUdp;
                changed = true;
            }
            ui.label(
                "Sets resolv.conf to the TUN device's virtual DNS address. DNS packets travel \
                through the TUN as regular UDP datagrams and are proxied upstream.",
            );
        });
        ui.add_space(6.0);

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dns_mode == WizardDnsMode::PassThrough;
            if ui
                .selectable_label(sel, "Pass through  (host DNS)")
                .clicked()
            {
                self.manage_wizard.dns_mode = WizardDnsMode::PassThrough;
                changed = true;
            }
            ui.label("Do not rewrite resolv.conf. The container inherits the host nameserver.");
        });
        ui.add_space(6.0);

        section_frame(ui, |ui| {
            let sel = self.manage_wizard.dns_mode == WizardDnsMode::Custom;
            if ui.selectable_label(sel, "Custom nameserver").clicked() {
                self.manage_wizard.dns_mode = WizardDnsMode::Custom;
                changed = true;
            }
            if self.manage_wizard.dns_mode == WizardDnsMode::Custom {
                ui.horizontal(|ui| {
                    ui.label("Nameserver IP:");
                    if ui
                        .text_edit_singleline(&mut self.manage_wizard.dns_custom_text)
                        .changed()
                    {
                        changed = true;
                    }
                });
            }
        });

        if changed {
            self.manage_wizard.hot.resolv_conf_dns = match &self.manage_wizard.dns_mode {
                WizardDnsMode::InternalServer => "127.0.0.1".to_string(),
                WizardDnsMode::TunUdp => "100.68.0.1".to_string(),
                WizardDnsMode::PassThrough => String::new(),
                WizardDnsMode::Custom => self.manage_wizard.dns_custom_text.trim().to_string(),
            };
            self.manage_wizard.hot_json =
                serde_json::to_string_pretty(&self.manage_wizard.hot).unwrap_or_default();
        }
    }

    fn render_wizard_review_hotconfig(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("Review Configuration");
        ui.add_space(4.0);
        ui.label(
            "Review the full profile JSON below (template + embedded hot config). \
            Adjust the hot config in the editor; the preview updates automatically.",
        );
        ui.add_space(6.0);

        // Full profile JSON preview (TemplateConfig with hot_init embedded)
        section_frame(ui, |ui| {
            ui.label(RichText::new("Profile JSON (preview)").strong());
            ui.add_space(4.0);
            let mut preview_tmpl = self.manage_wizard.template.clone();
            preview_tmpl.dbus = self.manage_wizard.dbus_mode.clone();
            preview_tmpl.hot = std::path::PathBuf::from("@/hot.json");
            preview_tmpl.hot_init = Some(self.manage_wizard.hot.clone());
            let preview_json = serde_json::to_string_pretty(&preview_tmpl).unwrap_or_default();
            let mut preview_json_display = preview_json.clone();
            egui::ScrollArea::vertical()
                .id_salt("wizard-review-preview-scroll")
                .max_height(520.0)
                .show(ui, |ui| {
                    let mut editor = CodeEditor::default()
                        .id_source("wizard-review-preview-editor")
                        .with_rows(18)
                        .with_theme(ColorTheme::GRUVBOX)
                        .with_numlines(true)
                        .with_ui_fontsize(ui);
                    let _ = editor.show(ui, &mut preview_json_display, &json_syntax());
                });
        });
        ui.add_space(8.0);

        // Merge-from-file section
        section_frame(ui, |ui| {
            ui.label(RichText::new("Merge from existing hot.json").strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Path:");
                ui.text_edit_singleline(&mut self.manage_wizard.merge_path);
                if ui.button("Merge").clicked() {
                    let path = self.manage_wizard.merge_path.trim().to_string();
                    match std::fs::read_to_string(&path) {
                        Ok(content) => match serde_json::from_str::<HotConfig>(&content) {
                            Ok(imported) => {
                                // Merge: union dns, locals, mounts; overwrite route/resolv if non-empty
                                self.manage_wizard.hot.dns.extend(imported.dns);
                                self.manage_wizard.hot.locals.extend(imported.locals);
                                self.manage_wizard.hot.mounts.extend(imported.mounts);
                                if !imported.resolv_conf_dns.is_empty() {
                                    self.manage_wizard.hot.resolv_conf_dns =
                                        imported.resolv_conf_dns;
                                }
                                if !matches!(imported.default_route, nsproxy_core::HotRoute::None) {
                                    self.manage_wizard.hot.default_route = imported.default_route;
                                }
                                self.manage_wizard.hot_json =
                                    serde_json::to_string_pretty(&self.manage_wizard.hot)
                                        .unwrap_or_default();
                                self.manage_wizard.merge_error = None;
                            }
                            Err(e) => {
                                self.manage_wizard.merge_error = Some(format!("Parse error: {e}"));
                            }
                        },
                        Err(e) => {
                            self.manage_wizard.merge_error = Some(format!("Read error: {e}"));
                        }
                    }
                }
            });
            if let Some(err) = &self.manage_wizard.merge_error {
                ui.colored_label(Color32::LIGHT_RED, err);
            }
        });
        ui.add_space(8.0);

        // Show the hotconfig editor (same form as the Hotconfig tab)
        let demo_display = self.demo_mode.then(|| {
            (
                self.display_hotconfig(&self.manage_wizard.hot),
                self.display_text(&self.manage_wizard.hot_json),
            )
        });
        let changed = Self::render_hotconfig_editor_split(
            ui,
            &mut self.int_input,
            "manage-wizard-hotconfig",
            &mut self.manage_wizard.hot,
            &mut self.manage_wizard.hot_json,
            &mut self.manage_wizard.hot_json_error,
            demo_display,
        );
        if changed {
            // Sync resolv_conf_dns back to dns_mode state
            self.manage_wizard.dns_mode = match self.manage_wizard.hot.resolv_conf_dns.as_str() {
                "127.0.0.1" => WizardDnsMode::InternalServer,
                "100.68.0.1" => WizardDnsMode::TunUdp,
                "" => WizardDnsMode::PassThrough,
                other => {
                    self.manage_wizard.dns_custom_text = other.to_string();
                    WizardDnsMode::Custom
                }
            };
        }
    }

    fn render_wizard_name(&mut self, ui: &mut egui::Ui) {
        self.render_wizard_breadcrumb(ui);
        ui.heading("Create Profile");
        ui.add_space(6.0);

        // Summary
        section_frame(ui, |ui| {
            ui.label(RichText::new("Summary").strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.colored_label(Color32::from_gray(160), "Template:");
                if self.manage_wizard.mode == WizardMode::CloneExisting {
                    ui.label(format!(
                        "Cloned from: {}",
                        self.display_text(&self.manage_wizard.clone_source)
                    ));
                } else {
                    match &self.manage_wizard.template_kind {
                        WizardTemplateKind::OverlayBasic => {
                            ui.label("Overlay — Basic");
                        }
                        WizardTemplateKind::Pivot => {
                            if self.manage_wizard.pivot_apps.is_empty() {
                                ui.label("Pivot — (no apps)");
                            } else {
                                let names: Vec<&str> = self
                                    .manage_wizard
                                    .pivot_apps
                                    .iter()
                                    .map(PivotAppKind::label)
                                    .collect();
                                ui.label(format!("Pivot — {}", names.join(", ")));
                            }
                        }
                    };
                }
            });
            ui.horizontal(|ui| {
                ui.colored_label(Color32::from_gray(160), "Sandbox:");
                ui.label(format!("{:?}", self.manage_wizard.template.sandbox_mode));
            });
            ui.horizontal(|ui| {
                ui.colored_label(Color32::from_gray(160), "D-Bus:");
                let (label, color) = match &self.manage_wizard.dbus_mode {
                    DbusMode::Block => ("block", Color32::from_gray(160)),
                    DbusMode::Proxy => ("proxy (legacy no-op)", Color32::from_gray(160)),
                    DbusMode::Container => ("container", Color32::LIGHT_GREEN),
                    DbusMode::Pass => ("pass ⚠", Color32::from_rgb(236, 168, 52)),
                };
                ui.colored_label(color, label);
            });
            ui.horizontal(|ui| {
                ui.colored_label(Color32::from_gray(160), "Port listeners:");
                let ports: Vec<String> = self
                    .manage_wizard
                    .hot
                    .locals
                    .keys()
                    .map(|p| p.to_string())
                    .collect();
                if ports.is_empty() {
                    ui.colored_label(Color32::from_gray(120), "none");
                } else {
                    ui.label(ports.join(", "));
                }
            });
            ui.horizontal(|ui| {
                ui.colored_label(Color32::from_gray(160), "DNS:");
                ui.label(&self.manage_wizard.hot.resolv_conf_dns);
            });
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Profile name:");
            ui.text_edit_singleline(&mut self.manage_wizard.new_name);
        });

        let name = self.manage_wizard.new_name.trim().to_string();
        let name_ok = !name.is_empty() && !name.contains('/');
        if !name_ok && !name.is_empty() {
            ui.colored_label(Color32::LIGHT_RED, "Name must not be empty or contain '/'");
        }

        if let Some(status) = &self.manage_wizard.status {
            ui.add_space(4.0);
            ui.label(status);
        }

        // Check if creation succeeded (profile appeared in snapshot)
        let created = !self.manage_wizard.new_name.is_empty()
            && self
                .snapshot
                .profiles
                .contains_key(self.manage_wizard.new_name.trim());
        if created {
            ui.add_space(8.0);
            ui.colored_label(
                Color32::LIGHT_GREEN,
                format!(
                    "Profile '{}' created successfully.",
                    self.manage_wizard.new_name.trim()
                ),
            );
            if ui.button("Start over").clicked() {
                self.manage_wizard = ManageWizard::default();
            }
        }
    }

    fn render_veth_editor(
        &mut self,
        ui: &mut egui::Ui,
        profile: &ContainerName,
        hot: &mut HotConfig,
    ) -> bool {
        let mut changed = false;
        let known_profiles = self
            .snapshot
            .profiles
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let veth_status = self
            .snapshot
            .profiles
            .get(profile)
            .map(|state| state.veth_status.clone())
            .unwrap_or_default();
        let drafts = self
            .hotconfig_veth_drafts
            .entry(profile.clone())
            .or_default();

        section_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("veth pairs");
                if ui.button("+ Add veth").clicked() {
                    drafts.push(VethDraft {
                        add_on_start: true,
                        ..Default::default()
                    });
                    changed = true;
                }
                if ui.button("+ Add temp veth").clicked() {
                    drafts.push(VethDraft::default());
                }
            });
            ui.small("Create a pair between this profile and another running profile.");
            ui.add_space(4.0);

            let mut remove_ix = None;
            for (index, draft) in drafts.iter_mut().enumerate() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.push_id(("veth-card", index), |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!("Veth pair {}", index + 1));
                            if ui
                                .checkbox(&mut draft.add_on_start, "on container creation")
                                .changed()
                            {
                                changed = true;
                            }
                            if Self::remove_icon_button(ui, "Remove veth pair").clicked() {
                                remove_ix = Some(index);
                                changed |= draft.add_on_start;
                            }
                        });
                        if let Some(status) = veth_status.get(index) {
                            ui.colored_label(
                                if status.success {
                                    Color32::LIGHT_GREEN
                                } else {
                                    Color32::LIGHT_RED
                                },
                                format!(
                                    "veth {}: {}",
                                    if status.success { "ready" } else { "failed" },
                                    status.detail
                                ),
                            );
                        }
                        ui.horizontal(|ui| {
                            ui.label("connect to");
                            let mut peer_changed = false;
                            ui.add_enabled_ui(!draft.basis_namespace, |ui| {
                                peer_changed = ui.text_edit_singleline(&mut draft.peer).changed();
                            });
                            if peer_changed {
                                draft.submitted = false;
                                changed |= draft.add_on_start;
                            }
                            if ui
                                .checkbox(&mut draft.basis_namespace, "basis namespace")
                                .changed()
                            {
                                draft.submitted = false;
                                changed |= draft.add_on_start;
                            }
                            let peer = draft.peer.trim();
                            let valid_peer = draft.basis_namespace
                                || (!peer.is_empty()
                                    && peer != profile.as_str()
                                    && known_profiles.contains(peer));
                            Self::validation_icon(
                                ui,
                                valid_peer,
                                if valid_peer {
                                    if draft.basis_namespace {
                                        "Connect to the basis namespace"
                                    } else {
                                        "Valid target container"
                                    }
                                } else {
                                    "Target must be another running container"
                                },
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Pair name");
                            if ui.text_edit_singleline(&mut draft.name).changed() {
                                draft.submitted = false;
                                changed |= draft.add_on_start;
                            }
                            ui.small("optional; defaults to profile names");
                        });
                        ui.horizontal(|ui| {
                            ui.label("IPv4 addresses");
                            ui.text_edit_singleline(&mut draft.src_ip4);
                            ui.label(RichText::new(regular::ARROW_RIGHT).size(12.0));
                            ui.text_edit_singleline(&mut draft.dst_ip4);
                            ui.small("optional; blank uses auto allocation");
                        });
                        ui.horizontal(|ui| {
                            ui.label("Prefix length");
                            if ui.text_edit_singleline(&mut draft.prefix_len).changed() {
                                draft.submitted = false;
                                changed |= draft.add_on_start;
                            }
                        });
                        let peer = draft.peer.trim();
                        let valid_peer = draft.basis_namespace
                            || (!peer.is_empty()
                                && peer != profile.as_str()
                                && known_profiles.contains(peer));
                        let valid_name = draft.name.trim().is_empty()
                            || (draft.name.len() <= 15
                                && draft.name.chars().all(|ch| {
                                    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
                                }));
                        let ready = valid_peer && valid_name;
                        let fixed_ips = draft.src_ip4.trim().is_empty()
                            && draft.dst_ip4.trim().is_empty()
                            || (draft.src_ip4.trim().parse::<std::net::Ipv4Addr>().is_ok()
                                && draft.dst_ip4.trim().parse::<std::net::Ipv4Addr>().is_ok());
                        let valid_prefix = draft
                            .prefix_len
                            .trim()
                            .parse::<u8>()
                            .is_ok_and(|p| p > 0 && p < 32);
                        let ready = ready && fixed_ips && valid_prefix;
                        if ui
                            .add_enabled(ready, egui::Button::new("Create veth pair"))
                            .clicked()
                        {
                            let src_ip4 = draft.src_ip4.trim().parse().ok();
                            let dst_ip4 = draft.dst_ip4.trim().parse().ok();
                            let prefix_len = draft.prefix_len.trim().parse().unwrap_or(30);
                            self.supervisor.send(SupervisorCommand::CreateVeth {
                                profile: profile.clone(),
                                peer: if draft.basis_namespace {
                                    "basis".to_string()
                                } else {
                                    peer.to_string()
                                },
                                veth_name: (!draft.name.trim().is_empty())
                                    .then(|| draft.name.trim().to_string()),
                                src_ip4,
                                dst_ip4,
                                prefix_len,
                            });
                            draft.submitted = true;
                        }
                        if draft.submitted {
                            ui.colored_label(
                                Color32::LIGHT_BLUE,
                                "Creation requested; see Logs for result.",
                            );
                        }
                        if draft.add_on_start {
                            ui.small("Saved to hotconfig; retried when this container starts.");
                        } else {
                            ui.small("Temporary; applies only when you click Create veth pair.");
                        }
                    });
                });
                ui.add_space(4.0);
            }
            if let Some(index) = remove_ix {
                drafts.remove(index);
            }
        });

        let persisted = drafts
            .iter()
            .filter(|draft| draft.add_on_start)
            .map(|draft| HotVeth {
                src: profile.clone(),
                dst: if draft.basis_namespace {
                    "basis".to_owned()
                } else {
                    draft.peer.trim().to_string()
                },
                veth_name: (!draft.name.trim().is_empty()).then(|| draft.name.trim().to_string()),
                src_ip4: draft.src_ip4.trim().parse().ok(),
                dst_ip4: draft.dst_ip4.trim().parse().ok(),
                prefix_len: draft.prefix_len.trim().parse().unwrap_or(30),
            })
            .collect::<Vec<_>>();
        if hot.veth != persisted {
            hot.veth = persisted;
            changed = true;
        }
        changed
    }

    fn render_hotconfig_tab(&mut self, ui: &mut egui::Ui) {
        self.refresh_hotconfig_editor_target();

        if self.selected_profile.is_none() {
            ui.label("Select a profile to edit Hotconfig");
            return;
        }

        let profile_name = self.selected_profile.clone().unwrap_or_default();
        let hotconfig_unsaved = self.hotconfig_editor_error.is_some()
            || self
                .snapshot
                .profiles
                .get(&profile_name)
                .map_or(true, |profile| {
                    self.hotconfig_editor_value != profile.hotconfig
                });
        let (dns_state, sandbox_status, child_alive, dbus_mode) = self
            .snapshot
            .profiles
            .get(&profile_name)
            .map(|profile| {
                (
                    profile.dns_state.clone(),
                    profile.sandbox_status.clone(),
                    profile.child_alive,
                    profile.template.dbus.clone(),
                )
            })
            .unwrap_or((None, None, false, DbusMode::Block));
        ui.horizontal(|ui| {
            ui.heading(format!("Hotconfig - {}", self.display_text(&profile_name)));
            if ui.button("Reload").clicked() {
                self.supervisor
                    .send(SupervisorCommand::ReloadHotconfig(profile_name.clone()));
                self.supervisor
                    .send(SupervisorCommand::LoadProfile(profile_name.clone()));
                self.hotconfig_editor_target = None;
            }
            if ui.button("Save").clicked() {
                self.save_hotconfig_editor();
            }
            if ui.button("Apply Sandbox").clicked() {
                self.supervisor.send(SupervisorCommand::RunSandbox {
                    profile: profile_name.clone(),
                    reason: "manual hotconfig action".to_string(),
                });
            }
            if hotconfig_unsaved {
                ui.colored_label(
                    Color32::from_rgb(235, 175, 65),
                    RichText::new("unsaved").strong(),
                );
            }
        });
        if let Some(status) = self.effective_hotconfig_status(&profile_name) {
            ui.label(status);
        }
        if let Some(dns_state) = &dns_state {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(format!(
                    "DNS: {} domains, {} IPv4, {} IPv6",
                    dns_state.domain_count, dns_state.ip4_count, dns_state.ip6_count
                ));
                if dns_state.aaaa_only {
                    ui.label(RichText::new("AAAA stripped").color(Color32::LIGHT_BLUE));
                }
            });
        }
        ui.add_space(4.0);
        egui::Frame::NONE
            .fill(Color32::from_gray(18))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("D-Bus:").strong());
                    match dbus_mode {
                        DbusMode::Block => {
                            ui.colored_label(Color32::from_gray(150), "block (no dbus)");
                        }
                        DbusMode::Proxy => {
                            ui.colored_label(
                                Color32::from_gray(150),
                                "proxy (legacy no-op, no dbus)",
                            );
                        }
                        DbusMode::Pass => {
                            ui.label(
                                RichText::new("pass — host session bus exposed")
                                    .color(Color32::from_rgb(236, 168, 52))
                                    .strong(),
                            );
                            ui.colored_label(
                                Color32::from_rgb(200, 140, 40),
                                "⚠ container can reach host dbus services",
                            );
                        }
                        DbusMode::Container => {
                            ui.colored_label(
                                Color32::LIGHT_GREEN,
                                "container (private dbus-daemon)",
                            );
                        }
                    }
                });
            });
        ui.add_space(8.0);
        match sandbox_status.as_ref() {
            Some(status) => self.render_sandbox_status_panel(ui, status),
            None => {
                egui::Frame::NONE
                    .fill(Color32::from_gray(18))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.heading("Sandbox State");
                            ui.colored_label(
                                Color32::from_gray(130),
                                if child_alive {
                                    "No sandbox snapshot yet. Use Save or Apply Sandbox to run sp sandbox."
                                } else {
                                    "Container is not running yet. The first startup will trigger sp sandbox."
                                },
                            );
                        });
                    });
            }
        }
        ui.add_space(6.0);

        let mut hotconfig_for_veth = std::mem::take(&mut self.hotconfig_editor_value);
        let veth_changed = self.render_veth_editor(ui, &profile_name, &mut hotconfig_for_veth);
        self.hotconfig_editor_value = hotconfig_for_veth;
        ui.add_space(6.0);

        let demo_display = self.demo_mode.then(|| {
            (
                self.display_hotconfig(&self.hotconfig_editor_value),
                self.display_text(&self.hotconfig_editor_json),
            )
        });
        let changed = Self::render_hotconfig_editor_split(
            ui,
            &mut self.int_input,
            "hotconfig-tab",
            &mut self.hotconfig_editor_value,
            &mut self.hotconfig_editor_json,
            &mut self.hotconfig_editor_error,
            demo_display,
        );
        if veth_changed || changed {
            self.hotconfig_editor_json = serde_json::to_string_pretty(&self.hotconfig_editor_value)
                .unwrap_or_else(|_| "{}".to_string());
            self.hotconfig_editor_status = None;
        }
    }

    fn render_sandbox_status_panel(&self, ui: &mut egui::Ui, status: &SandboxStatus) {
        egui::Frame::NONE
            .fill(Color32::from_gray(18))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading("Sandbox State");
                    ui.label(
                        RichText::new(format!("mode {:?}", status.configured_mode))
                            .color(Color32::LIGHT_BLUE),
                    );
                    let detected_color = if matches!(
                        status.detected_state,
                        nsproxy_core::sandbox::SandboxState::Pivoted
                    ) {
                        Color32::LIGHT_GREEN
                    } else {
                        Color32::from_rgb(236, 198, 92)
                    };
                    ui.label(
                        RichText::new(format!("detected {:?}", status.detected_state))
                            .color(detected_color),
                    );
                    ui.colored_label(
                        Color32::from_gray(130),
                        format!("updated {}", status.updated_at_secs),
                    );
                });

                if let Some(err) = &status.last_error {
                    ui.colored_label(Color32::LIGHT_RED, err);
                }

                ui.add_space(8.0);
                ui.label(RichText::new("Mount Points").strong());
                if status.mounts.is_empty() {
                    ui.colored_label(Color32::from_gray(120), "No configured sandbox mounts");
                    return;
                }

                egui::ScrollArea::horizontal()
                    .id_salt("sandbox-status-mounts")
                    .show(ui, |ui| {
                        TableBuilder::new(ui)
                            .id_salt("sandbox-status-mounts-table")
                            .striped(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::remainder().at_least(180.0))
                            .column(Column::remainder().at_least(180.0))
                            .column(Column::auto().at_least(90.0))
                            .column(Column::auto().at_least(110.0))
                            .column(Column::remainder().at_least(150.0))
                            .header(20.0, |mut header| {
                                header.col(|ui| {
                                    ui.strong("Target");
                                });
                                header.col(|ui| {
                                    ui.strong("Source");
                                });
                                header.col(|ui| {
                                    ui.strong("Flags");
                                });
                                header.col(|ui| {
                                    ui.strong("State");
                                });
                                header.col(|ui| {
                                    ui.strong("Meta");
                                });
                            })
                            .body(|mut body| {
                                body.rows(24.0, status.mounts.len(), |mut row| {
                                    let mount = &status.mounts[row.index()];
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(self.display_path(&mount.target))
                                                .monospace(),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(self.display_path(&mount.source))
                                                .monospace(),
                                        );
                                    });
                                    row.col(|ui| {
                                        let mut flags =
                                            if mount.read_only { "ro" } else { "rw" }.to_string();
                                        if mount.recursive {
                                            flags.push_str(" rec");
                                        }
                                        ui.label(flags);
                                    });
                                    row.col(|ui| {
                                        let mounted_color = if mount.mounted {
                                            Color32::LIGHT_GREEN
                                        } else {
                                            Color32::LIGHT_RED
                                        };
                                        ui.label(
                                            RichText::new(if mount.mounted {
                                                "mounted"
                                            } else {
                                                "missing"
                                            })
                                            .color(mounted_color),
                                        );
                                        if mount.mounted {
                                            let match_color = if mount.target_matches_source {
                                                Color32::LIGHT_GREEN
                                            } else {
                                                Color32::from_rgb(236, 198, 92)
                                            };
                                            ui.colored_label(
                                                match_color,
                                                if mount.target_matches_source {
                                                    "source-ok"
                                                } else {
                                                    "source-drift"
                                                },
                                            );
                                        }
                                    });
                                    row.col(|ui| {
                                        ui.label(format!(
                                            "{} • {} • {}",
                                            mount.target_status.kind.as_deref().unwrap_or("-"),
                                            format_mode_bits(mount.target_status.mode),
                                            format_uid_gid(
                                                mount.target_status.uid,
                                                mount.target_status.gid,
                                            ),
                                        ));
                                        ui.colored_label(
                                            Color32::from_gray(120),
                                            format_optional_size(mount.target_status.size),
                                        );
                                        if let Some(err) = &mount.target_status.error {
                                            ui.colored_label(Color32::LIGHT_RED, err);
                                        }
                                    });
                                });
                            });
                    });
            });
    }

    fn render_state_tab(&mut self, ui: &mut egui::Ui) {
        let Some(profile_name) = self.selected_profile.clone() else {
            ui.label("Select a profile to view its state.");
            return;
        };

        let Some(cs) = self.snapshot.profiles.get(&profile_name).cloned() else {
            ui.label("Profile state not yet loaded.");
            return;
        };

        let sandbox_mode = &cs.template.sandbox_mode;
        let is_pivot = *sandbox_mode == SandboxMode::Pivot;

        // ── Header ────────────────────────────────────────────────────────────
        ui.heading(format!("State — {}", self.display_text(&profile_name)));
        ui.add_space(4.0);
        egui::Frame::NONE
            .fill(Color32::from_gray(22))
            .inner_margin(egui::Margin::same(10))
            .corner_radius(egui::CornerRadius::same(6))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "The totality of state that is accessible by the container is illustrated as follows.",
                    )
                    .strong()
                    .size(14.0),
                );
            });

        ui.add_space(8.0);

        // ── Sandbox Mode ──────────────────────────────────────────────────────
        egui::Frame::NONE
            .fill(Color32::from_gray(18))
            .inner_margin(egui::Margin::same(10))
            .corner_radius(egui::CornerRadius::same(6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Filesystem isolation mode:").strong());
                    if is_pivot {
                        ui.colored_label(Color32::LIGHT_BLUE, "Pivot");
                    } else {
                        ui.colored_label(Color32::from_rgb(236, 198, 92), "Overlay");
                    }
                });
                ui.add_space(4.0);
                if is_pivot {
                    ui.label(
                        "In Pivot mode the container's filesystem access is explicitly and \
                         precisely controlled. The container root is replaced via pivot_root(2) \
                         with a fresh isolated tree. Every path the container can reach has been \
                         deliberately mounted — no host path is accessible unless it appears in \
                         the mount list below. Sources prefixed with @ refer to nsproxy-managed \
                         state directories that nsproxy owns and maintains. The previous host \
                         root is accessible inside the container at /pivot, giving an explicit \
                         and auditable escape hatch. This mode maximises reproducibility, \
                         privacy hygiene, and blast-radius reduction.",
                    );
                } else {
                    ui.label(
                        "In Overlay mode the container inherits the entire host filesystem \
                         unchanged. The container can read and write everything the launching \
                         user can access on the host. This mode offers maximum compatibility \
                         and minimal breakage — applications see a familiar, complete \
                         environment — but it makes no isolation guarantees. Anything on the \
                         host is reachable. Use Pivot mode when reproducibility, privacy \
                         hygiene, or explicit access control matters.",
                    );
                }
            });

        ui.add_space(10.0);

        // ── Persistent State Paths ─────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("Persistent State Paths").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    "All filesystem paths that nsproxy uses to store, expose, or wire \
                     state for this container. These exist on the host regardless of \
                     whether the container is running.",
                );
                ui.add_space(6.0);

                let paths: &[(&str, PathBuf, &str)] = &[
                    (
                        "Profile config dir",
                        state_paths::profile_dir(&profile_name),
                        "Root directory for all persistent state of this profile",
                    ),
                    (
                        "Profile config (profile.json)",
                        state_paths::profile_config(&profile_name),
                        "Template / profile schema — defines sandbox mode, mounts, env, etc.",
                    ),
                    (
                        "Hot config",
                        state_paths::hot_config(&profile_name),
                        "Frequently-reloaded runtime config: DNS, TUN, mounts, daemons",
                    ),
                    (
                        "Sandbox status snapshot",
                        state_paths::sandbox_status(&profile_name),
                        "Latest sandbox inspection result written by sp sandbox",
                    ),
                    (
                        "Network namespace bind",
                        state_paths::profile_netns_bind(&profile_name),
                        "Bind-mounted network namespace file that keeps the netns alive",
                    ),
                    (
                        "Namespace metadata",
                        state_paths::profile_ns_meta(&profile_name),
                        "JSON record of live PIDs and namespace identities (ns_alive.json)",
                    ),
                    (
                        "Rootfs dir",
                        state_paths::profile_rootfs_dir(&profile_name),
                        "Pivot-mode root filesystem tree (used only when mode = Pivot)",
                    ),
                    (
                        "Pivot staging dir",
                        state_paths::pivot_root_mem(&profile_name),
                        "Temporary staging path in RAM used during pivot_root(2) transitions",
                    ),
                    (
                        "Logs dir",
                        state_paths::logs_root(),
                        "Per-process diagnostic log files for all profiles",
                    ),
                    (
                        "Uplink state root",
                        state_paths::uplink_root(),
                        "Root for uplink (proxy) runtime state shared across profiles",
                    ),
                ];

                egui::ScrollArea::horizontal()
                    .id_salt("state-paths-scroll")
                    .show(ui, |ui| {
                        TableBuilder::new(ui)
                            .id_salt("state-paths-table")
                            .striped(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::auto().at_least(200.0))
                            .column(Column::remainder().at_least(260.0))
                            .column(Column::remainder().at_least(220.0))
                            .header(20.0, |mut h| {
                                h.col(|ui| {
                                    ui.strong("Name");
                                });
                                h.col(|ui| {
                                    ui.strong("Path");
                                });
                                h.col(|ui| {
                                    ui.strong("Purpose");
                                });
                            })
                            .body(|mut body| {
                                body.rows(22.0, paths.len(), |mut row| {
                                    let (name, path, desc) = &paths[row.index()];
                                    let exists = path.exists();
                                    row.col(|ui| {
                                        ui.label(RichText::new(*name).strong());
                                    });
                                    row.col(|ui| {
                                        let color = if exists {
                                            Color32::LIGHT_GREEN
                                        } else {
                                            Color32::from_gray(110)
                                        };
                                        ui.label(
                                            RichText::new(self.display_path(path))
                                                .monospace()
                                                .color(color),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.colored_label(Color32::from_gray(190), *desc);
                                    });
                                });
                            });
                    });
            });

        ui.add_space(8.0);

        // ── Template Mounts ───────────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("Profile Mounts (template)").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    "Bind mounts declared in profile.json. These are applied once when the \
                     container starts. Sources marked @ are nsproxy-managed state directories.",
                );
                ui.add_space(4.0);
                if cs.template.mounts.is_empty() {
                    ui.colored_label(Color32::from_gray(130), "No profile mounts configured.");
                } else {
                    self.render_profile_mount_list(ui, &cs.template.mounts, "state-tmpl-mounts");
                }
            });

        ui.add_space(8.0);

        // ── Hotconfig Mounts ──────────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("Hotconfig Mounts (hot.json)").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    "Bind mounts from hot.json. These are applied on every hot-reload \
                     without restarting the container.",
                );
                ui.add_space(4.0);
                let has_mounts = !cs.hotconfig.mounts.is_empty();
                let has_mnt = !cs.hotconfig.mnt.is_empty();
                if !has_mounts && !has_mnt {
                    ui.colored_label(Color32::from_gray(130), "No hotconfig mounts configured.");
                } else {
                    if has_mounts {
                        ui.label(RichText::new("mounts (structured):").italics());
                        self.render_profile_mount_list(
                            ui,
                            &cs.hotconfig.mounts,
                            "state-hot-mounts",
                        );
                        ui.add_space(4.0);
                    }
                    if has_mnt {
                        ui.label(RichText::new("mnt (shorthand source → target map):").italics());
                        egui::ScrollArea::horizontal()
                            .id_salt("state-hot-mnt-scroll")
                            .show(ui, |ui| {
                                TableBuilder::new(ui)
                                    .id_salt("state-hot-mnt-table")
                                    .striped(true)
                                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                    .column(Column::remainder().at_least(240.0))
                                    .column(Column::remainder().at_least(240.0))
                                    .header(20.0, |mut h| {
                                        h.col(|ui| {
                                            ui.strong("Source (host)");
                                        });
                                        h.col(|ui| {
                                            ui.strong("Target (container)");
                                        });
                                    })
                                    .body(|mut body| {
                                        let entries: Vec<_> = cs.hotconfig.mnt.iter().collect();
                                        body.rows(22.0, entries.len(), |mut row| {
                                            let (target, source) = entries[row.index()];
                                            row.col(|ui| {
                                                ui.label(
                                                    RichText::new(self.display_path(source))
                                                        .monospace(),
                                                );
                                            });
                                            row.col(|ui| {
                                                ui.label(
                                                    RichText::new(self.display_path(target))
                                                        .monospace(),
                                                );
                                            });
                                        });
                                    });
                            });
                    }
                }
            });

        ui.add_space(8.0);

        // ── Sandbox Status (live mount inspection) ────────────────────────────
        egui::CollapsingHeader::new(RichText::new("Live Sandbox State").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    "Result of the most recent sp sandbox inspection. Shows whether each \
                     configured mount is actually present in the container's mount namespace.",
                );
                ui.add_space(4.0);
                match cs.sandbox_status.as_ref() {
                    Some(status) => self.render_sandbox_status_panel(ui, status),
                    None => {
                        ui.colored_label(
                            Color32::from_gray(130),
                            "No sandbox snapshot available yet. Run sp sandbox or start the container.",
                        );
                    }
                }
            });

        ui.add_space(8.0);

        // ── Environment Variables ─────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("Environment Variables (template)").strong())
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    "Environment variables set for processes inside this container. When \
                     inherit_env is enabled these override the parent environment; otherwise \
                     they replace it entirely.",
                );
                ui.add_space(4.0);
                let inherit = cs.template.inherit_env;
                ui.horizontal(|ui| {
                    ui.label(RichText::new("inherit_env:").strong());
                    if inherit {
                        ui.colored_label(
                            Color32::LIGHT_GREEN,
                            "true — parent env inherited, overrides applied",
                        );
                    } else {
                        ui.colored_label(
                            Color32::from_rgb(236, 198, 92),
                            "false — env is fully replaced",
                        );
                    }
                });
                ui.add_space(4.0);
                if cs.template.env.is_empty() {
                    ui.colored_label(
                        Color32::from_gray(130),
                        "No environment overrides configured.",
                    );
                } else {
                    egui::ScrollArea::horizontal()
                        .id_salt("state-env-scroll")
                        .show(ui, |ui| {
                            TableBuilder::new(ui)
                                .id_salt("state-env-table")
                                .striped(true)
                                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                .column(Column::auto().at_least(200.0))
                                .column(Column::remainder().at_least(300.0))
                                .header(20.0, |mut h| {
                                    h.col(|ui| {
                                        ui.strong("Variable");
                                    });
                                    h.col(|ui| {
                                        ui.strong("Value");
                                    });
                                })
                                .body(|mut body| {
                                    let mut entries: Vec<_> = cs.template.env.iter().collect();
                                    entries.sort_by_key(|(k, _)| k.as_str());
                                    body.rows(22.0, entries.len(), |mut row| {
                                        let (key, val) = entries[row.index()];
                                        row.col(|ui| {
                                            ui.label(
                                                RichText::new(key.as_str()).monospace().strong(),
                                            );
                                        });
                                        row.col(|ui| {
                                            ui.label(RichText::new(val.as_str()).monospace());
                                        });
                                    });
                                });
                        });
                }
            });

        ui.add_space(8.0);

        // ── Chmod / Ownership Operations ──────────────────────────────────────
        if !cs.template.chmod.is_empty() {
            egui::CollapsingHeader::new(
                RichText::new("Chmod / Ownership Operations (template)").strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    "Permission and ownership adjustments applied inside the container \
                         root after mounts are in place.",
                );
                ui.add_space(4.0);
                egui::ScrollArea::horizontal()
                    .id_salt("state-chmod-scroll")
                    .show(ui, |ui| {
                        TableBuilder::new(ui)
                            .id_salt("state-chmod-table")
                            .striped(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::remainder().at_least(220.0))
                            .column(Column::auto().at_least(80.0))
                            .column(Column::auto().at_least(60.0))
                            .column(Column::auto().at_least(60.0))
                            .column(Column::auto().at_least(60.0))
                            .header(20.0, |mut h| {
                                h.col(|ui| {
                                    ui.strong("Path");
                                });
                                h.col(|ui| {
                                    ui.strong("Mode");
                                });
                                h.col(|ui| {
                                    ui.strong("UID");
                                });
                                h.col(|ui| {
                                    ui.strong("GID");
                                });
                                h.col(|ui| {
                                    ui.strong("mkdir");
                                });
                            })
                            .body(|mut body| {
                                body.rows(22.0, cs.template.chmod.len(), |mut row| {
                                    let c = &cs.template.chmod[row.index()];
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(self.display_path(&c.path)).monospace(),
                                        );
                                    });
                                    row.col(|ui| match c.mode {
                                        Some(m) => {
                                            ui.label(format!("{:04o}", m));
                                        }
                                        None => {
                                            ui.colored_label(Color32::from_gray(120), "—");
                                        }
                                    });
                                    row.col(|ui| match c.uid {
                                        Some(u) => {
                                            ui.label(u.to_string());
                                        }
                                        None => {
                                            ui.colored_label(Color32::from_gray(120), "—");
                                        }
                                    });
                                    row.col(|ui| match c.gid {
                                        Some(g) => {
                                            ui.label(g.to_string());
                                        }
                                        None => {
                                            ui.colored_label(Color32::from_gray(120), "—");
                                        }
                                    });
                                    row.col(|ui| {
                                        if c.mkdir {
                                            ui.colored_label(Color32::LIGHT_GREEN, "yes");
                                        } else {
                                            ui.colored_label(Color32::from_gray(120), "no");
                                        }
                                    });
                                });
                            });
                    });
            });
            ui.add_space(8.0);
        }

        // ── D-Bus Mode ────────────────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("D-Bus Exposure").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.label(
                    "Controls whether and how the D-Bus session bus is visible inside \
                     the container. Blocking it improves isolation; passing it grants \
                     access to host services.",
                );
                ui.add_space(4.0);
                egui::Frame::NONE
                    .fill(Color32::from_gray(14))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("D-Bus mode:").strong());
                            match &cs.template.dbus {
                                DbusMode::Block => {
                                    ui.colored_label(Color32::from_gray(160), "block — D-Bus is completely absent inside the container.");
                                }
                                DbusMode::Proxy => {
                                    ui.colored_label(Color32::from_gray(160), "proxy — legacy no-op; no D-Bus service is started.");
                                }
                                DbusMode::Pass => {
                                    ui.colored_label(
                                        Color32::from_rgb(236, 168, 52),
                                        "pass — host session bus forwarded directly. Container can reach all host D-Bus services.",
                                    );
                                }
                                DbusMode::Container => {
                                    ui.colored_label(Color32::LIGHT_GREEN, "container — private per-container dbus-daemon session bus. Isolated from host session bus.");
                                }
                            }
                        });
                    });
            });

        ui.add_space(8.0);

        // ── Namespace Identity ────────────────────────────────────────────────
        if cs.child_alive {
            egui::CollapsingHeader::new(RichText::new("Active Namespace Identity").strong())
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(
                        "Live namespace handles for the running container. These kernel \
                         identities uniquely describe the container's isolation boundaries.",
                    );
                    ui.add_space(4.0);
                    if let Some(ns) = &cs.up_ns {
                        ui.label(RichText::new("up daemon namespaces:").italics());
                        if let Some(mnt) = &ns.mnt {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("mnt:").strong());
                                ui.label(RichText::new(mnt).monospace());
                            });
                        }
                        if let Some(net) = &ns.net {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("net:").strong());
                                ui.label(RichText::new(net).monospace());
                            });
                        }
                        if let Some(pid) = &ns.pid {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("pid:").strong());
                                ui.label(RichText::new(pid).monospace());
                            });
                        }
                    }
                    if let Some(ns_alive) = &cs.ns_alive {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Recorded identity (ns_alive.json):").italics());
                        if let Some(pid) = ns_alive.child_pid {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("container pid:").strong());
                                ui.label(RichText::new(pid.to_string()).monospace());
                            });
                        }
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("netns bind mount:").strong());
                            ui.label(
                                RichText::new(self.display_path(&ns_alive.bind_mount)).monospace(),
                            );
                        });
                    }
                });
        }
    }

    fn render_profile_mount_list(&self, ui: &mut egui::Ui, mounts: &[ProfileMount], salt: &str) {
        egui::ScrollArea::horizontal().id_salt(salt).show(ui, |ui| {
            TableBuilder::new(ui)
                .id_salt(format!("{}-table", salt))
                .striped(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder().at_least(200.0))
                .column(Column::remainder().at_least(200.0))
                .column(Column::auto().at_least(40.0))
                .column(Column::auto().at_least(50.0))
                .column(Column::auto().at_least(70.0))
                .header(20.0, |mut h| {
                    h.col(|ui| {
                        ui.strong("Source (host / @-var)");
                    });
                    h.col(|ui| {
                        ui.strong("Target (container)");
                    });
                    h.col(|ui| {
                        ui.strong("ro");
                    });
                    h.col(|ui| {
                        ui.strong("rec");
                    });
                    h.col(|ui| {
                        ui.strong("optional");
                    });
                })
                .body(|mut body| {
                    body.rows(22.0, mounts.len(), |mut row| {
                        let m = &mounts[row.index()];
                        let src_str = m.source.display().to_string();
                        let is_managed =
                            src_str == "@" || src_str.starts_with("@/") || src_str.starts_with('@');
                        row.col(|ui| {
                            let color = if is_managed {
                                Color32::from_rgb(130, 200, 255)
                            } else {
                                Color32::from_gray(220)
                            };
                            let text = RichText::new(self.display_text(&src_str))
                                .monospace()
                                .color(color);
                            let resp = ui.label(text);
                            if is_managed {
                                resp.on_hover_text(
                                    "@ refers to nsproxy-managed state for this profile",
                                );
                            }
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(self.display_path(&m.target)).monospace());
                        });
                        row.col(|ui| {
                            if m.read_only {
                                ui.colored_label(Color32::LIGHT_GREEN, "ro");
                            } else {
                                ui.colored_label(Color32::from_gray(120), "rw");
                            }
                        });
                        row.col(|ui| {
                            if m.recursive {
                                ui.colored_label(Color32::from_gray(160), "rec");
                            } else {
                                ui.colored_label(Color32::from_gray(100), "—");
                            }
                        });
                        row.col(|ui| {
                            if m.skip_missing {
                                ui.colored_label(Color32::from_rgb(236, 198, 92), "optional");
                            } else {
                                ui.colored_label(Color32::from_gray(120), "required");
                            }
                        });
                    });
                });
        });
    }

    fn render_profile_editor_tab(&mut self, ui: &mut egui::Ui) {
        self.refresh_profile_editor_target();

        ui.horizontal(|ui| {
            match self.selected_profile.as_ref() {
                Some(profile_name) => {
                    ui.heading(format!("Profile - {}", self.display_text(profile_name)))
                }
                None => ui.heading("Profile - New Container"),
            };

            if ui.button("Reload").clicked() {
                if let Some(profile_name) = self.selected_profile.clone() {
                    self.supervisor
                        .send(SupervisorCommand::ReloadProfile(profile_name.clone()));
                    self.supervisor
                        .send(SupervisorCommand::LoadProfile(profile_name));
                    self.profile_editor_target = None;
                } else {
                    self.supervisor.send(SupervisorCommand::Init);
                    self.profile_editor_target = None;
                }
            }

            if ui.button("Save").clicked() {
                self.save_profile_editor();
            }

            ui.separator();
            ui.label("Create name");
            ui.text_edit_singleline(&mut self.profile_editor_create_name);
            if ui.button("Create").clicked() {
                self.create_profile_from_editor();
            }
        });

        if let Some(status) = self.effective_profile_editor_status() {
            ui.label(status);
        }
        ui.add_space(6.0);

        ui.columns(2, |columns| {
            columns[0].heading("Form");
            egui::ScrollArea::vertical()
                .id_salt("profile-editor-form-scroll")
                .show(&mut columns[0], |ui| {
                    let form_changed = self.render_template_form(ui);
                    if form_changed {
                        self.refresh_profile_editor_json_from_template();
                        self.profile_editor_json_error = None;
                    }
                });

            columns[1].heading("Formatted JSON");
            egui::ScrollArea::vertical()
                .id_salt("profile-editor-json-scroll")
                .show(&mut columns[1], |ui| {
                    let mut editor = CodeEditor::default()
                        .id_source("profile-editor-template-json")
                        .with_rows(42)
                        .with_theme(ColorTheme::GRUVBOX)
                        .with_numlines(true)
                        .with_ui_fontsize(ui);
                    let (output, _) =
                        editor.show(ui, &mut self.profile_editor_json, &json_syntax());
                    if output.response.changed() {
                        match serde_json::from_str::<TemplateConfig>(&self.profile_editor_json) {
                            Ok(parsed) => {
                                self.profile_editor_template = parsed;
                                self.profile_editor_json_error = None;
                                self.profile_editor_hot_init_error = None;
                                self.refresh_hot_init_json_from_template();
                            }
                            Err(err) => {
                                self.profile_editor_json_error = Some(format!("JSON error: {err}"));
                            }
                        }
                    }

                    if let Some(err) = &self.profile_editor_json_error {
                        ui.colored_label(egui::Color32::LIGHT_RED, err);
                    }
                });
        });
    }

    fn render_proxy_detail_window(&mut self, ctx: &egui::Context) {
        let Some(detail_id) = self.detail_proxy_id.clone() else {
            return;
        };

        let proxy_name = self
            .proxies
            .get(&detail_id)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| detail_id.nym().to_string());

        let live_stats: Option<ProxyStats> = self
            .selected_profile
            .as_ref()
            .and_then(|p| self.snapshot.profiles.get(p))
            .and_then(|p| p.proxy_stats.get(&detail_id).cloned());

        // Trigger fit-to-data for a few frames (on open and when button is pressed).
        let fit = self.detail_fit_frames_left > 0;

        let mut open = true;
        egui::Window::new(format!("Proxy Detail — {}", proxy_name))
            .open(&mut open)
            .default_size([640.0, 600.0])
            .resizable(true)
            .show(ctx, |ui| {
                if let Some(item) = self.proxies.get(&detail_id) {
                    ui.horizontal(|ui| {
                        ui.label("URL:");
                        let url = if self.hide_secret {
                            &self.cover_text
                        } else {
                            &item.url
                        };
                        ui.label(egui::RichText::new(url).monospace());
                    });
                    if !item.resolved_ips.is_empty() {
                        ui.label("Resolved IPs:");
                        for ip in &item.resolved_ips {
                            ui.label(egui::RichText::new(ip.to_string()).monospace());
                        }
                    }
                    ui.separator();
                }

                if let Some(stats) = &live_stats {
                    // ---- Summary table ----
                    ui.heading("Summary");
                    let time_windows = [
                        ("Minute", stats.past_minute()),
                        ("Hour", stats.past_hour()),
                        ("Day", stats.past_day()),
                        ("Week", stats.past_week()),
                    ];
                    egui::Grid::new("detail_stats_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Window");
                            ui.strong("Attempts");
                            ui.strong("Successes");
                            ui.strong("Success%");
                            ui.strong("Avg Latency");
                            ui.strong("↑ Up");
                            ui.strong("↓ Down");
                            ui.end_row();
                            for (label, slot) in &time_windows {
                                ui.label(*label);
                                ui.label(format!("{}", slot.attempts));
                                ui.label(format!("{}", slot.successes));
                                ui.label(
                                    slot.success_rate()
                                        .map(|r| format!("{:.1}%", r * 100.0))
                                        .unwrap_or_else(|| "—".into()),
                                );
                                ui.label(
                                    slot.avg_latency_ms()
                                        .map(|l| format!("{:.0}ms", l))
                                        .unwrap_or_else(|| "—".into()),
                                );
                                ui.label(format_bytes(slot.bytes_up));
                                ui.label(format_bytes(slot.bytes_down));
                                ui.end_row();
                            }
                        });

                    ui.add_space(8.0);
                    // ---- Fit View button ----
                    if ui.button("⟲ Fit View (all graphs)").clicked() {
                        self.detail_fit_frames_left = 3;
                    }
                    ui.add_space(6.0);

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.heading("Latency (ms) — past hour");
                        render_detail_latency_plot(ui, stats, &detail_id, fit);

                        ui.add_space(10.0);
                        ui.heading("Attempts & Fail % — past hour");
                        render_detail_attempts_plot(ui, stats, &detail_id, fit);

                        ui.add_space(10.0);
                        ui.heading("Traffic — past hour");
                        render_detail_traffic_plot(ui, stats, &detail_id, fit);
                    });
                } else {
                    ui.label("No live stats available. Connect to a running container.");
                }
            });

        if self.detail_fit_frames_left > 0 {
            self.detail_fit_frames_left = self.detail_fit_frames_left.saturating_sub(1);
        }

        if !open {
            self.detail_proxy_id = None;
        }
    }
}

fn format_relative_age_label(age: f64) -> String {
    if age < 15.0 {
        "now".to_string()
    } else if age < 90.0 {
        format!("{:.0}s ago", age)
    } else if age < 3600.0 {
        let m = (age / 60.0).round() as u64;
        format!("{}m ago", m)
    } else {
        let h = (age / 3600.0 * 10.0).round() / 10.0;
        if (h - h.floor()).abs() < 0.05 {
            format!("{:.0}h ago", h)
        } else {
            format!("{:.1}h ago", h)
        }
    }
}

/// Format a plot x-value as a human-readable age label.
/// `x` is negative seconds relative to now: 0 = now, -3600 = 1 hour ago.
fn format_age_label(x: f64, _window_secs: f64) -> String {
    format_relative_age_label((-x).max(0.0))
}

fn format_timestamp_age(ts: Timestamp) -> String {
    let age = Timestamp::now().elapsed_since(ts).as_secs_f64();
    format_relative_age_label(age)
}

fn format_conn_timestamp(ts: diag::Timestamp) -> String {
    use chrono::TimeZone;

    let clock = chrono::Local
        .timestamp_opt(ts.as_secs() as i64, ((ts.0 % 1_000_000) * 1_000) as u32)
        .single()
        .map(|datetime| datetime.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".to_string());
    format!("{} {}", format_timestamp_age(ts), clock)
}

fn conn_phase_label(phase: diag::ConnPhase) -> &'static str {
    match phase {
        diag::ConnPhase::Accepted => "accepted",
        diag::ConnPhase::Routing => "connecting",
        diag::ConnPhase::Connected => "connected",
        diag::ConnPhase::DnsResolved => "DNS resolved",
        diag::ConnPhase::DnsFailed => "DNS failed",
        diag::ConnPhase::Finished => "finished",
        diag::ConnPhase::Killed => "killed",
        diag::ConnPhase::Failed => "failed",
        diag::ConnPhase::RouteExhausted => "retry limit reached",
        diag::ConnPhase::RouteRejected => "route rejected",
    }
}

fn conn_phase_color(phase: diag::ConnPhase) -> Color32 {
    match phase {
        diag::ConnPhase::Finished | diag::ConnPhase::DnsResolved => Color32::LIGHT_GREEN,
        diag::ConnPhase::Killed => Color32::GRAY,
        diag::ConnPhase::Failed | diag::ConnPhase::DnsFailed | diag::ConnPhase::RouteRejected => {
            Color32::LIGHT_RED
        }
        diag::ConnPhase::RouteExhausted => Color32::YELLOW,
        diag::ConnPhase::Connected => Color32::LIGHT_BLUE,
        diag::ConnPhase::Accepted | diag::ConnPhase::Routing => Color32::GRAY,
    }
}

fn conn_route_label(route: Option<&nsproxy_common::routing::RoutingResovled>) -> String {
    use nsproxy_common::routing::{DropReason, RoutingResovled};

    match route {
        Some(RoutingResovled::NoProxy(address)) => {
            format!("NoProxy {} {address}", regular::ARROW_RIGHT)
        }
        Some(RoutingResovled::NoProxyDomain { host, port }) => {
            format!("NoProxy {} {host}:{port}", regular::ARROW_RIGHT)
        }
        Some(RoutingResovled::NATByTUN(address)) => {
            format!("TUN {} {address}", regular::ARROW_RIGHT)
        }
        Some(RoutingResovled::ProxyResovled { target, id }) => {
            format!("Proxy {id} {} {target}", regular::ARROW_RIGHT)
        }
        Some(RoutingResovled::Drop(DropReason::MaxRetry)) => "Retry limit reached".to_string(),
        Some(RoutingResovled::Drop(DropReason::Preprocess(reason))) => {
            format!("Rejected: {reason}")
        }
        None => "—".to_string(),
    }
}

fn conn_transition_label(kind: &diag::ConnTransitionKind) -> String {
    use nsproxy_common::routing::{DropReason, RoutingResovled};

    match kind {
        diag::ConnTransitionKind::Accepted => "Accepted".to_string(),
        diag::ConnTransitionKind::Dispatched { dispatch_us } => format!(
            "Dispatched after {}",
            diag::summary::format_duration_us(*dispatch_us as f64)
        ),
        diag::ConnTransitionKind::Route(RoutingResovled::Drop(DropReason::MaxRetry)) => {
            "Retry limit reached".to_string()
        }
        diag::ConnTransitionKind::Route(RoutingResovled::Drop(DropReason::Preprocess(reason))) => {
            format!("Route rejected: {reason}")
        }
        diag::ConnTransitionKind::Route(RoutingResovled::NoProxy(address)) => {
            format!("NoProxy: {address}")
        }
        diag::ConnTransitionKind::Route(RoutingResovled::NoProxyDomain { host, port }) => {
            format!("NoProxy: {host}:{port}")
        }
        diag::ConnTransitionKind::Route(RoutingResovled::NATByTUN(address)) => {
            format!("Direct through TUN: {address}")
        }
        diag::ConnTransitionKind::Route(RoutingResovled::ProxyResovled { target, id }) => {
            format!("Proxy {id} {} {target}", regular::ARROW_RIGHT)
        }
        diag::ConnTransitionKind::Connected => "Upstream connected".to_string(),
        diag::ConnTransitionKind::AttemptFailed { error } => {
            format!("Route attempt failed: {error}")
        }
        diag::ConnTransitionKind::DnsResolved { domain, result } => {
            format!("DNS {domain}: {result}")
        }
        diag::ConnTransitionKind::Finished { error: Some(error) } => {
            format!("Failed: {error}")
        }
        diag::ConnTransitionKind::Finished { error: None } => "Finished successfully".to_string(),
        diag::ConnTransitionKind::Killed => "Killed by user".to_string(),
    }
}

fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let mut value = bytes_per_sec;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn render_transfer_rate_cell(
    ui: &mut egui::Ui,
    bytes_per_sec: Option<f64>,
    summary: Option<nsproxy_common::stats::TransferRateSummary>,
    sample: Option<TransferRateSample>,
) {
    const LIVE_RATE_AGE: Duration = Duration::from_secs(2);
    let now = Timestamp::now();
    let live_sample =
        sample.filter(|sample| now.elapsed_since(sample.observed_at) <= LIVE_RATE_AGE);
    let displayed_rate = live_sample
        .map(TransferRateSample::bytes_per_sec)
        .or(bytes_per_sec);
    let text = displayed_rate
        .map(format_bytes_per_sec)
        .unwrap_or_else(|| "—".to_string());
    let response = if live_sample.is_some() {
        ui.label(text)
    } else if bytes_per_sec.is_some() {
        ui.colored_label(Color32::LIGHT_BLUE, text)
    } else {
        ui.label(text)
    };

    let mut details = Vec::new();
    if let Some(summary) = summary {
        details.push(format!(
            "Average: {}",
            format_bytes_per_sec(summary.average_bytes_per_sec)
        ));
        details.push(format!(
            "Minimum: {}",
            format_bytes_per_sec(summary.min_bytes_per_sec)
        ));
        details.push(format!(
            "Maximum: {}",
            format_bytes_per_sec(summary.max_bytes_per_sec)
        ));
        details.push(format!("Rate observations: {}", summary.sample_count));
    }
    if let Some(sample) = sample {
        details.push(format!(
            "Latest lower-bound estimate: {} over {:.2}s elapsed ({:.2}s between data events; {} forwarded events), observed {}",
            format_bytes_per_sec(sample.bytes_per_sec()),
            sample.duration_secs(),
            sample.data_span_secs(),
            sample.event_count,
            format_timestamp_age(sample.observed_at)
        ));
    }
    if details.is_empty() {
        details.push("No transfer rate observations yet.".to_string());
    }
    response.on_hover_text(details.join("\n"));
}

fn list_persisted_log_files() -> Vec<PersistedLogFileInfo> {
    let Ok(dir_entries) = std::fs::read_dir(state_paths::logs_root()) else {
        return Vec::new();
    };

    let mut files = dir_entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
        .filter_map(|path| {
            let metadata = std::fs::metadata(&path).ok();
            let file_name = path.file_name()?.to_str()?.to_string();
            let stem = path.file_stem()?.to_str()?.to_string();
            let (process_label, pid) = match stem.rsplit_once('-') {
                Some((label, pid_s)) => (label.to_string(), pid_s.parse::<u32>().ok()),
                None => (stem.clone(), None),
            };
            Some(PersistedLogFileInfo {
                path,
                file_name,
                process_label,
                pid,
                modified: metadata.and_then(|meta| meta.modified().ok()),
            })
        })
        .collect::<Vec<_>>();

    files.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });
    files
}

fn load_persisted_log_file_entries(path: &Path) -> Vec<PersistedProcessLogEntry> {
    let source_label = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| stem.to_string())
        .unwrap_or_else(|| path.display().to_string());
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for line in BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if let Ok(log) = serde_json::from_str::<LogEntry>(&line) {
            entries.push(PersistedProcessLogEntry {
                source_label: source_label.clone(),
                log,
            });
        }
    }
    entries.sort_by_key(|entry| entry.log.ts);
    entries
}

fn build_persisted_logs_snapshot(
    selected_file: Option<&Path>,
    selected_pid: Option<u32>,
    logs_tab_visible: bool,
    process_logs_visible: bool,
) -> PersistedLogsSnapshot {
    let files = list_persisted_log_files();
    let mut entries_by_pid: HashMap<u32, Vec<PersistedProcessLogEntry>> = HashMap::new();
    let mut selected_file_entries = Vec::new();

    for file in &files {
        let should_load_selected_file =
            logs_tab_visible && selected_file.is_some_and(|selected| selected == file.path);
        let should_load_pid_entries =
            process_logs_visible && selected_pid.is_some_and(|pid| file.pid == Some(pid));

        if !(should_load_selected_file || should_load_pid_entries) {
            continue;
        }

        let entries = load_persisted_log_file_entries(&file.path);
        if should_load_pid_entries {
            if let Some(pid) = file.pid {
                entries_by_pid
                    .entry(pid)
                    .or_default()
                    .extend(entries.iter().cloned());
            }
        }
        if should_load_selected_file {
            selected_file_entries = entries;
        }
    }

    for entries in entries_by_pid.values_mut() {
        entries.sort_by_key(|entry| entry.log.ts);
    }

    PersistedLogsSnapshot {
        files,
        entries_by_pid,
        selected_file_path: selected_file.map(Path::to_path_buf),
        selected_file_entries,
    }
}

/// Grid spacer for a 1-hour window: minor marks every 5 min, medium every 15 min, major every 30 min.
fn time_grid_spacer_1h() -> impl Fn(GridInput) -> Vec<GridMark> {
    |input: GridInput| {
        let (min, max) = input.bounds;
        let step = 300.0_f64; // 5 minutes
        let i0 = (min / step).ceil() as i64;
        let i1 = (max / step).floor() as i64;
        (i0..=i1)
            .map(|i| {
                let v = i as f64 * step;
                // step_size drives line thickness: larger = thicker
                let step_size = if i % 6 == 0 {
                    1800.0
                } else if i % 3 == 0 {
                    900.0
                } else {
                    300.0
                };
                GridMark {
                    value: v,
                    step_size,
                }
            })
            .collect()
    }
}

/// Split a sparse `Option<TsPoint>` slice into solid segments and dashed gap-bridge segments.
/// Returns `(solid_segs, gap_segs)` where each element is a `PlotPoints` pair.
///
/// If `x_bounds` is `Some((x_min, x_max))`, dashed segments are also added from `x_min` to the
/// first data point and from the last data point to `x_max`, so the full time span is covered.
fn split_ts_segments(
    pts: &[Option<TsPoint>],
    x_bounds: Option<(f64, f64)>,
) -> (Vec<PlotPoints>, Vec<PlotPoints>) {
    let mut solid_segs: Vec<PlotPoints> = Vec::new();
    let mut gap_segs: Vec<PlotPoints> = Vec::new();
    let mut cur: Vec<[f64; 2]> = Vec::new();
    let mut last_pt: Option<[f64; 2]> = None;
    let mut first_pt: Option<[f64; 2]> = None;
    for p in pts {
        match p {
            Some(tp) => {
                let pt = [tp.x, tp.val];
                if first_pt.is_none() {
                    first_pt = Some(pt);
                }
                if cur.is_empty() {
                    if let Some(lp) = last_pt {
                        gap_segs.push(PlotPoints::from(vec![lp, pt]));
                    }
                }
                cur.push(pt);
                last_pt = Some(pt);
            }
            None => {
                if !cur.is_empty() {
                    solid_segs.push(PlotPoints::from(cur.drain(..).collect::<Vec<_>>()));
                }
            }
        }
    }
    if !cur.is_empty() {
        solid_segs.push(PlotPoints::from(cur));
    }

    // Extend dashes to window edges so the full span is always covered.
    if let Some((x_min, x_max)) = x_bounds {
        if let Some(fp) = first_pt {
            if fp[0] > x_min {
                gap_segs.push(PlotPoints::from(vec![[x_min, fp[1]], fp]));
            }
        }
        if let Some(lp) = last_pt {
            if lp[0] < x_max {
                gap_segs.push(PlotPoints::from(vec![lp, [x_max, lp[1]]]));
            }
        }
    }

    (solid_segs, gap_segs)
}

/// A single time-series point.
#[derive(Clone)]
struct TsPoint {
    /// Seconds relative to "now" (negative = past, 0 = now).
    x: f64,
    /// The value for this bucket.
    val: f64,
}

/// Split a stored range's data proportionally across query buckets.
/// Each bucket gets (overlap / stored_span) * data so totals are not duplicated.
fn bucket_timeseries(
    stats: &ProxyStats,
    window_us: u64,
    num_buckets: usize,
    now: nsproxy_common::stats::Timestamp,
    extract: impl Fn(&nsproxy_common::stats::SlotData) -> f64,
) -> Vec<TsPoint> {
    use nsproxy_common::stats::{DAY_US, HOUR_US, MINUTE_US};

    let bucket_us = (window_us / num_buckets as u64).max(1);
    let window_start_us = now.0.saturating_sub(window_us);

    let mut buckets = vec![0.0_f64; num_buckets];

    let mut process_entry =
        |ts: u64, data: &nsproxy_common::stats::SlotData, granularity_us: u64| {
            if ts < window_start_us || ts > now.0 {
                return;
            }
            let r_start = ts;
            let r_end = ts + granularity_us - 1;
            let r_start_clipped = r_start.max(window_start_us);
            let r_end_clipped = r_end.min(now.0);
            if r_end_clipped < r_start_clipped {
                return;
            }
            let stored_span = (r_end - r_start + 1) as f64;
            let val = extract(data);

            let first_bucket = ((r_start_clipped - window_start_us) / bucket_us) as usize;
            let last_bucket = ((r_end_clipped - window_start_us) / bucket_us) as usize;
            for b in first_bucket..=last_bucket.min(num_buckets - 1) {
                let b_start_us = window_start_us + b as u64 * bucket_us;
                let b_end_us = b_start_us + bucket_us - 1;
                let overlap_start = r_start.max(b_start_us) as f64;
                let overlap_end = (r_end.min(b_end_us) + 1) as f64;
                let overlap = (overlap_end - overlap_start).max(0.0);
                buckets[b] += val * overlap / stored_span;
            }
        };

    for (ts, data) in stats.minute_data.iter() {
        process_entry(ts.0, data, MINUTE_US);
    }
    for (ts, data) in stats.hour_data.iter() {
        process_entry(ts.0, data, HOUR_US);
    }
    for (ts, data) in stats.day_data.iter() {
        process_entry(ts.0, data, DAY_US);
    }

    // x is negative seconds relative to now: 0 = now, -window_secs = oldest bucket.
    let bucket_secs = bucket_us as f64 / 1_000_000.0;
    let window_secs = window_us as f64 / 1_000_000.0;
    buckets
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            let x = i as f64 * bucket_secs + bucket_secs * 0.5 - window_secs;
            TsPoint { x, val: v }
        })
        .collect()
}

/// Compute per-bucket average latency (ms).  Returns None for buckets with no samples.
fn bucket_avg_latency(
    stats: &ProxyStats,
    window_us: u64,
    num_buckets: usize,
    now: nsproxy_common::stats::Timestamp,
) -> Vec<Option<TsPoint>> {
    let sum_pts = bucket_timeseries(stats, window_us, num_buckets, now, |d| {
        d.latency_sum_ms as f64
    });
    let cnt_pts = bucket_timeseries(stats, window_us, num_buckets, now, |d| {
        d.latency_count as f64
    });
    sum_pts
        .into_iter()
        .zip(cnt_pts)
        .map(|(s, c)| {
            if c.val >= 0.5 {
                Some(TsPoint {
                    x: s.x,
                    val: s.val / c.val,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Convert a slice of TsPoint to PlotPoints.
fn ts_to_plot(pts: &[TsPoint]) -> PlotPoints {
    pts.iter().map(|p| [p.x, p.val]).collect()
}

fn render_mini_sparkline(ui: &mut egui::Ui, stats: &ProxyStats, proxy_id: &ProxyID) {
    use nsproxy_common::stats::Timestamp;

    let hour_us: u64 = 3_600 * 1_000_000;
    let num_buckets = 20;
    let now = Timestamp::now();

    let lat_pts = bucket_avg_latency(stats, hour_us, num_buckets, now);
    let att_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.attempts as f64);
    let suc_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.successes as f64);

    // Compute fail-rate per bucket = (attempts - successes) / attempts
    // Use None for buckets with no attempts so the line has the same x-extent as latency.
    let fail_rate_pts: Vec<Option<TsPoint>> = att_pts
        .iter()
        .zip(suc_pts.iter())
        .map(|(a, s)| {
            if a.val >= 0.5 {
                let fail = ((a.val - s.val) / a.val * 100.0).max(0.0);
                Some(TsPoint { x: a.x, val: fail })
            } else {
                None
            }
        })
        .collect();

    let has_latency = lat_pts.iter().any(|p| p.is_some());
    let has_attempts = fail_rate_pts.iter().any(|p| p.is_some());

    if !has_latency && !has_attempts {
        ui.vertical(|ui| {
            let h = stats.past_hour();
            if let Some(r) = h.success_rate() {
                let fail = 1.0 - r;
                let color = if fail < 0.1 {
                    Color32::LIGHT_GREEN
                } else if fail < 0.3 {
                    Color32::YELLOW
                } else {
                    Color32::LIGHT_RED
                };
                ui.colored_label(color, format!("{:.0}%ok", r * 100.0));
            } else {
                ui.label(
                    egui::RichText::new("no data")
                        .small()
                        .color(Color32::from_gray(120)),
                );
            }
        });
        return;
    }

    // Pin x-axis to the full window so sparse data never appears truncated.
    let window_secs = hour_us as f64 / 1_000_000.0;
    let bounds = Some((-window_secs, 0.0));

    let (lat_solid, lat_gaps) = split_ts_segments(&lat_pts, bounds);
    let (fail_solid, fail_gaps) = split_ts_segments(&fail_rate_pts, bounds);

    let lat_color = Color32::from_rgb(100, 180, 255);
    let lat_color_dim = Color32::from_rgb(60, 110, 160);
    let fail_color = Color32::from_rgb(255, 100, 100);
    let fail_color_dim = Color32::from_rgb(160, 60, 60);

    let id = format!("mini_spark_{}", proxy_id);
    egui_plot::Plot::new(id)
        .height(60.0)
        .width(120.0)
        .show_axes(false)
        .show_grid(false)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .allow_boxed_zoom(false)
        .include_y(0.0)
        .include_x(-window_secs)
        .include_x(0.0)
        .auto_bounds(egui::Vec2b::new(false, true))
        .set_margin_fraction(egui::Vec2::new(0.0, 0.15))
        .show(ui, |plot_ui| {
            if has_latency {
                for (i, seg) in lat_solid.into_iter().enumerate() {
                    let name = if i == 0 {
                        "latency".to_string()
                    } else {
                        format!("lat_s_{}", i)
                    };
                    plot_ui.line(Line::new(name, seg).color(lat_color).width(1.5));
                }
                for (i, gap) in lat_gaps.into_iter().enumerate() {
                    plot_ui.line(
                        Line::new(format!("lat_g_{}", i), gap)
                            .color(lat_color_dim)
                            .width(1.0)
                            .style(LineStyle::Dashed { length: 4.0 }),
                    );
                }
            }
            if has_attempts {
                for (i, seg) in fail_solid.into_iter().enumerate() {
                    let name = if i == 0 {
                        "fail%".to_string()
                    } else {
                        format!("fail_s_{}", i)
                    };
                    plot_ui.line(Line::new(name, seg).color(fail_color).width(1.0));
                }
                for (i, gap) in fail_gaps.into_iter().enumerate() {
                    plot_ui.line(
                        Line::new(format!("fail_g_{}", i), gap)
                            .color(fail_color_dim)
                            .width(1.0)
                            .style(LineStyle::Dashed { length: 4.0 }),
                    );
                }
            }
        });
}

/// Render a single `DiagEvent` as a compact horizontal row for the Traffic Logs sub-view.
fn render_diag_event_row(ui: &mut egui::Ui, event: &diag::DiagEvent) {
    ui.horizontal(|ui| match event {
        diag::DiagEvent::Accept {
            id, kind, src, dst, ..
        } => {
            ui.colored_label(Color32::from_rgb(100, 180, 220), "Accept");
            ui.label(format!("#{} {:?} {} → {}", id.0, kind, src, dst));
        }
        diag::DiagEvent::Route { id, route, .. } => {
            ui.colored_label(Color32::from_rgb(180, 220, 100), "Route");
            ui.label(format!("#{} → {:?}", id.0, route));
        }
        diag::DiagEvent::Connected { id, .. } => {
            ui.colored_label(Color32::LIGHT_GREEN, "Connected");
            ui.label(format!("#{}", id.0));
        }
        diag::DiagEvent::AttemptFailed { id, error, .. } => {
            ui.colored_label(Color32::YELLOW, "Attempt failed");
            ui.label(format!("#{} {}", id.0, error));
        }
        diag::DiagEvent::Finished {
            id,
            error,
            bytes_up,
            bytes_down,
            ..
        } => {
            if error.is_some() {
                ui.colored_label(Color32::LIGHT_RED, "Finished");
            } else {
                ui.colored_label(Color32::from_gray(160), "Finished");
            }
            let err_str = error.as_deref().unwrap_or("ok");
            ui.label(format!(
                "#{} {} ↑{:.0} ↓{:.0}",
                id.0, err_str, bytes_up, bytes_down
            ));
        }
        diag::DiagEvent::Killed { id, .. } => {
            ui.colored_label(Color32::from_gray(150), "Killed");
            ui.label(format!("#{} by user", id.0));
        }
        diag::DiagEvent::DnsQuery { id, query, .. } => {
            ui.colored_label(Color32::from_rgb(200, 200, 100), "DNS?");
            ui.label(format!("#{} {}", id.0, query));
        }
        diag::DiagEvent::DnsResolved {
            id, domain, result, ..
        } => {
            ui.colored_label(Color32::from_rgb(200, 200, 100), "DNS✓");
            ui.label(format!("#{} {} → {}", id.0, domain, result));
        }
        diag::DiagEvent::Dispatched { id, dispatch_us } => {
            ui.colored_label(Color32::from_gray(130), "Dispatch");
            ui.label(format!("#{} {}µs", id.0, dispatch_us));
        }
        diag::DiagEvent::HotConfigReloaded {
            ok, source, error, ..
        } => {
            let color = if *ok {
                Color32::LIGHT_GREEN
            } else {
                Color32::LIGHT_RED
            };
            ui.colored_label(color, "HotConfig");
            let detail = error.as_deref().unwrap_or(source.as_str());
            ui.label(detail);
        }
        diag::DiagEvent::Log(entry) => {
            ui.colored_label(log_level_color(&entry.level), &entry.level);
            ui.colored_label(LOG_SYNTAX_BLUE, format!("[{}]", entry.target));
            ui.horizontal_wrapped(|ui| {
                ui.label(egui_sgr::ansi_to_layout_job(
                    &entry.message,
                    log_ansi_theme(),
                ));
                for field in &entry.fields {
                    ui.add_space(6.0);
                    ui.colored_label(LOG_SYNTAX_CYAN, format!("{}=", field.name));
                    ui.label(
                        RichText::new(&field.value)
                            .monospace()
                            .color(LOG_SYNTAX_GREEN),
                    );
                }
            });
        }
        other => {
            ui.colored_label(Color32::from_gray(120), diag_event_kind_label(other));
        }
    });
}

fn diag_event_kind_label(ev: &diag::DiagEvent) -> &'static str {
    match ev {
        diag::DiagEvent::Accept { .. } => "Accept",
        diag::DiagEvent::Dispatched { .. } => "Dispatched",
        diag::DiagEvent::Route { .. } => "Route",
        diag::DiagEvent::Connected { .. } => "Connected",
        diag::DiagEvent::AttemptFailed { .. } => "AttemptFailed",
        diag::DiagEvent::Finished { .. } => "Finished",
        diag::DiagEvent::Killed { .. } => "Killed",
        diag::DiagEvent::DnsResolved { .. } => "DnsResolved",
        diag::DiagEvent::DnsQuery { .. } => "DnsQuery",
        diag::DiagEvent::Wait { .. } => "Wait",
        diag::DiagEvent::WaitEnded { .. } => "WaitEnded",
        diag::DiagEvent::HotConfigReloaded { .. } => "HotConfigReloaded",
        diag::DiagEvent::HotConfigSnapshot { .. } => "HotConfigSnapshot",
        diag::DiagEvent::DnsState { .. } => "DnsState",
        diag::DiagEvent::RoutingState { .. } => "RoutingState",
        diag::DiagEvent::UplinkStatsSnapshot { .. } => "UplinkStatsSnapshot",
        diag::DiagEvent::HostRouteStatsSnapshot { .. } => "HostRouteStatsSnapshot",
        diag::DiagEvent::HostRouteStatsUpdated { .. } => "HostRouteStatsUpdated",
        diag::DiagEvent::ConnectionsExpired { .. } => "ConnectionsExpired",
        diag::DiagEvent::Log(_) => "Log",
        diag::DiagEvent::RecentLogs(_) => "RecentLogs",
        diag::DiagEvent::RecentDiagEvents(_) => "RecentDiagEvents",
        diag::DiagEvent::ConnsStateSnapshot { .. } => "ConnsStateSnapshot",
    }
}

fn render_detail_latency_plot(
    ui: &mut egui::Ui,
    stats: &ProxyStats,
    proxy_id: &ProxyID,
    fit: bool,
) {
    use nsproxy_common::stats::Timestamp;

    let hour_us: u64 = 3_600 * 1_000_000;
    let num_buckets = 60;
    const WINDOW_SECS: f64 = 3600.0;
    let now = Timestamp::now();

    let lat_pts = bucket_avg_latency(stats, hour_us, num_buckets, now);
    let has_data = lat_pts.iter().any(|p| p.is_some());
    if !has_data {
        ui.label("No latency data for the past hour.");
        return;
    }
    let gap_bounds = Some((-WINDOW_SECS, 0.0));
    let (solid_segs, gap_segs) = split_ts_segments(&lat_pts, gap_bounds);

    let lat_color = Color32::from_rgb(100, 180, 255);
    let lat_color_dim = Color32::from_rgb(60, 110, 160);

    let mut plot = egui_plot::Plot::new(format!("detail_lat_{}", proxy_id))
        .height(160.0)
        .x_axis_formatter(|mark, _| format_age_label(mark.value, WINDOW_SECS))
        .x_grid_spacer(time_grid_spacer_1h())
        .y_axis_label("Latency (ms)")
        .set_margin_fraction(egui::Vec2::new(0.0, 0.15));
    if fit {
        // Explicit reset ensures recovery after manual pan/zoom.
        plot = plot.reset().auto_bounds(egui::Vec2b::new(true, true));
    } else {
        // Keep user pan/zoom state between frames.
        plot = plot.auto_bounds(egui::Vec2b::new(true, true));
    }
    plot.show(ui, |plot_ui| {
        for (i, seg) in solid_segs.into_iter().enumerate() {
            let name = if i == 0 {
                "Latency (ms)".to_string()
            } else {
                format!("lat_seg_{}", i)
            };
            plot_ui.line(Line::new(name, seg).color(lat_color).width(2.0));
        }
        for (i, gap) in gap_segs.into_iter().enumerate() {
            plot_ui.line(
                Line::new(format!("lat_gap_{}", i), gap)
                    .color(lat_color_dim)
                    .width(1.5)
                    .style(LineStyle::Dashed { length: 6.0 }),
            );
        }
    });
}

fn render_detail_attempts_plot(
    ui: &mut egui::Ui,
    stats: &ProxyStats,
    proxy_id: &ProxyID,
    fit: bool,
) {
    use nsproxy_common::stats::Timestamp;

    let hour_us: u64 = 3_600 * 1_000_000;
    let num_buckets = 60;
    let now = Timestamp::now();

    let att_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.attempts as f64);
    let suc_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.successes as f64);

    // Use Option so empty buckets become dashed gaps rather than zero-filled lines.
    let att_opt: Vec<Option<TsPoint>> = att_pts
        .iter()
        .map(|p| if p.val >= 0.5 { Some(p.clone()) } else { None })
        .collect();
    let fail_opt: Vec<Option<TsPoint>> = att_pts
        .iter()
        .zip(suc_pts.iter())
        .map(|(a, s)| {
            if a.val >= 0.5 {
                Some(TsPoint {
                    x: a.x,
                    val: ((a.val - s.val) / a.val * 100.0).max(0.0),
                })
            } else {
                None
            }
        })
        .collect();

    let has_data = att_opt.iter().any(|p| p.is_some());
    if !has_data {
        ui.label("No attempt data for the past hour.");
        return;
    }

    let gap_bounds = Some((-WINDOW_SECS_ATT, 0.0));
    let (att_solid, att_gaps) = split_ts_segments(&att_opt, gap_bounds);
    let (fail_solid, fail_gaps) = split_ts_segments(&fail_opt, gap_bounds);

    let att_color = Color32::from_rgb(180, 220, 100);
    let att_color_dim = Color32::from_rgb(100, 140, 60);
    let fail_color = Color32::from_rgb(255, 100, 100);
    let fail_color_dim = Color32::from_rgb(160, 60, 60);

    const WINDOW_SECS_ATT: f64 = 3600.0;
    let mut plot = egui_plot::Plot::new(format!("detail_att_{}", proxy_id))
        .height(160.0)
        .x_axis_formatter(|mark, _| format_age_label(mark.value, WINDOW_SECS_ATT))
        .x_grid_spacer(time_grid_spacer_1h())
        .y_axis_label("Attempts / Fail%")
        .set_margin_fraction(egui::Vec2::new(0.0, 0.15));
    if fit {
        plot = plot.reset().auto_bounds(egui::Vec2b::new(true, true));
    } else {
        plot = plot.auto_bounds(egui::Vec2b::new(true, true));
    }
    plot.show(ui, |plot_ui| {
        for (i, seg) in att_solid.into_iter().enumerate() {
            let name = if i == 0 {
                "Attempts".to_string()
            } else {
                format!("att_s_{}", i)
            };
            plot_ui.line(Line::new(name, seg).color(att_color).width(2.0));
        }
        for (i, gap) in att_gaps.into_iter().enumerate() {
            plot_ui.line(
                Line::new(format!("att_g_{}", i), gap)
                    .color(att_color_dim)
                    .width(1.5)
                    .style(LineStyle::Dashed { length: 6.0 }),
            );
        }
        for (i, seg) in fail_solid.into_iter().enumerate() {
            let name = if i == 0 {
                "Fail %".to_string()
            } else {
                format!("fail_s_{}", i)
            };
            plot_ui.line(Line::new(name, seg).color(fail_color).width(1.5));
        }
        for (i, gap) in fail_gaps.into_iter().enumerate() {
            plot_ui.line(
                Line::new(format!("fail_g_{}", i), gap)
                    .color(fail_color_dim)
                    .width(1.0)
                    .style(LineStyle::Dashed { length: 6.0 }),
            );
        }
    });
}

fn render_detail_traffic_plot(
    ui: &mut egui::Ui,
    stats: &ProxyStats,
    proxy_id: &ProxyID,
    fit: bool,
) {
    use nsproxy_common::stats::Timestamp;

    let hour_us: u64 = 3_600 * 1_000_000;
    let num_buckets = 60;
    let now = Timestamp::now();

    let up_pts_raw = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.bytes_up as f64);
    let down_pts_raw = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.bytes_down as f64);

    let has_data = up_pts_raw
        .iter()
        .chain(down_pts_raw.iter())
        .any(|p| p.val > 0.0);
    if !has_data {
        ui.label("No traffic data for the past hour.");
        return;
    }

    let max_bytes = up_pts_raw
        .iter()
        .chain(down_pts_raw.iter())
        .map(|p| p.val)
        .fold(0.0, f64::max);
    let (divisor, unit) = determine_byte_unit(max_bytes);

    let up_pts: Vec<TsPoint> = up_pts_raw
        .iter()
        .map(|p| TsPoint {
            x: p.x,
            val: p.val / divisor,
        })
        .collect();
    let down_pts: Vec<TsPoint> = down_pts_raw
        .iter()
        .map(|p| TsPoint {
            x: p.x,
            val: p.val / divisor,
        })
        .collect();

    // Use Option so zero-traffic buckets become dashed gaps.
    let up_opt: Vec<Option<TsPoint>> = up_pts
        .iter()
        .map(|p| if p.val > 0.0 { Some(p.clone()) } else { None })
        .collect();
    let down_opt: Vec<Option<TsPoint>> = down_pts
        .iter()
        .map(|p| if p.val > 0.0 { Some(p.clone()) } else { None })
        .collect();

    let gap_bounds = Some((-WINDOW_SECS_TRF, 0.0));
    let (up_solid, up_gaps) = split_ts_segments(&up_opt, gap_bounds);
    let (down_solid, down_gaps) = split_ts_segments(&down_opt, gap_bounds);

    let up_color = Color32::from_rgb(100, 200, 140);
    let up_color_dim = Color32::from_rgb(60, 120, 80);
    let down_color = Color32::from_rgb(200, 140, 100);
    let down_color_dim = Color32::from_rgb(120, 80, 60);

    const WINDOW_SECS_TRF: f64 = 3600.0;
    let mut plot = egui_plot::Plot::new(format!("detail_traffic_{}", proxy_id))
        .height(160.0)
        .x_axis_formatter(|mark, _| format_age_label(mark.value, WINDOW_SECS_TRF))
        .x_grid_spacer(time_grid_spacer_1h())
        .y_axis_label(unit)
        .set_margin_fraction(egui::Vec2::new(0.0, 0.15));
    if fit {
        plot = plot.reset().auto_bounds(egui::Vec2b::new(true, true));
    } else {
        plot = plot.auto_bounds(egui::Vec2b::new(true, true));
    }
    plot.show(ui, |plot_ui| {
        for (i, seg) in up_solid.into_iter().enumerate() {
            let name = if i == 0 {
                format!("Upload ({})", unit)
            } else {
                format!("up_s_{}", i)
            };
            plot_ui.line(Line::new(name, seg).color(up_color).width(2.0));
        }
        for (i, gap) in up_gaps.into_iter().enumerate() {
            plot_ui.line(
                Line::new(format!("up_g_{}", i), gap)
                    .color(up_color_dim)
                    .width(1.5)
                    .style(LineStyle::Dashed { length: 6.0 }),
            );
        }
        for (i, seg) in down_solid.into_iter().enumerate() {
            let name = if i == 0 {
                format!("Download ({})", unit)
            } else {
                format!("down_s_{}", i)
            };
            plot_ui.line(Line::new(name, seg).color(down_color).width(2.0));
        }
        for (i, gap) in down_gaps.into_iter().enumerate() {
            plot_ui.line(
                Line::new(format!("down_g_{}", i), gap)
                    .color(down_color_dim)
                    .width(1.5)
                    .style(LineStyle::Dashed { length: 6.0 }),
            );
        }
    });
}

fn render_ansi_line(ui: &mut egui::Ui, line: &str) {
    use egui::text::{LayoutJob, TextFormat};
    let mono = egui::FontId::monospace(12.0);
    let default_fg = Color32::from_gray(220);
    let mut job = LayoutJob::default();
    let mut fg = default_fg;
    let mut remaining = line;
    while !remaining.is_empty() {
        match remaining.find('\x1b') {
            Some(0) => {
                if remaining.starts_with("\x1b[") {
                    let rest = &remaining[2..];
                    if let Some(m_pos) = rest.find('m') {
                        let params = &rest[..m_pos];
                        remaining = &rest[m_pos + 1..];
                        for seg in params.split(';') {
                            fg = ansi_sgr_color(seg.trim(), fg, default_fg);
                        }
                        continue;
                    }
                }
                remaining = &remaining[1..];
            }
            Some(esc_pos) => {
                job.append(
                    &remaining[..esc_pos],
                    0.0,
                    TextFormat {
                        font_id: mono.clone(),
                        color: fg,
                        ..Default::default()
                    },
                );
                remaining = &remaining[esc_pos..];
            }
            None => {
                job.append(
                    remaining,
                    0.0,
                    TextFormat {
                        font_id: mono.clone(),
                        color: fg,
                        ..Default::default()
                    },
                );
                break;
            }
        }
    }
    if job.sections.is_empty() {
        ui.label(egui::RichText::new(" ").font(mono));
    } else {
        ui.label(job);
    }
}

fn ansi_sgr_color(code: &str, current: Color32, default_fg: Color32) -> Color32 {
    match code.parse::<u32>().unwrap_or(0) {
        0 => default_fg,
        30 => Color32::from_gray(30),
        31 => Color32::from_rgb(205, 49, 49),
        32 => Color32::from_rgb(13, 188, 121),
        33 => Color32::from_rgb(229, 229, 16),
        34 => Color32::from_rgb(36, 114, 200),
        35 => Color32::from_rgb(188, 63, 188),
        36 => Color32::from_rgb(17, 168, 205),
        37 => Color32::from_gray(229),
        39 => default_fg,
        90 => Color32::from_gray(102),
        91 => Color32::from_rgb(241, 76, 76),
        92 => Color32::from_rgb(35, 209, 139),
        93 => Color32::from_rgb(245, 245, 67),
        94 => Color32::from_rgb(59, 142, 234),
        95 => Color32::from_rgb(214, 112, 214),
        96 => Color32::from_rgb(41, 184, 219),
        97 => Color32::WHITE,
        _ => current,
    }
}

fn format_bytes(bytes: u128) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_mode_bits(mode: Option<u32>) -> String {
    let Some(mode) = mode else {
        return "-".to_string();
    };
    let perms = mode & 0o777;
    let mut text = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let chunk = (perms >> shift) & 0o7;
        text.push(if chunk & 0o4 != 0 { 'r' } else { '-' });
        text.push(if chunk & 0o2 != 0 { 'w' } else { '-' });
        text.push(if chunk & 0o1 != 0 { 'x' } else { '-' });
    }
    format!("{} ({:03o})", text, perms)
}

fn format_uid_gid(uid: Option<u32>, gid: Option<u32>) -> String {
    match (uid, gid) {
        (Some(uid), Some(gid)) => format!("{}:{}", uid, gid),
        (Some(uid), None) => format!("{}:-", uid),
        (None, Some(gid)) => format!("-:{}", gid),
        (None, None) => "-".to_string(),
    }
}

fn format_optional_size(size: Option<u64>) -> String {
    size.map(|bytes| format_bytes(bytes as u128))
        .unwrap_or_else(|| "-".to_string())
}

fn determine_byte_unit(max_bytes: f64) -> (f64, &'static str) {
    if max_bytes < 1024.0 {
        (1.0, "B")
    } else if max_bytes < 1024.0 * 1024.0 {
        (1024.0, "KB")
    } else if max_bytes < 1024.0 * 1024.0 * 1024.0 {
        (1024.0 * 1024.0, "MB")
    } else {
        (1024.0 * 1024.0 * 1024.0, "GB")
    }
}

fn format_namespace_indicator(ns: &supervisor::NamespaceIndicator) -> String {
    let mnt = ns.mnt.as_deref().unwrap_or("?");
    let net = ns.net.as_deref().unwrap_or("?");
    let pid_ns = ns.pid.as_deref().unwrap_or("?");
    format!("mnt={mnt} net={net} pid={pid_ns}")
}

fn render_namespace_badge(ui: &mut egui::Ui, label: &str, value: Option<&str>, accent: Color32) {
    let text = format!("{label} {}", value.unwrap_or("?"));
    ui.label(
        RichText::new(text)
            .small()
            .background_color(accent.linear_multiply(0.18))
            .color(Color32::from_gray(220)),
    );
}

fn render_namespace_indicator_row(
    ui: &mut egui::Ui,
    label: &str,
    pid: Option<i32>,
    ns: Option<&supervisor::NamespaceIndicator>,
    accent: Color32,
) {
    let title = pid
        .map(|pid| format!("{label}[{pid}]"))
        .unwrap_or_else(|| label.to_string());

    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(title).strong().color(accent));
        if let Some(ns) = ns {
            render_namespace_badge(ui, "mnt", ns.mnt.as_deref(), accent);
            render_namespace_badge(ui, "net", ns.net.as_deref(), accent);
            render_namespace_badge(ui, "pid", ns.pid.as_deref(), accent);
        } else {
            ui.label(
                RichText::new("unavailable")
                    .small()
                    .italics()
                    .color(Color32::GRAY),
            );
        }
    });
}

/// Helper to draw a large rectangular selectable box used in the left sidebar.
fn sidebar_box(
    ui: &mut eframe::egui::Ui,
    title: &str,
    subtitle: &str,
    selected: bool,
    status_color: eframe::egui::Color32,
) -> eframe::egui::Response {
    sidebar_box_width(ui, title, subtitle, selected, status_color, None)
}

fn sidebar_box_width(
    ui: &mut eframe::egui::Ui,
    title: &str,
    subtitle: &str,
    selected: bool,
    status_color: eframe::egui::Color32,
    width_override: Option<f32>,
) -> eframe::egui::Response {
    use eframe::egui::{Align2, FontId};

    let desired = ui.available_size_before_wrap();
    let width = width_override.unwrap_or_else(|| desired.x.max(220.0).min(ui.available_width()));
    let size = eframe::egui::vec2(width, 76.0_f32);
    let (rect, resp) = ui.allocate_exact_size(size, eframe::egui::Sense::click());

    let visuals = ui.visuals();
    let bg = if selected {
        // translucent accent when selected
        let sel = visuals.selection.bg_fill;
        eframe::egui::Color32::from_rgba_unmultiplied(sel.r(), sel.g(), sel.b(), 60)
    } else if resp.hovered() {
        let h = visuals.widgets.hovered.bg_fill;
        eframe::egui::Color32::from_rgba_unmultiplied(h.r(), h.g(), h.b(), 30)
    } else {
        eframe::egui::Color32::TRANSPARENT
    };

    // Background only — no border
    ui.painter().rect_filled(rect, 8.0, bg);

    // Avatar circle on the left
    let avatar_radius = 20.0;
    let avatar_center =
        rect.min + eframe::egui::vec2(12.0 + avatar_radius, rect.height() / 2.0 - 2.0);
    let avatar_fill = if selected {
        status_color
    } else {
        status_color.linear_multiply(0.9)
    };
    ui.painter()
        .circle_filled(avatar_center, avatar_radius, avatar_fill);

    // Initial letter inside avatar
    let initial = title
        .chars()
        .next()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "?".to_string());
    ui.painter().text(
        avatar_center,
        Align2::CENTER_CENTER,
        initial,
        FontId::proportional(16.0),
        eframe::egui::Color32::WHITE,
    );

    // Title & subtitle
    let text_x = avatar_center.x + avatar_radius + 12.0;
    let name_pos = eframe::egui::pos2(text_x, rect.min.y + 12.0);
    let status_pos = eframe::egui::pos2(text_x, rect.min.y + 34.0);
    ui.painter().text(
        name_pos,
        Align2::LEFT_TOP,
        title,
        FontId::proportional(16.0),
        visuals.text_color(),
    );
    ui.painter().text(
        status_pos,
        Align2::LEFT_TOP,
        subtitle,
        FontId::proportional(12.0),
        visuals.widgets.inactive.fg_stroke.color,
    );

    // Status dot on the top-right
    let dot_center = rect.right_top() + eframe::egui::vec2(-18.0, 18.0);
    ui.painter().circle_filled(dot_center, 6.0, status_color);

    resp
}

/// Styled section frame for form widget groups: subtle fill, no border, full container width.
fn section_frame<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, 15))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
}

/// Navigation card used in the wizard bottom bar.
/// Looks like a minimal card with a title and a small keyboard-shortcut hint below it.
fn wizard_nav_card(
    ui: &mut egui::Ui,
    title: &str,
    shortcut_hint: &str,
    enabled: bool,
) -> egui::Response {
    use eframe::egui::{Align2, FontId};

    let desired_width = (title.len() as f32 * 9.0 + 32.0).max(120.0).min(240.0);
    let size = egui::vec2(desired_width, 48.0);
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);

    if ui.is_rect_visible(rect) {
        let visuals = ui.visuals();
        let bg = if !enabled {
            egui::Color32::TRANSPARENT
        } else if resp.is_pointer_button_down_on() {
            let c = visuals.selection.bg_fill;
            egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 80)
        } else if resp.hovered() {
            let h = visuals.widgets.hovered.bg_fill;
            egui::Color32::from_rgba_unmultiplied(h.r(), h.g(), h.b(), 40)
        } else {
            egui::Color32::TRANSPARENT
        };
        ui.painter().rect_filled(rect, 6.0, bg);

        let title_color = if enabled {
            visuals.text_color()
        } else {
            egui::Color32::from_gray(80)
        };
        let hint_color = egui::Color32::from_gray(if enabled { 110 } else { 55 });

        ui.painter().text(
            egui::pos2(rect.min.x + 8.0, rect.min.y + 8.0),
            Align2::LEFT_TOP,
            title,
            FontId::proportional(13.0),
            title_color,
        );
        ui.painter().text(
            egui::pos2(rect.min.x + 8.0, rect.min.y + 28.0),
            Align2::LEFT_TOP,
            shortcut_hint,
            FontId::proportional(10.0),
            hint_color,
        );
    }

    resp
}

/// Compact launch card for an Actions application.
/// The application name is the primary label; its container is the subtext.
fn action_app_card(
    ui: &mut egui::Ui,
    app_name: &str,
    container_name: &str,
    enabled: bool,
    launched: bool,
) -> egui::Response {
    use eframe::egui::{Align2, FontId};

    let longest_label = app_name.len().max(container_name.len()) as f32;
    let desired_width = (longest_label * 9.0 + 32.0).max(140.0).min(260.0);
    let size = egui::vec2(desired_width, 56.0);
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);

    if ui.is_rect_visible(rect) {
        let visuals = ui.visuals();
        let bg = if !enabled {
            Color32::from_rgba_unmultiplied(255, 255, 255, 24)
        } else if resp.is_pointer_button_down_on() {
            let c = visuals.selection.bg_fill;
            Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 80)
        } else if resp.hovered() {
            let h = visuals.widgets.hovered.bg_fill;
            Color32::from_rgba_unmultiplied(h.r(), h.g(), h.b(), 40)
        } else {
            Color32::from_rgba_unmultiplied(255, 255, 255, 15)
        };
        ui.painter().rect_filled(rect, 6.0, bg);

        let title_color = if enabled {
            visuals.text_color()
        } else {
            Color32::from_gray(210)
        };
        let subtext_color = Color32::from_gray(if enabled { 130 } else { 170 });
        ui.painter().text(
            egui::pos2(rect.min.x + 10.0, rect.min.y + 10.0),
            Align2::LEFT_TOP,
            app_name,
            FontId::proportional(14.0),
            title_color,
        );
        ui.painter().text(
            egui::pos2(rect.min.x + 10.0, rect.min.y + 32.0),
            Align2::LEFT_TOP,
            container_name,
            FontId::proportional(11.0),
            subtext_color,
        );
        if launched {
            let dot_center = rect.right_top() + egui::vec2(-11.0, 11.0);
            ui.painter()
                .circle_filled(dot_center, 5.0, Color32::LIGHT_GREEN);
        }
    }

    resp
}

/// Try to load a CJK font from common system paths and register it with egui.
fn setup_cjk_font(ctx: &egui::Context) {
    use std::path::Path;

    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);

    // Common Noto CJK / Source Han / WQY font locations across major Linux distros.
    let candidates = [
        // Fedora (google-noto-sans-cjk-fonts)
        "/usr/share/fonts/google-noto-sans-cjk-fonts/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc",
        // Fedora (NotoSansCJK packaged path)
        "/usr/share/fonts/NotoSansCJK/NotoSansCJK-Regular.ttc",
        // Noto Sans CJK (Fedora / RHEL / Arch / Debian / Ubuntu)
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        // SC-only variants (Ubuntu / Debian)
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/noto-cjk/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKsc-Regular.otf",
        // Other Noto Sans CJK variants (JP/KR/TC)
        "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf",
        "/usr/share/fonts/opentype/noto/NotoSansCJKkr-Regular.otf",
        "/usr/share/fonts/opentype/noto/NotoSansCJKtc-Regular.otf",
        "/usr/share/fonts/noto/NotoSansCJKjp-Regular.otf",
        "/usr/share/fonts/noto/NotoSansCJKkr-Regular.otf",
        "/usr/share/fonts/noto/NotoSansCJKtc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKjp-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKkr-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKtc-Regular.otf",
        // Source Han Sans (Adobe)
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Regular.otf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansTC-Regular.otf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansCN-Regular.otf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansJP-Regular.otf",
        "/usr/share/fonts/opentype/source-han-sans/SourceHanSansKR-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansSC-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansTC-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansCN-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansJP-Regular.otf",
        "/usr/share/fonts/adobe-source-han-sans/SourceHanSansKR-Regular.otf",
        // Droid / fallback CJK fonts
        "/usr/share/fonts/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/google-droid-sans-fonts/DroidSansFallbackFull.ttf",
        // WenQuanYi Micro Hei – very widely available
        "/usr/share/fonts/wqy-microhei/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        // WenQuanYi Zen Hei
        "/usr/share/fonts/wqy-zenhei/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    ];

    let existing = candidates
        .iter()
        .copied()
        .filter(|path| {
            Path::new(path)
                .metadata()
                .map(|m| m.is_file())
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    for path in existing {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
            // Append after the built-in proportional fonts so Latin glyphs stay sharp.
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push("cjk".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

fn configure_ui_context(cc: &eframe::CreationContext<'_>) {
    setup_cjk_font(&cc.egui_ctx);
    // Set every text style to 16px for consistent sizing.
    cc.egui_ctx.style_mut_of(cc.egui_ctx.theme(), |style| {
        for ts in &[
            egui::TextStyle::Heading,
            egui::TextStyle::Body,
            egui::TextStyle::Monospace,
            egui::TextStyle::Button,
            egui::TextStyle::Small,
        ] {
            style
                .text_styles
                .insert(ts.clone(), egui::FontId::proportional(16.0));
        }
    });
}

fn run_manual_loop() -> Result<(), Box<dyn std::error::Error>> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "nsproxy - dashboard",
        native_options,
        Box::new(|cc| {
            let ctx = cc.egui_ctx.clone();
            configure_ui_context(cc);
            Ok(Box::new(App::new(ctx)))
        }),
    )
    .map_err(|err| err.into())
}

fn protocol_build_hash(args: &UiCli) -> String {
    args.build_hash
        .clone()
        .unwrap_or_else(nsproxy_core::build_identity)
}

fn main() {
    let args = UiCli::parse();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .try_init();

    let protocol_build_hash = protocol_build_hash(&args);
    diag::set_protocol_version(protocol_build_hash.clone());
    diag::set_protocol_lenient(args.lenient);

    if let Some(control_fd) = args.term_window_fd {
        if let Err(err) = run_term_window_process(control_fd) {
            tracing::error!(%err, "terminal child process failed");
            std::process::exit(1);
        }
        return;
    }

    info!(build_hash = %protocol_build_hash, lenient = args.lenient, "starting nsproxy-ui");
    info!("launching ui event loop");
    if let Err(err) = run_manual_loop() {
        tracing::error!(%err, "ui event loop failed");
        std::process::exit(1);
    }
}
