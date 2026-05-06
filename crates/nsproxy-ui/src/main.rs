use diag::{LogEntry, Timestamp};
use eframe::egui;
use eframe::egui::Color32;
use egui::{RichText, Vec2};
use egui_code_editor::{CodeEditor, ColorTheme, Syntax};
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular;
use egui_plot::{GridInput, GridMark, Line, LineStyle, PlotPoints};
use clap::Parser;
use nsproxy_common::crdt::CRDT;
use nsproxy_common::normalize_domain;
use nsproxy_common::routing::ProxyID;
use nsproxy_common::stats::ProxyStats;
use nsproxy_core::sandbox::SandboxStatus;
use nsproxy_core::shell::ShellArgs;
use nsproxy_core::state_blueprint::PersistentState as _;
use nsproxy_core::uplink::clash::{ClashState, GroupId};
use nsproxy_core::uplink::{
    uplink_proxy_default_udp_expected, UplinkHub, UplinkProxy, UplinkStatsState,
};
use nsproxy_core::personal::PersonalConstants;
use nsproxy_core::{
    state_paths, HotConfig, NsAlive, ProfileChmod, ProfileMount, SandboxMode, TemplateConfig,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tracing::info;
use tracing_subscriber::EnvFilter;
use twox_hash::XxHash3_64;
use which;

mod alacritty_window;
mod personal;
mod profile_loader;
mod supervisor;

use alacritty_window::{run_term_window_process, ExternalTermWindowClient};
use profile_loader::ProfileInfo;
use supervisor::{
    ContainerName, EditorStatus, LogSource, RenderedLogEntry, SupervisorCommand,
    SupervisorHandle,
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

#[derive(Clone, Debug)]
enum RoutingMode {
    Simple { selected_proxy: Option<String> },
    Unknown,
}

impl RoutingMode {
    fn selected_proxy(&self) -> Option<&str> {
        match self {
            RoutingMode::Simple { selected_proxy } => selected_proxy.as_deref(),
            RoutingMode::Unknown => None,
        }
    }
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::Unknown
    }
}

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

struct ProxySnapshot {
    proxies: BTreeMap<ProxyID, ProxyItem>,
    nym_to_id: BTreeMap<String, ProxyID>,
    proxy_groups: BTreeMap<ProxyID, HashSet<GroupId>>,
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
    Actions,
    Processes,
    Traffic,
    Hotconfig,
    ProfileEditor,
}

/// Sub-view toggle inside the Traffic tab.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
enum TrafficSubview {
    #[default]
    Connections,
    Logs,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
enum LogMinLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
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
    selected_groups: HashSet<GroupId>,
    selected_types: HashSet<ProxyType>,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    sort_frequency: SortFrequency,
}

impl Default for ProxyFilters {
    fn default() -> Self {
        ProxyFilters {
            selected_groups: HashSet::new(),
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
                let resp = ui.add(egui::TextEdit::singleline(input).id_source(text_edit_id));
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
    proxies: BTreeMap<ProxyID, ProxyItem>,
    nym_to_id: BTreeMap<String, ProxyID>,
    proxy_groups: BTreeMap<ProxyID, HashSet<GroupId>>,
    filtered_proxy_ids: Vec<ProxyID>,
    filters_dirty: bool,
    hovered_proxy: Option<usize>,
    reload_tx: flume::Sender<()>,
    proxy_rx: flume::Receiver<ProxySnapshot>,
    proxy_filters: ProxyFilters,
    all_groups: HashSet<GroupId>,
    supervisor: SupervisorHandle,
    personal_state: personal::PersonalUiState,
    snapshot: supervisor::SupervisorSnapshot,
    run_command: RunCommandDraft,
    int_input: IntInput,
    hide_secret: bool,
    cover_text: String,
    tokio_rt: Option<Runtime>,
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
    selected_traffic_conn: Option<diag::ConnId>,
    traffic_subview: TrafficSubview,
    traffic_subscription_profile: Option<ContainerName>,
    /// Which process's raw logs are currently being inspected (profile, slot-pid).
    selected_process_logs: Option<(ContainerName, u32)>,
    /// State for the special swap terminal child process, if any.
    swap_term_window: ExternalTermWindowClient,
    /// Dedicated PTY windows keyed by their owning (profile, slot-pid).
    dedicated_term_windows: HashMap<(ContainerName, u32), ExternalTermWindowClient>,
    /// Last consumed auto-open token from supervisor snapshots.
    last_auto_open_logs_token: u64,
    /// Which process's SpawnArgs are currently being inspected (profile, slot-pid).
    selected_process_spawn_args: Option<(ContainerName, u32)>,
    raw_log_show_details: bool,
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
    /// ANSI-render cache for raw process logs keyed by a fast collision-tolerant hash.
    cached_log: HashMap<u64, Vec<egui::RichText>>,
    log_panel_min_level: LogMinLevel,
}

fn fast_hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = XxHash3_64::default();
    value.hash(&mut hasher);
    hasher.finish()
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
        };
    }

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
        let groups: HashSet<GroupId> = clash_state
            .proxy_group
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
        proxy_groups: clash_state.proxy_group,
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

    pub fn new(ectx: egui::Context) -> Self {
        info!("initializing nsproxy-ui app state");
        let snapshot = load_proxies_from_persisted();
        let proxies = snapshot.proxies.clone();
        let nym_to_id = snapshot.nym_to_id.clone();
        let proxy_groups = snapshot.proxy_groups.clone();

        // Collect all groups from all proxies
        let mut all_groups = HashSet::new();
        for groups in snapshot.proxies.values() {
            all_groups.extend(groups.groups.iter().cloned());
        }

        let filtered_proxy_ids: Vec<ProxyID> = snapshot.proxies.keys().cloned().collect();

        // Background reload: caller sends () to trigger a reload on a worker thread.
        let (reload_tx, reload_rx) = flume::bounded::<()>(1);
        let (proxy_tx, proxy_rx) = flume::bounded::<ProxySnapshot>(1);
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
        Self {
            selected_profile: None,
            remove_containers_armed: false,
            right_tab: RightTab::Proxies,
            proxies,
            nym_to_id,
            proxy_groups,
            filtered_proxy_ids,
            filters_dirty: false,
            hovered_proxy: None,
            reload_tx,
            proxy_rx,
            proxy_filters: ProxyFilters::default(),
            all_groups,
            supervisor,
            personal_state,
            snapshot: supervisor::SupervisorSnapshot {
                profiles: BTreeMap::new(),
                ui_ns: supervisor::NamespaceIndicator::default(),
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
            hotconfig_editor_value: HotConfig::default(),
            hotconfig_editor_json: default_hotconfig_text(),
            hotconfig_editor_error: None,
            hotconfig_editor_status: None,
            selected_traffic_conn: None,
            traffic_subview: TrafficSubview::default(),
            traffic_subscription_profile: None,
            selected_process_logs: None,
            swap_term_window: ExternalTermWindowClient::default(),
            dedicated_term_windows: HashMap::new(),
            last_auto_open_logs_token: 0,
            selected_process_spawn_args: None,
            raw_log_show_details: false,
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
            cached_log: HashMap::new(),
            log_panel_min_level: LogMinLevel::default(),
        }
    }

    fn right_tab_label(&self) -> &'static str {
        match self.right_tab {
            RightTab::Proxies => "Proxies",
            RightTab::Daemon => "Daemon",
            RightTab::Actions => "Actions",
            RightTab::Processes => "Processes",
            RightTab::Traffic => "Traffic",
            RightTab::Hotconfig => "Hotconfig",
            RightTab::ProfileEditor => "ProfileEditor",
        }
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
        text_edit = text_edit.frame(true);
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
        text_edit = text_edit.frame(true);
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
        text_edit = text_edit.frame(true);
        let visuals = ui.visuals_mut();
        let old_bg = visuals.extreme_bg_color;
        visuals.extreme_bg_color = bg_color;
        let response = ui.add(text_edit);
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
                self.hotconfig_editor_value = HotConfig::default();
            }
        } else {
            self.hotconfig_editor_value = HotConfig::default();
        }
        self.hotconfig_editor_json = serde_json::to_string_pretty(&self.hotconfig_editor_value)
            .unwrap_or_else(|_| "{}".to_string());
    }

    fn save_hotconfig_editor(&mut self) {
        let Some(profile_name) = self.selected_profile.clone() else {
            self.hotconfig_editor_status = Some("Select a profile to save hotconfig.".to_string());
            return;
        };

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
                if ui.text_edit_singleline(text).changed() {
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
        id_salt: impl std::hash::Hash,
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

    fn render_mount_list(ui: &mut egui::Ui, mounts: &mut Vec<ProfileMount>, title: &str) -> bool {
        let mut changed = false;
        ui.group(|ui| {
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
                    ui.separator();
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
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong("chmod");
                if ui.button("+ Add").clicked() {
                    chmod.push(ProfileChmod {
                        path: "/".into(),
                        mode: None,
                        uid: None,
                        gid: None,
                        mkdir: false
                    });
                    changed = true;
                }
            });

            let mut remove_ixs = Vec::new();
            for (i, op) in chmod.iter_mut().enumerate() {
                ui.push_id(("chmod-row", i), |ui| {
                    ui.separator();
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

        ui.group(|ui| {
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

        ui.group(|ui| {
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

        ui.group(|ui| {
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

        ui.group(|ui| {
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
        ui.group(|ui| {
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
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", i + 1));
                        if ui.button("Remove").clicked() {
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

    fn render_hotconfig_form(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        id_prefix: &str,
        hot: &mut HotConfig,
    ) -> bool {
        let mut changed = false;

        if Self::render_string_map(ui, "dns", &mut hot.dns, id_prefix) {
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
        if Self::render_mount_list(ui, &mut hot.mounts, "mounts") {
            changed = true;
        }
        if Self::render_shell_args_list(ui, int_input, &mut hot.daemons, id_prefix) {
            changed = true;
        }

        ui.group(|ui| {
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

        changed
    }

    fn render_hotconfig_editor_split(
        ui: &mut egui::Ui,
        int_input: &mut IntInput,
        id_prefix: &str,
        hot: &mut HotConfig,
        json_text: &mut String,
        json_error: &mut Option<String>,
    ) -> bool {
        let mut changed = false;
        ui.columns(2, |columns| {
            columns[0].heading("Form");
            egui::ScrollArea::vertical()
                .id_salt(format!("{}-form-scroll", id_prefix))
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
                .show(&mut columns[1], |ui| {
                    let mut editor = CodeEditor::default()
                        .id_source(format!("{}-json-editor", id_prefix))
                        .with_rows(28)
                        .with_theme(ColorTheme::GRUVBOX)
                        .with_syntax(json_syntax())
                        .with_numlines(true)
                        .with_ui_fontsize(ui);
                    let output = editor.show(ui, json_text);
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
        ui.group(|ui| {
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

            let mut args_text = sargs.args.join(" ");
            ui.horizontal(|ui| {
                ui.label("args");
                if ui.text_edit_singleline(&mut args_text).changed() {
                    sargs.args = args_text
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    changed = true;
                }
            });
        });
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
        ui.group(|ui| {
            ui.strong("SpawnArgs");

            if read_only {
                ui.label(format!("uid: {:?}", args.uid));
                ui.label(format!("gid: {:?}", args.gid));
                ui.label(format!("exec: {:?}", args.exec));
                ui.label(format!("cwd: {:?}", args.cwd));
                ui.label(format!("gids: {:?}", args.gids));
                ui.label(format!("ringbuf_size: {:?}", args.ringbuf_size));
                ui.label("argv:");
                for (i, arg) in args.args.iter().enumerate() {
                    ui.monospace(format!("  [{i}] {arg}"));
                }
                return;
            }

            // track if we programmatically changed uid/gid so input buffers sync
            let mut uid_gid_value_changed = false;
            ui.horizontal(|ui| {
                if ui.button("default user").clicked() {
                    apply_default_spawn_user(args);
                    changed = true;
                    uid_gid_value_changed = true;
                }
                if ui.button("root").clicked() {
                    args.uid = Some(0);
                    args.gid = Some(0);
                    args.gids = vec![];
                    changed = true;
                    uid_gid_value_changed = true;
                }
            });

            if Self::render_optional_u32(ui, int_input, "uid", &mut args.uid, uid_gid_value_changed)
            {
                changed = true;
            }
            if Self::render_optional_u32(ui, int_input, "gid", &mut args.gid, uid_gid_value_changed)
            {
                changed = true;
            }
            if Self::render_optional_text(ui, "exec", &mut args.exec) {
                changed = true;
            }

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
                if enabled && ui.text_edit_singleline(&mut cwd_text).changed() {
                    args.cwd = Some(std::path::PathBuf::from(cwd_text.clone()));
                    changed = true;
                }
            });

            let mut gids_csv = args
                .gids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            ui.horizontal(|ui| {
                ui.label("gids csv");
                if ui.text_edit_singleline(&mut gids_csv).changed() {
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

            ui.label("argv (args)");
            let mut remove_ix: Option<usize> = None;
            for i in 0..args.args.len() {
                ui.horizontal(|ui| {
                    ui.label(format!("[{i}]"));
                    if ui.text_edit_singleline(&mut args.args[i]).changed() {
                        changed = true;
                    }
                    if ui.small_button("x").clicked() {
                        remove_ix = Some(i);
                    }
                });
            }
            if let Some(ix) = remove_ix {
                args.args.remove(ix);
                changed = true;
            }
            if ui.button("+ Add arg").clicked() {
                args.args.push(String::new());
                changed = true;
            }

            if args.args.is_empty() {
                ui.colored_label(
                    Color32::from_rgb(220, 170, 90),
                    "argv is empty; argv[0] is typically the executable name",
                );
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
                        .clamp_range(1..=u32::MAX),
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
        ui.group(|ui| {
            let mut enabled = self.profile_editor_template.hot_init.is_some();
            if ui.checkbox(&mut enabled, "hot_init").changed() {
                changed = true;
                if enabled && self.profile_editor_template.hot_init.is_none() {
                    self.profile_editor_template.hot_init = Some(HotConfig::default());
                    refresh_hot_init_json = true;
                }
                if !enabled {
                    self.profile_editor_template.hot_init = None;
                    self.profile_editor_hot_init_error = None;
                }
            }

            if enabled {
                ui.separator();
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

                // Filter by groups if any groups are selected
                if !self.proxy_filters.selected_groups.is_empty() {
                    if !item
                        .groups
                        .iter()
                        .any(|g| self.proxy_filters.selected_groups.contains(g))
                    {
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
    serde_json::to_string_pretty(&HotConfig::default()).unwrap_or_else(|_| "{}".to_string())
}

fn default_profile_text() -> String {
    serde_json::to_string_pretty(&TemplateConfig::default()).unwrap_or_else(|_| "{}".to_string())
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
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => {
            return LoadResult {
                text: fallback.map_or_else(|| default_profile_text(), |f| f()),
                error: None,
            };
        }
    };
    match serde_json::from_str::<TemplateConfig>(&content) {
        Ok(parsed) => LoadResult {
            text: serde_json::to_string_pretty(&parsed).unwrap_or(content),
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

fn routing_mode_from_diag(state: &diag::RoutingState) -> RoutingMode {
    RoutingMode::Simple {
        selected_proxy: state.selected_proxy.as_ref().map(|p| p.nym().to_string()),
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        use egui::Color32;

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
            self.nym_to_id = updated.nym_to_id.clone();
            self.proxy_groups = updated.proxy_groups.clone();

            // Collect all groups from all proxies
            self.all_groups.clear();
            for item in self.proxies.values() {
                self.all_groups.extend(item.groups.iter().cloned());
            }

            // Reapply filters with new data
            self.apply_filters();
        }

        // Update snapshot from supervisor (single source of truth)
        let mut drained_snapshots = 0usize;
        while let Some(snapshot) = self.supervisor.try_recv_snapshot() {
            drained_snapshots += 1;
            self.snapshot = snapshot;
        }
        if drained_snapshots > 0 {
            if let Some(target) = self.snapshot.auto_open_logs_target.as_ref() {
                if target.token > self.last_auto_open_logs_token {
                    self.selected_process_logs = Some((target.profile.clone(), target.pid));
                    self.request_process_logs(&target.profile, target.pid);
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
                self.selected_process_logs = None;
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
            && !ctx.wants_keyboard_input()
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

        egui::SidePanel::left("left_sidebar")
            .resizable(false)
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.heading("Containers");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if Self::refresh_button(ui, "Reload all container status").clicked() {
                            self.reload_all_ns_alive();
                        }
                    });
                });

                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.toggle_value(&mut self.remove_containers_armed, "remove containers")
                        .on_hover_text("Enable Ctrl+D to remove the selected container");
                });

                ui.add_space(6.0);

                // Global configuration box at the top
                let global_selected = self.selected_profile.is_none();
                let global_status_color = egui::Color32::from_rgb(100, 150, 240);
                if sidebar_box(ui, "all", "", global_selected, global_status_color).clicked() {
                    self.selected_profile = None;
                }

                ui.add_space(6.0);
                // Profiles
                if self.snapshot.profiles.is_empty() {
                    ui.label(egui::RichText::new("No profiles found").color(egui::Color32::GRAY));
                    ui.small(format!(
                        "Create profiles in {}",
                        state_paths::persist_root().display()
                    ));
                } else {
                    for (profile_name, profile_snapshot) in &self.snapshot.profiles {
                        let is_selected = self.selected_profile.as_ref() == Some(profile_name);

                        let running = profile_snapshot.container_lifecycle.is_active()
                            || profile_snapshot.serve_alive;

                        let status_color = if running {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::LIGHT_RED
                        };
                        let status_text = match profile_snapshot.container_lifecycle {
                            supervisor::ContainerLifecycleState::Stopped => "stopped",
                            supervisor::ContainerLifecycleState::Starting => "starting",
                            supervisor::ContainerLifecycleState::Running => "running",
                            supervisor::ContainerLifecycleState::Stopping { .. } => "stopping",
                            supervisor::ContainerLifecycleState::Killing { .. } => "killing",
                        };

                        if sidebar_box(
                            ui,
                            profile_name.as_str(),
                            status_text,
                            is_selected,
                            status_color,
                        )
                        .clicked()
                        {
                            self.selected_profile = Some(profile_name.clone());
                            self.supervisor
                                .send(supervisor::SupervisorCommand::LoadProfile(
                                    profile_name.clone(),
                                ));
                        }
                        ui.add_space(6.0);
                    }
                }

                ui.add_space(6.0);

                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Namespaces")
                                .small()
                                .strong()
                                .color(egui::Color32::GRAY),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if Self::refresh_button(ui, "Refresh namespace view").clicked() {
                                self.supervisor.send(SupervisorCommand::RefreshNamespaces);
                            }
                        });
                    });

                    ui.add_space(4.0);

                    render_namespace_indicator_row(
                        ui,
                        "UI",
                        Some(std::process::id() as i32),
                        Some(&self.snapshot.ui_ns),
                        Color32::from_rgb(100, 150, 240),
                    );

                    if let Some(profile_name) = &self.selected_profile {
                        if let Some(profile_snapshot) = self.snapshot.profiles.get(profile_name) {
                            let up_pid = profile_snapshot
                                .ns_alive
                                .as_ref()
                                .and_then(|ns| ns.up_pid)
                                .map(|p| p as i32);
                            let child_pid = profile_snapshot
                                .ns_alive
                                .as_ref()
                                .and_then(|ns| ns.child_pid)
                                .map(|p| p as i32);

                            if let Some(pid) = up_pid {
                                ui.add_space(4.0);
                                render_namespace_indicator_row(
                                    ui,
                                    "up",
                                    Some(pid),
                                    profile_snapshot.up_ns.as_ref(),
                                    Color32::from_rgb(120, 200, 140),
                                );
                            }
                            if let Some(pid) = child_pid {
                                ui.add_space(4.0);
                                render_namespace_indicator_row(
                                    ui,
                                    "keeper",
                                    Some(pid),
                                    profile_snapshot.keeper_ns.as_ref(),
                                    Color32::from_rgb(220, 180, 90),
                                );
                            }
                            if up_pid.is_none() && child_pid.is_none() {
                                ui.label(
                                    egui::RichText::new("Selected profile has no live pid yet")
                                        .small()
                                        .color(Color32::GRAY),
                                );
                            }
                        }
                    } else {
                        ui.label(
                            egui::RichText::new("Select a profile to compare its namespace state")
                                .small()
                                .color(Color32::GRAY),
                        );
                    }
                });

                // minimal dev-only frame info intentionally omitted here
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Tabs
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

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            let scroll_id = format!("right_tab_panel_scroll_{}", self.right_tab_label());
            egui::ScrollArea::vertical()
                .id_salt(scroll_id)
                .auto_shrink([false, false])
                .show(ui, |ui| match self.right_tab {
                    RightTab::Proxies => self.render_proxies_tab(ui),
                    RightTab::Daemon => self.render_daemon_tab(ui),
                    RightTab::Actions => personal::render_actions_tab(self, ui),
                    RightTab::Processes => self.render_processes_tab(ui),
                    RightTab::Traffic => self.render_traffic_tab(ui),
                    RightTab::Hotconfig => self.render_hotconfig_tab(ui),
                    RightTab::ProfileEditor => self.render_profile_editor_tab(ui),
                });
        });

        self.render_external_pty_window(ctx);
        self.render_proxy_detail_window(ctx);

        // Minimal dev-only watermark at bottom-left: non-intrusive, low-contrast
        egui::Area::new(egui::Id::new("dev_frame_watermark"))
            .anchor(egui::Align2::LEFT_BOTTOM, egui::Vec2::new(8.0, -8.0))
            .movable(false)
            .show(ctx, |ui| {
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
                        egui::RichText::new(format!("{}ms  {:.1}fps", self.last_frame_elapsed_ms, fps))
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

        // Routing mode selector
        ui.horizontal(|ui| {
            ui.label("Routing Mode:");
            if ui.selectable_label(true, "Simple").clicked() {
                // Simple routing is current default
            }
            if ui.selectable_label(false, "Group").clicked() {
                // Group routing will be implemented in future
            }
        });
        ui.add_space(4.0);

        self.render_selected_proxy_summary(ui);
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        self.render_proxy_filters(ui);
        if self.filters_dirty {
            self.apply_filters();
            self.filters_dirty = false;
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        self.render_proxies_table(ui);
        ui.add_space(8.0);
    }

    fn render_selected_proxy_summary(&self, ui: &mut egui::Ui) {
        if let Some(profile_name) = &self.selected_profile {
            if let Some(profile) = self.snapshot.profiles.get(profile_name) {
                ui.horizontal(|ui| {
                    ui.label("Selected:");
                    if let Some(routing) = &profile.routing_state {
                        if let Some(proxy_id) = &routing.selected_proxy {
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
            if !self.proxy_filters.selected_types.is_empty()
                || !self.proxy_filters.selected_groups.is_empty()
            {
                if ui.button("Clear Filters").clicked() {
                    self.proxy_filters.selected_types.clear();
                    self.filters_dirty = true;
                }
            }
        });

        if !self.all_groups.is_empty() {
            ui.label("Group Filter:");
            ui.horizontal_wrapped(|ui| {
                for group in self.all_groups.iter() {
                    let is_selected = self.proxy_filters.selected_groups.contains(group);
                    if ui.selectable_label(is_selected, group.as_str()).clicked() {
                        if is_selected {
                            self.proxy_filters.selected_groups.remove(group);
                        } else {
                            self.proxy_filters.selected_groups.insert(group.clone());
                        }
                        self.filters_dirty = true;
                    }
                }
                if ui.button("Clear Filters").clicked() {
                    self.proxy_filters.selected_groups.clear();
                    self.filters_dirty = true;
                }
            });
        }

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

        if self.proxy_filters.sort_column != SortColumn::None {
            ui.label(format!(
                "Current sort: {:?} ({:?})",
                self.proxy_filters.sort_column, self.proxy_filters.sort_direction
            ));
        }
    }

    fn render_proxies_table(&mut self, ui: &mut egui::Ui) {
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

                        body.rows(row_h, self.filtered_proxy_ids.len(), |mut row| {
                            let i = row.index();
                            if i >= self.filtered_proxy_ids.len() {
                                return;
                            }

                            self.render_proxy_row(
                                &mut row,
                                i,
                                row_width,
                                selected_proxy_id.as_ref(),
                                &live_stats,
                                &mut next_hovered_proxy,
                            );
                        });
                    });
            });

        self.hovered_proxy = next_hovered_proxy;
    }

    fn render_proxy_row(
        &mut self,
        row: &mut egui_extras::TableRow,
        i: usize,
        row_width: f32,
        selected_proxy_id: Option<&ProxyID>,
        live_stats: &HashMap<ProxyID, ProxyStats>,
        next_hovered: &mut Option<usize>,
    ) {
        let proxy_id = match self.filtered_proxy_ids.get(i) {
            Some(id) => id.clone(),
            None => return,
        };

        let proxy_item = match self.proxies.get(&proxy_id) {
            Some(item) => item.clone(),
            None => return,
        };

        let stats = live_stats.get(&proxy_id);

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
        let is_selected = selected_proxy_id.map(|id| id == &proxy_id).unwrap_or(false);

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
                        let expanded = self.expanded_ip_rows.contains(&proxy_id);
                        let toggle = if expanded { "IPs ▾" } else { "IPs ▸" };
                        if ui.small_button(toggle).clicked() {
                            if expanded {
                                self.expanded_ip_rows.remove(&proxy_id);
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
                render_mini_sparkline(ui, proxy_stats, &proxy_id);
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
            ui.heading(format!("Processes - {}", profile_name.as_str()));
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
    ) {
        egui::Frame::none()
            .fill(Color32::from_gray(18))
            .stroke(egui::Stroke::new(1.0, Color32::from_gray(60)))
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
                                ui.selectable_value(
                                    log_panel_min_level,
                                    level,
                                    level.label(),
                                );
                            }
                        });
                    ui.add_space(8.0);
                    ui.colored_label(
                        Color32::from_gray(130),
                        format!("showing {} / {}", total, total_entries),
                    );
                });

                ui.add_space(6.0);

                let row_h = ui.text_style_height(&egui::TextStyle::Body);

                egui::ScrollArea::both()
                    .id_salt(format!("log_panel_{}", panel_id))
                    .max_height(500.0)
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, total, |ui, row_range| {
                        if total_entries == 0 {
                            ui.colored_label(Color32::from_gray(110), empty_message);
                            return;
                        }

                        if entries.is_empty() {
                            ui.colored_label(Color32::from_gray(110), no_level_message);
                            return;
                        }

                        let mut row_index = row_range.start;
                        while row_index < row_range.end {
                            let Some(entry) = entries.get(row_index) else {
                                break;
                            };
                            let (badge_text, badge_color) = match entry.entry.src {
                                LogSource::Serve => ("serve", Color32::from_rgb(100, 180, 130)),
                                LogSource::Up => ("up", Color32::from_rgb(100, 150, 210)),
                                LogSource::RootDaemon => {
                                    ("daemon", Color32::from_rgb(210, 140, 90))
                                }
                                LogSource::Pid(_) => ("pid", Color32::from_rgb(140, 140, 220)),
                            };
                            ui.horizontal(|ui| {
                                ui.colored_label(badge_color, badge_text);

                                let level_color = match entry.entry.log.level.as_str() {
                                    "ERROR" => Color32::from_rgb(220, 80, 80),
                                    "WARN" => Color32::from_rgb(210, 160, 60),
                                    "DEBUG" | "TRACE" => Color32::from_gray(120),
                                    _ => Color32::from_gray(200),
                                };
                                ui.colored_label(level_color, &entry.entry.log.level);

                                ui.colored_label(
                                    Color32::from_gray(100),
                                    format!("[{}]", entry.entry.log.target),
                                );

                                for part in entry.ansi_parts.iter() {
                                    ui.label(part.clone());
                                }
                                for field in &entry.entry.log.fields {
                                    ui.add_space(6.0);
                                    ui.colored_label(
                                        Color32::from_gray(110),
                                        format!("{}=", field.name),
                                    );
                                    ui.monospace(&field.value);
                                }
                            });
                            row_index += 1;
                        }
                    });
            });
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

        Self::render_structured_log_panel(
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
        );

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
            ));

        ui.horizontal(|ui| {
            let spacing = ui.spacing().item_spacing.x;
            let width_each = (ui.available_width() - spacing).max(0.0) / 2.0;

            let up_disabled = !up_running && template_error.is_some();
            let up_subtitle = if up_disabled {
                template_error.as_deref().unwrap_or("invalid").to_string()
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
            let up_title = match container_lifecycle {
                supervisor::ContainerLifecycleState::Stopped => "Start Container",
                supervisor::ContainerLifecycleState::Starting
                | supervisor::ContainerLifecycleState::Running => "Restart Container",
                supervisor::ContainerLifecycleState::Stopping { .. }
                | supervisor::ContainerLifecycleState::Killing { .. } => "Kill Container",
            };
            let up_color = if up_disabled {
                egui::Color32::from_rgb(160, 80, 80)
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
                match container_lifecycle {
                    supervisor::ContainerLifecycleState::Stopped => {
                        info!(
                            profile = profile_name.as_str(),
                            "ui clicked Start Container"
                        );
                        self.supervisor.send(SupervisorCommand::StartUp {
                            profile: profile_name.clone(),
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
            Self::render_structured_log_panel(
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
            );
        } else {
            Self::render_structured_log_panel(
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
            );
        }

        self.log_panel_min_level = log_panel_min_level;
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

        egui::Frame::none()
            .fill(Color32::from_gray(16))
            .stroke(egui::Stroke::new(1.0, Color32::from_gray(55)))
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
                            if cli_meta.is_serve {
                                "serve"
                            } else {
                                "spawncli"
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
            ui.label("No daemon processes reported by sp up.");
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
            .column(Column::auto()) // Profile
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
                    ui.strong("Profile");
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
                            ui.label(row_profile.as_str());
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
                                let prog = if cli_meta.is_serve {
                                    "sp serve".to_string()
                                } else {
                                    "sp spawncli".to_string()
                                };
                                (format!("[output] {}", prog), "-".to_string())
                            }
                        };

                        row.col(|ui| {
                            ui.label(&prog);
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

                        // Logs button
                        row.col(|ui| {
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
            self.selected_process_logs = Some((profile.clone(), pid));
            self.request_process_logs(&profile, pid);
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
                let program = if cli_meta.is_serve {
                    "sp-serve".to_string()
                } else {
                    "sp-spawncli".to_string()
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

        ui.add_space(8.0);
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.heading(format!("Output — PID {slot_pid}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    self.selected_process_logs = None;
                    return;
                }
                if Self::refresh_button(ui, "Refresh").clicked() {
                    self.request_process_logs(&profile, slot_pid);
                }
                let details_label = if self.raw_log_show_details {
                    "Hide details"
                } else {
                    "Details"
                };
                if ui.small_button(details_label).clicked() {
                    self.raw_log_show_details = !self.raw_log_show_details;
                }
            });
        });

        let show_details = self.raw_log_show_details;
        let logs_guard = self
            .snapshot
            .profiles
            .get(&profile)
            .map(|p| p.process_raw_logs.read().unwrap_or_else(|e| e.into_inner()));
        let cached_log = &mut self.cached_log;

        egui::Frame::none()
            .fill(Color32::from_gray(15))
            .stroke(egui::Stroke::new(1.0, Color32::from_gray(55)))
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_size(egui::Vec2::new(ui.available_width(), 200.0));
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                let total = logs_guard
                    .as_ref()
                    .and_then(|logs| logs.get(&slot_pid).map(Vec::len))
                    .unwrap_or(0);
                egui::ScrollArea::vertical()
                    .id_salt(format!("raw_logs_{}_{}", profile, slot_pid))
                    .max_height(400.0)
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show_rows(ui, row_h, total, |ui, row_range| {
                        if total == 0 {
                            ui.colored_label(
                                Color32::from_gray(100),
                                "no output captured yet — click Refresh",
                            );
                            return;
                        }
                        for i in row_range {
                            let Some(entry) = logs_guard
                                .as_ref()
                                .and_then(|logs| logs.get(&slot_pid))
                                .and_then(|logs| logs.get(i))
                            else {
                                continue;
                            };
                            ui.horizontal(|ui| {
                                if show_details {
                                    ui.colored_label(
                                        Color32::from_gray(90),
                                        format_timestamp_age(entry.ts),
                                    );
                                    // Stream badge
                                    let (badge, badge_color) = match entry.kind {
                                        diag::RawLogKind::Stdout => {
                                            ("out", Color32::from_rgb(140, 200, 140))
                                        }
                                        diag::RawLogKind::Stderr => {
                                            ("err", Color32::from_rgb(220, 130, 80))
                                        }
                                    };
                                    ui.colored_label(badge_color, badge);
                                };
                                cached_log
                                    .entry(fast_hash_value(&entry.content))
                                    .or_insert_with(|| egui_sgr::ansi_to_rich_text(&entry.content));
                                if let Some(ansi_parts) = cached_log.get(&fast_hash_value(&entry.content)) {
                                    for part in ansi_parts {
                                        ui.label(part.clone());
                                    }
                                }
                            });
                        }
                    });
            });
    }

    fn render_run_command_section(&mut self, ui: &mut egui::Ui, profile: &ContainerName) {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.heading("Run Command (POSIX compatible command line)");
            ui.add_space(10.0);
            if ui.button("Run").clicked() {
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
                } else {
                    refresh_run_command_preview(&mut self.run_command);
                    self.run_command.status = None;
                }
            }
        });

        let response = ui.text_edit_singleline(&mut self.run_command.command_line);
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
                    self.run_command.status = Some("Output-mode spawn request sent".to_string());
                }
                self.run_command.parse_error = None;
            } else if response.lost_focus() {
                refresh_run_command_preview(&mut self.run_command);
                self.run_command.status = None;
            }
        }

        let ns_toggled = ui
            .checkbox(
                &mut self.run_command.spawn_inside_container,
                "Spawn inside container namespace",
            )
            .changed();

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

        if let Some(err) = self.run_command.parse_error.as_ref() {
            ui.colored_label(Color32::LIGHT_RED, err);
        }
        if let Some(status) = self.run_command.status.as_ref() {
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
    }

    fn render_traffic_tab(&mut self, ui: &mut egui::Ui) {
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
            ui.heading(format!("Traffic — {}", profile_name));
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
            if let Some(proxy_id) = &routing.selected_proxy {
                ui.label(format!("Routing: selected proxy {}", proxy_id));
            } else {
                ui.label("Routing: no proxy selected");
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
                                            ui.label(format!("{} -> {}", q, r));
                                        }
                                        (Some(q), None) => {
                                            ui.label(format!("{} -> …", q));
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
                                            ui.colored_label(
                                                Color32::RED,
                                                format!("{}", &err[..err.len().min(40)]),
                                            );
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

        // BTreeMap<ConnId, _> is ordered by ascending ConnId (monotonically assigned),
        // so .rev() gives newest-first with no sort needed.
        let active_entries: Vec<(&diag::ConnId, &diag::ConnEntry)> = conns
            .conns
            .iter()
            .rev()
            .filter(|(_, e)| e.finished_at.is_none())
            .collect();
        let finished_entries: Vec<(&diag::ConnId, &diag::ConnEntry)> = conns
            .conns
            .iter()
            .rev()
            .filter(|(_, e)| e.finished_at.is_some())
            .collect();

        if conns.conns.is_empty() {
            ui.colored_label(Color32::from_gray(110), "no active connections");
        }

        let render_conn_table = |ui: &mut egui::Ui,
                                 id_salt: String,
                                 entries: &[(&diag::ConnId, &diag::ConnEntry)],
                                 show_status: bool| {
            egui::ScrollArea::horizontal()
                .id_salt(id_salt.clone())
                .show(ui, |ui| {
                    let mut builder = TableBuilder::new(ui)
                        .id_salt(format!("{}_tbl", id_salt))
                        .striped(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::auto().at_least(70.0)) // ID
                        .column(Column::remainder().at_least(140.0)) // Route
                        .column(Column::remainder().at_least(160.0)); // Dst
                    if show_status {
                        builder = builder
                            .column(Column::auto().at_least(55.0)) // Status
                            .column(Column::auto().at_least(70.0)); // Duration
                    }
                    builder
                        .header(row_height, |mut header| {
                            header.col(|ui| {
                                ui.strong("ID");
                            });
                            header.col(|ui| {
                                ui.strong("Route");
                            });
                            if show_status {
                                header.col(|ui| {
                                    ui.strong("Duration");
                                });
                            }
                            header.col(|ui| {
                                ui.strong("Destination");
                            });
                            if show_status {
                                header.col(|ui| {
                                    ui.strong("Status");
                                });
                            }
                        })
                        .body(|mut body| {
                            body.rows(row_height, entries.len(), |mut row| {
                                let (id, entry) = &entries[row.index()];
                                row.col(|ui| {
                                    ui.colored_label(Color32::LIGHT_BLUE, format!("{}", id.0));
                                });
                                row.col(|ui| match &entry.route {
                                    Some(r) => {
                                        ui.label(format!("{:?}", r));
                                    }
                                    None => {}
                                });
                                if show_status {
                                    row.col(|ui| {
                                        if let Some(fin) = entry.finished_at {
                                            let us =
                                                fin.elapsed_since(entry.accepted_at).as_micros()
                                                    as f64;
                                            ui.label(diag::summary::format_duration_us(us));
                                        }
                                    });
                                }
                                row.col(|ui| {
                                    ui.label(format!("{}", entry.dst));
                                });
                                if show_status {
                                    row.col(|ui| match &entry.error {
                                        Some(e) => {
                                            ui.colored_label(Color32::RED, "error")
                                                .on_hover_text(e.as_str());
                                        }
                                        None => {
                                            ui.colored_label(Color32::LIGHT_GREEN, "OK");
                                        }
                                    });
                                }
                            });
                        });
                });
        };

        if !active_entries.is_empty() {
            ui.label(egui::RichText::new("Active").strong());
            render_conn_table(
                ui,
                format!("conns_active_{}", profile_name),
                &active_entries,
                false,
            );
            ui.add_space(4.0);
        }

        if !finished_entries.is_empty() {
            ui.label(egui::RichText::new("Recently Finished").strong());
            render_conn_table(
                ui,
                format!("conns_finished_{}", profile_name),
                &finished_entries,
                true,
            );
        }
    }

    fn render_hotconfig_tab(&mut self, ui: &mut egui::Ui) {
        self.refresh_hotconfig_editor_target();

        if self.selected_profile.is_none() {
            ui.label("Select a profile to edit Hotconfig");
            return;
        }

        let profile_name = self.selected_profile.clone().unwrap_or_default();
        let (dns_state, sandbox_status, child_alive) = self
            .snapshot
            .profiles
            .get(&profile_name)
            .map(|profile| {
                (
                    profile.dns_state.clone(),
                    profile.sandbox_status.clone(),
                    profile.child_alive,
                )
            })
            .unwrap_or((None, None, false));
        ui.horizontal(|ui| {
            ui.heading(format!("Hotconfig - {}", profile_name));
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
        ui.add_space(8.0);
        match sandbox_status.as_ref() {
            Some(status) => Self::render_sandbox_status_panel(ui, status),
            None => {
                egui::Frame::none()
                    .fill(Color32::from_gray(18))
                    .stroke(egui::Stroke::new(1.0, Color32::from_gray(60)))
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

        let changed = Self::render_hotconfig_editor_split(
            ui,
            &mut self.int_input,
            "hotconfig-tab",
            &mut self.hotconfig_editor_value,
            &mut self.hotconfig_editor_json,
            &mut self.hotconfig_editor_error,
        );
        if changed {
            self.hotconfig_editor_status = None;
        }
    }

    fn render_sandbox_status_panel(ui: &mut egui::Ui, status: &SandboxStatus) {
        egui::Frame::none()
            .fill(Color32::from_gray(18))
            .stroke(egui::Stroke::new(1.0, Color32::from_gray(60)))
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
                                            RichText::new(mount.target.display().to_string())
                                                .monospace(),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(mount.source.display().to_string())
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

    fn render_profile_editor_tab(&mut self, ui: &mut egui::Ui) {
        self.refresh_profile_editor_target();

        ui.horizontal(|ui| {
            match self.selected_profile.as_ref() {
                Some(profile_name) => ui.heading(format!("Profile - {}", profile_name)),
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
                        .with_syntax(json_syntax())
                        .with_numlines(true)
                        .with_ui_fontsize(ui);
                    let output = editor.show(ui, &mut self.profile_editor_json);
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
            let level_color = match entry.level.as_str() {
                "ERROR" => Color32::from_rgb(220, 80, 80),
                "WARN" => Color32::from_rgb(210, 160, 60),
                "DEBUG" | "TRACE" => Color32::from_gray(120),
                _ => Color32::from_gray(200),
            };
            ui.colored_label(level_color, &entry.level);
            ui.colored_label(Color32::from_gray(100), format!("[{}]", entry.target));
            ui.horizontal_wrapped(|ui| {
                for part in egui_sgr::ansi_to_rich_text(&entry.message) {
                    ui.label(part);
                }
                for field in &entry.fields {
                    ui.add_space(6.0);
                    ui.colored_label(Color32::from_gray(110), format!("{}=", field.name));
                    ui.monospace(&field.value);
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
        diag::DiagEvent::Finished { .. } => "Finished",
        diag::DiagEvent::DnsResolved { .. } => "DnsResolved",
        diag::DiagEvent::DnsQuery { .. } => "DnsQuery",
        diag::DiagEvent::Wait { .. } => "Wait",
        diag::DiagEvent::WaitEnded { .. } => "WaitEnded",
        diag::DiagEvent::HotConfigReloaded { .. } => "HotConfigReloaded",
        diag::DiagEvent::HotConfigSnapshot { .. } => "HotConfigSnapshot",
        diag::DiagEvent::DnsState { .. } => "DnsState",
        diag::DiagEvent::RoutingState { .. } => "RoutingState",
        diag::DiagEvent::UplinkStatsSnapshot { .. } => "UplinkStatsSnapshot",
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

fn render_namespace_badge(
    ui: &mut egui::Ui,
    label: &str,
    value: Option<&str>,
    accent: Color32,
) {
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
    use eframe::egui::{Align2, FontId, Stroke};

    let desired = ui.available_size_before_wrap();
    let width = width_override.unwrap_or_else(|| desired.x.max(220.0).min(ui.available_width()));
    let size = eframe::egui::vec2(width, 76.0_f32);
    let (rect, resp) = ui.allocate_exact_size(size, eframe::egui::Sense::click());

    let visuals = ui.visuals();
    let bg = if selected {
        visuals.widgets.active.bg_fill
    } else if resp.hovered() {
        visuals.widgets.hovered.bg_fill
    } else {
        visuals.widgets.inactive.bg_fill
    };

    // Background and border
    ui.painter().rect_filled(rect, 8.0, bg);
    let stroke_color = if selected {
        visuals.selection.stroke.color
    } else if resp.hovered() {
        visuals.widgets.hovered.fg_stroke.color
    } else {
        visuals.widgets.inactive.fg_stroke.color
    };
    ui.painter().rect_stroke(
        rect,
        8.0,
        Stroke::new(if selected { 2.0 } else { 1.0 }, stroke_color),
        egui::StrokeKind::Middle,
    );

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
    cc.egui_ctx.style_mut(|style| {
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
    let native_options = eframe::NativeOptions::default();
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
