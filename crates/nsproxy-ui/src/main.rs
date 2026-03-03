use eframe::egui;
use eframe::egui::Color32;
use egui_extras::{Column, TableBuilder};
use egui_json_tree::{DefaultExpand, JsonTree};
use egui_plot::{GridInput, GridMark, Line, LineStyle, PlotPoints};
use nsproxy_common::crdt::CRDT;
use nsproxy_common::routing::ProxyID;
use nsproxy_common::stats::ProxyStats;
use nsproxy_core::shell::ShellArgs;
use nsproxy_core::state_blueprint::PersistentState as _;
use nsproxy_core::uplink::clash::{ClashState, GroupId};
use nsproxy_core::uplink::{UplinkHub, UplinkProxy, UplinkStatsState};
use nsproxy_core::{state_paths, HotConfig, NsAlive, TemplateConfig};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::thread;
use std::time::SystemTime;
use tokio::runtime::Runtime;

mod profile_loader;
mod supervisor;

use profile_loader::ProfileInfo;
use supervisor::{daemon_unit_id, ProfileName, SupervisorCommand, SupervisorHandle, UnitId};

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
    udp_capable: bool,
    status: String,
    enabled_globally: bool,
    latency_ms: Option<u64>,
    conn_ok: Option<bool>,
    resolved_ip: Option<IpAddr>,
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
    Processes,
    Diagnostics,
    Dns,
    Hotconfig,
    ProfileEditor,
}

#[derive(Clone, Default)]
struct ProxyFilters {
    selected_groups: HashSet<GroupId>,
    selected_types: HashSet<ProxyType>,
}

struct LoadResult {
    text: String,
    error: Option<String>,
}

#[derive(Default, Clone)]
struct DaemonForm {
    shell: String,
    args: String,
    cwd: String,
}

struct App {
    selected_profile: Option<ProfileName>,
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
    snapshot: supervisor::SupervisorSnapshot,
    daemon_form: DaemonForm,
    hide_secret: bool,
    cover_text: String,
    tokio_rt: Runtime,
    detail_proxy_id: Option<ProxyID>,
    /// Number of upcoming frames that should force-fit/reset detail plots.
    detail_fit_frames_left: u8,
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

        let (name, url, udp_capable) = match proxy {
            UplinkProxy::Trojan(t) => (
                t.name.clone(),
                format!("trojan://{}:{}", t.server_name, t.server_addr.port()),
                false,
            ),
            UplinkProxy::Remote(a) => (nym.clone(), format!("{}://{}", a.proxy_type, a.addr), true),
            UplinkProxy::Geph => (nym.clone(), "geph://".into(), false),
            UplinkProxy::File(p) => (nym.clone(), format!("file://{}", p.display()), false),
        };

        // Get resolved IP from clash state if available
        let resolved_ip: Option<IpAddr> = clash_state
            .get_latest_proxy_ips(&nym)
            .and_then(|ips| ips.iter().next().copied());

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
                udp_capable,
                status: "idle".into(),
                enabled_globally: false,
                latency_ms,
                conn_ok,
                resolved_ip,
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

fn build_shell_args(form: &DaemonForm) -> Option<ShellArgs> {
    let shell = form.shell.trim();
    if shell.is_empty() {
        return None;
    }
    let args = form
        .args
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let cwd = form.cwd.trim();
    Some(ShellArgs {
        uid: None,
        gid: None,
        shell: Some(shell.to_string()),
        cwd: if cwd.is_empty() {
            None
        } else {
            Some(cwd.into())
        },
        gids: Vec::new(),
        args,
    })
}

impl App {
    pub fn new(ectx: egui::Context) -> Self {
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
            while reload_rx.recv().is_ok() {
                let updated = load_proxies_from_persisted();
                eprintln!("uplink reloaded: {} proxies", updated.proxies.len());
                let _ = proxy_tx.send(updated); // drop error if GUI has exited
            }
        });

        let tokio_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for ui supervisor");
        let (supervisor, supervisor_task) = SupervisorHandle::new(ectx.clone());
        tokio_rt.spawn(supervisor_task.run());

        // Initialize supervisor: discover and load all profiles
        supervisor.send(supervisor::SupervisorCommand::Init);

        Self {
            selected_profile: None,
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
            snapshot: supervisor::SupervisorSnapshot {
                profiles: BTreeMap::new(),
                generated_at: SystemTime::now(),
            },
            daemon_form: DaemonForm::default(),
            hide_secret: false,
            cover_text: "redacted".to_string(),
            tokio_rt,
            detail_proxy_id: None,
            detail_fit_frames_left: 0,
        }
    }

    fn get_selected_profile(&self) -> Option<&supervisor::ProfileSnapshot> {
        self.selected_profile
            .as_ref()
            .and_then(|name| self.snapshot.profiles.get(name))
    }

    fn get_selected_profile_mut(&mut self) -> Option<&mut supervisor::ProfileSnapshot> {
        if let Some(name) = self.selected_profile.clone() {
            self.snapshot.profiles.get_mut(&name)
        } else {
            None
        }
    }

    fn reload_all_ns_alive(&self) {
        let profiles: Vec<_> = self.snapshot.profiles.keys().cloned().collect();
        if !profiles.is_empty() {
            self.supervisor
                .send(supervisor::SupervisorCommand::LoadProfiles(profiles));
        }
    }

    fn apply_filters(&mut self) {
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
    }
}

fn default_hotconfig_text() -> String {
    serde_json::to_string_pretty(&HotConfig::default()).unwrap_or_else(|_| "{}".to_string())
}

fn default_profile_text() -> String {
    serde_json::to_string_pretty(&TemplateConfig::default()).unwrap_or_else(|_| "{}".to_string())
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

fn profile_unit_ids(profile: &ProfileName) -> (UnitId, UnitId) {
    (
        UnitId::new(format!("{}:up", profile.as_str())),
        UnitId::new(format!("{}:serve", profile.as_str())),
    )
}

fn unit_running(snapshot: &supervisor::SupervisorSnapshot, unit_id: &UnitId) -> bool {
    snapshot
        .profiles
        .values()
        .flat_map(|profile| profile.units.iter())
        .find(|u| &u.id == unit_id)
        .map(|u| matches!(u.status, supervisor::UnitStatus::Running))
        .unwrap_or(false)
}

fn load_scope_from_disk<FH, FP>(
    profile: &ProfileName,
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

        // Drain any reload results pushed by the background thread.
        if let Ok(updated) = self.proxy_rx.try_recv() {
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
        while let Some(snapshot) = self.supervisor.try_recv_snapshot() {
            self.snapshot = snapshot;
        }

        egui::SidePanel::left("left_sidebar")
            .resizable(false)
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Containers");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button("🔄")
                            .on_hover_text("Reload all container status")
                            .clicked()
                        {
                            self.reload_all_ns_alive();
                        }
                    });
                });

                ui.add_space(6.0);

                // Global configuration box at the top
                let global_selected = self.selected_profile.is_none();
                let global_status_color = egui::Color32::from_rgb(100, 150, 240);
                if sidebar_box(ui, "Global", "", global_selected, global_status_color).clicked() {
                    self.selected_profile = None;
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

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

                        // Determine if units are running
                        let (up_id, serve_id) = profile_unit_ids(profile_name);
                        let running = profile_snapshot.units.iter().any(|u| {
                            (u.id == up_id || u.id == serve_id)
                                && matches!(u.status, supervisor::UnitStatus::Running)
                        });

                        let status_color = if running {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::LIGHT_RED
                        };
                        let status_text = if running { "running" } else { "stopped" };

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
                ui.horizontal(|ui| {
                    let btn_label = if self.hide_secret {
                        "🔓 Show secrets"
                    } else {
                        "🔒 Hide secrets"
                    };
                    if ui
                        .button(btn_label)
                        .on_hover_text("Toggle masking of sensitive text")
                        .clicked()
                    {
                        self.hide_secret = !self.hide_secret;
                    }
                });
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
                if ui
                    .selectable_label(self.right_tab == RightTab::Processes, "Processes")
                    .clicked()
                {
                    self.right_tab = RightTab::Processes;
                }
                if ui
                    .selectable_label(self.right_tab == RightTab::Diagnostics, "Diagnostics")
                    .clicked()
                {
                    self.right_tab = RightTab::Diagnostics;
                    if let Some(profile_name) = &self.selected_profile {
                        self.supervisor
                            .send(supervisor::SupervisorCommand::OnTabOpen {
                                profile: profile_name.clone(),
                                tab: supervisor::TabKind::Diagnostics,
                            });
                    }
                }
                if ui
                    .selectable_label(self.right_tab == RightTab::Dns, "DNS")
                    .clicked()
                {
                    self.right_tab = RightTab::Dns;
                    if let Some(profile_name) = &self.selected_profile {
                        self.supervisor
                            .send(supervisor::SupervisorCommand::OnTabOpen {
                                profile: profile_name.clone(),
                                tab: supervisor::TabKind::Dns,
                            });
                    }
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

                let diag_status = self
                    .selected_profile
                    .as_ref()
                    .and_then(|profile| self.snapshot.profiles.get(profile))
                    .map(|profile| profile.diag_connected);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(status) = diag_status {
                        let (label, color) = if status {
                            ("Diag: connected", Color32::LIGHT_GREEN)
                        } else {
                            ("Diag: disconnected", Color32::LIGHT_RED)
                        };
                        ui.colored_label(color, label);
                    } else if self.selected_profile.is_some() {
                        ui.colored_label(Color32::from_gray(140), "Diag: unknown");
                    }
                });
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            match self.right_tab {
                RightTab::Proxies => self.render_proxies_tab(ui),
                RightTab::Processes => self.render_processes_tab(ui),
                RightTab::Diagnostics => self.render_diagnostics_tab(ui),
                RightTab::Dns => self.render_dns_tab(ui),
                RightTab::Hotconfig => self.render_hotconfig_tab(ui),
                RightTab::ProfileEditor => self.render_profile_editor_tab(ui),
            }
        });

        self.render_proxy_detail_window(ctx);
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
                    let serve_id = UnitId::new(format!("{}:serve", profile_name.as_str()));
                    self.supervisor.send(SupervisorCommand::Ctrl {
                        unit_id: serve_id,
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
    }

    fn render_proxies_table(&mut self, ui: &mut egui::Ui) {
        let header_h = 28.0;
        let row_h = 96.0;
        let mut next_hovered_proxy: Option<usize> = None;

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

        egui::ScrollArea::vertical().show(ui, |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                // name width, proxy URL made modest (not using remainder)
                .column(Column::exact(160.0))
                .column(Column::exact(200.0))
                .column(Column::exact(80.0))
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
                        ui.strong("Latency");
                    });
                    header.col(|ui| {
                        ui.strong("Stats");
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
                    ui.small(format!("Status: {}", proxy_item.status));
                } else if proxy_item.udp_capable {
                    ui.small("UDP + TCP");
                } else {
                    ui.small("TCP only");
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

                if let Some(ip) = proxy_item.resolved_ip {
                    ui.small(format!("IP: {}", ip));
                }

                if is_hover {
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Select proxy").clicked() {
                            if let Some(profile_name) = self.selected_profile.clone() {
                                let serve_id =
                                    UnitId::new(format!("{}:serve", profile_name.as_str()));
                                self.supervisor.send(SupervisorCommand::Ctrl {
                                    unit_id: serve_id,
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
                                let serve_id =
                                    UnitId::new(format!("{}:serve", profile_name.as_str()));
                                self.supervisor.send(SupervisorCommand::Ctrl {
                                    unit_id: serve_id,
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
            let status = &proxy_item.status;
            let (status_color, status_text) = match display_conn_ok {
                Some(true) => (egui::Color32::LIGHT_GREEN, "ok".to_owned()),
                Some(false) => (egui::Color32::LIGHT_RED, "fail".to_owned()),
                None => (
                    if status.contains("OK") {
                        egui::Color32::LIGHT_GREEN
                    } else {
                        egui::Color32::from_gray(160)
                    },
                    status.clone(),
                ),
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
                    ui.small(format!("Global: {}", enabled));
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
        ui.separator();
        ui.add_space(8.0);

        self.render_units_table(ui, &profile_name);

        if let Some(profile) = &profile_name {
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            self.render_hotconfig_daemons_section(ui, profile);
            self.render_run_command_section(ui, profile);
        }
    }

    fn render_process_controls(&mut self, ui: &mut egui::Ui, profile_name: &ProfileName) {
        let (up_id, serve_id) = profile_unit_ids(profile_name);
        let up_running = unit_running(&self.snapshot, &up_id);
        let serve_running = unit_running(&self.snapshot, &serve_id);

        ui.horizontal(|ui| {
            let spacing = ui.spacing().item_spacing.x;
            let width_each = (ui.available_width() - spacing).max(0.0) / 2.0;

            let (up_title, up_subtitle) = if up_running {
                ("Stop Container", "sp up")
            } else {
                ("Start Container", "sp up")
            };
            let up_color = if up_running {
                egui::Color32::from_rgb(80, 160, 220)
            } else {
                egui::Color32::from_rgb(180, 180, 180)
            };

            if sidebar_box_width(
                ui,
                up_title,
                up_subtitle,
                up_running,
                up_color,
                Some(width_each),
            )
            .clicked()
            {
                self.supervisor
                    .send(SupervisorCommand::EnsureUnit(supervisor::build_up_unit(
                        profile_name,
                    )));
            }

            let (serve_title, serve_subtitle) = if serve_running {
                ("Stop TUN", "sp serve")
            } else {
                ("Start TUN", "sp serve")
            };
            let serve_color = if serve_running {
                egui::Color32::from_rgb(120, 200, 140)
            } else {
                egui::Color32::from_rgb(180, 180, 180)
            };

            sidebar_box_width(
                ui,
                serve_title,
                serve_subtitle,
                serve_running,
                serve_color,
                Some(width_each),
            );
        });
    }

    fn render_units_table(&self, ui: &mut egui::Ui, profile_name: &Option<ProfileName>) {
        let mut rows: Vec<&supervisor::UnitState> = Vec::new();
        if let Some(profile) = profile_name {
            if let Some(profile_snapshot) = self.snapshot.profiles.get(profile) {
                rows.extend(profile_snapshot.units.iter());
            }
        } else {
            for profile_snapshot in self.snapshot.profiles.values() {
                rows.extend(profile_snapshot.units.iter());
            }
        }

        if rows.is_empty() {
            ui.label("No supervisor data available yet.");
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::auto())
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Unit");
                    });
                    header.col(|ui| {
                        ui.strong("Status");
                    });
                    header.col(|ui| {
                        ui.strong("PID");
                    });
                    header.col(|ui| {
                        ui.strong("Desired");
                    });
                    header.col(|ui| {
                        ui.strong("Diag");
                    });
                })
                .body(|mut body| {
                    for unit in rows {
                        body.row(20.0, |mut row| {
                            row.col(|ui| {
                                ui.label(format!("{} ({:?})", unit.id.as_str(), unit.kind));
                            });
                            row.col(|ui| {
                                ui.label(format!("{:?}", unit.status));
                            });
                            row.col(|ui| {
                                ui.label(
                                    unit.pid
                                        .map(|p| p.to_string())
                                        .unwrap_or_else(|| "-".into()),
                                );
                            });
                            row.col(|ui| {
                                ui.label(format!("{:?}", unit.desired));
                            });
                            row.col(|ui| {
                                if let Some(profile_name) = profile_name {
                                    if let Some(prof_snap) =
                                        self.snapshot.profiles.get(profile_name)
                                    {
                                        if prof_snap.diag_connected {
                                            if let Some(summary) = &prof_snap.diag_summary {
                                                ui.label(format!(
                                                    "active {} / total {}",
                                                    summary.active_conns, summary.total_conns
                                                ));
                                            } else {
                                                ui.label("connected");
                                            }
                                        } else {
                                            ui.label("disconnected");
                                        }
                                    } else {
                                        ui.label("-");
                                    }
                                } else {
                                    ui.label("-");
                                }
                            });
                        });
                    }
                });
        }
    }

    fn render_hotconfig_daemons_section(&mut self, ui: &mut egui::Ui, profile: &ProfileName) {
        ui.heading("Hotconfig Daemons");
        ui.horizontal(|ui| {
            if ui.button("Load Hotconfig").clicked() {
                self.supervisor
                    .send(supervisor::SupervisorCommand::ReloadHotconfig(
                        profile.clone(),
                    ));
            }
            if ui.button("Start All Daemons").clicked() {
                self.supervisor
                    .send(supervisor::SupervisorCommand::StartHotconfigDaemons {
                        profile: profile.clone(),
                    });
            }
        });

        if let Some(pstate) = self.snapshot.profiles.get(profile) {
            let daemon_units: Vec<_> = pstate
                .units
                .iter()
                .filter(|u| u.kind == supervisor::UnitKind::Daemon)
                .collect();

            if daemon_units.is_empty() {
                ui.label("No daemons running. Use 'Load Hotconfig' to start them.");
            } else {
                for unit in daemon_units {
                    ui.horizontal(|ui| {
                        ui.label(unit.id.as_str());
                        ui.label(format!("{:?}", unit.status));
                        if ui.button("Stop").clicked() {
                            self.supervisor
                                .send(supervisor::SupervisorCommand::StopUnit(unit.id.clone()));
                        }
                    });
                }
            }
        }
    }

    fn render_run_command_section(&mut self, ui: &mut egui::Ui, profile: &ProfileName) {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ui.heading("Run Command");
        ui.horizontal(|ui| {
            ui.label("Program");
            ui.text_edit_singleline(&mut self.daemon_form.shell);
        });
        ui.horizontal(|ui| {
            ui.label("Args");
            ui.text_edit_singleline(&mut self.daemon_form.args);
        });
        ui.horizontal(|ui| {
            ui.label("Cwd");
            ui.text_edit_singleline(&mut self.daemon_form.cwd);
        });
        if ui.button("Start Command").clicked() {
            if let Some(args) = build_shell_args(&self.daemon_form) {
                self.supervisor.send(SupervisorCommand::StartDaemon {
                    profile: profile.clone(),
                    args,
                });
            }
        }
    }

    fn render_diagnostics_tab(&self, ui: &mut egui::Ui) {
        if self.selected_profile.is_none() {
            ui.heading("Diagnostics — Global");
            ui.label(format!("Profiles: {}", self.snapshot.profiles.len()));
            let running = self
                .snapshot
                .profiles
                .values()
                .flat_map(|p| &p.units)
                .filter(|u| matches!(u.status, supervisor::UnitStatus::Running))
                .count();
            ui.label(format!("Running: {}", running));
        } else if let Some(profile_name) = self.selected_profile.as_ref() {
            if let Some(profile) = self.snapshot.profiles.get(profile_name) {
                ui.heading(format!("Diagnostics — {}", profile_name.as_str()));
                if let Some(dns) = &profile.dns_state {
                    ui.add_space(6.0);
                    ui.label(format!(
                        "DNS: domains={}, v4={}, v6={}, aaaa_only={}",
                        dns.domain_count, dns.ip4_count, dns.ip6_count, dns.aaaa_only
                    ));
                }
                if let Some(routing) = &profile.routing_state {
                    ui.add_space(6.0);
                    if let Some(proxy_id) = &routing.selected_proxy {
                        ui.label(format!("Routing: selected proxy {}", proxy_id));
                    } else {
                        ui.label("Routing: no proxy selected");
                    }
                }
            }
        }
    }

    fn render_dns_tab(&self, ui: &mut egui::Ui) {
        ui.heading("DNS");
        ui.label("DNS settings are not implemented yet (placeholder).");
    }

    fn render_hotconfig_tab(&self, ui: &mut egui::Ui) {
        if let Some(profile_name) = self.selected_profile.clone() {
            if let Some(profile_snapshot) = self.snapshot.profiles.get(&profile_name) {
                ui.horizontal(|ui| {
                    ui.heading("Hotconfig");
                    ui.add_space(8.0);
                    if ui.button("Reload").clicked() {
                        self.supervisor
                            .send(SupervisorCommand::ReloadHotconfig(profile_name.clone()));
                    }
                });
                ui.add_space(6.0);

                JsonTree::new(
                    format!("hotconfig-{}", profile_name.as_str()),
                    &profile_snapshot.hotconfig_value,
                )
                .default_expand(DefaultExpand::All)
                .show(ui);
            }
        } else {
            ui.label("Select a profile to edit Hotconfig");
        }
    }

    fn render_profile_editor_tab(&self, ui: &mut egui::Ui) {
        if let Some(profile_name) = self.selected_profile.clone() {
            if let Some(profile_snapshot) = self.snapshot.profiles.get(&profile_name) {
                ui.horizontal(|ui| {
                    ui.heading("Profile JSON");
                    ui.add_space(8.0);
                    if ui.button("Reload").clicked() {
                        self.supervisor
                            .send(SupervisorCommand::ReloadProfile(profile_name.clone()));
                    }
                });
                ui.add_space(6.0);

                JsonTree::new(
                    format!("profile-{}", profile_name),
                    &profile_snapshot.template_value,
                )
                .default_expand(DefaultExpand::All)
                .show(ui);
            }
        } else {
            ui.label("Select a profile to edit Profile JSON");
        }
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
                    if let Some(ip) = item.resolved_ip {
                        ui.label(format!("Resolved IP: {}", ip));
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
                        ui.heading("Traffic (KB) — past hour");
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

/// Format a plot x-value as a human-readable age label.
/// `x` is negative seconds relative to now: 0 = now, -3600 = 1 hour ago.
fn format_age_label(x: f64, _window_secs: f64) -> String {
    let age = (-x).max(0.0);
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
    let bucket_us = (window_us / num_buckets as u64).max(1);
    let window_start_us = now.0.saturating_sub(window_us);

    let mut buckets = vec![0.0_f64; num_buckets];

    for (range, data) in stats.data.iter() {
        let r_start = range.start().0;
        let r_end = range.end().0;
        if r_end < window_start_us || r_start > now.0 {
            continue;
        }
        let r_start_clipped = r_start.max(window_start_us);
        let r_end_clipped = r_end.min(now.0);
        if r_end_clipped < r_start_clipped {
            continue;
        }
        let stored_span = (r_end - r_start + 1) as f64;
        let val = extract(data);

        // Determine which buckets this range overlaps.
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
    let sum_pts = bucket_timeseries(stats, window_us, num_buckets, now, |d| d.latency_sum_ms as f64);
    let cnt_pts = bucket_timeseries(stats, window_us, num_buckets, now, |d| d.latency_count as f64);
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

/// Convert a slice of Option<TsPoint> to PlotPoints, only including Some values.
fn opt_ts_to_plot(pts: &[Option<TsPoint>]) -> PlotPoints {
    pts.iter()
        .filter_map(|p| p.as_ref())
        .map(|p| [p.x, p.val])
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

    let up_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| d.bytes_up as f64 / 1024.0);
    let down_pts = bucket_timeseries(stats, hour_us, num_buckets, now, |d| {
        d.bytes_down as f64 / 1024.0
    });

    let has_data = up_pts.iter().chain(down_pts.iter()).any(|p| p.val > 0.0);
    if !has_data {
        ui.label("No traffic data for the past hour.");
        return;
    }

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
        .y_axis_label("KB")
        .set_margin_fraction(egui::Vec2::new(0.0, 0.15));
    if fit {
        plot = plot.reset().auto_bounds(egui::Vec2b::new(true, true));
    } else {
        plot = plot.auto_bounds(egui::Vec2b::new(true, true));
    }
    plot.show(ui, |plot_ui| {
        for (i, seg) in up_solid.into_iter().enumerate() {
            let name = if i == 0 {
                "Upload (KB)".to_string()
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
                "Download (KB)".to_string()
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

fn format_bytes(bytes: f32) -> String {
    if bytes < 1024.0 {
        format!("{:.0}B", bytes)
    } else if bytes < 1024.0 * 1024.0 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
            let mut fonts = egui::FontDefinitions::default();
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
            ctx.set_fonts(fonts);
            return;
        }
    }
}

fn main() {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "nsproxy - dashboard",
        native_options,
        Box::new(|cc| {
            let ctx = cc.egui_ctx.clone();
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
                    style.text_styles.insert(ts.clone(), egui::FontId::proportional(16.0));
                }
            });
            Ok(Box::new(App::new(ctx)))
        }),
    );
}
