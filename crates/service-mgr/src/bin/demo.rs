use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use eframe::egui;
use service_mgr::{
    OutputCursor, Ownership, ServiceEvent, ServiceId, ServiceInfo, ServiceManager, ServiceSpec,
    ServiceState,
};
use term_view::{PtyIpc, TermSession, TermView, flush_term_outputs, pump_pty_io};

const MAX_INCOMING_BYTES: usize = 256 * 1024;
const MAX_LOG_LINES: usize = 200;
type ServiceKey = (usize, ServiceId);

struct UiPtyState {
    incoming: Mutex<HashMap<ServiceId, VecDeque<u8>>>,
    generations: Mutex<HashMap<ServiceId, u64>>,
    wake: Condvar,
    notice: Mutex<String>,
}

impl UiPtyState {
    fn new() -> Self {
        Self {
            incoming: Mutex::new(HashMap::new()),
            generations: Mutex::new(HashMap::new()),
            wake: Condvar::new(),
            notice: Mutex::new("No events yet".to_string()),
        }
    }

    fn append_output(&self, id: ServiceId, data: &[u8]) {
        let mut incoming = self
            .incoming
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let buffer = incoming.entry(id).or_default();
        buffer.extend(data.iter().copied());
        while buffer.len() > MAX_INCOMING_BYTES {
            buffer.pop_front();
        }
        drop(incoming);

        let mut generations = self
            .generations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *generations.entry(id).or_default() = generations
            .get(&id)
            .copied()
            .unwrap_or_default()
            .saturating_add(1);
        self.wake.notify_all();
    }

    fn set_notice(&self, notice: String) {
        *self
            .notice
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = notice;
    }

    fn notice(&self) -> String {
        self.notice
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

#[derive(Default)]
struct EventLog {
    entries: Mutex<VecDeque<String>>,
}

impl EventLog {
    fn push(&self, line: String) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.push_back(line);
        while entries.len() > MAX_LOG_LINES {
            entries.pop_front();
        }
    }

    fn snapshot(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

#[derive(Clone)]
struct Scope {
    label: String,
    manager: ServiceManager,
    shared: Arc<UiPtyState>,
}

#[derive(Clone)]
struct ServicePtyIpc {
    manager: ServiceManager,
    shared: Arc<UiPtyState>,
    id: ServiceId,
}

impl PtyIpc for ServicePtyIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        self.shared
            .incoming
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.id)
            .map(|buffer| buffer.into_iter().collect())
            .unwrap_or_default()
    }

    fn wait_for_incoming(&self, observed_generation: u64) -> u64 {
        let mut generations = self
            .shared
            .generations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            let generation = generations.get(&self.id).copied().unwrap_or_default();
            if generation > observed_generation {
                return generation;
            }
            generations = self
                .shared
                .wake
                .wait(generations)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    fn wake_waiters(&self) {
        self.shared.wake.notify_all();
    }

    fn send_input(&self, data: Vec<u8>) {
        let _ = self.manager.write_input(self.id, &data);
    }

    fn send_resize(&self, cols: u16, rows: u16) {
        let _ = self.manager.resize(self.id, rows, cols);
    }
}

struct DemoApp {
    root: Scope,
    children: Vec<Scope>,
    logs: Arc<EventLog>,
    sessions: Arc<Mutex<HashMap<ServiceKey, TermSession>>>,
    popups: Arc<Mutex<HashSet<ServiceKey>>>,
    selected: Option<ServiceKey>,
}

impl DemoApp {
    fn new(ctx: &egui::Context) -> Self {
        let logs = Arc::new(EventLog::default());
        let root = Self::new_scope("root supervisor", ctx, Arc::clone(&logs));
        let children = ["profile-alpha", "profile-beta"]
            .into_iter()
            .map(|label| Self::new_scope(label, ctx, Arc::clone(&logs)))
            .collect::<Vec<_>>();
        let mut app = Self {
            root,
            children,
            logs,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            popups: Arc::new(Mutex::new(HashSet::new())),
            selected: None,
        };
        app.seed_services();
        app
    }

    fn new_scope(label: &str, ctx: &egui::Context, logs: Arc<EventLog>) -> Scope {
        let (manager, handle) = ServiceManager::new();
        let shared = Arc::new(UiPtyState::new());
        let event_ctx = ctx.clone();
        let event_shared = Arc::clone(&shared);
        let event_label = label.to_string();
        std::thread::Builder::new()
            .name(format!("events-{label}"))
            .spawn(move || {
                while let Ok(event) = handle.events.recv() {
                    match &event {
                        ServiceEvent::Output { id, chunk } => {
                            event_shared.append_output(*id, &chunk.data);
                            let text = String::from_utf8_lossy(&chunk.data).trim_end().to_string();
                            if !text.is_empty() {
                                logs.push(format!(
                                    "[{event_label} #{id} {:?}] {text}",
                                    chunk.stream
                                ));
                            }
                        }
                        ServiceEvent::Started { id, pid } => {
                            let line = format!("[{event_label} #{id}] started pid {pid}");
                            event_shared.set_notice(line.clone());
                            logs.push(line);
                        }
                        ServiceEvent::StateChanged { id, state } => {
                            let line = format!("[{event_label} #{id}] state {state:?}");
                            event_shared.set_notice(line.clone());
                            logs.push(line);
                        }
                    }
                    event_ctx.request_repaint();
                }
            })
            .expect("failed to start manager event bridge");
        Scope {
            label: label.to_string(),
            manager,
            shared,
        }
    }

    fn seed_services(&mut self) {
        for (index, child) in self.children.iter().enumerate() {
            let mut manager_process = ServiceSpec::new("/bin/sh");
            manager_process.args = vec![
                "-c".into(),
                format!(
                    "printf 'nested manager {} ready\\n'; sleep 3600",
                    child.label
                ),
            ];
            manager_process.ownership = Ownership {
                manager: "root supervisor".into(),
                parent: None,
                label: Some(format!("manager for {}", child.label)),
            };
            let parent = self.root.manager.spawn(manager_process).ok();

            let mut worker = ServiceSpec::new("/bin/sh");
            worker.args = vec![
                "-c".into(),
                format!(
                    "i=0; while true; do i=$((i+1)); printf '{} worker tick %s\\n' \"$i\"; sleep 2; done",
                    child.label
                ),
            ];
            worker.ownership = Ownership {
                manager: child.label.clone(),
                parent,
                label: Some(format!("{} worker", child.label)),
            };
            let _ = child.manager.spawn(worker);

            if index == 0 {
                let mut shell = ServiceSpec::new("/bin/sh");
                shell.args = vec!["-i".into()];
                shell.rows = 30;
                shell.cols = 100;
                shell.ownership = Ownership {
                    manager: child.label.clone(),
                    parent,
                    label: Some("interactive shell".into()),
                };
                if let Ok(id) = child.manager.spawn_pty(shell) {
                    self.selected = Some((index + 1, id));
                }
            }
        }
    }

    fn scope(&self, index: usize) -> &Scope {
        if index == 0 {
            &self.root
        } else {
            &self.children[index - 1]
        }
    }

    fn scope_count(&self) -> usize {
        self.children.len() + 1
    }

    fn spawn_pipe(&mut self, scope_index: usize) {
        let scope_label = self.scope(scope_index).label.clone();
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec![
            "-c".into(),
            format!(
                "printf '{} one-shot stdout\\n'; printf '{} one-shot stderr\\n' >&2",
                scope_label, scope_label
            ),
        ];
        spec.ownership = Ownership {
            manager: scope_label.clone(),
            parent: None,
            label: Some("non-PTY one-shot".into()),
        };
        if let Err(error) = self.scope(scope_index).manager.spawn(spec) {
            self.scope(scope_index).shared.set_notice(error.to_string());
        }
    }

    fn spawn_shell(&mut self, scope_index: usize) {
        let scope_label = self.scope(scope_index).label.clone();
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec!["-i".into()];
        spec.rows = 30;
        spec.cols = 100;
        spec.ownership = Ownership {
            manager: scope_label,
            parent: None,
            label: Some("interactive PTY".into()),
        };
        match self.scope(scope_index).manager.spawn_pty(spec) {
            Ok(id) => self.selected = Some((scope_index, id)),
            Err(error) => self.scope(scope_index).shared.set_notice(error.to_string()),
        }
    }

    fn replay_selected_journal(&self) {
        let Some((scope_index, id)) = self.selected else {
            return;
        };
        let scope = self.scope(scope_index);
        let Ok(path) = scope.manager.journal_path(id) else {
            return;
        };
        match scope.manager.journal_replay(id, OutputCursor(0)) {
            Ok(replay) => {
                self.logs.push(format!(
                    "[{} #{id}] replayed {} chunk(s) from {}{}",
                    scope.label,
                    replay.chunks.len(),
                    path.path().display(),
                    if replay.truncated {
                        " (history truncated)"
                    } else {
                        ""
                    }
                ));
                for chunk in replay.chunks {
                    let text = String::from_utf8_lossy(&chunk.data).trim_end().to_string();
                    if !text.is_empty() {
                        self.logs.push(format!(
                            "[replay {} #{id} {:?}] {text}",
                            scope.label, chunk.stream
                        ));
                    }
                }
            }
            Err(error) => self.logs.push(format!(
                "[{} #{id}] journal replay failed: {error}",
                scope.label
            )),
        }
    }

    fn popup_open(&self, key: ServiceKey) -> bool {
        self.popups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(&key)
    }

    fn viewport_id(key: ServiceKey) -> egui::ViewportId {
        egui::ViewportId::from_hash_of(("nested-service-mgr-popup", key.0, key.1))
    }

    fn service_info(&self, key: ServiceKey) -> Option<ServiceInfo> {
        self.scope(key.0)
            .manager
            .list()
            .into_iter()
            .find(|service| service.id == key.1)
    }

    fn render_scope(&mut self, ui: &mut egui::Ui, index: usize) {
        let scope = self.scope(index).clone();
        let services = scope.manager.list();
        ui.collapsing(
            format!("{} — {} service(s)", scope.label, services.len()),
            |ui| {
                egui::Grid::new(format!("service-list-{index}"))
                    .striped(true)
                    .min_col_width(42.0)
                    .show(ui, |ui| {
                        for heading in [
                            "ID", "PID", "State", "Program", "Owner", "Switch", "Popup", "Kill",
                        ] {
                            ui.strong(heading);
                        }
                        ui.end_row();
                        for service in services {
                            self.render_service_row(ui, index, &scope, service);
                        }
                    });
                ui.horizontal(|ui| {
                    if ui.button("spawn pipe job").clicked() {
                        self.spawn_pipe(index);
                    }
                    if ui.button("spawn PTY shell").clicked() {
                        self.spawn_shell(index);
                    }
                    ui.label(scope.shared.notice());
                });
            },
        );
    }

    fn render_service_row(
        &mut self,
        ui: &mut egui::Ui,
        scope_index: usize,
        scope: &Scope,
        service: ServiceInfo,
    ) {
        let key = (scope_index, service.id);
        let selected = self.selected == Some(key);
        if ui
            .selectable_label(selected, service.id.to_string())
            .clicked()
        {
            self.selected = Some(key);
        }
        ui.label(service.pid.to_string());
        ui.colored_label(state_color(service.state), state_label(service.state));
        ui.label(service.command.display().to_string());
        ui.label(
            scope
                .manager
                .ownership(service.id)
                .ok()
                .and_then(|owner| owner.label)
                .unwrap_or_else(|| "unlabeled".into()),
        );
        let popup_open = self.popup_open(key);
        if ui
            .add_enabled(!popup_open, egui::Button::new("switch"))
            .clicked()
        {
            self.selected = Some(key);
        }
        if ui
            .button(if popup_open { "close" } else { "popup" })
            .clicked()
        {
            let mut popups = self
                .popups
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if popup_open {
                popups.remove(&key);
                ui.ctx()
                    .send_viewport_cmd_to(Self::viewport_id(key), egui::ViewportCommand::Close);
            } else {
                popups.insert(key);
                self.selected = Some(key);
            }
        }
        let can_kill = matches!(
            service.state,
            ServiceState::Running | ServiceState::Starting
        );
        if ui
            .add_enabled(can_kill, egui::Button::new("kill"))
            .clicked()
        {
            if let Err(error) = scope.manager.terminate(service.id) {
                scope.shared.set_notice(error.to_string());
            }
        }
        ui.end_row();
    }

    fn render_terminal(&mut self, ui: &mut egui::Ui) {
        let Some(key) = self.selected else {
            ui.centered_and_justified(|ui| ui.label("Select a service"));
            return;
        };
        let Some(info) = self.service_info(key) else {
            ui.centered_and_justified(|ui| ui.label("Selected service no longer exists"));
            return;
        };
        if let Ok(path) = self.scope(key.0).manager.journal_path(key.1) {
            ui.label(format!("Journal: {}", path.path().display()));
        }
        if self.popup_open(key) {
            ui.centered_and_justified(|ui| {
                ui.label(format!(
                    "{} #{} is open in a popup",
                    self.scope(key.0).label,
                    key.1
                ));
            });
            return;
        }
        if key.0 != 0 && self.scope(key.0).manager.output(key.1).is_ok() {
            let owner = self
                .scope(key.0)
                .manager
                .ownership(key.1)
                .ok()
                .and_then(|owner| owner.label)
                .unwrap_or_else(|| "service".into());
            ui.horizontal(|ui| {
                ui.strong(format!("{} — {}", owner, info.command.display()));
                ui.label(state_label(info.state));
            });
        }
        let manager = self.scope(key.0).manager.clone();
        let shared = Arc::clone(&self.scope(key.0).shared);
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = sessions
            .entry(key)
            .or_insert_with(|| TermSession::new(info.pid));
        ui.separator();
        Self::render_terminal_content(ui, manager, shared, key.1, session);
    }

    fn render_terminal_content(
        ui: &mut egui::Ui,
        manager: ServiceManager,
        shared: Arc<UiPtyState>,
        id: ServiceId,
        session: &mut TermSession,
    ) {
        let ipc = ServicePtyIpc {
            manager,
            shared,
            id,
        };
        let mut input_frames = Vec::new();
        let mut resize_event = None;
        pump_pty_io(&ipc, session);
        ui.add(
            TermView::new(session, &mut input_frames, &mut resize_event)
                .set_size(ui.available_size()),
        );
        flush_term_outputs(&ipc, input_frames, resize_event);
    }

    fn render_popups(&self, ctx: &egui::Context) {
        let keys = self
            .popups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            let Some(info) = self.service_info(key) else {
                continue;
            };
            let manager = self.scope(key.0).manager.clone();
            let shared = Arc::clone(&self.scope(key.0).shared);
            let sessions = Arc::clone(&self.sessions);
            let popups = Arc::clone(&self.popups);
            let title = format!(
                "{} #{} — {}",
                self.scope(key.0).label,
                key.1,
                info.command.display()
            );
            ctx.show_viewport_deferred(
                Self::viewport_id(key),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([900.0, 520.0]),
                move |popup_ctx, viewport_class| {
                    if popup_ctx.input(|input| input.viewport().close_requested()) {
                        popups
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&key);
                        return;
                    }
                    let mut render = |ui: &mut egui::Ui| {
                        let mut sessions =
                            sessions.lock().unwrap_or_else(|error| error.into_inner());
                        let session = sessions
                            .entry(key)
                            .or_insert_with(|| TermSession::new(info.pid));
                        DemoApp::render_terminal_content(
                            ui,
                            manager.clone(),
                            Arc::clone(&shared),
                            key.1,
                            session,
                        );
                    };
                    match viewport_class {
                        egui::ViewportClass::Embedded => {
                            egui::Window::new(format!("service {} terminal", key.1))
                                .show(popup_ctx, |ui| render(ui));
                        }
                        egui::ViewportClass::Root
                        | egui::ViewportClass::Immediate
                        | egui::ViewportClass::Deferred => {
                            egui::CentralPanel::default().show(popup_ctx, |ui| render(ui));
                        }
                    }
                },
            );
        }
    }
}

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("root pipe job").clicked() {
                    self.spawn_pipe(0);
                }
                if ui.button("alpha PTY").clicked() {
                    self.spawn_shell(1);
                }
                if ui.button("beta PTY").clicked() {
                    self.spawn_shell(2);
                }
                if ui.button("replay selected journal").clicked() {
                    self.replay_selected_journal();
                }
                ui.separator();
                ui.label("Nested topology: root supervisor → profile managers → services");
            });
        });

        egui::SidePanel::right("event-log")
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.heading("Replayable event journal");
                ui.label("Live events are retained by each manager's bounded output hub.");
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in self.logs.snapshot() {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Nested service managers");
            ui.label("The root manager owns profile-manager services; each profile manager owns its own PTY and pipe services.");
            ui.separator();
            for index in 0..self.scope_count() {
                self.render_scope(ui, index);
            }
            ui.separator();
            self.render_terminal(ui);
        });
        self.render_popups(ctx);
    }
}

fn state_label(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Starting => "starting",
        ServiceState::Running => "running",
        ServiceState::Terminating => "stopping",
        ServiceState::Exited(_) => "exited",
        ServiceState::Signaled(_) => "signaled",
    }
}

fn state_color(state: ServiceState) -> egui::Color32 {
    match state {
        ServiceState::Starting => egui::Color32::YELLOW,
        ServiceState::Running => egui::Color32::LIGHT_GREEN,
        ServiceState::Terminating => egui::Color32::from_rgb(220, 165, 60),
        ServiceState::Exited(_) => egui::Color32::GRAY,
        ServiceState::Signaled(_) => egui::Color32::LIGHT_RED,
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "service-mgr nested supervisor demo",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(DemoApp::new(&cc.egui_ctx)))),
    )
}
