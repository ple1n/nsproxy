use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use eframe::egui;
use service_mgr::{
    ServiceEvent, ServiceId, ServiceInfo, ServiceManager, ServiceSpec, ServiceState,
};
use term_view::{PtyIpc, TermSession, TermView, flush_term_outputs, pump_pty_io};

const MAX_INCOMING_BYTES: usize = 256 * 1024;

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
            notice: Mutex::new("No services".to_string()),
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
        let generation = generations.entry(id).or_default();
        *generation = generation.saturating_add(1);
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

#[derive(Clone)]
struct ServicePtyIpc {
    manager: ServiceManager,
    shared: Arc<UiPtyState>,
    id: ServiceId,
}

impl PtyIpc for ServicePtyIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        let mut incoming = self
            .shared
            .incoming
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        incoming
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
    manager: ServiceManager,
    shared: Arc<UiPtyState>,
    sessions: Arc<Mutex<HashMap<ServiceId, TermSession>>>,
    popups: Arc<Mutex<HashSet<ServiceId>>>,
    selected: Option<ServiceId>,
}

impl DemoApp {
    fn new(ctx: &egui::Context) -> Self {
        let (manager, handle) = ServiceManager::new();
        let shared = Arc::new(UiPtyState::new());
        let event_shared = Arc::clone(&shared);
        let event_ctx = ctx.clone();
        std::thread::Builder::new()
            .name("service-mgr-ui-events".to_string())
            .spawn(move || {
                while let Ok(event) = handle.events.recv() {
                    match event {
                        ServiceEvent::Output { id, chunk } => {
                            event_shared.append_output(id, &chunk.data);
                        }
                        ServiceEvent::Started { id, pid } => {
                            event_shared.set_notice(format!("Started service {id} (pid {pid})"));
                        }
                        ServiceEvent::StateChanged { id, state } => {
                            event_shared.set_notice(format!("Service {id} changed to {state:?}"));
                        }
                    }
                    event_ctx.request_repaint();
                }
            })
            .expect("failed to start service manager event bridge");

        Self {
            manager,
            shared,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            popups: Arc::new(Mutex::new(HashSet::new())),
            selected: None,
        }
    }

    fn spawn(&mut self, spec: ServiceSpec) {
        match self.manager.spawn_pty(spec) {
            Ok(id) => {
                self.selected = Some(id);
            }
            Err(error) => self.shared.set_notice(error.to_string()),
        }
    }

    fn start_shell(&mut self) {
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec!["-i".to_string()];
        spec.rows = 30;
        spec.cols = 100;
        self.spawn(spec);
    }

    fn start_worker(&mut self) {
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec![
            "-c".to_string(),
            "i=0; while true; do i=$((i+1)); printf 'worker tick %s\\n' \"$i\"; sleep 1; done"
                .to_string(),
        ];
        spec.rows = 30;
        spec.cols = 100;
        self.spawn(spec);
    }

    fn selected_info<'a>(&self, services: &'a [ServiceInfo]) -> Option<&'a ServiceInfo> {
        self.selected
            .and_then(|id| services.iter().find(|service| service.id == id))
    }

    fn popup_open(&self, id: ServiceId) -> bool {
        self.popups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(&id)
    }

    fn viewport_id(id: ServiceId) -> egui::ViewportId {
        egui::ViewportId::from_hash_of(("service-mgr-popup", id))
    }

    fn render_service_table(&mut self, ui: &mut egui::Ui, services: &[ServiceInfo]) {
        egui::Grid::new("service-list")
            .striped(true)
            .min_col_width(44.0)
            .show(ui, |ui| {
                for heading in [
                    "ID", "PID", "State", "Program", "Uptime", "Switch", "Popup", "Kill",
                ] {
                    ui.strong(heading);
                }
                ui.end_row();

                for service in services {
                    let selected = self.selected == Some(service.id);
                    if ui
                        .selectable_label(selected, service.id.to_string())
                        .clicked()
                    {
                        self.selected = Some(service.id);
                    }
                    ui.label(service.pid.to_string());
                    ui.colored_label(state_color(service.state), state_label(service.state));
                    ui.label(service.command.display().to_string());
                    ui.label(format_duration(service.uptime));
                    let popup_open = self.popup_open(service.id);
                    if ui
                        .add_enabled(!popup_open, egui::Button::new("switch"))
                        .clicked()
                    {
                        self.selected = Some(service.id);
                    }
                    let popup_enabled = popup_open || self.selected == Some(service.id);
                    if ui
                        .add_enabled(
                            popup_enabled,
                            egui::Button::new(if popup_open { "close" } else { "popup" }),
                        )
                        .clicked()
                    {
                        let mut popups = self
                            .popups
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        if popup_open {
                            popups.remove(&service.id);
                            ui.ctx().send_viewport_cmd_to(
                                Self::viewport_id(service.id),
                                egui::ViewportCommand::Close,
                            );
                        } else {
                            popups.insert(service.id);
                            self.selected = Some(service.id);
                        }
                    }
                    let can_kill = matches!(
                        service.state,
                        ServiceState::Running | ServiceState::Starting
                    );
                    if ui
                        .add_enabled(can_kill, egui::Button::new("Kill"))
                        .clicked()
                    {
                        if let Err(error) = self.manager.terminate(service.id) {
                            self.shared.set_notice(error.to_string());
                        }
                    }
                    ui.end_row();
                }
            });
    }

    fn render_terminal(&mut self, ui: &mut egui::Ui, services: &[ServiceInfo]) {
        let Some(info) = self.selected_info(services) else {
            ui.centered_and_justified(|ui| ui.label("Select a service to open its terminal"));
            return;
        };
        let id = info.id;
        if self.popup_open(id) {
            ui.centered_and_justified(|ui| {
                ui.label(format!(
                    "Terminal for service {id} is open in a popup window."
                ));
            });
            return;
        }
        let pid = info.pid;
        let manager = self.manager.clone();
        let shared = Arc::clone(&self.shared);

        ui.horizontal(|ui| {
            ui.strong(format!(
                "Embedded terminal — {} ({id})",
                info.command.display()
            ));
            ui.label(state_label(info.state));
        });
        ui.separator();

        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = sessions.entry(id).or_insert_with(|| TermSession::new(pid));
        Self::render_terminal_content(ui, manager, shared, id, session);
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

    fn render_popups(&self, ctx: &egui::Context, services: &[ServiceInfo]) {
        let open_ids = self
            .popups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .copied()
            .collect::<Vec<_>>();

        for id in open_ids {
            let Some(info) = services.iter().find(|service| service.id == id).cloned() else {
                continue;
            };
            let manager = self.manager.clone();
            let shared = Arc::clone(&self.shared);
            let sessions = Arc::clone(&self.sessions);
            let popups = Arc::clone(&self.popups);
            ctx.show_viewport_deferred(
                Self::viewport_id(id),
                egui::ViewportBuilder::default()
                    .with_title(format!("service {} — {}", id, info.command.display()))
                    .with_inner_size([900.0, 520.0]),
                move |popup_ctx, viewport_class| {
                    if popup_ctx.input(|input| input.viewport().close_requested()) {
                        popups
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&id);
                        return;
                    }

                    let mut render = |ui: &mut egui::Ui| {
                        let mut sessions =
                            sessions.lock().unwrap_or_else(|error| error.into_inner());
                        let session = sessions
                            .entry(id)
                            .or_insert_with(|| TermSession::new(info.pid));
                        DemoApp::render_terminal_content(
                            ui,
                            manager.clone(),
                            Arc::clone(&shared),
                            id,
                            session,
                        );
                    };

                    match viewport_class {
                        egui::ViewportClass::Embedded => {
                            egui::Window::new(format!("service {} terminal", id))
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
        let services = self.manager.list();

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Start shell").clicked() {
                    self.start_shell();
                }
                if ui.button("Start worker").clicked() {
                    self.start_worker();
                }
                ui.separator();
                ui.label(self.shared.notice());
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Services");
            ui.label(format!("{} managed service(s)", services.len()));
            ui.separator();
            if services.is_empty() {
                ui.label("No managed services. Start a shell or worker above.");
            } else {
                self.render_service_table(ui, &services);
            }
            ui.separator();
            self.render_terminal(ui, &services);
        });
        self.render_popups(ctx, &services);
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

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "service-mgr demo",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(DemoApp::new(&cc.egui_ctx)))),
    )
}
