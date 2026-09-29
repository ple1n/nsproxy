use std::collections::HashMap;
use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::term::{self, test::TermSize, Term};
use alacritty_terminal::vte::ansi::Processor;
use eframe::egui;
use service_mgr::{
    ServiceEvent, ServiceId, ServiceInfo, ServiceManager, ServiceSpec, ServiceState,
};

struct PtyWriter {
    id: ServiceId,
    replies: mpsc::Sender<(ServiceId, String)>,
}

impl EventListener for PtyWriter {
    fn send_event(&self, event: Event) {
        if let Event::PtyWrite(data) = event {
            let _ = self.replies.send((self.id, data));
        }
    }
}

struct TerminalState {
    terminal: Term<PtyWriter>,
    processor: Processor,
}

impl TerminalState {
    fn new(id: ServiceId, replies: mpsc::Sender<(ServiceId, String)>) -> Self {
        Self {
            terminal: Term::new(
                term::Config::default(),
                &TermSize::new(100, 30),
                PtyWriter { id, replies },
            ),
            processor: Processor::new(),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        self.processor.advance(&mut self.terminal, data);
    }

    fn text(&self) -> String {
        let grid = self.terminal.grid();
        let mut text = String::new();
        for indexed in grid.display_iter() {
            if indexed.point.column.0 == 0 && !text.is_empty() {
                text.push('\n');
            }
            text.push(indexed.c);
        }
        text
    }
}

struct DemoApp {
    manager: ServiceManager,
    events: mpsc::Receiver<ServiceEvent>,
    replies: mpsc::Receiver<(ServiceId, String)>,
    reply_tx: mpsc::Sender<(ServiceId, String)>,
    terminals: HashMap<ServiceId, TerminalState>,
    selected: Option<ServiceId>,
    input: String,
    notice: String,
}

impl DemoApp {
    fn new() -> Self {
        let (manager, handle) = ServiceManager::new();
        let (reply_tx, replies) = mpsc::channel();
        Self {
            manager,
            events: handle.events,
            replies,
            reply_tx,
            terminals: HashMap::new(),
            selected: None,
            input: String::new(),
            notice: "No services".to_string(),
        }
    }

    fn spawn(&mut self, spec: ServiceSpec) {
        match self.manager.spawn_pty(spec) {
            Ok(id) => {
                self.terminals
                    .insert(id, TerminalState::new(id, self.reply_tx.clone()));
                self.selected = Some(id);
                self.notice = format!("Started service {id}");
            }
            Err(error) => self.notice = error.to_string(),
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

    fn poll(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(ServiceEvent::Output { id, chunk }) => {
                    if let Some(terminal) = self.terminals.get_mut(&id) {
                        terminal.feed(&chunk.data);
                    }
                }
                Ok(ServiceEvent::StateChanged { id, state }) => {
                    self.notice = format!("Service {id} changed to {state:?}");
                }
                Ok(ServiceEvent::Started { .. }) => {}
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }

        while let Ok((id, reply)) = self.replies.try_recv() {
            let _ = self.manager.write_input(id, reply.as_bytes());
        }
    }

    fn selected_info<'a>(&self, services: &'a [ServiceInfo]) -> Option<&'a ServiceInfo> {
        self.selected
            .and_then(|id| services.iter().find(|service| service.id == id))
    }

    fn render_service_table(&mut self, ui: &mut egui::Ui, services: &[ServiceInfo]) {
        egui::Grid::new("service-list")
            .striped(true)
            .min_col_width(44.0)
            .show(ui, |ui| {
                for heading in [
                    "ID", "PID", "State", "Program", "Uptime", "Terminal", "Kill",
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
                    if ui.button("View").clicked() {
                        self.selected = Some(service.id);
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
                            self.notice = error.to_string();
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
        ui.horizontal(|ui| {
            ui.strong(format!(
                "Embedded terminal — {} ({})",
                info.command.display(),
                id
            ));
            ui.label(state_label(info.state));
        });
        ui.separator();
        if let Some(terminal) = self.terminals.get(&id) {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .max_height(360.0)
                .show(ui, |ui| {
                    ui.monospace(terminal.text());
                });
        }
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.input).hint_text("Type input and press Enter"),
        );
        if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
            let input = std::mem::take(&mut self.input);
            let _ = self
                .manager
                .write_input(id, format!("{input}\n").as_bytes());
            response.request_focus();
        }
    }
}

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
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
                ui.label(&self.notice);
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

        ctx.request_repaint_after(Duration::from_millis(50));
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
        Box::new(|_cc| Ok(Box::new(DemoApp::new()))),
    )
}
