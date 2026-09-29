use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::Grid;
use alacritty_terminal::term::{self, test::TermSize, Term};
use alacritty_terminal::vte::ansi::Processor;
use eframe::egui;
use service_mgr::{ServiceEvent, ServiceManager, ServiceSpec};

struct PtyWriter {
    replies: std::sync::mpsc::Sender<String>,
}

impl EventListener for PtyWriter {
    fn send_event(&self, event: Event) {
        if let Event::PtyWrite(data) = event {
            let _ = self.replies.send(data);
        }
    }
}

struct DemoApp {
    manager: ServiceManager,
    events: std::sync::mpsc::Receiver<ServiceEvent>,
    service: Option<service_mgr::ServiceId>,
    output: Vec<u8>,
    terminal: Term<PtyWriter>,
    processor: Processor,
    replies: std::sync::mpsc::Receiver<String>,
    status: String,
}

impl DemoApp {
    fn new() -> Self {
        let (manager, handle) = ServiceManager::new();
        let (reply_tx, replies) = std::sync::mpsc::channel();
        Self {
            manager,
            events: handle.events,
            service: None,
            output: Vec::new(),
            terminal: Term::new(
                term::Config::default(),
                &TermSize::new(100, 30),
                PtyWriter { replies: reply_tx },
            ),
            processor: Processor::new(),
            replies,
            status: "Stopped".to_string(),
        }
    }

    fn start(&mut self) {
        if self.service.is_some() {
            return;
        }
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec![
            "-c".to_string(),
            "printf 'service-mgr demo\\n'; exec sh".to_string(),
        ];
        spec.rows = 30;
        spec.cols = 100;
        match self.manager.spawn_pty(spec) {
            Ok(id) => {
                self.service = Some(id);
                self.status = format!("Running {id:?}");
            }
            Err(error) => self.status = error.to_string(),
        }
    }

    fn stop(&mut self) {
        if let Some(id) = self.service {
            if let Err(error) = self.manager.terminate(id) {
                self.status = error.to_string();
            } else {
                self.status = "Stopping".to_string();
            }
        }
    }

    fn poll(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(ServiceEvent::Output { chunk, .. }) => {
                    self.output.extend_from_slice(&chunk.data);
                    self.processor.advance(&mut self.terminal, &chunk.data);
                }
                Ok(ServiceEvent::StateChanged { state, .. }) => {
                    self.status = format!("{state:?}");
                    if matches!(
                        state,
                        service_mgr::ServiceState::Exited(_)
                            | service_mgr::ServiceState::Signaled(_)
                    ) {
                        self.service = None;
                    }
                }
                Ok(ServiceEvent::Started { .. }) => {}
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        while let Ok(reply) = self.replies.try_recv() {
            if let Some(id) = self.service {
                let _ = self.manager.write_input(id, reply.as_bytes());
            }
        }
    }

    fn terminal_text(&self) -> String {
        let grid: &Grid<_> = self.terminal.grid();
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

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Start shell").clicked() {
                    self.start();
                }
                if ui.button("Stop").clicked() {
                    self.stop();
                }
                ui.label(&self.status);
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.monospace(self.terminal_text());
                });
            ui.separator();
            ui.small(format!("raw PTY bytes: {}", self.output.len()));
        });
        ctx.request_repaint_after(Duration::from_millis(30));
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "service-mgr demo",
        eframe::NativeOptions::default(),
        Box::new(|_cc| Ok(Box::new(DemoApp::new()))),
    )
}
