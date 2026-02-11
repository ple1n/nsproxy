use std::time::Duration;
use tokio::runtime::Handle;
use eframe::egui;
use flume::{Sender, Receiver};

struct App {
    updates_rx: Receiver<u32>,
    updates_tx: Sender<u32>,
    rt: Option<Handle>,
    last: Option<u32>,
}

impl App {
    fn new(rx: Receiver<u32>, tx: Sender<u32>, rt: Handle) -> Self {
        Self { updates_rx: rx, updates_tx: tx, rt: Some(rt), last: None }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(val) = self.updates_rx.try_recv() {
            self.last = Some(val);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if ui.button("Spawn async task (1s)").clicked() {
                if let Some(handle) = self.rt.as_ref() {
                    let tx = self.updates_tx.clone();
                    let ctx_clone = ctx.clone();
                    let handle = handle.clone();
                    handle.spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let _ = tx.send(42);
                        ctx_clone.request_repaint();
                    });
                }
            }

            ui.label(match self.last { Some(v) => format!("Last update: {}", v), None => "No updates yet".to_owned() });
        });
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let rt_handle = rt.handle().clone();

    let (tx, rx) = flume::unbounded::<u32>();

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "nsproxy-ui demo",
        native_options,
        Box::new(move |_cc| Box::new(App::new(rx, tx, rt_handle))),
    );
}
