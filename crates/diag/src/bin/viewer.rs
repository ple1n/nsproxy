//! EGUI diagnostic viewer for nsproxy tun2socks5.
//!
//! Connects to `/nsp3/{profile}/tun_diag.sock` and displays a rolling log
//! of connection events with visual timing indicators.
//!
//! Usage: nsp-diag <instance-name>
//!   e.g. nsp-diag myprofile

#[cfg(feature = "egui-client")]
fn main() -> eframe::Result<()> {
    use diag::{diag_sock_path, summary::DiagAccumulator, DiagEvent};
    use eframe::egui;
    use egui_extras::{Column, TableBuilder};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nsp-diag <instance-name>");
        eprintln!("  Connects to /nsp3/<name>/tun_diag.sock");
        std::process::exit(1);
    }
    let instance_name = args[1].clone();
    let sock_path = diag_sock_path(&instance_name);

    let events: Arc<Mutex<VecDeque<DiagEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
    let accumulator: Arc<Mutex<DiagAccumulator>> =
        Arc::new(Mutex::new(DiagAccumulator::new(2000, 500)));
    let connected: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let conn_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Spawn a background tokio runtime for reading from the socket
    let events_bg = events.clone();
    let acc_bg = accumulator.clone();
    let connected_bg = connected.clone();
    let conn_error_bg = conn_error.clone();
    let sock_path_bg = sock_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            loop {
                match diag::connect(&sock_path_bg).await {
                    Ok(mut stream) => {
                        *connected_bg.lock().unwrap() = true;
                        *conn_error_bg.lock().unwrap() = None;
                        loop {
                            match stream.next().await {
                                Ok(Some(event)) => {
                                    let mut acc = acc_bg.lock().unwrap();
                                    acc.ingest(&event);
                                    let mut evts = events_bg.lock().unwrap();
                                    evts.push_back(event);
                                    if evts.len() > 5000 {
                                        evts.pop_front();
                                    }
                                }
                                Ok(None) => {
                                    *connected_bg.lock().unwrap() = false;
                                    break;
                                }
                                Err(e) => {
                                    *connected_bg.lock().unwrap() = false;
                                    *conn_error_bg.lock().unwrap() =
                                        Some(format!("read error: {}", e));
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        *connected_bg.lock().unwrap() = false;
                        *conn_error_bg.lock().unwrap() = Some(format!("{}", e));
                    }
                }
                // Retry after delay
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 700.0]),
        ..Default::default()
    };

    eframe::run_simple_native(
        &format!("nsp-diag: {}", instance_name),
        options,
        move |ctx, _frame| {
            egui::TopBottomPanel::top("header").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("nsproxy diagnostics");
                    ui.separator();
                    let is_connected = *connected.lock().unwrap();
                    if is_connected {
                        ui.colored_label(egui::Color32::GREEN, "⬤ connected");
                    } else {
                        ui.colored_label(egui::Color32::RED, "⬤ disconnected");
                        if let Some(err) = conn_error.lock().unwrap().as_ref() {
                            ui.label(err.as_str());
                        }
                    }
                    ui.separator();
                    ui.label(format!("socket: {}", sock_path.display()));
                });

                // Loop stats
                let acc = accumulator.lock().unwrap();
                ui.horizontal(|ui| {
                    use diag::summary::format_duration_us;
                    ui.label(format!(
                        "loop body — avg: {}  max: {}  min: {}  samples: {}",
                        format_duration_us(acc.loop_stats.avg_us()),
                        format_duration_us(acc.loop_stats.max_us() as f64),
                        format_duration_us(acc.loop_stats.min_us() as f64),
                        acc.loop_stats.recent.len(),
                    ));
                    ui.separator();
                    ui.label(format!("connections tracked: {}", acc.conns.len()));
                });
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                let acc = accumulator.lock().unwrap();
                let row_height = 18.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::auto().at_least(60.0))
                    .column(Column::auto().at_least(80.0))
                    .column(Column::auto().at_least(120.0))
                    .column(Column::remainder().at_least(160.0))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::auto().at_least(80.0))
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
                            ui.strong("Dispatch");
                        });
                        header.col(|ui| {
                            ui.strong("Connect Lat");
                        });
                        header.col(|ui| {
                            ui.strong("Duration");
                        });
                        header.col(|ui| {
                            ui.strong("Status");
                        });
                    })
                    .body(|mut body| {
                        body.rows(row_height, acc.conn_order.len(), |mut row| {
                            let conn_id = &acc.conn_order[row.index()];
                            if let Some(c) = acc.conns.get(conn_id) {
                                row.col(|ui| {
                                    ui.label(format!("{}", c.id.0));
                                });
                                row.col(|ui| {
                                    ui.label(&c.kind);
                                });
                                row.col(|ui| {
                                    ui.label(&c.src);
                                });
                                row.col(|ui| {
                                    let dest_label = if c.route.is_empty() {
                                        c.dst.clone()
                                    } else {
                                        c.route.clone()
                                    };
                                    ui.label(&dest_label);
                                });

                                row.col(|ui| {
                                    use diag::summary::format_duration_us;
                                    let color = if c.dispatch_us > 1000 {
                                        egui::Color32::RED
                                    } else if c.dispatch_us > 100 {
                                        egui::Color32::YELLOW
                                    } else {
                                        egui::Color32::GREEN
                                    };
                                    ui.colored_label(color, format_duration_us(c.dispatch_us as f64));
                                });

                                row.col(|ui| {
                                    if let Some(lat) = c.connect_latency() {
                                        use diag::summary::format_duration_us;
                                        let us = lat.as_secs_f64() * 1_000_000.0;
                                        let color = if us > 500_000.0 {
                                            egui::Color32::RED
                                        } else if us > 100_000.0 {
                                            egui::Color32::YELLOW
                                        } else {
                                            egui::Color32::GREEN
                                        };
                                        ui.colored_label(color, format_duration_us(us));
                                    } else {
                                        ui.label("…");
                                    }
                                });

                                row.col(|ui| {
                                    if let Some(dur) = c.total_duration() {
                                        use diag::summary::format_duration_us;
                                        let us = dur.as_secs_f64() * 1_000_000.0;
                                        ui.label(format_duration_us(us));
                                    } else {
                                        ui.label("active");
                                    }
                                });

                                row.col(|ui| {
                                    if let Some(ref err) = c.error {
                                        ui.colored_label(
                                            egui::Color32::RED,
                                            format!("{}", &err[..err.len().min(40)]),
                                        );
                                    } else if c.finished_ts.is_some() {
                                        ui.colored_label(egui::Color32::GREEN, "OK");
                                    }
                                });
                            }
                        });
                    });
            });

            // Repaint periodically to show updates
            ctx.request_repaint_after(Duration::from_millis(500));
        },
    )
}

#[cfg(not(feature = "egui-client"))]
fn main() {
    eprintln!("This binary requires the 'egui-client' feature. Build with:");
    eprintln!("  cargo build -p diag --features egui-client --bin nsp-diag");
    std::process::exit(1);
}
