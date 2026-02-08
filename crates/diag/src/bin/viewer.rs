//! EGUI diagnostic viewer for nsproxy tun2socks5.
//!
//! Connects to `/nsp3/{profile}/tun_diag.sock` and displays a rolling log
//! of connection events with visual timing indicators.
//!
//! Usage: nsp-diag <instance-name>
//!   e.g. nsp-diag myprofile

#[cfg(feature = "egui-client")]
use nix::sched::CloneFlags;

#[cfg(feature = "egui-client")]
use nsproxy_common::{NsAlive, state_paths};

#[cfg(feature = "egui-client")]
use std::fs::File;

#[cfg(feature = "egui-client")]
use std::os::fd::AsFd;

#[cfg(feature = "egui-client")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "egui-client")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "egui-client")]
static QUERY_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "egui-client")]
fn main() -> eframe::Result<()> {
    use diag::{diag_sock_path, summary::DiagAccumulator, DiagEvent};
    use eframe::egui;
    use egui_extras::{Column, TableBuilder};
    use futures::stream::FuturesUnordered;
    use futures::StreamExt as FuturesStreamExt;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    let (ping_tx, ping_rx) = flume::unbounded::<PingRequest>();

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
    let ping_state: Arc<Mutex<PingState>> = Arc::new(Mutex::new(PingState::default()));
    let mass_ping_state: Arc<Mutex<MassPingState>> =
        Arc::new(Mutex::new(MassPingState::default()));
    let burst_test_state: Arc<Mutex<BurstTestState>> =
        Arc::new(Mutex::new(BurstTestState::default()));
    let selected_conn: Arc<Mutex<Option<diag::ConnId>>> = Arc::new(Mutex::new(None));
    let dns_config: Arc<Mutex<String>> = Arc::new(Mutex::new("8.8.8.8:53".to_string()));
    let events_bg = events.clone();
    let acc_bg = accumulator.clone();
    let connected_bg = connected.clone();
    let conn_error_bg = conn_error.clone();
    let ping_bg = ping_state.clone();
    let mass_ping_bg = mass_ping_state.clone();
    let burst_test_bg = burst_test_state.clone();
    let sock_path_bg = sock_path.clone();
    let ping_rx_bg = ping_rx.clone();
    let dns_config_bg = dns_config.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let ping_state_bg = ping_bg.clone();
            let mass_state_bg = mass_ping_bg.clone();
            let burst_state_bg = burst_test_bg.clone();
            tokio::spawn(async move {
                while let Ok(req) = ping_rx_bg.recv_async().await {
                    match req {
                        PingRequest::Single(domain, dns_addr) => {
                            if let Err(err) = send_dns_ping_async(&dns_addr, domain).await {
                                let mut ping = ping_state_bg.lock().unwrap();
                                ping.last_error = Some(format!("dns ping error: {}", err));
                            }
                        }
                        PingRequest::BurstTest(dns_addr) => {
                            let started = now_epoch_us();
                            {
                                let mut burst = burst_state_bg.lock().unwrap();
                                burst.running = true;
                                burst.started_ts = Some(started);
                                burst.finished_ts = None;
                                burst.results.clear();
                                burst.threshold_size = None;
                                burst.last_error = None;
                            }

                            let test_sizes = vec![10u64, 100, 1000, 10000];
                            let mut threshold_found = false;

                            for size in test_sizes {
                                let now_us = now_epoch_us();
                                let mut domains = Vec::with_capacity(size as usize);
                                for i in 0..size {
                                    domains.push(format!("burst-{}-{}.diag", now_us, i));
                                }

                                let mut tasks = FuturesUnordered::new();
                                for domain in domains {
                                    let dns = dns_addr.clone();
                                    tasks.push(async move {
                                        send_dns_ping_async(&dns, domain).await
                                    });
                                }

                                let mut errs = 0u64;
                                let mut done = 0u64;
                                while let Some(res) = tasks.next().await {
                                    done += 1;
                                    if res.is_err() {
                                        errs += 1;
                                    }
                                }

                                let failure_rate = if done > 0 {
                                    (errs as f64) / (done as f64) * 100.0
                                } else {
                                    0.0
                                };

                                let result = BurstTestResult {
                                    size,
                                    requested: size,
                                    completed: done,
                                    errors: errs,
                                    failure_rate,
                                };

                                {
                                    let mut burst = burst_state_bg.lock().unwrap();
                                    burst.results.push(result.clone());
                                    if !threshold_found && failure_rate > 5.0 {
                                        burst.threshold_size = Some(size);
                                        threshold_found = true;
                                    }
                                }

                                if threshold_found {
                                    break;
                                }
                            }

                            let finished = now_epoch_us();
                            let mut burst = burst_state_bg.lock().unwrap();
                            burst.running = false;
                            burst.finished_ts = Some(finished);
                        }
                        PingRequest::Batch(domains, dns_addr) => {
                            let batch_started = now_epoch_us();
                            let mut tasks = FuturesUnordered::new();
                            for domain in domains {
                                let dns = dns_addr.clone();
                                tasks.push(async move {
                                    send_dns_ping_async(&dns, domain).await
                                });
                            }
                            let mut errs = 0u64;
                            let mut done = 0u64;
                            let mut rtt_sum_us = 0u64;
                            let mut rtt_min_us = u64::MAX;
                            let mut rtt_max_us = 0u64;
                            let mut rtt_samples = 0u64;
                            while let Some(res) = tasks.next().await {
                                done += 1;
                                match res {
                                    Ok(rtt_us) => {
                                        rtt_samples += 1;
                                        rtt_sum_us = rtt_sum_us.saturating_add(rtt_us);
                                        rtt_min_us = rtt_min_us.min(rtt_us);
                                        rtt_max_us = rtt_max_us.max(rtt_us);
                                    }
                                    Err(_) => {
                                        errs += 1;
                                    }
                                }
                            }
                            let batch_finished = now_epoch_us();
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
                                    if let DiagEvent::DnsQuery { id, query, .. } = &event {
                                        if let Some(c) = acc.conns.get(id) {
                                            let mut ping = ping_bg.lock().unwrap();
                                            if let Some(ref last) = ping.last_domain {
                                                if normalize_domain(last) == normalize_domain(query) {
                                                    if let Some(sent_us) = ping.last_sent_us {
                                                        let accept_us = c.accept_ts.0;
                                                        ping.last_accept_delta_us =
                                                            Some(accept_us.saturating_sub(sent_us));
                                                        ping.last_accept_ts = Some(accept_us);
                                                        ping.last_conn_id = Some(id.0);
                                                    }
                                                }
                                            }
                                        }
                                    }
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

            egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("DNS Server:");
                    {
                        let mut dns_addr = dns_config.lock().unwrap();
                        ui.text_edit_singleline(&mut *dns_addr);
                    }
                    
                    if ui.button("Random IP").clicked() {
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        let ip = format!(
                            "{}.{}.{}.{}:53",
                            rng.gen_range(1..=254),
                            rng.gen_range(0..=255),
                            rng.gen_range(0..=255),
                            rng.gen_range(1..=254)
                        );
                        *dns_config.lock().unwrap() = ip;
                    }
                });
                
                ui.horizontal(|ui| {
                    if ui.button("DNS ping").clicked() {
                        let now_us = now_epoch_us();
                        let domain = format!("ping-{}.diag", now_us);
                        let dns_addr = dns_config.lock().unwrap().clone();
                        {
                            let mut ping = ping_state.lock().unwrap();
                            ping.last_domain = Some(domain.clone());
                            ping.last_sent_us = Some(now_us);
                            ping.last_accept_delta_us = None;
                            ping.last_accept_ts = None;
                            ping.last_conn_id = None;
                            ping.last_error = None;
                        }
                        let _ = ping_tx.send(PingRequest::Single(domain, dns_addr));
                    }

                    let burst_running = burst_test_state.lock().unwrap().running;
                    ui.add_enabled_ui(!burst_running, |ui| {
                        if ui.button("Burst Test").on_hover_text("Test burst sizes (10, 100, 1000, 10000) to find >5% failure rate").clicked() {
                            let dns_addr = dns_config.lock().unwrap().clone();
                            let _ = ping_tx.send(PingRequest::BurstTest(dns_addr));
                        }
                    });

                    if ui.button("DNS ping x100").clicked() {
                        let now_us = now_epoch_us();
                        let mut domains = Vec::with_capacity(100);
                        for i in 0..100u64 {
                            domains.push(format!("ping-{}-{}.diag", now_us, i));
                        }
                        let dns_addr = dns_config.lock().unwrap().clone();
                        {
                            let mut mass = mass_ping_state.lock().unwrap();
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
                        let _ = ping_tx.send(PingRequest::Batch(domains, dns_addr));
                    }

                    let ping = ping_state.lock().unwrap();
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
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });

                ui.horizontal(|ui| {
                    let mass = mass_ping_state.lock().unwrap();
                    if let Some(ts) = mass.last_batch {
                        ui.label(format!("batch: {}", ts));
                    }
                    ui.label(format!("requested: {}", mass.requested));
                    ui.label(format!("in_flight: {}", mass.in_flight));
                    ui.label(format!("completed: {}", mass.completed));
                    if let Some(dur) = mass.duration_us {
                        use diag::summary::format_duration_us;
                        ui.label(format!("duration: {}", format_duration_us(dur as f64)));
                        if mass.completed > 0 {
                            let rps = (mass.completed as f64) / (dur as f64 / 1_000_000.0);
                            ui.label(format!("rate: {:.1}/s", rps));
                        }
                    } else if mass.in_flight > 0 {
                        use diag::summary::format_duration_us;
                        if let Some(started) = mass.started_ts {
                            let elapsed = now_epoch_us().saturating_sub(started);
                            ui.label(format!("elapsed: {}", format_duration_us(elapsed as f64)));
                        }
                    }
                    if let Some(avg) = mass.rtt_avg_us {
                        use diag::summary::format_duration_us;
                        let min = mass.rtt_min_us.unwrap_or(avg);
                        let max = mass.rtt_max_us.unwrap_or(avg);
                        ui.label(format!(
                            "rtt avg/min/max: {} / {} / {} (n={})",
                            format_duration_us(avg as f64),
                            format_duration_us(min as f64),
                            format_duration_us(max as f64),
                            mass.rtt_samples
                        ));
                    }
                    if mass.errors > 0 {
                        ui.colored_label(egui::Color32::RED, format!("errors: {}", mass.errors));
                    }
                    if let Some(err) = mass.last_error.as_ref() {
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });

                ui.horizontal(|ui| {
                    let burst = burst_test_state.lock().unwrap();
                    if burst.running {
                        ui.label("⏳ Burst test running...");
                        if let Some(started) = burst.started_ts {
                            let elapsed = now_epoch_us().saturating_sub(started);
                            use diag::summary::format_duration_us;
                            ui.label(format!("elapsed: {}", format_duration_us(elapsed as f64)));
                        }
                    } else if !burst.results.is_empty() {
                        ui.label("Burst test results:");
                        for result in &burst.results {
                            let color = if result.failure_rate > 5.0 {
                                egui::Color32::RED
                            } else if result.failure_rate > 1.0 {
                                egui::Color32::YELLOW
                            } else {
                                egui::Color32::GREEN
                            };
                            ui.colored_label(
                                color,
                                format!(
                                    "n={}: {}/{} ({:.1}% err)",
                                    result.size,
                                    result.completed.saturating_sub(result.errors),
                                    result.requested,
                                    result.failure_rate
                                ),
                            );
                        }
                        if let Some(threshold) = burst.threshold_size {
                            ui.colored_label(
                                egui::Color32::RED,
                                format!("⚠ Threshold: >5% failures at n={}", threshold),
                            );
                        } else {
                            ui.colored_label(egui::Color32::GREEN, "✓ All tests passed (<5% failures)");
                        }
                    }
                    if let Some(err) = burst.last_error.as_ref() {
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });

                ui.separator();
                let acc = accumulator.lock().unwrap();
                let selected = *selected_conn.lock().unwrap();
                if let Some(id) = selected {
                    if let Some(c) = acc.conns.get(&id) {
                        ui.heading(format!("Connection {}", c.id.0));
                        ui.label(format!("kind: {}", c.kind));
                        ui.label(format!("src: {}", c.src));
                        ui.label(format!("dst: {}", c.dst));
                        if !c.route.is_empty() {
                            ui.label(format!("route: {}", c.route));
                        }
                        ui.label(format!("accept_ts: {}", c.accept_ts.0));
                        if let Some(ts) = c.connected_ts {
                            ui.label(format!("connected_ts: {}", ts.0));
                        }
                        if let Some(ts) = c.finished_ts {
                            ui.label(format!("finished_ts: {}", ts.0));
                        }
                        ui.label(format!("dispatch_us: {}", c.dispatch_us));
                        if let Some(ref q) = c.dns_query {
                            ui.label(format!("dns_query: {}", q));
                        }
                        if let Some(ref r) = c.dns_response {
                            ui.label(format!("dns_response: {}", r));
                        }
                        if let Some(ref err) = c.error {
                            ui.colored_label(egui::Color32::RED, format!("error: {}", err));
                        }
                        ui.label(format!("bytes_up: {}  bytes_down: {}", c.bytes_up, c.bytes_down));
                    } else {
                        ui.label("Selected connection not found");
                    }
                } else {
                    ui.label("Select a connection row to see details");
                }
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                let acc = accumulator.lock().unwrap();
                let selected = *selected_conn.lock().unwrap();
                let row_height = 18.0;
                egui::ScrollArea::horizontal().show(ui, |ui| {
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
                                        let is_selected = selected == Some(c.id);
                                        if ui.selectable_label(is_selected, format!("{}", c.id.0)).clicked() {
                                            *selected_conn.lock().unwrap() = Some(c.id);
                                        }
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
                                        match (&c.dns_query, &c.dns_response) {
                                            (Some(q), Some(r)) => {
                                                ui.label(format!("{} -> {}", q, r));
                                            }
                                            (Some(q), None) => {
                                                ui.label(format!("{} -> …", q));
                                            }
                                            _ => {}
                                        }
                                    });

                                    row.col(|ui| {
                                        use diag::summary::format_duration_us;
                                        let color = if c.kind == "Wait" {
                                            egui::Color32::LIGHT_BLUE
                                        } else if c.dispatch_us > 1000 {
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
            });

            // Repaint periodically to show updates
            ctx.request_repaint_after(Duration::from_millis(500));
        },
    )
}

#[derive(Debug, Default)]
struct PingState {
    last_domain: Option<String>,
    last_sent_us: Option<u64>,
    last_accept_delta_us: Option<u64>,
    last_accept_ts: Option<u64>,
    last_conn_id: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Default)]
struct MassPingState {
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
struct BurstTestResult {
    size: u64,
    requested: u64,
    completed: u64,
    errors: u64,
    failure_rate: f64,
}

#[derive(Debug, Default)]
struct BurstTestState {
    running: bool,
    started_ts: Option<u64>,
    finished_ts: Option<u64>,
    results: Vec<BurstTestResult>,
    threshold_size: Option<u64>,
    last_error: Option<String>,
}

enum PingRequest {
    Single(String, String),  // domain, dns_address
    Batch(Vec<String>, String),  // domains, dns_address
    BurstTest(String),  // dns_address
}

fn now_epoch_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
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

async fn send_dns_ping_async(target: &str, domain: String) -> anyhow::Result<u64> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    let id = (QUERY_ID_COUNTER.fetch_add(1, Ordering::SeqCst) & 0xFFFF) as u16;
    let query = build_dns_query(&domain, id);
    let start = tokio::time::Instant::now();
    let _ = sock.send_to(&query, target).await?;

    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(20_000), sock.recv_from(&mut buf)).await??;
    let rtt = start.elapsed().as_micros() as u64;

    Ok(rtt)
}

fn enter_instance_namespace(instance_name: &str) -> anyhow::Result<()> {
    let ns_path = state_paths::profile_netns_bind(instance_name);
    let ns_meta = state_paths::profile_ns_meta(instance_name);

    let ns_alive: Option<NsAlive> = if ns_meta.exists() {
        std::fs::read_to_string(&ns_meta)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
    } else {
        None
    };

    if let Some(ns_alive) = ns_alive {
        if let Some(child_pid) = ns_alive.child_pid {
            let mnt_path = format!("/proc/{}/ns/mnt", child_pid);
            let net_path = format!("/proc/{}/ns/net", child_pid);
            let mnt = File::open(mnt_path)?;
            nix::sched::setns(mnt.as_fd(), CloneFlags::CLONE_NEWNS)?;
            let net = File::open(net_path)?;
            nix::sched::setns(net.as_fd(), CloneFlags::CLONE_NEWNET)?;
            return Ok(());
        }
    }

    let net = File::open(ns_path)?;
    nix::sched::setns(net.as_fd(), CloneFlags::CLONE_NEWNET)?;

    Ok(())
}

#[cfg(not(feature = "egui-client"))]
fn main() {
    eprintln!("This binary requires the 'egui-client' feature. Build with:");
    eprintln!("  cargo build -p diag --features egui-client --bin nsp-diag");
    std::process::exit(1);
}
