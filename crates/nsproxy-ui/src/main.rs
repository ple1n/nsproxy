use eframe::egui;
use egui_extras::{Column, TableBuilder};

#[derive(Clone, Default)]
struct Profile {
    name: String,
    status: String,
    proxies: Vec<String>,
    instantiated: bool,
}

#[derive(Clone)]
struct Proxy {
    name: String,
    url: String,
    udp_capable: bool,
    status: String,
    enabled_globally: bool,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Selected {
    Global,
    Profile(usize),
}

impl Default for Selected {
    fn default() -> Self { Selected::Global }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum RightTab {
    Proxies,
    Processes,
    Diagnostics,
    Dns,
}

struct App {
    profiles: Vec<Profile>,
    selected: Selected,
    right_tab: RightTab,
    proxies: Vec<Proxy>,
    hovered_proxy: Option<usize>,
}

impl Default for App {
    fn default() -> Self {
        let mut proxies = Vec::new();
        for i in 0..24 {
            let udp_capable = i % 3 == 1;
            let enabled_globally = i % 5 == 0;
            let status = if i % 7 == 0 { "TCP OK" } else { "idle" };
            let name = format!("proxy-{}", (b'a' + (i % 26) as u8) as char);
            let url = if i % 2 == 0 {
                format!("proxy-{}.local:{}", i + 1, 8000 + i as u16)
            } else {
                format!("proxy-{}.remote:{}", i + 1, 3000 + i as u16)
            };
            proxies.push(Proxy {
                name,
                url,
                udp_capable,
                status: status.to_owned(),
                enabled_globally,
            });
        }

        let profiles = vec![
            Profile { name: "office".into(), status: "stopped".into(), proxies: vec![], instantiated: false },
            Profile { name: "guest".into(), status: "running".into(), proxies: vec![proxies[0].url.clone()], instantiated: true },
            Profile { name: "dev".into(), status: "stopped".into(), proxies: vec![], instantiated: false },
        ];

        Self { profiles, selected: Selected::Global, right_tab: RightTab::Proxies, proxies, hovered_proxy: None }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        use egui::Color32;

        egui::SidePanel::left("left_sidebar").resizable(false).default_width(280.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Network Namespaces");
            });

            ui.add_space(6.0);

            // Global configuration box at the top
            let global_selected = matches!(self.selected, Selected::Global);
            let global_status_color = egui::Color32::from_rgb(100, 150, 240);
            if sidebar_box(ui, "Global Configuration", "Apply proxy configuration globally", global_selected, global_status_color).clicked() {
                self.selected = Selected::Global;
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            // Profiles
            for (i, profile) in self.profiles.iter().enumerate() {
                let is_selected = matches!(self.selected, Selected::Profile(idx) if idx == i);
                let status_color = if profile.instantiated { Color32::LIGHT_GREEN } else { Color32::LIGHT_RED };
                if sidebar_box(ui, &profile.name, &profile.status, is_selected, status_color).clicked() {
                    self.selected = Selected::Profile(i);
                }
                ui.add_space(6.0);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Tabs
            ui.horizontal(|ui| {
                if ui.selectable_label(self.right_tab == RightTab::Proxies, "Proxies").clicked() {
                    self.right_tab = RightTab::Proxies;
                }
                if ui.selectable_label(self.right_tab == RightTab::Processes, "Processes").clicked() {
                    self.right_tab = RightTab::Processes;
                }
                if ui.selectable_label(self.right_tab == RightTab::Diagnostics, "Diagnostics").clicked() {
                    self.right_tab = RightTab::Diagnostics;
                }
                if ui.selectable_label(self.right_tab == RightTab::Dns, "DNS").clicked() {
                    self.right_tab = RightTab::Dns;
                }
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            match self.right_tab {
                RightTab::Proxies => {
                    let header_h = 28.0;
                    let row_h = 96.0;
                    let mut next_hovered_proxy: Option<usize> = None;

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        TableBuilder::new(ui)
                            .striped(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::exact(160.0))
                            .column(Column::remainder())
                            .column(Column::exact(120.0))
                            .header(header_h, |mut header| {
                                header.col(|ui| { ui.strong("Name"); });
                                header.col(|ui| { ui.strong("Proxy URL"); });
                                header.col(|ui| { ui.strong("Status"); });
                            })
                            .body(|mut body| {
                                let widths = body.widths().to_vec();
                                let spacing_x = body.ui_mut().spacing().item_spacing.x;
                                let row_width = widths.iter().sum::<f32>()
                                    + spacing_x * (widths.len().saturating_sub(1) as f32);

                                body.rows(row_h, self.proxies.len(), |mut row| {
                                    let i = row.index();
                                    let mut row_hot = false;
                                    let mut is_active = false;

                                    row.col(|ui| {
                                        ui.vertical(|ui| {
                                            let resp = ui.label(egui::RichText::new(&self.proxies[i].name).strong());
                                            let row_rect = egui::Rect::from_min_size(
                                                resp.rect.min,
                                                egui::vec2(row_width, row_h),
                                            );
                                            let pointer_pos = ui.ctx().input(|i| {
                                                i.pointer.interact_pos().or(i.pointer.hover_pos())
                                            });
                                            row_hot = pointer_pos.is_some_and(|pos| row_rect.contains(pos));
                                            is_active = row_hot || self.hovered_proxy == Some(i);

                                            if is_active {
                                                ui.small(format!("Status: {}", self.proxies[i].status));
                                            } else if self.proxies[i].udp_capable {
                                                ui.small("UDP + TCP");
                                            } else {
                                                ui.small("TCP only");
                                            }
                                        });
                                    });

                                    row.col(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(&self.proxies[i].url);
                                            if is_active {
                                                ui.add_space(4.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    ui.checkbox(&mut self.proxies[i].enabled_globally, "Enabled globally");

                                                    if let Selected::Profile(pidx) = self.selected {
                                                        if let Some(profile) = self.profiles.get_mut(pidx) {
                                                            let mut assigned = profile.proxies.contains(&self.proxies[i].url);
                                                            if ui.checkbox(&mut assigned, "Assigned").changed() {
                                                                if assigned {
                                                                    profile.proxies.push(self.proxies[i].url.clone());
                                                                } else {
                                                                    profile.proxies.retain(|x| x != &self.proxies[i].url);
                                                                }
                                                            }
                                                        }
                                                    }

                                                    if ui.button("Test TCP").clicked() {
                                                        self.proxies[i].status = "TCP OK".to_owned();
                                                    }
                                                    if self.proxies[i].udp_capable && ui.button("Test DNS").clicked() {
                                                        self.proxies[i].status = "DNS OK".to_owned();
                                                    }
                                                });
                                                ui.small("Hover the row to show controls and status.");
                                            } else {
                                                ui.small("Hover for controls");
                                            }
                                        });
                                    });

                                    row.col(|ui| {
                                        let status = &self.proxies[i].status;
                                        let status_color = if status.contains("OK") {
                                            egui::Color32::LIGHT_GREEN
                                        } else {
                                            egui::Color32::from_gray(160)
                                        };
                                        ui.vertical(|ui| {
                                            ui.colored_label(status_color, status);
                                            if is_active {
                                                let enabled = if self.proxies[i].enabled_globally { "on" } else { "off" };
                                                ui.small(format!("Global: {}", enabled));
                                            }
                                        });
                                    });

                                    if row_hot {
                                        next_hovered_proxy = Some(i);
                                    }
                                });
                            });
                    });

                    self.hovered_proxy = next_hovered_proxy;

                    ui.add_space(8.0);
                    if ui.button("Apply enabled-to-all profiles").clicked() {
                        for profile in &mut self.profiles {
                            profile.proxies.clear();
                            for p in &self.proxies {
                                if p.enabled_globally {
                                    profile.proxies.push(p.url.clone());
                                }
                            }
                        }
                    }
                }

                RightTab::Processes => {
                    if matches!(self.selected, Selected::Global) {
                        ui.heading("Global Processes");
                        ui.label("No global processes available (placeholder).");
                    } else if let Selected::Profile(idx) = self.selected {
                        if let Some(profile) = self.profiles.get(idx) {
                            ui.heading(format!("Processes — {}", profile.name));
                            ui.label("No processes tracked for this profile (placeholder).");
                        } else {
                            ui.label("Profile not found");
                        }
                    }
                }

                RightTab::Diagnostics => {
                    if matches!(self.selected, Selected::Global) {
                        ui.heading("Diagnostics — Global");
                        ui.label(format!("Profiles: {}", self.profiles.len()));
                        let running = self.profiles.iter().filter(|p| p.instantiated).count();
                        ui.label(format!("Running: {}", running));
                    } else if let Selected::Profile(idx) = self.selected {
                        if let Some(profile) = self.profiles.get(idx) {
                            ui.heading(format!("Diagnostics — {}", profile.name));
                            ui.label(format!("Status: {}", profile.status));
                            ui.label(format!("Proxies: {}", profile.proxies.join(", ")));
                        } else {
                            ui.label("Profile not found");
                        }
                    }
                }

                RightTab::Dns => {
                    ui.heading("DNS");
                    ui.label("DNS settings are not implemented yet (placeholder).");
                }
            }
        });
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
    use eframe::egui::{Align2, FontId, Stroke};

    let desired = ui.available_size_before_wrap();
    let width = desired.x.max(220.0).min(ui.available_width());
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
    let avatar_center = rect.min + eframe::egui::vec2(12.0 + avatar_radius, rect.height() / 2.0 - 2.0);
    let avatar_fill = if selected { status_color } else { status_color.linear_multiply(0.9) };
    ui.painter().circle_filled(avatar_center, avatar_radius, avatar_fill);

    // Initial letter inside avatar
    let initial = title.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "?".to_string());
    ui.painter().text(avatar_center, Align2::CENTER_CENTER, initial, FontId::proportional(16.0), eframe::egui::Color32::WHITE);

    // Title & subtitle
    let text_x = avatar_center.x + avatar_radius + 12.0;
    let name_pos = eframe::egui::pos2(text_x, rect.min.y + 12.0);
    let status_pos = eframe::egui::pos2(text_x, rect.min.y + 34.0);
    ui.painter().text(name_pos, Align2::LEFT_TOP, title, FontId::proportional(16.0), visuals.text_color());
    ui.painter().text(status_pos, Align2::LEFT_TOP, subtitle, FontId::proportional(12.0), visuals.widgets.inactive.fg_stroke.color);

    // Status dot on the top-right
    let dot_center = rect.right_top() + eframe::egui::vec2(-18.0, 18.0);
    ui.painter().circle_filled(dot_center, 6.0, status_color);

    resp
}

fn main() {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "nsproxy - dashboard",
        native_options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    );
}
