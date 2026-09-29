use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use egui::text::{LayoutJob, TextFormat};
use service_mgr::{
    OutputCursor, Ownership, ServiceEvent, ServiceId, ServiceInfo, ServiceKind, ServiceManager,
    ServiceSpec, ServiceState,
};
use term_view::{PtyIpc, TermSession, TermView, flush_term_outputs, pump_pty_io};

const MAX_INCOMING_BYTES: usize = 256 * 1024;
const MAX_LOG_LINES: usize = 100_000;
const LOG_PREFIX_WIDTH: usize = 32;
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

#[derive(Clone)]
struct LogSpan {
    text: String,
    color: egui::Color32,
    bold: bool,
}

#[derive(Clone, Default)]
struct LogLine {
    spans: Vec<LogSpan>,
    plain: String,
}

trait LogItem: Clone {
    fn to_text(&self) -> String;
}

impl LogItem for LogLine {
    fn to_text(&self) -> String {
        self.plain.clone()
    }
}

struct LogViewer<I: LogItem = LogLine> {
    items: Mutex<VecDeque<I>>,
    pending: Mutex<HashMap<(ServiceId, u8), I>>,
    text_cache: Mutex<HashMap<u64, Arc<str>>>,
    color: Mutex<egui::Color32>,
    bold: Mutex<bool>,
    selection: Mutex<Option<((usize, usize), (usize, usize))>>,
    drag_origin: Mutex<Option<(usize, f32)>>,
}

impl Default for LogViewer<LogLine> {
    fn default() -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            pending: Mutex::new(HashMap::new()),
            text_cache: Mutex::new(HashMap::new()),
            color: Mutex::new(egui::Color32::LIGHT_GRAY),
            bold: Mutex::new(false),
            selection: Mutex::new(None),
            drag_origin: Mutex::new(None),
        }
    }
}

impl LogViewer<LogLine> {
    fn cached_text(&self, item: &LogLine) -> Arc<str> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        item.plain.hash(&mut hasher);
        for span in &item.spans {
            span.text.hash(&mut hasher);
            span.color.hash(&mut hasher);
            span.bold.hash(&mut hasher);
        }
        let key = hasher.finish();
        let mut cache = self
            .text_cache
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Arc::clone(
            cache
                .entry(key)
                .or_insert_with(|| Arc::<str>::from(item.to_text())),
        )
    }

    fn push(&self, text: String) {
        let mut item = LogLine::default();
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    let mut code = String::new();
                    while let Some(next) = chars.next() {
                        if next.is_ascii_alphabetic() {
                            if next == 'm' {
                                self.apply_sgr(&code);
                            }
                            break;
                        }
                        code.push(next);
                    }
                }

                continue;
            }
            let color = *self.color.lock().unwrap_or_else(|error| error.into_inner());
            let bold = *self.bold.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(span) = item.spans.last_mut() {
                if span.color == color && span.bold == bold {
                    span.text.push(ch);
                } else {
                    item.spans.push(LogSpan {
                        text: ch.to_string(),
                        color,
                        bold,
                    });
                }
            } else {
                item.spans.push(LogSpan {
                    text: ch.to_string(),
                    color,
                    bold,
                });
            }
            item.plain.push(ch);
        }
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        items.push_back(item);
        while items.len() > MAX_LOG_LINES {
            items.pop_front();
        }
    }

    fn append_stream(&self, key: (ServiceId, u8), prefix: &str, text: &str) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut item = pending.remove(&key).unwrap_or_default();
        let mut completed_items = Vec::new();
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if item.plain.is_empty() {
                self.append_plain(&mut item, prefix);
            }
            if ch == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    let mut code = String::new();
                    while let Some(next) = chars.next() {
                        if next.is_ascii_alphabetic() {
                            if next == 'm' {
                                self.apply_sgr(&code);
                            }
                            break;
                        }
                        code.push(next);
                    }
                }
                continue;
            }
            let color = *self.color.lock().unwrap_or_else(|error| error.into_inner());
            let bold = *self.bold.lock().unwrap_or_else(|error| error.into_inner());
            self.append_char(&mut item, ch, color, bold);
            if ch == '\n' {
                completed_items.push(std::mem::take(&mut item));
            }
        }
        if !item.plain.is_empty() {
            pending.insert(key, item);
        }
        drop(pending);
        if !completed_items.is_empty() {
            let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
            items.extend(completed_items);
            while items.len() > MAX_LOG_LINES {
                items.pop_front();
            }
        }
    }

    fn flush_stream(&self, key: (ServiceId, u8)) {
        let Some(item) = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&key)
        else {
            return;
        };
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        items.push_back(item);
        while items.len() > MAX_LOG_LINES {
            items.pop_front();
        }
    }

    fn append_plain(&self, line: &mut LogLine, text: &str) {
        let color = *self.color.lock().unwrap_or_else(|error| error.into_inner());
        let bold = *self.bold.lock().unwrap_or_else(|error| error.into_inner());
        for ch in text.chars() {
            self.append_char(line, ch, color, bold);
        }
    }

    fn append_char(&self, line: &mut LogLine, ch: char, color: egui::Color32, bold: bool) {
        if let Some(span) = line.spans.last_mut() {
            if span.color == color && span.bold == bold {
                span.text.push(ch);
            } else {
                line.spans.push(LogSpan {
                    text: ch.to_string(),
                    color,
                    bold,
                });
            }
        } else {
            line.spans.push(LogSpan {
                text: ch.to_string(),
                color,
                bold,
            });
        }
        line.plain.push(ch);
    }

    fn apply_sgr(&self, codes: &str) {
        let mut color = self.color.lock().unwrap_or_else(|error| error.into_inner());
        let mut bold = self.bold.lock().unwrap_or_else(|error| error.into_inner());
        let values = if codes.is_empty() {
            vec![0]
        } else {
            codes
                .split(';')
                .filter_map(|value| value.parse::<u32>().ok())
                .collect()
        };
        for value in values {
            match value {
                0 => {
                    *color = egui::Color32::LIGHT_GRAY;
                    *bold = false;
                }
                1 => *bold = true,
                22 => *bold = false,
                30..=37 => *color = ansi_color(value - 30),
                39 => *color = egui::Color32::LIGHT_GRAY,
                90..=97 => *color = ansi_color(value - 90 + 8),
                _ => {}
            }
        }
    }

    fn snapshot(&self) -> Vec<LogLine> {
        let items = self
            .items
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut lines = Vec::new();
        for item in items.into_iter().chain(pending) {
            let _cached_text = self.cached_text(&item);
            let mut line = LogLine::default();
            for span in item.spans {
                for ch in span.text.chars() {
                    if ch == '\n' {
                        lines.push(std::mem::take(&mut line));
                    } else {
                        if let Some(last) = line.spans.last_mut() {
                            if last.color == span.color && last.bold == span.bold {
                                last.text.push(ch);
                            } else {
                                line.spans.push(LogSpan {
                                    text: ch.to_string(),
                                    color: span.color,
                                    bold: span.bold,
                                });
                            }
                        } else {
                            line.spans.push(LogSpan {
                                text: ch.to_string(),
                                color: span.color,
                                bold: span.bold,
                            });
                        }
                        line.plain.push(ch);
                    }
                }
            }
            if !line.plain.is_empty() || lines.is_empty() {
                lines.push(line);
            }
        }
        lines
    }

    fn selected_text(&self) -> String {
        let lines = self.snapshot();
        let Some((start, end)) = *self
            .selection
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        else {
            return String::new();
        };
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        let mut result = String::new();
        for (line_index, line) in lines
            .iter()
            .enumerate()
            .skip(start.0)
            .take(end.0 - start.0 + 1)
        {
            let from = if line_index == start.0 { start.1 } else { 0 };
            let to = if line_index == end.0 {
                end.1
            } else {
                line.plain.chars().count()
            };
            result.extend(line.plain.chars().skip(from).take(to.saturating_sub(from)));
            if line_index < end.0 {
                result.push('\n');
            }
        }
        result
    }

    fn row_count(&self) -> usize {
        let completed = self
            .items
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        completed + pending
    }

    fn row_at(&self, row: usize) -> LogLine {
        let items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(item) = items.get(row) {
            return item.clone();
        }
        let completed_len = items.len();
        drop(items);
        self.pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .nth(row.saturating_sub(completed_len))
            .cloned()
            .unwrap_or_default()
    }

    fn show(&self, ui: &mut egui::Ui) {
        let row_count = self.row_count().max(1);
        let font_id = egui::FontId::monospace(12.0);
        let row_height = ui.fonts_mut(|fonts| fonts.row_height(&font_id));
        let selection = *self
            .selection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::ScrollArea::both()
            .id_salt("nested-service-log-view")
            .max_height(ui.available_height().max(row_height))
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, row_height, row_count, |ui, rows| {
                for row in rows {
                    let line = self.row_at(row);
                    let mut job = LayoutJob::default();
                    for span in &line.spans {
                        job.append(
                            &span.text,
                            0.0,
                            TextFormat {
                                font_id: font_id.clone(),
                                color: span.color,
                                ..Default::default()
                            },
                        );
                    }
                    job.wrap.max_width = f32::INFINITY;
                    let galley = ui.painter().layout_job(job);
                    let row_width = ui.available_width().max(galley.size().x + 8.0);
                    ui.set_min_width(row_width);
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(row_width, row_height),
                        egui::Sense::click_and_drag(),
                    );
                    let pos = rect.left_top() + egui::vec2(4.0, 0.0);
                    if let Some((start, end)) = selection {
                        let (start, end) = if start <= end {
                            (start, end)
                        } else {
                            (end, start)
                        };
                        if row >= start.0 && row <= end.0 {
                            let from = if row == start.0 { start.1 } else { 0 };
                            let to = if row == end.0 {
                                end.1
                            } else {
                                line.plain.chars().count()
                            };
                            let highlight = egui::Rect::from_min_size(
                                pos + egui::vec2(from as f32 * 7.2, 0.0),
                                egui::vec2(to.saturating_sub(from) as f32 * 7.2, row_height),
                            );
                            ui.painter().rect_filled(
                                highlight,
                                0.0,
                                egui::Color32::from_rgba_unmultiplied(70, 110, 180, 130),
                            );
                        }
                        if start == end && row == end.0 {
                            let caret_x = pos.x + end.1 as f32 * 7.2;
                            ui.painter().line_segment(
                                [
                                    egui::pos2(caret_x, pos.y + 2.0),
                                    egui::pos2(caret_x, pos.y + row_height - 2.0),
                                ],
                                egui::Stroke::new(1.0, egui::Color32::WHITE),
                            );
                        }
                    }
                    ui.painter().galley(pos, galley, egui::Color32::WHITE);
                    let pointer_pressed =
                        response.hovered() && ui.input(|input| input.pointer.primary_pressed());
                    if pointer_pressed
                        || response.clicked()
                        || response.drag_started()
                        || response.dragged()
                    {
                        if let Some(pointer) = response.interact_pointer_pos() {
                            let mut selection = self
                                .selection
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let mut drag_origin = self
                                .drag_origin
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let new_gesture = pointer_pressed || response.drag_started();
                            let target_row = if new_gesture || response.clicked() {
                                *drag_origin = None;
                                row
                            } else {
                                if response.drag_started() {
                                    *drag_origin = Some((row, pointer.y));
                                }
                                let (origin_row, origin_y) =
                                    drag_origin.unwrap_or((row, pointer.y));
                                (origin_row as isize
                                    + ((pointer.y - origin_y) / row_height).round() as isize)
                                    .clamp(0, row_count.saturating_sub(1) as isize)
                                    as usize
                            };
                            let target_line = self.row_at(target_row);
                            let column = ((pointer.x - pos.x) / 7.2).max(0.0) as usize;
                            let point = (target_row, column.min(target_line.plain.chars().count()));
                            if new_gesture {
                                *drag_origin = Some((row, pointer.y));
                                *selection = Some((point, point));
                            } else if response.clicked() {
                                *selection = Some((point, point));
                            } else {
                                let anchor = selection.map(|value| value.0).unwrap_or(point);
                                *selection = Some((anchor, point));
                            }
                        }
                    }
                }
            });
        let copy_requested = ui.input(|input| {
            input
                .events
                .iter()
                .any(|event| matches!(event, egui::Event::Copy))
        });
        if copy_requested {
            let selected = self.selected_text();
            if !selected.is_empty() {
                ui.ctx().copy_text(selected);
            }
        }
    }
}

fn ansi_color(index: u32) -> egui::Color32 {
    const COLORS: [egui::Color32; 16] = [
        egui::Color32::from_rgb(0, 0, 0),
        egui::Color32::from_rgb(205, 49, 49),
        egui::Color32::from_rgb(13, 188, 121),
        egui::Color32::from_rgb(229, 229, 16),
        egui::Color32::from_rgb(36, 114, 200),
        egui::Color32::from_rgb(188, 63, 188),
        egui::Color32::from_rgb(17, 168, 205),
        egui::Color32::from_rgb(229, 229, 229),
        egui::Color32::from_rgb(102, 102, 102),
        egui::Color32::from_rgb(241, 76, 76),
        egui::Color32::from_rgb(35, 209, 139),
        egui::Color32::from_rgb(245, 245, 67),
        egui::Color32::from_rgb(59, 142, 234),
        egui::Color32::from_rgb(214, 112, 214),
        egui::Color32::from_rgb(41, 184, 219),
        egui::Color32::from_rgb(255, 255, 255),
    ];
    COLORS[index.min(15) as usize]
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
    logs: Arc<LogViewer>,
    sessions: Arc<Mutex<HashMap<ServiceKey, TermSession>>>,
    pipe_viewers: HashMap<ServiceKey, LogViewer>,
    pipe_cursors: HashMap<ServiceKey, OutputCursor>,
    popups: Arc<Mutex<HashSet<ServiceKey>>>,
    selected: Option<ServiceKey>,
    focus_terminal: Option<ServiceKey>,
    frame_window_start: Instant,
    frame_count: u32,
    last_fps: f32,
    last_frame_ms: u128,
}

impl DemoApp {
    fn new(ctx: &egui::Context) -> Self {
        let logs = Arc::new(LogViewer::default());
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
            pipe_viewers: HashMap::new(),
            pipe_cursors: HashMap::new(),
            popups: Arc::new(Mutex::new(HashSet::new())),
            selected: None,
            focus_terminal: None,
            frame_window_start: Instant::now(),
            frame_count: 0,
            last_fps: 0.0,
            last_frame_ms: 0,
        };
        app.seed_services();
        app
    }

    fn new_scope(label: &str, ctx: &egui::Context, logs: Arc<LogViewer>) -> Scope {
        let journal_root = PathBuf::from("/tmp")
            .join("service-mgr-demo")
            .join(std::process::id().to_string())
            .join(label.replace(' ', "-"));
        let (manager, handle) = ServiceManager::with_journal_root(journal_root);
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
                        }
                        ServiceEvent::Started { id, pid } => {
                            let prefix = format!("[{event_label} #{id}] ");
                            let line = format!(
                                "{prefix:<width$}started pid {pid}",
                                width = LOG_PREFIX_WIDTH
                            );
                            event_shared.set_notice(line.clone());
                            logs.push(line);
                        }
                        ServiceEvent::StateChanged { id, state } => {
                            logs.flush_stream((*id, 1));
                            logs.flush_stream((*id, 2));
                            let prefix = format!("[{event_label} #{id}] ");
                            let line = format!(
                                "{prefix:<width$}state {state:?}",
                                width = LOG_PREFIX_WIDTH
                            );
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
                    "i=0; while true; do i=$((i+1)); printf '\\033[3%sm{} worker tick %s\\033[0m\\n' \"$((i % 8 + 1))\" \"$i\"; sleep 2; done",
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

    fn spawn_log_stress(&mut self, scope_index: usize) {
        let scope_label = self.scope(scope_index).label.clone();
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec![
            "-c".into(),
            "i=1; while [ \"$i\" -le 100000 ]; do printf 'stress %06d %s\\n' \"$i\" \"$i\"; i=$((i+1)); done"
                .into(),
        ];
        spec.output_capacity = 8 * 1024 * 1024;
        spec.ownership = Ownership {
            manager: scope_label,
            parent: None,
            label: Some("virtual-scroll stress log".into()),
        };
        match self.scope(scope_index).manager.spawn(spec) {
            Ok(id) => self.selected = Some((scope_index, id)),
            Err(error) => self.scope(scope_index).shared.set_notice(error.to_string()),
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
            self.focus_terminal = Some(key);
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
            self.focus_terminal = Some(key);
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
        if info.kind == ServiceKind::Pipe {
            let cursor = self
                .pipe_cursors
                .get(&key)
                .copied()
                .unwrap_or(OutputCursor(0));
            if let Ok(replay) = manager.journal_replay(key.1, cursor) {
                let viewer = self.pipe_viewers.entry(key).or_default();
                for chunk in replay.chunks {
                    viewer.append_stream(
                        (key.1, chunk.stream as u8),
                        "",
                        &String::from_utf8_lossy(&chunk.data),
                    );
                }
                self.pipe_cursors.insert(key, replay.next);
            }
            ui.separator();
            if let Some(viewer) = self.pipe_viewers.get(&key) {
                viewer.show(ui);
            }
            return;
        }
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = sessions
            .entry(key)
            .or_insert_with(|| TermSession::new(info.pid));
        let request_focus = self.focus_terminal.take() == Some(key);
        ui.separator();
        Self::render_terminal_content(ui, manager, shared, key.1, session, request_focus);
    }

    fn render_terminal_content(
        ui: &mut egui::Ui,
        manager: ServiceManager,
        shared: Arc<UiPtyState>,
        id: ServiceId,
        session: &mut TermSession,
        request_focus: bool,
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
                .set_size(ui.available_size())
                .request_focus_if(request_focus),
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
                            false,
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
        let frame_started = Instant::now();
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("root pipe job").clicked() {
                    self.spawn_pipe(0);
                }
                if ui.button("stress 100k logs").clicked() {
                    self.spawn_log_stress(1);
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
                ui.horizontal(|ui| {
                    if ui.button("copy selection").clicked() {
                        ui.ctx().copy_text(self.logs.selected_text());
                    }
                    if ui.button("clear selection").clicked() {
                        *self
                            .logs
                            .selection
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = None;
                    }
                });
                self.logs.show(ui);
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

        egui::Area::new(egui::Id::new("service_mgr_frame_watermark"))
            .anchor(egui::Align2::LEFT_BOTTOM, egui::vec2(8.0, -8.0))
            .show(ctx, |ui| {
                let color = if self.last_frame_ms <= 16 {
                    egui::Color32::from_rgba_unmultiplied(120, 220, 120, 150)
                } else if self.last_frame_ms <= 33 {
                    egui::Color32::from_rgba_unmultiplied(240, 200, 120, 150)
                } else {
                    egui::Color32::from_rgba_unmultiplied(220, 100, 100, 150)
                };
                ui.colored_label(
                    color,
                    format!("{}ms  {:.1}fps", self.last_frame_ms, self.last_fps),
                );
            });
        self.last_frame_ms = frame_started.elapsed().as_millis();
        self.frame_count += 1;
        let elapsed = self.frame_window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.last_fps = self.frame_count as f32 / elapsed.as_secs_f32();
            self.frame_count = 0;
            self.frame_window_start = Instant::now();
        }
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
