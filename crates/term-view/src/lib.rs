use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::Scroll;
use alacritty_terminal::term::cell;
use alacritty_terminal::term::{TermDamage, TermMode};
use alacritty_terminal::term::{self, test::TermSize, Term};
use alacritty_terminal::vte::ansi::{Color, NamedColor, Processor};
use egui::epaint::{Galley, RectShape};
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, CornerRadius, FontId, Key, Painter, Pos2, Rect, Response, Shape, Vec2, Widget};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BG_DEFAULT: Color32 = Color32::from_rgb(10, 12, 16);
const FG_DEFAULT: Color32 = Color32::from_rgb(200, 200, 200);

/// IPC interface that `ExternalPtyViewport` uses to communicate with the rest
/// of the system.  Implemented by the `nsproxy-ui` side; kept in this crate so
/// the entire hot PTY data path runs at `opt-level = 3`.
pub trait PtyIpc: Send + Sync + 'static {
    /// Drain any PTY bytes the daemon has sent since the last call.
    fn drain_incoming(&self) -> Vec<u8>;
    /// Forward bytes typed in the terminal back to the PTY slave.
    fn send_input(&self, data: Vec<u8>);
    /// Notify the PTY slave of a terminal resize.
    fn send_resize(&self, cols: u16, rows: u16);
}

/// Self-contained state for an external PTY OS window (deferred viewport).
///
/// Generic over `I: PtyIpc` so the hot path (data draining, input forwarding,
/// TermSession feed, TermView render) all live here in `term-view` and are
/// therefore compiled at `opt-level = 3` even in debug builds.
pub struct ExternalPtyViewport<I: PtyIpc> {
    pub ipc: I,
    pub pid: u32,
    session: Mutex<TermSession>,
    pub closed: AtomicBool,
    pub viewport_id: egui::ViewportId,
    pub title: String,
}

impl<I: PtyIpc> ExternalPtyViewport<I> {
    pub fn new(ipc: I, pid: u32, title: String) -> Self {
        Self {
            ipc,
            pid,
            session: Mutex::new(TermSession::new(pid)),
            closed: AtomicBool::new(false),
            viewport_id: egui::ViewportId::from_hash_of("pty-external"),
            title,
        }
    }

    /// Called from the deferred viewport's `Fn(&Context, ViewportClass)` callback.
    /// The entire hot path — drain, feed, render, input dispatch — runs here.
    pub fn viewport_ui(this: &Arc<Self>, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) {
            this.closed.store(true, Ordering::Relaxed);
            return;
        }

        let incoming = this.ipc.drain_incoming();
        let mut session = this.session.lock().unwrap_or_else(|e| e.into_inner());

        if !incoming.is_empty() {
            session.feed(&incoming);
            for resp in session.drain_responses() {
                if !resp.is_empty() {
                    this.ipc.send_input(resp);
                }
            }
        }

        let mut input_frames: Vec<Vec<u8>> = Vec::new();
        let mut resize_evt: Option<(u16, u16)> = None;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add(
                TermView::new(&mut session, &mut input_frames, &mut resize_evt)
                    .set_size(ui.available_size()),
            );
        });

        for data in input_frames {
            if !data.is_empty() {
                this.ipc.send_input(data);
            }
        }
        if let Some((cols, rows)) = resize_evt {
            this.ipc.send_resize(cols, rows);
        }
    }
}

/// Per-viewport-row cached render data.
/// Positions are stored in grid-space (col index) so they remain valid
/// across window moves; pixel coords are computed cheaply at emit time.
#[derive(Clone)]
struct CachedRow {
    /// Background fill rects: (start_col, width_in_cells, color).
    /// Adjacent same-color cells are coalesced into single spans.
    bg_rects: Vec<(usize, f32, Color32)>,
    /// Single pre-shaped galley for the entire row, built from a LayoutJob
    /// with one TextFormat section per color run. None when the row is blank.
    row_galley: Option<Arc<Galley>>,
}

/// Event listener that captures PtyWrite responses (device attribute replies,
/// color queries, etc.) so they can be sent back to the PTY.
///
/// Uses a `flume` channel — no Mutex contention between the alacritty
/// event callback (sender) and the drain path (receiver sit in TermSession).
#[derive(Clone, Debug)]
pub struct PtyWriteCollector {
    tx: flume::Sender<Vec<u8>>,
}

impl EventListener for PtyWriteCollector {
    fn send_event(&self, event: Event) {
        if let Event::PtyWrite(text) = event {
            let _ = self.tx.try_send(text.into_bytes());
        }
    }
}

pub struct TermSession {
    term: Term<PtyWriteCollector>,
    processor: Processor,
    write_rx: flume::Receiver<Vec<u8>>,
    pub pid: u32,
    pub last_size: (u16, u16),

    /// Per-viewport-row render cache, indexed 0..num_rows.
    /// `None` means the row is dirty and must be rebuilt before use.
    row_cache: Vec<Option<CachedRow>>,

    /// Set when the entire row cache needs an unconditional rebuild
    /// (e.g. after a scroll that shifts which grid lines are on screen).
    force_full_rebuild: bool,

    /// Cached (cell_w, cell_h) from a single fonts_mut call.
    /// The font is fixed (monospace 14pt) so this never changes at runtime;
    /// we measure it once on first frame and reuse forever.
    cached_cell_dims: Option<(f32, f32)>,

    /// Cached FontId — avoids `String` allocation in `FontId::monospace()` per frame.
    cached_font_id: FontId,

    /// Pre-allocated per-row scratch buffer: indexed [0..num_rows].
    /// Each inner Vec accumulates (col, char, fg, bg, wide) for dirty rows.
    /// Cleared in-place each frame — no per-frame heap allocation.
    dirty_row_cells: Vec<Vec<(usize, char, Color32, Color32, bool)>>,

    /// Reusable scratch: dense (char, fg) cell buffer for one row during rebuild.
    cell_buf: Vec<(char, Color32)>,

    /// Reusable scratch: background rects for one row during rebuild.
    bg_rect_buf: Vec<(usize, f32, Color32)>,

    /// Reusable scratch: LayoutJob segment text builder.
    seg_text_buf: String,

    /// Reusable shapes vec, cleared each frame but retains its capacity.
    shapes_buf: Vec<Shape>,
}

impl TermSession {
    pub fn new(pid: u32) -> Self {
        let size = TermSize::new(120, 50);
        let (tx, write_rx) = flume::unbounded();
        let event_collector = PtyWriteCollector { tx };
        let term = Term::new(term::Config::default(), &size, event_collector);
        let num_rows = 50usize;
        let num_cols = 120usize;
        Self {
            term,
            processor: Processor::new(),
            write_rx,
            pid,
            last_size: (120, 50),
            row_cache: vec![None; num_rows],
            force_full_rebuild: true,
            cached_cell_dims: None,
            cached_font_id: FontId::monospace(14.0),
            dirty_row_cells: (0..num_rows).map(|_| Vec::new()).collect(),
            cell_buf: vec![(' ', FG_DEFAULT); num_cols],
            bg_rect_buf: Vec::with_capacity(32),
            seg_text_buf: String::with_capacity(num_cols),
            shapes_buf: Vec::with_capacity(num_rows * 2 + 2),
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.processor.advance(&mut self.term, data);
        // Do NOT call reset_damage here; damage is consumed in show().
    }

    /// Drain PtyWrite responses generated by alacritty_terminal
    /// (e.g. device attribute replies). These must be sent back to the PTY.
    pub fn drain_responses(&mut self) -> Vec<Vec<u8>> {
        self.write_rx.try_iter().collect()
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(2);
        let rows = rows.max(2);
        self.last_size = (cols, rows);
        self.term.resize(TermSize::new(cols as usize, rows as usize));
        // Resize invalidates all cached row positions and content.
        let r = rows as usize;
        let c = cols as usize;
        self.row_cache.resize_with(r, || None);
        for slot in &mut self.row_cache {
            *slot = None;
        }
        self.dirty_row_cells.resize_with(r, Vec::new);
        self.cell_buf.resize(c, (' ', FG_DEFAULT));
        self.force_full_rebuild = true;
    }

    pub fn scroll(&mut self, delta: i32) {
        let mode = *self.term.mode();
        if mode.contains(TermMode::ALTERNATE_SCROLL | TermMode::ALT_SCREEN) {
            return;
        }
        self.term.grid_mut().scroll_display(Scroll::Delta(delta));
        // Scroll shifts which grid lines are in the viewport — invalidate all rows.
        self.force_full_rebuild = true;
    }
}

pub struct TermView<'a> {
    session: &'a mut TermSession,
    has_focus: bool,
    size: Vec2,
    input_sink: &'a mut Vec<Vec<u8>>,
    resize_sink: &'a mut Option<(u16, u16)>,
}

impl<'a> TermView<'a> {
    pub fn new(
        session: &'a mut TermSession,
        input_sink: &'a mut Vec<Vec<u8>>,
        resize_sink: &'a mut Option<(u16, u16)>,
    ) -> Self {
        Self {
            session,
            has_focus: true,
            size: Vec2::ZERO,
            input_sink,
            resize_sink,
        }
    }

    pub fn set_focus(mut self, has_focus: bool) -> Self {
        self.has_focus = has_focus;
        self
    }

    pub fn set_size(mut self, size: Vec2) -> Self {
        self.size = size;
        self
    }

    fn process_input(&mut self, layout: &Response) {
        if !layout.has_focus() {
            return;
        }

        let is_app_cursor = self.session.term.mode().contains(TermMode::APP_CURSOR);

        let events = layout.ctx.input(|i| i.events.clone());

        // On some platforms (especially in a dedicated OS window / external viewport),
        // Ctrl+C is consumed by the compositor and arrives only as Event::Copy,
        // never as Event::Key{ctrl,C}. On others (inline panel) both arrive.
        // To avoid double-send we only treat Copy as ^C when there is no
        // Key{ctrl,C} already in the queue.
        let has_ctrl_c_key = events.iter().any(|e| {
            matches!(e, egui::Event::Key { key: Key::C, pressed: true, modifiers, .. }
                if modifiers.ctrl)
        });

        for event in &events {
            match event {
                egui::Event::Copy if !has_ctrl_c_key => {
                    self.input_sink.push(vec![0x03]);
                }
                // Cut → ^X is not standard terminal behaviour; ignore silently.
                egui::Event::Text(text) => {
                    if !text.chars().any(char::is_control) {
                        self.input_sink.push(text.as_bytes().to_vec());
                    }
                }
                egui::Event::Paste(text) => {
                    self.input_sink.push(text.as_bytes().to_vec());
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..  
                } => {
                    // Ctrl+letter sequences
                    if modifiers.ctrl {
                        let byte = match key {
                            Key::C => Some(0x03u8),
                            Key::D => Some(0x04),
                            Key::L => Some(0x0c),
                            Key::Z => Some(0x1a),
                            Key::A => Some(0x01),
                            Key::E => Some(0x05),
                            Key::U => Some(0x15),
                            Key::K => Some(0x0b),
                            Key::W => Some(0x17),
                            _ => None,
                        };
                        if let Some(b) = byte {
                            self.input_sink.push(vec![b]);
                            continue;
                        }
                    }
                    let bytes: &[u8] = match key {
                        Key::Backspace if modifiers.ctrl => &[0x17],
                        Key::Enter    => &[b'\r'],
                        Key::Backspace => &[0x7f],
                        Key::Tab      => &[b'\t'],
                        Key::Escape   => &[0x1b],
                        Key::ArrowUp    if is_app_cursor => b"\x1bOA",
                        Key::ArrowDown  if is_app_cursor => b"\x1bOB",
                        Key::ArrowRight if is_app_cursor => b"\x1bOC",
                        Key::ArrowLeft  if is_app_cursor => b"\x1bOD",
                        Key::ArrowUp    => b"\x1b[A",
                        Key::ArrowDown  => b"\x1b[B",
                        Key::ArrowRight => b"\x1b[C",
                        Key::ArrowLeft  => b"\x1b[D",
                        Key::Home if is_app_cursor => b"\x1bOH",
                        Key::End  if is_app_cursor => b"\x1bOF",
                        Key::Home  => b"\x1b[H",
                        Key::End   => b"\x1b[F",
                        Key::Delete   => b"\x1b[3~",
                        Key::PageUp   => b"\x1b[5~",
                        Key::PageDown => b"\x1b[6~",
                        Key::F1  => b"\x1bOP",
                        Key::F2  => b"\x1bOQ",
                        Key::F3  => b"\x1bOR",
                        Key::F4  => b"\x1bOS",
                        Key::F5  => b"\x1b[15~",
                        Key::F6  => b"\x1b[17~",
                        Key::F7  => b"\x1b[18~",
                        Key::F8  => b"\x1b[19~",
                        Key::F9  => b"\x1b[20~",
                        Key::F10 => b"\x1b[21~",
                        Key::F11 => b"\x1b[23~",
                        Key::F12 => b"\x1b[24~",
                        _ => &[],
                    };
                    if !bytes.is_empty() {
                        self.input_sink.push(bytes.to_vec());
                    }
                }
                egui::Event::MouseWheel { unit, delta, .. } => {
                    let lines = match unit {
                        egui::MouseWheelUnit::Line => {
                            delta.y.signum() as i32 * (delta.y.abs().ceil() as i32) * 3
                        }
                        egui::MouseWheelUnit::Point => {
                            let font_size = 14.0_f32;
                            (delta.y / font_size * 3.0).round() as i32
                        }
                        egui::MouseWheelUnit::Page => 0,
                    };
                    if lines != 0 {
                        self.session.scroll(lines);
                    }
                }
                _ => {}
            }
        }
    }

    fn font_measure(session: &mut TermSession, ctx: &egui::Context) -> (f32, f32) {
        if let Some(dims) = session.cached_cell_dims {
            return dims;
        }
        let dims = ctx.fonts_mut(|f| {
            (f.glyph_width(&session.cached_font_id, 'm'), f.row_height(&session.cached_font_id))
        });
        session.cached_cell_dims = Some(dims);
        dims
    }

    fn maybe_resize(&mut self, layout: &Response, cell_dims: (f32, f32)) {
        let (cell_w, cell_h) = cell_dims;
        let cols = (layout.rect.width() / cell_w).floor().max(2.0) as u16;
        let rows = (layout.rect.height() / cell_h).floor().max(2.0) as u16;
        if self.session.last_size != (cols, rows) {
            self.session.resize(cols, rows);
            *self.resize_sink = Some((cols, rows));
        }
    }

    fn show(&mut self, layout: &Response, painter: &Painter, cell_dims: (f32, f32)) {
        let (cell_w, cell_h) = cell_dims;
        let rect = layout.rect;

        // ── Step 1: apply alacritty damage tracking ──────────────────────────
        //
        // TermDamage tells us which viewport rows changed since the last
        // reset_damage() call. We mark those slots in row_cache as None so
        // they get rebuilt below. `force_full_rebuild` covers scroll/resize.
        let damage = self.session.term.damage();
        match damage {
            TermDamage::Full => {
                for slot in &mut self.session.row_cache {
                    *slot = None;
                }
            }
            TermDamage::Partial(iter) => {
                if self.session.force_full_rebuild {
                    for slot in &mut self.session.row_cache {
                        *slot = None;
                    }
                } else {
                    for bounds in iter {
                        if let Some(slot) = self.session.row_cache.get_mut(bounds.line) {
                            *slot = None;
                        }
                    }
                }
            }
        }
        self.session.term.reset_damage();
        self.session.force_full_rebuild = false;

        // ── Step 2: collect grid data ─────────────────────────────────────────
        let grid = self.session.term.grid();
        let cursor_point = grid.cursor.point;
        let display_offset = grid.display_offset() as i32;
        let num_rows = self.session.last_size.1 as usize;

        // Clear pre-allocated scratch buffers in-place (no allocation).
        for row in &mut self.session.dirty_row_cells {
            row.clear();
        }

        for indexed in grid.display_iter() {
            if indexed.cell.flags.contains(cell::Flags::WIDE_CHAR_SPACER) {
                continue;
            }
            let point = indexed.point;
            let vrow = (point.line.0 - display_offset) as usize;
            if vrow >= num_rows {
                continue;
            }
            // Only process if the slot needs rebuilding.
            if self.session.row_cache.get(vrow).map_or(true, |s| s.is_none()) {
                let mut fg = color_to_egui(indexed.fg, Color32::LIGHT_GRAY);
                let mut bg_cell = color_to_egui(indexed.bg, BG_DEFAULT);
                if indexed.cell.flags.contains(cell::Flags::INVERSE) {
                    std::mem::swap(&mut fg, &mut bg_cell);
                }
                let wide = indexed.cell.flags.contains(cell::Flags::WIDE_CHAR);
                if let Some(row) = self.session.dirty_row_cells.get_mut(vrow) {
                    row.push((point.column.0, indexed.c, fg, bg_cell, wide));
                }
            }
        }

        // ── Step 3: rebuild dirty rows using LayoutJob ────────────────────────
        //
        // For each dirty row, build a single LayoutJob whose sections correspond
        // to consecutive same-fg-color cell runs (including spaces so positions
        // stay aligned). One fonts_mut call shapes the job into a single
        // Arc<Galley> per row, emitted as one Shape::galley in step 4.
        let num_cols = self.session.last_size.0 as usize;
        let font_id = &self.session.cached_font_id;
        let row_cache = &mut self.session.row_cache;
        let dirty_row_cells = &self.session.dirty_row_cells;
        let cell_buf = &mut self.session.cell_buf;
        let bg_rect_buf = &mut self.session.bg_rect_buf;
        let seg_text = &mut self.session.seg_text_buf;

        for (vrow, cells) in dirty_row_cells.iter().enumerate().filter(|(_, c)| !c.is_empty()) {
            bg_rect_buf.clear();

            // Reset cell_buf slice to defaults (re-use allocation).
            for slot in cell_buf.iter_mut().take(num_cols) {
                *slot = (' ', FG_DEFAULT);
            }

            for &(col, c, fg, bg_cell, wide) in cells {
                let width_ratio = if wide { 2.0f32 } else { 1.0 };
                if bg_cell != Color32::TRANSPARENT && bg_cell != BG_DEFAULT {
                    // Coalesce adjacent same-color bg rects.
                    if let Some(last) = bg_rect_buf.last_mut() {
                        let (last_col, last_w, last_color) = last;
                        if *last_color == bg_cell && *last_col + (*last_w as usize) == col {
                            *last_w += width_ratio;
                        } else {
                            bg_rect_buf.push((col, width_ratio, bg_cell));
                        }
                    } else {
                        bg_rect_buf.push((col, width_ratio, bg_cell));
                    }
                }
                if col < num_cols {
                    cell_buf[col] = (c, fg);
                }
            }

            // Trim trailing spaces so the galley stays as narrow as needed.
            let trim_end = cell_buf[..num_cols]
                .iter()
                .rposition(|(c, _)| *c != ' ')
                .map_or(0, |i| i + 1);

            let row_galley = if trim_end == 0 {
                None
            } else {
                // Build one LayoutJob, merging consecutive same-color cells.
                let mut job = LayoutJob::default();
                let mut seg_color = cell_buf[0].1;
                seg_text.clear();

                for col in 0..trim_end {
                    let (c, fg) = cell_buf[col];
                    if fg != seg_color {
                        if !seg_text.is_empty() {
                            job.append(seg_text, 0.0, TextFormat {
                                font_id: font_id.clone(),
                                color: seg_color,
                                ..Default::default()
                            });
                            seg_text.clear();
                        }
                        seg_color = fg;
                    }
                    seg_text.push(c);
                }
                if !seg_text.is_empty() {
                    job.append(seg_text, 0.0, TextFormat {
                        font_id: font_id.clone(),
                        color: seg_color,
                        ..Default::default()
                    });
                    seg_text.clear();
                }

                // Single fonts_mut call per dirty row to shape the entire row.
                Some(painter.ctx().fonts_mut(|fonts| fonts.layout_job(job)))
            };

            if let Some(slot) = row_cache.get_mut(vrow) {
                *slot = Some(CachedRow {
                    bg_rects: bg_rect_buf.clone(),
                    row_galley,
                });
            }
        }

        // ── Step 4: emit shapes from cache ───────────────────────────────────
        //
        // Pixel positions are computed here from current rect / display_offset.
        // This is pure arithmetic — no font or grid access.
        // Reuse shapes_buf to avoid per-frame Vec allocation.
        let shapes = &mut self.session.shapes_buf;
        shapes.clear();
        shapes.push(Shape::Rect(RectShape::filled(
            Rect::from_min_max(rect.min, rect.max),
            CornerRadius::ZERO,
            BG_DEFAULT,
        )));

        for (vrow, slot) in self.session.row_cache.iter().enumerate() {
            let Some(row) = slot else { continue };
            let y = rect.min.y + cell_h * vrow as f32;

            for &(col, width_ratio, color) in &row.bg_rects {
                let x = rect.min.x + cell_w * col as f32;
                shapes.push(Shape::Rect(RectShape::filled(
                    Rect::from_min_size(
                        Pos2::new(x, y),
                        Vec2::new(cell_w * width_ratio + 1.0, cell_h + 1.0),
                    ),
                    CornerRadius::ZERO,
                    color,
                )));
            }

            // Single galley covers the entire row from column 0.
            if let Some(galley) = &row.row_galley {
                shapes.push(Shape::galley(
                    Pos2::new(rect.min.x, y),
                    Arc::clone(galley),
                    Color32::WHITE,
                ));
            }
        }

        // Cursor is drawn above the cached layer so it never invalidates row cache.
        let cvrow = (cursor_point.line.0 - display_offset) as usize;
        if cvrow < num_rows {
            let cx = rect.min.x + cell_w * cursor_point.column.0 as f32;
            let cy = rect.min.y + cell_h * cvrow as f32;
            shapes.push(Shape::Rect(RectShape::filled(
                Rect::from_min_size(Pos2::new(cx, cy), Vec2::new(cell_w, cell_h)),
                CornerRadius::ZERO,
                Color32::from_rgb(220, 220, 220),
            )));
        }

        painter.extend(std::mem::take(shapes));
    }
}

impl Widget for TermView<'_> {
    fn ui(mut self, ui: &mut egui::Ui) -> Response {
        let size = if self.size == Vec2::ZERO {
            ui.available_size()
        } else {
            self.size
        };
        let (layout, painter) = ui.allocate_painter(size, egui::Sense::click_and_drag());

        if layout.clicked() {
            layout.request_focus();
        }

        // While focused, capture ALL navigation keys including Escape so egui
        // never steals focus. Escape defocusing the terminal caused the
        // "input hang" after pressing Esc or any key that triggered egui's
        // focus-navigation paths.
        if layout.has_focus() {
            let id = layout.id;
            ui.memory_mut(|mem| mem.set_focus_lock_filter(id, egui::EventFilter {
                tab: true,
                horizontal_arrows: true,
                vertical_arrows: true,
                escape: true,  // must be true: false causes Esc to defocus the terminal
            }));
        }

        // Measure font — hits cache after first frame (font is fixed, never changes).
        let cell_dims = Self::font_measure(self.session, &layout.ctx);
        self.maybe_resize(&layout, cell_dims);
        self.process_input(&layout);
        self.show(&layout, &painter, cell_dims);
        layout
    }
}

#[inline]
fn color_to_egui(color: Color, default: Color32) -> Color32 {
    match color {
        Color::Spec(rgb) => Color32::from_rgb(rgb.r, rgb.g, rgb.b),
        Color::Named(named) => named_to_color(named).unwrap_or(default),
        _ => default,
    }
}

#[inline]
fn named_to_color(color: NamedColor) -> Option<Color32> {
    let c = match color {
        NamedColor::Foreground => Color32::from_rgb(220, 220, 220),
        NamedColor::Background => BG_DEFAULT,
        NamedColor::Black => Color32::from_rgb(20, 20, 20),
        NamedColor::Red => Color32::from_rgb(220, 90, 90),
        NamedColor::Green => Color32::from_rgb(110, 200, 120),
        NamedColor::Yellow => Color32::from_rgb(220, 190, 90),
        NamedColor::Blue => Color32::from_rgb(120, 170, 240),
        NamedColor::Magenta => Color32::from_rgb(190, 130, 220),
        NamedColor::Cyan => Color32::from_rgb(100, 200, 210),
        NamedColor::White => Color32::from_rgb(220, 220, 220),
        _ => return None,
    };
    Some(c)
}
