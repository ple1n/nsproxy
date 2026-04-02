#![cfg(feature = "alacritty-opengl")]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Instant;

use polling::{Event as PollingEvent, PollMode, Poller};
use winit::event::{Event as WinitEvent, WindowEvent};
use winit::event_loop::ActiveEventLoop;
use winit::raw_window_handle::HasDisplayHandle;
use winit::window::WindowId;

use alacritty_terminal::event::{Event as TerminalEvent, OnResize, WindowSize};
use alacritty_terminal::tty::{ChildEvent, EventedPty, EventedReadWrite};

use crate::ExternalPtyViewport;
use crate::PtyIpc;
use crate::cli::WindowOptions;
use crate::clipboard::Clipboard;
use crate::config::UiConfig;
use crate::event::{Event, EventSender, EventType};
use crate::scheduler::Scheduler;
use crate::window_context::WindowContext;

const PTY_READ_WRITE_TOKEN: usize = 0;
const PTY_CHILD_EVENT_TOKEN: usize = 1;

type PendingViewports = Arc<Mutex<VecDeque<Arc<dyn ExternalViewportHandle>>>>;

struct RuntimeQueueHandle {
    pending_viewports: PendingViewports,
    pending_events: Arc<Mutex<VecDeque<Event>>>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl RuntimeQueueHandle {
    fn sender(self: &Arc<Self>) -> EventSender {
        let handle = Arc::clone(self);
        EventSender::new(move |event| {
            let mut events = handle
                .pending_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            events.push_back(event);
            (handle.wake)();
        })
    }

    fn wake(&self) {
        (self.wake)();
    }
}

struct ExternalWindowRuntime {
    queue: Arc<RuntimeQueueHandle>,
    sender: EventSender,
    clipboard: Clipboard,
    scheduler: Scheduler,
    windows: HashMap<WindowId, ExternalWindowState>,
}

impl ExternalWindowRuntime {
    fn new(queue: Arc<RuntimeQueueHandle>) -> Self {
        let sender = queue.sender();
        Self {
            clipboard: Clipboard::new_nop(),
            scheduler: Scheduler::new(sender.clone()),
            sender,
            queue,
            windows: HashMap::new(),
        }
    }

    fn drain_pending_windows(&mut self, event_loop: &ActiveEventLoop) {
        loop {
            let viewport = {
                let mut pending = self
                    .queue
                    .pending_viewports
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.pop_front()
            };

            let Some(viewport) = viewport else {
                break;
            };

            match viewport.create_window_context(event_loop, self.sender.clone(), &mut self.clipboard)
            {
                Ok(window_context) => {
                    self.windows.insert(
                        window_context.id(),
                        ExternalWindowState {
                            viewport,
                            window_context,
                        },
                    );
                }
                Err(err) => {
                    eprintln!("term-view alacritty window error: {err}");
                    viewport.mark_start_failed();
                }
            }
        }
    }

    fn drain_pending_events(&mut self, event_loop: &ActiveEventLoop) {
        let events = {
            let mut pending = self
                .queue
                .pending_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.drain(..).collect::<Vec<_>>()
        };

        for event in events {
            self.handle_event(event_loop, event);
        }
    }

    fn process_pending(&mut self, event_loop: &ActiveEventLoop) {
        self.drain_pending_windows(event_loop);
        self.drain_pending_events(event_loop);
    }

    fn close_window(&mut self, window_id: WindowId) {
        if let Some(mut state) = self.windows.remove(&window_id) {
            self.scheduler.unschedule_window(window_id);
            state.window_context.shutdown();
            state.viewport.mark_closed();
        }
    }

    fn handle_event(&mut self, event_loop: &ActiveEventLoop, event: Event) {
        match (event.payload(), event.window_id()) {
            (EventType::CreateExternalWindow, _) => {
                self.drain_pending_windows(event_loop);
            }
            (EventType::Terminal(TerminalEvent::Wakeup), Some(window_id)) => {
                if let Some(state) = self.windows.get_mut(&window_id) {
                    state.window_context.dirty = true;
                    if state.window_context.display.window.has_frame {
                        state.window_context.display.window.request_redraw();
                    }
                }
            }
            (EventType::Terminal(TerminalEvent::Exit), Some(window_id)) => {
                self.close_window(window_id);
            }
            (EventType::Frame, Some(window_id)) => {
                if let Some(state) = self.windows.get_mut(&window_id) {
                    state.window_context.display.window.has_frame = true;
                    if state.window_context.dirty {
                        state.window_context.display.window.request_redraw();
                    }
                }
            }
            (payload, Some(window_id)) => {
                if let Some(state) = self.windows.get_mut(&window_id) {
                    state.window_context.handle_event(
                        #[cfg(target_os = "macos")]
                        event_loop,
                        &self.sender,
                        &mut self.clipboard,
                        &mut self.scheduler,
                        WinitEvent::UserEvent(Event::new(payload.clone(), window_id)),
                    );
                }
            }
            (payload, None) => {
                let event = WinitEvent::UserEvent(Event::new(payload.clone(), None));
                for state in self.windows.values_mut() {
                    state.window_context.handle_event(
                        #[cfg(target_os = "macos")]
                        event_loop,
                        &self.sender,
                        &mut self.clipboard,
                        &mut self.scheduler,
                        event.clone(),
                    );
                }
            }
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) -> Option<Instant> {
        self.process_pending(event_loop);

        let mut closed_windows = Vec::new();
        for (window_id, state) in self.windows.iter_mut() {
            if state.viewport.is_closed() {
                closed_windows.push(*window_id);
                continue;
            }

            state.window_context.handle_event(
                #[cfg(target_os = "macos")]
                event_loop,
                &self.sender,
                &mut self.clipboard,
                &mut self.scheduler,
                WinitEvent::AboutToWait,
            );

            if state.viewport.is_closed() {
                closed_windows.push(*window_id);
            }
        }

        for window_id in closed_windows {
            self.close_window(window_id);
        }

        self.drain_pending_events(event_loop);
        self.scheduler.update()
    }

    fn handle_window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) -> bool {
        self.process_pending(event_loop);

        let Some(state) = self.windows.get_mut(&window_id) else {
            return false;
        };

        let is_redraw = matches!(event, WindowEvent::RedrawRequested);
        state.window_context.handle_event(
            #[cfg(target_os = "macos")]
            event_loop,
            &self.sender,
            &mut self.clipboard,
            &mut self.scheduler,
            WinitEvent::WindowEvent { window_id, event },
        );

        if is_redraw {
            state.window_context.draw(&mut self.scheduler);
        }

        if state.viewport.is_closed() {
            self.close_window(window_id);
        }

        true
    }

    fn has_window(&self, window_id: WindowId) -> bool {
        self.windows.contains_key(&window_id)
    }

    fn shutdown(&mut self) {
        let window_ids: Vec<_> = self.windows.keys().copied().collect();
        for window_id in window_ids {
            self.close_window(window_id);
        }
        self.clipboard = Clipboard::new_nop();
    }
}

thread_local! {
    static RUNTIME_STATE: RefCell<Option<ExternalWindowRuntime>> = const { RefCell::new(None) };
}

static RUNTIME_QUEUE: OnceLock<Arc<RuntimeQueueHandle>> = OnceLock::new();

pub fn install_external_window_waker(
    wake: impl Fn() + Send + Sync + 'static,
) -> Result<(), String> {
    if RUNTIME_QUEUE.get().is_some() {
        return Ok(());
    }

    let handle = Arc::new(RuntimeQueueHandle {
        pending_viewports: Arc::new(Mutex::new(VecDeque::new())),
        pending_events: Arc::new(Mutex::new(VecDeque::new())),
        wake: Arc::new(wake),
    });

    RUNTIME_QUEUE
        .set(handle)
        .map_err(|_| "term-view external runtime already initialized".to_owned())
}

fn runtime_queue() -> Result<Arc<RuntimeQueueHandle>, String> {
    RUNTIME_QUEUE
        .get()
        .cloned()
        .ok_or_else(|| "term-view external runtime is not installed".to_owned())
}

fn with_runtime_mut<R>(f: impl FnOnce(&mut ExternalWindowRuntime) -> R) -> Option<R> {
    let queue = runtime_queue().ok()?;
    RUNTIME_STATE.with(|state| {
        let mut state = state.borrow_mut();
        let runtime = state.get_or_insert_with(|| ExternalWindowRuntime::new(queue));
        Some(f(runtime))
    })
}

pub fn open_external_window<I: PtyIpc + Send + Sync + 'static>(
    viewport: Arc<ExternalPtyViewport<I>>,
) -> Result<(), String> {
    let queue = runtime_queue()?;
    let mut pending = queue
        .pending_viewports
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pending.push_back(Arc::new(ExternalViewportRequest { viewport }));
    drop(pending);
    queue.wake();
    Ok(())
}

pub fn process_external_window_events(event_loop: &ActiveEventLoop) {
    let _ = with_runtime_mut(|runtime| runtime.process_pending(event_loop));
}

pub fn about_to_wait_external_windows(event_loop: &ActiveEventLoop) -> Option<Instant> {
    with_runtime_mut(|runtime| runtime.about_to_wait(event_loop)).flatten()
}

pub fn handle_external_window_event(
    event_loop: &ActiveEventLoop,
    window_id: WindowId,
    event: WindowEvent,
) -> bool {
    with_runtime_mut(|runtime| runtime.handle_window_event(event_loop, window_id, event))
        .unwrap_or(false)
}

pub fn has_external_window(window_id: WindowId) -> bool {
    with_runtime_mut(|runtime| runtime.has_window(window_id)).unwrap_or(false)
}

pub fn shutdown_external_windows() {
    RUNTIME_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(runtime) = state.as_mut() {
            runtime.shutdown();
        }
        *state = None;
    });
}

trait ExternalViewportHandle: Send + Sync {
    fn create_window_context(
        &self,
        event_loop: &ActiveEventLoop,
        sender: EventSender,
        clipboard: &mut Clipboard,
    ) -> Result<WindowContext, String>;

    fn is_closed(&self) -> bool;

    fn mark_closed(&self);

    fn mark_start_failed(&self);
}

struct ExternalViewportRequest<I: PtyIpc + Send + Sync + 'static> {
    viewport: Arc<ExternalPtyViewport<I>>,
}

impl<I: PtyIpc + Send + Sync + 'static> ExternalViewportHandle for ExternalViewportRequest<I> {
    fn create_window_context(
        &self,
        event_loop: &ActiveEventLoop,
        sender: EventSender,
        clipboard: &mut Clipboard,
    ) -> Result<WindowContext, String> {
        let pty = SocketEventedPty::new(Arc::clone(&self.viewport)).map_err(|err| err.to_string())?;
        let mut config = UiConfig::default();
        config.window.identity.title = self.viewport.title.clone();

        let mut window_options = WindowOptions::default();
        window_options.window_identity.title = Some(self.viewport.title.clone());

        unsafe {
            *clipboard = Clipboard::new(event_loop.display_handle().unwrap().as_raw());
        }

        // Keyboard mapping for external windows is resolved by WindowContext input/bindings.
        // Search anchors: default_key_bindings, Backspace, ModifiersState::CONTROL.
        WindowContext::external(event_loop, sender, Rc::new(config), window_options, pty)
            .map_err(|err| err.to_string())
    }

    fn is_closed(&self) -> bool {
        self.viewport.closed.load(Ordering::Relaxed)
    }

    fn mark_closed(&self) {
        self.viewport.closed.store(true, Ordering::Relaxed);
    }

    fn mark_start_failed(&self) {
        self.viewport.window_started.store(false, Ordering::Relaxed);
        self.viewport.closed.store(true, Ordering::Relaxed);
    }
}

struct ExternalWindowState {
    viewport: Arc<dyn ExternalViewportHandle>,
    window_context: WindowContext,
}

pub struct SocketEventedPty<I: PtyIpc + Send + Sync + 'static> {
    reader: UnixStream,
    writer: SocketPtyWriter<I>,
    signal_reader: UnixStream,
    _signal_writer: UnixStream,
    shutdown: Arc<AtomicBool>,
    _feed_thread: Option<thread::JoinHandle<()>>,
}

impl<I: PtyIpc + Send + Sync + 'static> SocketEventedPty<I> {
    pub fn new(viewport: Arc<ExternalPtyViewport<I>>) -> io::Result<Self> {
        let (reader, feeder_writer) = UnixStream::pair()?;
        let (signal_reader, signal_writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        signal_reader.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_bg = Arc::clone(&shutdown);
        let viewport_bg = Arc::clone(&viewport);
        let mut feeder_writer_bg = feeder_writer.try_clone()?;

        let feed_thread = thread::Builder::new()
            .name(format!("term-view-pty-feed-{}", viewport.pid))
            .spawn(move || {
                let mut observed_generation = 0;
                while !shutdown_bg.load(Ordering::Relaxed)
                    && !viewport_bg.closed.load(Ordering::Relaxed)
                {
                    let bytes = viewport_bg.ipc.drain_incoming();
                    if !bytes.is_empty() && feeder_writer_bg.write_all(&bytes).is_err() {
                        break;
                    }

                    if shutdown_bg.load(Ordering::Relaxed)
                        || viewport_bg.closed.load(Ordering::Relaxed)
                    {
                        break;
                    }

                    observed_generation = viewport_bg.ipc.wait_for_incoming(observed_generation);
                }
            })
            .map_err(io::Error::other)?;

        Ok(Self {
            reader,
            writer: SocketPtyWriter { viewport },
            signal_reader,
            _signal_writer: signal_writer,
            shutdown,
            _feed_thread: Some(feed_thread),
        })
    }
}

impl<I: PtyIpc + Send + Sync + 'static> Drop for SocketEventedPty<I> {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.writer.viewport.ipc.wake_waiters();
    }
}

impl<I: PtyIpc + Send + Sync + 'static> EventedReadWrite for SocketEventedPty<I> {
    type Reader = UnixStream;
    type Writer = SocketPtyWriter<I>;

    unsafe fn register(
        &mut self,
        poll: &std::sync::Arc<Poller>,
        mut interest: PollingEvent,
        poll_opts: PollMode,
    ) -> io::Result<()> {
        interest.key = PTY_READ_WRITE_TOKEN;
        unsafe { poll.add_with_mode(&self.reader, interest, poll_opts)? };
        unsafe {
            poll.add_with_mode(
                &self.signal_reader,
                PollingEvent::readable(PTY_CHILD_EVENT_TOKEN),
                PollMode::Level,
            )
        }
    }

    fn reregister(
        &mut self,
        poll: &std::sync::Arc<Poller>,
        mut interest: PollingEvent,
        poll_opts: PollMode,
    ) -> io::Result<()> {
        interest.key = PTY_READ_WRITE_TOKEN;
        poll.modify_with_mode(&self.reader, interest, poll_opts)?;
        poll.modify_with_mode(
            &self.signal_reader,
            PollingEvent::readable(PTY_CHILD_EVENT_TOKEN),
            PollMode::Level,
        )
    }

    fn deregister(&mut self, poll: &std::sync::Arc<Poller>) -> io::Result<()> {
        poll.delete(&self.reader)?;
        poll.delete(&self.signal_reader)
    }

    fn reader(&mut self) -> &mut Self::Reader {
        &mut self.reader
    }

    fn writer(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

impl<I: PtyIpc + Send + Sync + 'static> EventedPty for SocketEventedPty<I> {
    fn next_child_event(&mut self) -> Option<ChildEvent> {
        None
    }
}

impl<I: PtyIpc + Send + Sync + 'static> OnResize for SocketEventedPty<I> {
    fn on_resize(&mut self, window_size: WindowSize) {
        self.writer
            .viewport
            .ipc
            .send_resize(window_size.num_cols, window_size.num_lines);
    }
}

pub struct SocketPtyWriter<I: PtyIpc + Send + Sync + 'static> {
    viewport: Arc<ExternalPtyViewport<I>>,
}

impl<I: PtyIpc + Send + Sync + 'static> Write for SocketPtyWriter<I> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.is_empty() {
            self.viewport.ipc.send_input(buf.to_vec());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
