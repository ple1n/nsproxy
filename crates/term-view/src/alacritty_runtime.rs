#![cfg(feature = "alacritty-opengl")]

use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use polling::{Event as PollingEvent, PollMode, Poller};
use winit::application::ApplicationHandler;
use winit::event::{Event as WinitEvent, StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, DeviceEvents, EventLoop};
use winit::raw_window_handle::HasDisplayHandle;
use winit::window::WindowId;

use alacritty_terminal::event::{Event as TerminalEvent, OnResize, WindowSize};
use alacritty_terminal::tty::{self, ChildEvent, EventedPty, EventedReadWrite};

use crate::PtyIpc;
use crate::cli::Options;
use crate::clipboard::Clipboard;
use crate::config::{self, UiConfig};
use crate::event::{Event, EventSender, EventType};
use crate::scheduler::Scheduler;
use crate::window_context::WindowContext;

const PTY_READ_WRITE_TOKEN: usize = 0;

struct PendingWindow<I: PtyIpc + Send + Sync + 'static> {
    ipc: Arc<I>,
    pid: u32,
    closed: Arc<AtomicBool>,
}

struct StandaloneRuntime<I: PtyIpc + Send + Sync + 'static> {
    sender: EventSender,
    clipboard: Clipboard,
    scheduler: Scheduler,
    config: Rc<UiConfig>,
    pending: Option<PendingWindow<I>>,
    window: Option<WindowContext>,
    initial_error: Option<Box<dyn Error>>,
}

impl<I: PtyIpc + Send + Sync + 'static> StandaloneRuntime<I> {
    fn new(sender: EventSender, config: Rc<UiConfig>, pending: PendingWindow<I>) -> Self {
        Self {
            clipboard: Clipboard::new_nop(),
            scheduler: Scheduler::new(sender.clone()),
            sender,
            config,
            pending: Some(pending),
            window: None,
            initial_error: None,
        }
    }

    fn create_initial_window(&mut self, event_loop: &ActiveEventLoop) -> Result<(), Box<dyn Error>> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };

        let title_prefix_provider = {
            let ipc = Arc::clone(&pending.ipc);
            Arc::new(move || ipc.window_title_prefix())
        };

        unsafe {
            self.clipboard = Clipboard::new(event_loop.display_handle().unwrap().as_raw());
        }

        let ready_ipc = Arc::clone(&pending.ipc);

        let window_context = WindowContext::external(
            event_loop,
            self.sender.clone(),
            self.config.clone(),
            Default::default(),
            SocketEventedPty::new(pending.ipc, pending.pid, pending.closed)?,
            Some(title_prefix_provider),
        )?;

        self.window = Some(window_context);
        ready_ipc.window_ready();
        Ok(())
    }

    fn close_window(&mut self) {
        if let Some(mut window) = self.window.take() {
            self.scheduler.unschedule_window(window.id());
            window.shutdown();
        }
    }

    fn handle_user_event(&mut self, event_loop: &ActiveEventLoop, event: Event) {
        match (event.payload(), event.window_id()) {
            (EventType::Terminal(TerminalEvent::Wakeup), Some(window_id)) => {
                if let Some(window) = self.window.as_mut().filter(|window| window.id() == window_id) {
                    window.dirty = true;
                    if window.display.window.has_frame {
                        window.display.window.request_redraw();
                    }
                }
            }
            (EventType::Terminal(TerminalEvent::Exit), Some(window_id)) => {
                if self
                    .window
                    .as_ref()
                    .is_some_and(|window| window.id() == window_id)
                {
                    self.close_window();
                    event_loop.exit();
                }
            }
            (EventType::Frame, Some(window_id)) => {
                if let Some(window) = self.window.as_mut().filter(|window| window.id() == window_id) {
                    window.display.window.has_frame = true;
                    if window.dirty {
                        window.display.window.request_redraw();
                    }
                }
            }
            (payload, Some(window_id)) => {
                if let Some(window) = self.window.as_mut().filter(|window| window.id() == window_id) {
                    window.handle_event(
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
                if let Some(window) = self.window.as_mut() {
                    window.handle_event(
                        #[cfg(target_os = "macos")]
                        event_loop,
                        &self.sender,
                        &mut self.clipboard,
                        &mut self.scheduler,
                        WinitEvent::UserEvent(Event::new(payload.clone(), None)),
                    );
                }
            }
        }
    }
}

impl<I: PtyIpc + Send + Sync + 'static> ApplicationHandler<Event> for StandaloneRuntime<I> {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

    fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
        if cause != StartCause::Init {
            return;
        }

        if let Err(err) = self.create_initial_window(event_loop) {
            self.initial_error = Some(err);
            event_loop.exit();
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: Event) {
        self.handle_user_event(event_loop, event);
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        let close_requested = matches!(event, WindowEvent::CloseRequested);
        let is_redraw = matches!(event, WindowEvent::RedrawRequested);

        let Some(window) = self.window.as_mut().filter(|window| window.id() == window_id) else {
            return;
        };

        window.handle_event(
            #[cfg(target_os = "macos")]
            event_loop,
            &self.sender,
            &mut self.clipboard,
            &mut self.scheduler,
            WinitEvent::WindowEvent { window_id, event },
        );

        if is_redraw {
            window.draw(&mut self.scheduler);
        }

        if close_requested {
            self.close_window();
            event_loop.exit();
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(window) = self.window.as_mut() {
            window.handle_event(
                #[cfg(target_os = "macos")]
                event_loop,
                &self.sender,
                &mut self.clipboard,
                &mut self.scheduler,
                WinitEvent::AboutToWait,
            );
        } else {
            event_loop.exit();
            return;
        }

        event_loop.set_control_flow(
            self.scheduler
                .update()
                .map(ControlFlow::WaitUntil)
                .unwrap_or(ControlFlow::Wait),
        );
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.close_window();
        self.clipboard = Clipboard::new_nop();
    }
}

pub fn run_standalone_window<I: PtyIpc + Send + Sync + 'static>(
    ipc: Arc<I>,
    pid: u32,
    closed: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    let mut options = Options::default();
    let config = config::load(&mut options);

    tty::setup_env();
    for (key, value) in config.env.iter() {
        unsafe { env::set_var(key, value); }
    }

    let event_loop = EventLoop::<Event>::with_user_event().build()?;
    event_loop.listen_device_events(DeviceEvents::Never);

    let sender = EventSender::from_winit_proxy(event_loop.create_proxy());
    let mut runtime = StandaloneRuntime::new(
        sender,
        Rc::new(config),
        PendingWindow { ipc, pid, closed },
    );

    let result = event_loop.run_app(&mut runtime);
    if let Some(err) = runtime.initial_error.take() {
        return Err(err);
    }

    result.map_err(Into::into)
}

pub struct SocketPtyReader<I: PtyIpc + Send + Sync + 'static> {
    ipc: Arc<I>,
    wake_reader: UnixStream,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl<I: PtyIpc + Send + Sync + 'static> SocketPtyReader<I> {
    fn new(ipc: Arc<I>, wake_reader: UnixStream) -> Self {
        Self {
            ipc,
            wake_reader,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }

    fn refill_pending(&mut self) {
        if self.pending_offset < self.pending.len() {
            return;
        }

        self.pending = self.ipc.drain_incoming();
        self.pending_offset = 0;
    }

    fn drain_wake_bytes(&mut self) -> io::Result<()> {
        let mut buf = [0_u8; 256];
        loop {
            match self.wake_reader.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) if n < buf.len() => return Ok(()),
                Ok(_) => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

impl<I: PtyIpc + Send + Sync + 'static> io::Read for SocketPtyReader<I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.drain_wake_bytes()?;
        self.refill_pending();

        if self.pending_offset >= self.pending.len() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let remaining = &self.pending[self.pending_offset..];
        let count = remaining.len().min(buf.len());
        buf[..count].copy_from_slice(&remaining[..count]);
        self.pending_offset += count;

        if self.pending_offset >= self.pending.len() {
            self.pending.clear();
            self.pending_offset = 0;
        }

        Ok(count)
    }
}

pub struct SocketEventedPty<I: PtyIpc + Send + Sync + 'static> {
    reader: SocketPtyReader<I>,
    writer: SocketPtyWriter<I>,
    wake_reader: UnixStream,
    shutdown: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    child_exit_pending: bool,
    _wake_thread: Option<thread::JoinHandle<()>>,
}

impl<I: PtyIpc + Send + Sync + 'static> SocketEventedPty<I> {
    pub fn new(ipc: Arc<I>, pid: u32, closed: Arc<AtomicBool>) -> io::Result<Self> {
        let (wake_reader, wake_writer) = UnixStream::pair()?;
        wake_reader.set_nonblocking(true)?;
        wake_writer.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_bg = Arc::clone(&shutdown);
        let closed_bg = Arc::clone(&closed);
        let ipc_bg = Arc::clone(&ipc);
        let mut wake_writer_bg = wake_writer.try_clone()?;

        let wake_thread = thread::Builder::new()
            .name(format!("term-view-pty-wake-{pid}"))
            .spawn(move || {
                let mut observed_generation = 0;
                while !shutdown_bg.load(Ordering::Relaxed) && !closed_bg.load(Ordering::Relaxed) {
                    observed_generation = ipc_bg.wait_for_incoming(observed_generation);
                    let _ = wake_writer_bg.write(&[1]);
                    if shutdown_bg.load(Ordering::Relaxed) || closed_bg.load(Ordering::Relaxed) {
                        break;
                    }
                }
            })
            .map_err(io::Error::other)?;

        Ok(Self {
            reader: SocketPtyReader::new(Arc::clone(&ipc), wake_reader.try_clone()?),
            writer: SocketPtyWriter { ipc },
            wake_reader,
            shutdown,
            closed,
            child_exit_pending: true,
            _wake_thread: Some(wake_thread),
        })
    }
}

impl<I: PtyIpc + Send + Sync + 'static> Drop for SocketEventedPty<I> {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.writer.ipc.wake_waiters();
    }
}

impl<I: PtyIpc + Send + Sync + 'static> EventedReadWrite for SocketEventedPty<I> {
    type Reader = SocketPtyReader<I>;
    type Writer = SocketPtyWriter<I>;

    unsafe fn register(
        &mut self,
        poll: &std::sync::Arc<Poller>,
        mut interest: PollingEvent,
        poll_opts: PollMode,
    ) -> io::Result<()> {
        interest.key = PTY_READ_WRITE_TOKEN;
        unsafe { poll.add_with_mode(&self.wake_reader, interest, poll_opts) }
    }

    fn reregister(
        &mut self,
        poll: &std::sync::Arc<Poller>,
        mut interest: PollingEvent,
        poll_opts: PollMode,
    ) -> io::Result<()> {
        interest.key = PTY_READ_WRITE_TOKEN;
        poll.modify_with_mode(&self.wake_reader, interest, poll_opts)
    }

    fn deregister(&mut self, poll: &std::sync::Arc<Poller>) -> io::Result<()> {
        poll.delete(&self.wake_reader)
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
        if self.closed.load(Ordering::Relaxed) && self.child_exit_pending {
            self.child_exit_pending = false;
            return Some(ChildEvent::Exited(None));
        }
        None
    }
}

impl<I: PtyIpc + Send + Sync + 'static> OnResize for SocketEventedPty<I> {
    fn on_resize(&mut self, window_size: WindowSize) {
        self.writer
            .ipc
            .send_resize(window_size.num_cols, window_size.num_lines);
    }
}

pub struct SocketPtyWriter<I: PtyIpc + Send + Sync + 'static> {
    ipc: Arc<I>,
}

impl<I: PtyIpc + Send + Sync + 'static> Write for SocketPtyWriter<I> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.is_empty() {
            self.ipc.send_input(buf.to_vec());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
