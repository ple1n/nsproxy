use anyhow::{Context, Result};
use diag::{DaemonEvent, DaemonRequest, UpDaemonReader, UpDaemonWriter, UpWireEvent};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::future::pending;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use term_view::{PtyIpc, TermSession, TermView, flush_term_outputs, pump_pty_io};
use tracing::{error, info, warn};

use crate::supervisor::ContainerName;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermWindowTarget {
    pub profile: ContainerName,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TermWindowRequest {
    Attach { target: TermWindowTarget, focus: bool },
    Detach,
    Focus,
    Shutdown,
}

#[derive(Debug)]
enum BackendCommand {
    Control(TermWindowRequest),
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Shutdown,
}

struct TermWindowProcess {
    child: Child,
    control: UnixStream,
}

#[derive(Default)]
pub struct ExternalTermWindowClient {
    process: Option<TermWindowProcess>,
    current_target: Option<TermWindowTarget>,
}

impl ExternalTermWindowClient {
    pub fn current_target(&self) -> Option<&TermWindowTarget> {
        self.current_target.as_ref()
    }

    pub fn poll(&mut self) {
        let Some(process) = self.process.as_mut() else {
            return;
        };

        match process.child.try_wait() {
            Ok(Some(status)) => {
                info!(?status, "terminal window child exited");
                self.process = None;
                self.current_target = None;
            }
            Ok(None) => {}
            Err(err) => {
                warn!(%err, "failed to poll terminal window child status");
                self.process = None;
                self.current_target = None;
            }
        }
    }

    pub fn attach(&mut self, profile: ContainerName, pid: u32) -> Result<()> {
        let target = TermWindowTarget { profile, pid };
        self.send_request(TermWindowRequest::Attach {
            target: target.clone(),
            focus: true,
        })?;
        self.current_target = Some(target);
        Ok(())
    }

    pub fn focus(&mut self) -> Result<()> {
        self.send_request(TermWindowRequest::Focus)
    }

    pub fn detach(&mut self) -> Result<()> {
        self.send_request(TermWindowRequest::Detach)?;
        self.current_target = None;
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = write_frame(&mut process.control, &TermWindowRequest::Shutdown);
            let _ = process.control.shutdown(std::net::Shutdown::Both);
            match process.child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let _ = process.child.kill();
                    let _ = process.child.wait();
                }
                Err(_) => {}
            }
        }
        self.current_target = None;
    }

    fn send_request(&mut self, request: TermWindowRequest) -> Result<()> {
        self.ensure_process()?;

        let send = |process: &mut TermWindowProcess| {
            write_frame(&mut process.control, &request)
                .with_context(|| format!("send terminal window request: {request:?}"))
        };

        if let Some(process) = self.process.as_mut() {
            if send(process).is_ok() {
                return Ok(());
            }
        }

        self.shutdown();
        self.ensure_process()?;
        if let Some(process) = self.process.as_mut() {
            send(process)?;
        }
        Ok(())
    }

    fn ensure_process(&mut self) -> Result<()> {
        self.poll();
        if self.process.is_some() {
            return Ok(());
        }

        let (parent_sock, child_sock) = UnixStream::pair().context("create terminal control socket pair")?;
        set_fd_inheritable(child_sock.as_raw_fd()).context("make terminal child fd inheritable")?;

        let exe = std::env::current_exe().context("resolve current nsproxy-ui executable")?;
        let fd_arg = child_sock.as_raw_fd().to_string();
        let build_hash = diag::protocol_version().to_string();

        let child = Command::new(exe)
            .arg("--build-hash")
            .arg(build_hash)
            .args(diag::protocol_lenient().then_some("--lenient"))
            .arg("--term-window-fd")
            .arg(fd_arg)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn terminal window child")?;

        drop(child_sock);
        self.process = Some(TermWindowProcess {
            child,
            control: parent_sock,
        });
        Ok(())
    }
}

impl Drop for ExternalTermWindowClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct SharedPtyState {
    incoming: Mutex<Vec<u8>>,
    generation: Mutex<u64>,
    condvar: Condvar,
    target: Mutex<Option<TermWindowTarget>>,
    status: Mutex<Option<String>>,
    focus_requested: AtomicBool,
    close_requested: AtomicBool,
    ctx: egui::Context,
}

impl SharedPtyState {
    fn new(ctx: egui::Context) -> Self {
        Self {
            incoming: Mutex::new(Vec::new()),
            generation: Mutex::new(0),
            condvar: Condvar::new(),
            target: Mutex::new(None),
            status: Mutex::new(None),
            focus_requested: AtomicBool::new(false),
            close_requested: AtomicBool::new(false),
            ctx,
        }
    }

    fn clear_incoming(&self) {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
        drop(guard);
        self.bump_generation();
    }

    fn append_incoming(&self, data: &[u8]) {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        guard.extend_from_slice(data);
        drop(guard);
        self.bump_generation();
        self.ctx.request_repaint();
    }

    fn replace_target(&self, target: Option<TermWindowTarget>) {
        let mut guard = self.target.lock().unwrap_or_else(|e| e.into_inner());
        *guard = target;
        drop(guard);
        self.ctx.request_repaint();
    }

    fn target(&self) -> Option<TermWindowTarget> {
        self.target.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_status(&self, status: Option<String>) {
        let mut guard = self.status.lock().unwrap_or_else(|e| e.into_inner());
        *guard = status;
        drop(guard);
        self.ctx.request_repaint();
    }

    fn status(&self) -> Option<String> {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn request_focus(&self) {
        self.focus_requested.store(true, Ordering::Relaxed);
        self.ctx.request_repaint();
    }

    fn take_focus_request(&self) -> bool {
        self.focus_requested.swap(false, Ordering::Relaxed)
    }

    fn request_close(&self) {
        self.close_requested.store(true, Ordering::Relaxed);
        self.bump_generation();
        self.ctx.request_repaint();
    }

    fn take_close_request(&self) -> bool {
        self.close_requested.swap(false, Ordering::Relaxed)
    }

    fn wait_for_change(&self, observed_generation: u64) -> u64 {
        let mut guard = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let current = *guard;
            if current > observed_generation {
                return current;
            }
            guard = self.condvar.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn bump_generation(&self) {
        let mut guard = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *guard = guard.saturating_add(1);
        self.condvar.notify_all();
    }
}

#[derive(Clone)]
struct TermBackendIpc {
    shared: Arc<SharedPtyState>,
    cmd_tx: flume::Sender<BackendCommand>,
}

impl PtyIpc for TermBackendIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        let mut guard = self.shared.incoming.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }

    fn wait_for_incoming(&self, observed_generation: u64) -> u64 {
        self.shared.wait_for_change(observed_generation)
    }

    fn wake_waiters(&self) {
        self.shared.bump_generation();
    }

    fn send_input(&self, data: Vec<u8>) {
        let _ = self.cmd_tx.send(BackendCommand::Input(data));
    }

    fn send_resize(&self, cols: u16, rows: u16) {
        let _ = self.cmd_tx.send(BackendCommand::Resize { cols, rows });
    }
}

struct TermWindowApp {
    ipc: TermBackendIpc,
    shared: Arc<SharedPtyState>,
    session: Option<TermSession>,
    session_target: Option<TermWindowTarget>,
    title: String,
}

impl TermWindowApp {
    fn new(ctx: &egui::Context, control_fd: RawFd) -> Result<Self> {
        let shared = Arc::new(SharedPtyState::new(ctx.clone()));
        let (cmd_tx, cmd_rx) = flume::unbounded();

        let control_stream = unsafe { UnixStream::from_raw_fd(control_fd) };
        let control_reader = control_stream
            .try_clone()
            .context("clone terminal control socket for reader thread")?;

        let shared_for_control = Arc::clone(&shared);
        let cmd_tx_for_control = cmd_tx.clone();
        thread::Builder::new()
            .name("nsproxy-term-control".to_string())
            .spawn(move || {
                run_control_reader(control_reader, cmd_tx_for_control, shared_for_control);
            })
            .context("spawn terminal control reader thread")?;

        let shared_for_backend = Arc::clone(&shared);
        thread::Builder::new()
            .name("nsproxy-term-backend".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(err) => {
                        error!(%err, "failed to build terminal backend runtime");
                        shared_for_backend.set_status(Some(format!("runtime init failed: {err}")));
                        shared_for_backend.request_close();
                        return;
                    }
                };
                if let Err(err) = runtime.block_on(run_backend(cmd_rx, shared_for_backend)) {
                    error!(%err, "terminal backend stopped with error");
                }
            })
            .context("spawn terminal backend thread")?;

        Ok(Self {
            ipc: TermBackendIpc { shared: Arc::clone(&shared), cmd_tx },
            shared,
            session: None,
            session_target: None,
            title: "Terminal".to_string(),
        })
    }

    fn sync_target_state(&mut self, ctx: &egui::Context) {
        let target = self.shared.target();
        if target != self.session_target {
            self.session = target.as_ref().map(|t| TermSession::new(t.pid));
            self.session_target = target.clone();
        }

        let next_title = target
            .as_ref()
            .map(|t| format!("Terminal - {} / PID {}", t.profile, t.pid))
            .unwrap_or_else(|| "Terminal".to_string());

        if next_title != self.title {
            self.title = next_title;
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(self.title.clone()));
        }

        if self.shared.take_focus_request() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
    }
}

impl eframe::App for TermWindowApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.shared.take_close_request() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.sync_target_state(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(session) = self.session.as_mut() {
                pump_pty_io(&self.ipc, session);
                let mut input_frames = Vec::new();
                let mut resize_evt = None;
                ui.add(
                    TermView::new(session, &mut input_frames, &mut resize_evt)
                        .set_size(ui.available_size()),
                );
                flush_term_outputs(&self.ipc, input_frames, resize_evt);
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    ui.heading("Terminal window");
                    ui.add_space(8.0);
                    if let Some(status) = self.shared.status() {
                        ui.label(status);
                    } else {
                        ui.label("No PTY attached.");
                    }
                });
            }
        });
    }
}

impl Drop for TermWindowApp {
    fn drop(&mut self) {
        let _ = self.ipc.cmd_tx.send(BackendCommand::Shutdown);
        self.shared.request_close();
    }
}

fn run_control_reader(
    mut control: UnixStream,
    cmd_tx: flume::Sender<BackendCommand>,
    shared: Arc<SharedPtyState>,
) {
    loop {
        match read_frame::<TermWindowRequest>(&mut control) {
            Ok(Some(request)) => {
                if cmd_tx.send(BackendCommand::Control(request)).is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = cmd_tx.send(BackendCommand::Shutdown);
                break;
            }
            Err(err) => {
                warn!(%err, "terminal control socket read failed");
                shared.set_status(Some(format!("control socket error: {err}")));
                let _ = cmd_tx.send(BackendCommand::Shutdown);
                break;
            }
        }
    }
}

async fn run_backend(cmd_rx: flume::Receiver<BackendCommand>, shared: Arc<SharedPtyState>) -> Result<()> {
    let mut target: Option<TermWindowTarget> = None;
    let mut current_profile: Option<ContainerName> = None;
    let mut reader: Option<UpDaemonReader> = None;
    let mut writer: Option<UpDaemonWriter> = None;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv_async() => {
                let Ok(cmd) = cmd else {
                    break;
                };
                match cmd {
                    BackendCommand::Control(TermWindowRequest::Attach { target: next, focus }) => {
                        if focus {
                            shared.request_focus();
                        }
                        if let Some(prev) = target.as_ref() {
                            if let Some(active_writer) = writer.as_mut() {
                                if prev.pid != next.pid || prev.profile != next.profile {
                                    let _ = active_writer
                                        .send_unstable_request(&DaemonRequest::DetachPty { pid: prev.pid })
                                        .await;
                                }
                            }
                        }
                        if current_profile.as_ref() != Some(&next.profile) {
                            reader = None;
                            writer = None;
                            current_profile = None;
                        }
                        shared.clear_incoming();
                        shared.replace_target(Some(next.clone()));
                        shared.set_status(Some(format!("Connecting to {} / PID {}...", next.profile, next.pid)));
                        target = Some(next);
                        ensure_attached(&target, &shared, &mut current_profile, &mut reader, &mut writer).await;
                    }
                    BackendCommand::Control(TermWindowRequest::Detach) => {
                        if let Some(prev) = target.take() {
                            if let Some(active_writer) = writer.as_mut() {
                                let _ = active_writer
                                    .send_unstable_request(&DaemonRequest::DetachPty { pid: prev.pid })
                                    .await;
                            }
                        }
                        shared.clear_incoming();
                        shared.replace_target(None);
                        shared.set_status(Some("No PTY attached.".to_string()));
                    }
                    BackendCommand::Control(TermWindowRequest::Focus) => {
                        shared.request_focus();
                    }
                    BackendCommand::Control(TermWindowRequest::Shutdown) | BackendCommand::Shutdown => {
                        break;
                    }
                    BackendCommand::Input(data) => {
                        if let (Some(active_target), Some(active_writer)) = (target.as_ref(), writer.as_mut()) {
                            if let Err(err) = active_writer
                                .send_unstable_request(&DaemonRequest::PtyInput { pid: active_target.pid, data })
                                .await
                            {
                                warn!(%err, pid = active_target.pid, "terminal input send failed");
                                reader = None;
                                writer = None;
                                current_profile = None;
                            }
                        }
                    }
                    BackendCommand::Resize { cols, rows } => {
                        if let (Some(active_target), Some(active_writer)) = (target.as_ref(), writer.as_mut()) {
                            if let Err(err) = active_writer
                                .send_unstable_request(&DaemonRequest::PtyResize {
                                    pid: active_target.pid,
                                    cols,
                                    rows,
                                })
                                .await
                            {
                                warn!(%err, pid = active_target.pid, "terminal resize send failed");
                                reader = None;
                                writer = None;
                                current_profile = None;
                            }
                        }
                    }
                }
            }
            evt = async {
                match reader.as_mut() {
                    Some(active_reader) => active_reader.next_event().await,
                    None => pending::<Result<Option<UpWireEvent>>>().await,
                }
            } => {
                match evt {
                    Ok(Some(UpWireEvent::Unstable(event))) => {
                        handle_up_event(&shared, target.as_ref(), event);
                    }
                    Ok(Some(UpWireEvent::Stable(_))) => {}
                    Ok(None) => {
                        reader = None;
                        writer = None;
                        current_profile = None;
                        if let Some(active_target) = target.as_ref() {
                            shared.set_status(Some(format!(
                                "Disconnected from {} / PID {}; retrying...",
                                active_target.profile, active_target.pid
                            )));
                        }
                    }
                    Err(err) => {
                        warn!(%err, "terminal up stream error");
                        reader = None;
                        writer = None;
                        current_profile = None;
                        if let Some(active_target) = target.as_ref() {
                            shared.set_status(Some(format!(
                                "up socket error for {} / PID {}: {}",
                                active_target.profile, active_target.pid, err
                            )));
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)), if target.is_some() && writer.is_none() => {
                ensure_attached(&target, &shared, &mut current_profile, &mut reader, &mut writer).await;
            }
        }
    }

    if let (Some(active_target), Some(active_writer)) = (target.as_ref(), writer.as_mut()) {
        let _ = active_writer
            .send_unstable_request(&DaemonRequest::DetachPty { pid: active_target.pid })
            .await;
    }
    shared.request_close();
    Ok(())
}

async fn ensure_attached(
    target: &Option<TermWindowTarget>,
    shared: &Arc<SharedPtyState>,
    current_profile: &mut Option<ContainerName>,
    reader: &mut Option<UpDaemonReader>,
    writer: &mut Option<UpDaemonWriter>,
) {
    let Some(active_target) = target.as_ref() else {
        return;
    };

    if writer.is_none() || current_profile.as_ref() != Some(&active_target.profile) {
        let sock_path = diag::up_sock_path(&active_target.profile);
        match diag::connect_up_daemon(&sock_path).await {
            Ok(stream) => {
                let (next_reader, next_writer) = stream.split();
                *reader = Some(next_reader);
                *writer = Some(next_writer);
                *current_profile = Some(active_target.profile.clone());
            }
            Err(err) => {
                shared.set_status(Some(format!(
                    "Failed to connect to sp up for {}: {}",
                    active_target.profile, err
                )));
                return;
            }
        }
    }

    if let Some(active_writer) = writer.as_mut() {
        if let Err(err) = active_writer
            .send_unstable_request(&DaemonRequest::AttachPty { pid: active_target.pid })
            .await
        {
            shared.set_status(Some(format!(
                "Failed to attach PTY {} / PID {}: {}",
                active_target.profile, active_target.pid, err
            )));
            *reader = None;
            *writer = None;
            *current_profile = None;
            return;
        }
    }

    shared.set_status(None);
}

fn handle_up_event(
    shared: &Arc<SharedPtyState>,
    target: Option<&TermWindowTarget>,
    event: DaemonEvent,
) {
    let Some(active_target) = target else {
        return;
    };

    match event {
        DaemonEvent::PtyScrollback { pid, data } | DaemonEvent::PtyOutput { pid, data }
            if pid == active_target.pid =>
        {
            shared.append_incoming(&data);
            shared.set_status(None);
        }
        DaemonEvent::ProcessExit { pid } if pid == active_target.pid => {
            shared.set_status(Some(format!(
                "Process {} / PID {} exited.",
                active_target.profile, active_target.pid
            )));
        }
        DaemonEvent::Error { msg } => {
            shared.set_status(Some(msg));
        }
        _ => {}
    }
}

fn set_fd_inheritable(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = bincode::serialize(value).context("serialize terminal control frame")?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .context("write terminal control frame length")?;
    stream
        .write_all(&payload)
        .context("write terminal control frame payload")?;
    Ok(())
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("read terminal control frame length"),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .context("read terminal control frame payload")?;
    Ok(Some(
        bincode::deserialize(&payload).context("decode terminal control frame")?,
    ))
}

pub fn parse_term_window_fd_arg(args: &[String]) -> Option<RawFd> {
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--term-window-fd" {
            let value = args.get(idx + 1)?;
            return value.parse::<RawFd>().ok();
        }
        idx += 1;
    }
    None
}

pub fn run_term_window_process(control_fd: RawFd) -> Result<()> {
    info!(fd = control_fd, "starting terminal child window");
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Terminal",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(TermWindowApp::new(&cc.egui_ctx, control_fd)?))
        }),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(())
}