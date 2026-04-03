use anyhow::{Context, Result};
use diag::{DaemonEvent, DaemonRequest, UpDaemonReader, UpDaemonWriter, UpWireEvent};
use serde::{Deserialize, Serialize};
use std::future::pending;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use term_view::{ExternalPtyViewport, PtyIpc};
use tracing::{error, warn};

use crate::supervisor::ContainerName;

const TERMINAL_RESET_SEQUENCE: &[u8] = b"\x1bc";

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

enum BackendCommand {
    Control(TermWindowRequest),
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

struct SharedPtyState {
    incoming: Mutex<Vec<u8>>,
    generation: Mutex<u64>,
    condvar: Condvar,
    backend_stopped: AtomicBool,
}

impl SharedPtyState {
    fn new() -> Self {
        Self {
            incoming: Mutex::new(Vec::new()),
            generation: Mutex::new(0),
            condvar: Condvar::new(),
            backend_stopped: AtomicBool::new(false),
        }
    }

    fn append_incoming(&self, data: &[u8]) {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        guard.extend_from_slice(data);
        drop(guard);
        self.bump_generation();
    }

    fn reset_terminal(&self) {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
        guard.extend_from_slice(TERMINAL_RESET_SEQUENCE);
        drop(guard);
        self.bump_generation();
    }

    fn drain_incoming(&self) -> Vec<u8> {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
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

    fn mark_backend_stopped(&self) {
        self.backend_stopped.store(true, Ordering::Relaxed);
        self.bump_generation();
    }

    fn backend_stopped(&self) -> bool {
        self.backend_stopped.load(Ordering::Relaxed)
    }

    fn bump_generation(&self) {
        let mut guard = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *guard = guard.saturating_add(1);
        self.condvar.notify_all();
    }
}

#[derive(Clone)]
struct AlacrittyWindowIpc {
    shared: Arc<SharedPtyState>,
    cmd_tx: flume::Sender<BackendCommand>,
}

impl PtyIpc for AlacrittyWindowIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        self.shared.drain_incoming()
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

struct ExternalWindowHandle {
    viewport: Arc<ExternalPtyViewport<AlacrittyWindowIpc>>,
    shared: Arc<SharedPtyState>,
    cmd_tx: flume::Sender<BackendCommand>,
}

#[derive(Default)]
pub struct ExternalTermWindowClient {
    window: Option<ExternalWindowHandle>,
    current_target: Option<TermWindowTarget>,
}

impl ExternalTermWindowClient {
    pub fn current_target(&self) -> Option<&TermWindowTarget> {
        self.current_target.as_ref()
    }

    pub fn poll(&mut self) {
        let should_shutdown = self.window.as_ref().is_some_and(|window| {
            window.viewport.closed.load(Ordering::Relaxed) || window.shared.backend_stopped()
        });
        if should_shutdown {
            self.shutdown_current_window();
        }
    }

    pub fn attach(&mut self, profile: ContainerName, pid: u32) -> Result<()> {
        let target = TermWindowTarget { profile, pid };
        self.ensure_window()?;
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
        self.shutdown_current_window();
    }

    fn shutdown_current_window(&mut self) {
        if let Some(window) = self.window.take() {
            let _ = window.cmd_tx.send(BackendCommand::Control(TermWindowRequest::Shutdown));
            window.viewport.closed.store(true, Ordering::Relaxed);
            window.viewport.ipc.wake_waiters();
        }
        self.current_target = None;
    }

    fn send_request(&mut self, request: TermWindowRequest) -> Result<()> {
        self.ensure_window()?;

        let send = |window: &ExternalWindowHandle| {
            window
                .cmd_tx
                .send(BackendCommand::Control(request.clone()))
                .with_context(|| format!("send alacritty window request: {request:?}"))
        };

        if let Some(window) = self.window.as_ref() {
            if send(window).is_ok() {
                return Ok(());
            }
        }

        self.shutdown_current_window();
        self.ensure_window()?;
        if let Some(window) = self.window.as_ref() {
            send(window)?;
        }
        Ok(())
    }

    fn ensure_window(&mut self) -> Result<()> {
        self.poll();
        if self.window.is_some() {
            return Ok(());
        }

        let shared = Arc::new(SharedPtyState::new());
        let (cmd_tx, cmd_rx) = flume::unbounded();
        let ipc = AlacrittyWindowIpc {
            shared: Arc::clone(&shared),
            cmd_tx: cmd_tx.clone(),
        };
        let viewport = Arc::new(ExternalPtyViewport::new(ipc, 0, "Terminal".to_string()));

        let shared_for_thread = Arc::clone(&shared);
        thread::Builder::new()
            .name("nsproxy-alacritty-pty".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(err) => {
                        error!(%err, "failed to build alacritty PTY backend runtime");
                        shared_for_thread.mark_backend_stopped();
                        return;
                    }
                };
                if let Err(err) = runtime.block_on(run_backend(cmd_rx, Arc::clone(&shared_for_thread))) {
                    error!(%err, "alacritty PTY backend stopped with error");
                }
            })
            .context("spawn alacritty PTY backend thread")?;

        ExternalPtyViewport::ensure_native_window(&viewport);

        self.window = Some(ExternalWindowHandle {
            viewport,
            shared,
            cmd_tx,
        });
        Ok(())
    }
}

impl Drop for ExternalTermWindowClient {
    fn drop(&mut self) {
        self.shutdown();
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
                    BackendCommand::Control(TermWindowRequest::Attach { target: next, focus: _ }) => {
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
                        shared.reset_terminal();
                        target = Some(next);
                        ensure_attached(&target, &mut current_profile, &mut reader, &mut writer).await;
                    }
                    BackendCommand::Control(TermWindowRequest::Detach) => {
                        if let Some(prev) = target.take() {
                            if let Some(active_writer) = writer.as_mut() {
                                let _ = active_writer
                                    .send_unstable_request(&DaemonRequest::DetachPty { pid: prev.pid })
                                    .await;
                            }
                        }
                        shared.reset_terminal();
                    }
                    BackendCommand::Control(TermWindowRequest::Focus) => {}
                    BackendCommand::Control(TermWindowRequest::Shutdown) => {
                        break;
                    }
                    BackendCommand::Input(data) => {
                        if let (Some(active_target), Some(active_writer)) = (target.as_ref(), writer.as_mut()) {
                            if let Err(err) = active_writer
                                .send_unstable_request(&DaemonRequest::PtyInput { pid: active_target.pid, data })
                                .await
                            {
                                warn!(%err, pid = active_target.pid, "alacritty PTY input send failed");
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
                                warn!(%err, pid = active_target.pid, "alacritty PTY resize send failed");
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
                    }
                    Err(err) => {
                        if let Some(active_target) = target.as_ref() {
                            warn!(%err, pid = active_target.pid, "alacritty PTY up stream error");
                        } else {
                            warn!(%err, "alacritty PTY up stream error");
                        }
                        reader = None;
                        writer = None;
                        current_profile = None;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)), if target.is_some() && writer.is_none() => {
                ensure_attached(&target, &mut current_profile, &mut reader, &mut writer).await;
            }
        }
    }

    if let (Some(active_target), Some(active_writer)) = (target.as_ref(), writer.as_mut()) {
        let _ = active_writer
            .send_unstable_request(&DaemonRequest::DetachPty { pid: active_target.pid })
            .await;
    }

    shared.mark_backend_stopped();
    Ok(())
}

async fn ensure_attached(
    target: &Option<TermWindowTarget>,
    current_profile: &mut Option<ContainerName>,
    reader: &mut Option<UpDaemonReader>,
    writer: &mut Option<UpDaemonWriter>,
) {
    let Some(target) = target.as_ref() else {
        return;
    };

    if writer.is_none() || current_profile.as_ref() != Some(&target.profile) {
        let sock_path = diag::up_sock_path(&target.profile);
        match diag::connect_up_daemon(&sock_path).await {
            Ok(stream) => {
                let (next_reader, next_writer) = stream.split();
                *reader = Some(next_reader);
                *writer = Some(next_writer);
                *current_profile = Some(target.profile.clone());
            }
            Err(err) => {
                warn!(%err, profile = %target.profile, pid = target.pid, "failed to connect to sp up for alacritty PTY window");
                return;
            }
        }
    }

    if let Some(active_writer) = writer.as_mut() {
        if let Err(err) = active_writer
            .send_unstable_request(&DaemonRequest::AttachPty { pid: target.pid })
            .await
        {
            warn!(%err, profile = %target.profile, pid = target.pid, "failed to attach alacritty PTY window");
            *reader = None;
            *writer = None;
            *current_profile = None;
        }
    }
}

fn handle_up_event(shared: &Arc<SharedPtyState>, target: Option<&TermWindowTarget>, event: DaemonEvent) {
    let Some(target) = target else {
        return;
    };

    match event {
        DaemonEvent::PtyScrollback { pid, data } | DaemonEvent::PtyOutput { pid, data }
            if pid == target.pid =>
        {
            shared.append_incoming(&data);
        }
        DaemonEvent::ProcessExit { pid } if pid == target.pid => {
            shared.bump_generation();
        }
        DaemonEvent::Error { msg } => {
            warn!(%msg, profile = %target.profile, pid = target.pid, "alacritty PTY daemon error");
        }
        _ => {}
    }
}