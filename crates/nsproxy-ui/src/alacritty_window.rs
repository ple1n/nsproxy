use anyhow::{Context, Result};
use diag::{DaemonEvent, DaemonRequest, UpDaemonReader, UpDaemonWriter, UpWireEvent};
use serde::{Deserialize, Serialize};
use std::future::pending;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as TokioUnixStream;
use tokio::task::JoinHandle;
use term_view::{PtyIpc, run_standalone_window};
use tracing::{error, info, warn};

use crate::supervisor::ContainerName;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermWindowTarget {
    pub profile: ContainerName,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TermWindowRequest {
    Attach {
        target: TermWindowTarget,
        title: String,
        focus: bool,
    },
    Detach,
    Focus,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TermWindowSignal {
    WindowReady,
    Attached,
    Error(String),
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

struct PendingSpawn {
    target: TermWindowTarget,
    rx: flume::Receiver<Result<TermWindowProcess>>,
    handle: JoinHandle<()>,
}

#[derive(Default)]
pub struct ExternalTermWindowClient {
    process: Option<TermWindowProcess>,
    current_target: Option<TermWindowTarget>,
    pending_spawn: Option<PendingSpawn>,
}

impl ExternalTermWindowClient {
    pub fn is_open(&self) -> bool {
        self.process.is_some()
    }

    pub fn current_target(&self) -> Option<&TermWindowTarget> {
        self.current_target.as_ref()
    }

    pub fn pending_target(&self) -> Option<&TermWindowTarget> {
        self.pending_spawn.as_ref().map(|pending| &pending.target)
    }

    pub fn poll(&mut self) {
        if let Some(pending) = self.pending_spawn.as_ref() {
            match pending.rx.try_recv() {
                Ok(Ok(process)) => {
                    info!(target = ?pending.target, "terminal window child became ready");
                    self.process = Some(process);
                    self.current_target = Some(pending.target.clone());
                    self.pending_spawn = None;
                }
                Ok(Err(err)) => {
                    warn!(%err, target = ?pending.target, "terminal window child spawn failed");
                    self.pending_spawn = None;
                }
                Err(flume::TryRecvError::Empty) => {}
                Err(flume::TryRecvError::Disconnected) => {
                    warn!(target = ?pending.target, "terminal window spawn task disconnected");
                    self.pending_spawn = None;
                }
            }
        }

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

    pub fn attach(
        &mut self,
        rt: &tokio::runtime::Runtime,
        profile: ContainerName,
        pid: u32,
        title: String,
    ) -> Result<()> {
        let target = TermWindowTarget { profile, pid };

        if self.pending_spawn.is_some() {
            if self.pending_target().is_some_and(|pending| *pending == target) {
                return Ok(());
            }
            warn!(target = ?target, "terminal window spawn already pending; ignoring new attach request");
            return Ok(());
        }

        if self.process.is_some() {
            self.send_request(TermWindowRequest::Attach {
                target: target.clone(),
                title,
                focus: true,
            })?;
            self.current_target = Some(target);
            return Ok(());
        }

        let (tx, rx) = flume::bounded(1);
        let title_for_spawn = title;
        let target_for_spawn = target.clone();
        let handle = rt.spawn(async move {
            let result = spawn_terminal_window_process(target_for_spawn, title_for_spawn).await;
            let _ = tx.send(result);
        });

        self.pending_spawn = Some(PendingSpawn { target, rx, handle });
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
        if let Some(pending) = self.pending_spawn.take() {
            pending.handle.abort();
        }
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

        if self.pending_spawn.is_some() {
            return Ok(());
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

        if self.pending_spawn.is_some() {
            return Ok(());
        }

        anyhow::bail!("terminal window process is not ready yet");
        Ok(())
    }
}

impl Drop for ExternalTermWindowClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct SharedPtyState {
    incoming: Mutex<(u64, Vec<u8>)>,
    reset_requested: AtomicBool,
    reset_generation: AtomicU64,
    session_id: AtomicU64,
    generation: Mutex<u64>,
    condvar: Condvar,
    title_prefix: Mutex<String>,
    size: Mutex<Option<(u16, u16)>>,
    closed: Arc<AtomicBool>,
}

impl SharedPtyState {
    fn new() -> Self {
        Self {
            incoming: Mutex::new((1, Vec::new())),
            reset_requested: AtomicBool::new(false),
            reset_generation: AtomicU64::new(0),
            session_id: AtomicU64::new(1),
            generation: Mutex::new(0),
            condvar: Condvar::new(),
            title_prefix: Mutex::new("Terminal".to_string()),
            size: Mutex::new(None),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn append_incoming(&self, data: &[u8]) {
        let session_id = self.session_id();
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        if guard.0 != session_id {
            guard.0 = session_id;
            guard.1.clear();
        }
        guard.1.extend_from_slice(data);
        drop(guard);
        self.bump_generation();
    }

    fn reset_terminal(&self, title: &str) {
        let mut title_guard = self.title_prefix.lock().unwrap_or_else(|e| e.into_inner());
        *title_guard = title.to_string();
        drop(title_guard);

        let next_session_id = self.session_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        guard.0 = next_session_id;
        guard.1.clear();
        drop(guard);

        self.reset_requested.store(true, Ordering::Relaxed);
        self.reset_generation.fetch_add(1, Ordering::Relaxed);
        self.bump_generation();
    }

    fn drain_incoming(&self) -> Vec<u8> {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut guard.1)
    }

    fn drain_incoming_tagged(&self) -> (u64, Vec<u8>) {
        let mut guard = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        (guard.0, std::mem::take(&mut guard.1))
    }

    fn drain_reset_request(&self) -> bool {
        self.reset_requested.swap(false, Ordering::Relaxed)
    }

    fn reset_generation(&self) -> u64 {
        self.reset_generation.load(Ordering::Relaxed)
    }

    fn session_id(&self) -> u64 {
        self.session_id.load(Ordering::Relaxed)
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

    fn request_close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.bump_generation();
    }

    fn closed(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed)
    }

    fn title_prefix(&self) -> String {
        self.title_prefix
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_size(&self, cols: u16, rows: u16) {
        *self.size.lock().unwrap_or_else(|e| e.into_inner()) = Some((cols, rows));
    }

    fn size(&self) -> Option<(u16, u16)> {
        *self.size.lock().unwrap_or_else(|e| e.into_inner())
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
    signal_tx: Arc<Mutex<UnixStream>>,
}

impl PtyIpc for AlacrittyWindowIpc {
    fn drain_incoming(&self) -> Vec<u8> {
        self.shared.drain_incoming()
    }

    fn drain_incoming_tagged(&self) -> term_view::PtyIncomingChunk {
        let (session_id, data) = self.shared.drain_incoming_tagged();
        term_view::PtyIncomingChunk { session_id, data }
    }

    fn drain_reset_request(&self) -> bool {
        self.shared.drain_reset_request()
    }

    fn session_id(&self) -> u64 {
        self.shared.session_id()
    }

    fn reset_generation(&self) -> u64 {
        self.shared.reset_generation()
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

    fn window_title_prefix(&self) -> Option<String> {
        Some(self.shared.title_prefix())
    }

    fn window_ready(&self) {
        let _ = self.send_signal(TermWindowSignal::WindowReady);
    }
}

impl AlacrittyWindowIpc {
    fn send_signal(&self, signal: TermWindowSignal) -> Result<()> {
        let mut guard = self.signal_tx.lock().unwrap_or_else(|e| e.into_inner());
        write_frame(&mut guard, &signal)
    }
}

async fn run_backend(cmd_rx: flume::Receiver<BackendCommand>, ipc: Arc<AlacrittyWindowIpc>) -> Result<()> {
    let shared = Arc::clone(&ipc.shared);
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
                    BackendCommand::Control(TermWindowRequest::Attach {
                        target: next,
                        title,
                        focus: _,
                    }) => {
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
                        shared.reset_terminal(&title);
                        target = Some(next);
                        if let Err(err) = ensure_attached(&target, &mut current_profile, &mut reader, &mut writer).await {
                            let err_string = err.to_string();
                            let _ = ipc.send_signal(TermWindowSignal::Error(err_string.clone()));
                            return Err(anyhow::anyhow!(err_string));
                        }
                        if let Some(active_target) = target.as_ref() {
                            if let Err(err) = ipc.send_signal(TermWindowSignal::Attached) {
                                warn!(%err, pid = active_target.pid, "failed to notify parent that terminal attach succeeded");
                            }
                            if let (Some(active_writer), Some((cols, rows))) = (writer.as_mut(), shared.size()) {
                                if let Err(err) = active_writer
                                    .send_unstable_request(&DaemonRequest::PtyResize {
                                        pid: active_target.pid,
                                        cols,
                                        rows,
                                    })
                                    .await
                                {
                                    warn!(%err, pid = active_target.pid, cols, rows, "failed to sync terminal size after attach");
                                    reader = None;
                                    writer = None;
                                    current_profile = None;
                                }
                            }
                        }
                    }
                    BackendCommand::Control(TermWindowRequest::Detach) => {
                        if let Some(prev) = target.take() {
                            if let Some(active_writer) = writer.as_mut() {
                                let _ = active_writer
                                    .send_unstable_request(&DaemonRequest::DetachPty { pid: prev.pid })
                                    .await;
                            }
                        }
                        shared.reset_terminal("Terminal");
                    }
                    BackendCommand::Control(TermWindowRequest::Focus) => {}
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
                        shared.set_size(cols, rows);
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
                    }
                    Err(err) => {
                        if let Some(active_target) = target.as_ref() {
                            warn!(%err, pid = active_target.pid, "terminal up stream error");
                        } else {
                            warn!(%err, "terminal up stream error");
                        }
                        reader = None;
                        writer = None;
                        current_profile = None;
                    }
                }
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
    current_profile: &mut Option<ContainerName>,
    reader: &mut Option<UpDaemonReader>,
    writer: &mut Option<UpDaemonWriter>,
) -> Result<()> {
    let Some(target) = target.as_ref() else {
        return Ok(());
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
                return Err(err.into());
            }
        }
    }

    if let Some(active_writer) = writer.as_mut() {
        if let Err(err) = active_writer
            .send_unstable_request(&DaemonRequest::AttachPty { pid: target.pid })
            .await
        {
            *reader = None;
            *writer = None;
            *current_profile = None;
            return Err(err.into());
        }
    }

    Ok(())
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
        }
        DaemonEvent::ProcessExit { pid } if pid == active_target.pid => {
            shared.reset_terminal(&format!(
                "Terminal - {} / PID {} (exited)",
                active_target.profile, active_target.pid
            ));
        }
        DaemonEvent::Error { msg } => {
            warn!(%msg, "terminal daemon error");
        }
        _ => {}
    }
}

struct LaunchGuard {
    child: Option<Child>,
    control: Option<UnixStream>,
}

impl LaunchGuard {
    fn set_control(&mut self, control: UnixStream) {
        self.control = Some(control);
    }

    fn into_process(mut self) -> TermWindowProcess {
        TermWindowProcess {
            child: self.child.take().expect("child process present"),
            control: self.control.take().expect("control socket present"),
        }
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        if let Some(mut control) = self.control.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn spawn_terminal_window_process(
    target: TermWindowTarget,
    title: String,
) -> Result<TermWindowProcess> {
    let (parent_sock, child_sock) =
        UnixStream::pair().context("create terminal control socket pair")?;
    set_fd_inheritable(child_sock.as_raw_fd()).context("make terminal child fd inheritable")?;

    parent_sock
        .set_nonblocking(true)
        .context("set terminal parent socket nonblocking")?;
    let mut parent_sock = TokioUnixStream::from_std(parent_sock)
        .context("convert parent terminal control socket to tokio stream")?;

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

    let mut launch = LaunchGuard {
        child: Some(child),
        control: None,
    };

    drop(child_sock);

    read_terminal_signal(&mut parent_sock, TermWindowSignal::WindowReady).await?;
    write_frame_async(
        &mut parent_sock,
        &TermWindowRequest::Attach {
            target,
            title,
            focus: true,
        },
    )
    .await?;

    let control = parent_sock
        .into_std()
        .context("convert parent terminal control socket back to std stream")?;
    control
        .set_nonblocking(false)
        .context("set terminal parent control socket blocking")?;
    launch.set_control(control);

    let mut control_reader = launch
        .control
        .take()
        .expect("parent terminal control socket present");

    match read_frame::<TermWindowSignal>(&mut control_reader)? {
        Some(TermWindowSignal::Attached) => {
            launch.set_control(control_reader);
            Ok(launch.into_process())
        }
        Some(TermWindowSignal::Error(err)) => Err(anyhow::anyhow!(err)),
        Some(TermWindowSignal::WindowReady) => {
            Err(anyhow::anyhow!("unexpected duplicate window-ready signal"))
        }
        None => Err(anyhow::anyhow!(
            "terminal child closed control socket before attach confirmation"
        )),
    }
}

async fn read_terminal_signal(stream: &mut TokioUnixStream, expected: TermWindowSignal) -> Result<()> {
    loop {
        match read_terminal_signal_any(stream).await? {
            Some(signal) if std::mem::discriminant(&signal) == std::mem::discriminant(&expected) => {
                return Ok(())
            }
            Some(TermWindowSignal::Error(err)) => return Err(anyhow::anyhow!(err)),
            Some(_) => continue,
            None => return Err(anyhow::anyhow!("terminal child closed control socket unexpectedly")),
        }
    }
}

async fn read_terminal_signal_any(stream: &mut TokioUnixStream) -> Result<Option<TermWindowSignal>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("read terminal signal length"),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read terminal signal payload")?;
    Ok(Some(
        bincode::deserialize(&payload).context("decode terminal signal")?,
    ))
}

async fn write_frame_async<T: Serialize>(stream: &mut TokioUnixStream, value: &T) -> Result<()> {
    let payload = bincode::serialize(value).context("serialize terminal control frame")?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await
        .context("write terminal control frame length")?;
    stream
        .write_all(&payload)
        .await
        .context("write terminal control frame payload")?;
    Ok(())
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

fn run_control_reader(mut control: UnixStream, cmd_tx: flume::Sender<BackendCommand>) {
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
                let _ = cmd_tx.send(BackendCommand::Shutdown);
                break;
            }
        }
    }
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

    let shared = Arc::new(SharedPtyState::new());
    shared.reset_terminal("Terminal");

    let (cmd_tx, cmd_rx) = flume::unbounded();
    let control_stream = unsafe { UnixStream::from_raw_fd(control_fd) };
    let signal_tx = Arc::new(Mutex::new(control_stream.try_clone().context("clone terminal control socket for signal writer")?));
    let control_reader = control_stream
        .try_clone()
        .context("clone terminal control socket for reader thread")?;

    let cmd_tx_for_control = cmd_tx.clone();
    thread::Builder::new()
        .name("nsproxy-term-control".to_string())
        .spawn(move || run_control_reader(control_reader, cmd_tx_for_control))
        .context("spawn terminal control reader thread")?;

    let ipc = Arc::new(AlacrittyWindowIpc {
        shared: Arc::clone(&shared),
        cmd_tx: cmd_tx.clone(),
        signal_tx: Arc::clone(&signal_tx),
    });
    let backend_ipc = Arc::clone(&ipc);
    thread::Builder::new()
        .name("nsproxy-term-backend".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    error!(%err, "failed to build terminal backend runtime");
                    backend_ipc.shared.request_close();
                    return;
                }
            };
            if let Err(err) = runtime.block_on(run_backend(cmd_rx, backend_ipc)) {
                error!(%err, "terminal backend stopped with error");
            }
        })
        .context("spawn terminal backend thread")?;
    run_standalone_window(ipc, 0, shared.closed())
        .map_err(|err| anyhow::anyhow!("run standalone terminal window: {err}"))
}
