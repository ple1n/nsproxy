//! Small Linux service supervision primitives.
//!
//! The crate deliberately does not know about nsproxy profiles or namespaces.
//! It owns service identity, PTY lifetime, output replay, and lifecycle events.

use std::collections::{HashMap, VecDeque};
use std::env;
use std::ffi::{CStr, CString, NulError};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("argument contains an embedded NUL byte")]
    Nul(#[from] NulError),
    #[error("service {0} does not exist")]
    UnknownService(ServiceId),
    #[error("service {0} is not a PTY service")]
    NotPtyService(ServiceId),
    #[error("service command is empty")]
    EmptyCommand,
    #[error("PTY operation is only supported on Linux")]
    UnsupportedPlatform,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceId(pub u64);

impl std::fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Starting,
    Running,
    Terminating,
    Exited(i32),
    Signaled(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputStream {
    Pty,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    Pty,
    Pipe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChunk {
    pub sequence: u64,
    pub stream: OutputStream,
    pub data: Vec<u8>,
}

/// A stable position in a service's bounded output journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCursor(pub u64);

#[derive(Debug, Clone)]
pub struct OutputReplay {
    pub chunks: Vec<OutputChunk>,
    pub next: OutputCursor,
    /// True when the requested cursor predates the retained journal.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalPath(PathBuf);

impl JournalPath {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn runtime(service: ServiceId) -> Self {
        let root = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|p| p.join("nsproxy"))
            .unwrap_or_else(|| {
                let run = PathBuf::from("/run/nsproxy");
                if run.exists() {
                    run
                } else {
                    PathBuf::from("/tmp/nsproxy")
                }
            });
        Self::under_root(root, service)
    }
    pub fn under_root(root: impl Into<PathBuf>, service: ServiceId) -> Self {
        Self(root.into().join(format!("service-{service}.journal")))
    }
}

#[derive(Clone)]
pub struct Journal {
    inner: Arc<Mutex<JournalState>>,
}

struct JournalState {
    file: File,
    path: PathBuf,
    capacity: usize,
    records: VecDeque<OutputChunk>,
    bytes: usize,
    next_sequence: u64,
}

impl Journal {
    pub fn open(path: impl Into<PathBuf>, capacity: usize) -> Result<Self, Error> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let records = recover_journal(&mut file)?;
        let next_sequence = records.back().map(|r| r.sequence + 1).unwrap_or(0);
        let bytes = records.iter().map(|r| r.data.len() + 13).sum();
        let journal = Self {
            inner: Arc::new(Mutex::new(JournalState {
                file,
                path,
                capacity,
                records,
                bytes,
                next_sequence,
            })),
        };
        journal.trim()?;
        Ok(journal)
    }

    pub fn path(&self) -> JournalPath {
        JournalPath::new(
            self.inner
                .lock()
                .expect("journal lock poisoned")
                .path
                .clone(),
        )
    }
    pub fn append(&self, stream: OutputStream, data: Vec<u8>) -> Result<OutputChunk, Error> {
        let mut state = self.inner.lock().expect("journal lock poisoned");
        let chunk = OutputChunk {
            sequence: state.next_sequence,
            stream,
            data,
        };
        let payload_len = (13 + chunk.data.len()) as u32;
        state.file.write_all(&payload_len.to_le_bytes())?;
        state.file.write_all(&chunk.sequence.to_le_bytes())?;
        state.file.write_all(&[stream as u8])?;
        state
            .file
            .write_all(&(chunk.data.len() as u32).to_le_bytes())?;
        state.file.write_all(&chunk.data)?;
        state.file.flush()?;
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.bytes += chunk.data.len() + 13;
        state.records.push_back(chunk.clone());
        drop(state);
        self.trim()?;
        Ok(chunk)
    }
    pub fn cursor(&self) -> OutputCursor {
        OutputCursor(
            self.inner
                .lock()
                .expect("journal lock poisoned")
                .next_sequence,
        )
    }
    pub fn replay_from(&self, cursor: OutputCursor) -> OutputReplay {
        let state = self.inner.lock().expect("journal lock poisoned");
        let oldest = state
            .records
            .front()
            .map(|r| r.sequence)
            .unwrap_or(state.next_sequence);
        OutputReplay {
            chunks: state
                .records
                .iter()
                .filter(|r| r.sequence >= cursor.0.max(oldest))
                .cloned()
                .collect(),
            next: OutputCursor(state.next_sequence),
            truncated: cursor.0 < oldest,
        }
    }
    fn trim(&self) -> Result<(), Error> {
        let mut state = self.inner.lock().expect("journal lock poisoned");
        let original = state.records.len();
        while state.bytes > state.capacity {
            if let Some(old) = state.records.pop_front() {
                state.bytes -= old.data.len() + 13;
            } else {
                break;
            }
        }
        if state.records.len() == original {
            return Ok(());
        }
        state.file.set_len(0)?;
        state.file.seek(std::io::SeekFrom::Start(0))?;
        let records = state.records.iter().cloned().collect::<Vec<_>>();
        for chunk in records {
            let len = (13 + chunk.data.len()) as u32;
            state.file.write_all(&len.to_le_bytes())?;
            state.file.write_all(&chunk.sequence.to_le_bytes())?;
            state.file.write_all(&[chunk.stream as u8])?;
            state
                .file
                .write_all(&(chunk.data.len() as u32).to_le_bytes())?;
            state.file.write_all(&chunk.data)?;
        }
        state.file.flush()?;
        Ok(())
    }
}

fn recover_journal(file: &mut File) -> Result<VecDeque<OutputChunk>, Error> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut records = VecDeque::new();
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if len < 13 || offset + 4 + len > bytes.len() {
            break;
        }
        let start = offset + 4;
        let sequence = u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
        let stream = match bytes[start + 8] {
            0 => OutputStream::Pty,
            1 => OutputStream::Stdout,
            2 => OutputStream::Stderr,
            _ => break,
        };
        let data_len =
            u32::from_le_bytes(bytes[start + 9..start + 13].try_into().unwrap()) as usize;
        if data_len + 13 != len {
            break;
        }
        records.push_back(OutputChunk {
            sequence,
            stream,
            data: bytes[start + 13..start + 13 + data_len].to_vec(),
        });
        offset += 4 + len;
    }
    if offset != bytes.len() {
        file.set_len(offset as u64)?;
        file.seek(std::io::SeekFrom::Start(offset as u64))?;
    }
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ownership {
    /// Identifier of the manager that created the service.
    pub manager: String,
    /// Optional parent service, useful for nested supervisors.
    pub parent: Option<ServiceId>,
    pub label: Option<String>,
}

impl Default for Ownership {
    fn default() -> Self {
        Self {
            manager: "service-mgr".into(),
            parent: None,
            label: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceEvent {
    Started { id: ServiceId, pid: u32 },
    Output { id: ServiceId, chunk: OutputChunk },
    StateChanged { id: ServiceId, state: ServiceState },
}

#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub rows: u16,
    pub cols: u16,
    pub output_capacity: usize,
    pub ownership: Ownership,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub id: ServiceId,
    pub pid: u32,
    pub state: ServiceState,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub uptime: Duration,
    pub ownership: Ownership,
    pub kind: ServiceKind,
}

impl ServiceSpec {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            rows: 24,
            cols: 80,
            output_capacity: 256 * 1024,
            ownership: Ownership::default(),
        }
    }
}

#[derive(Clone)]
pub struct OutputHub {
    inner: Arc<Mutex<OutputHubState>>,
}

struct OutputHubState {
    next_sequence: u64,
    capacity: usize,
    bytes: usize,
    history: VecDeque<OutputChunk>,
    subscribers: Vec<mpsc::Sender<OutputChunk>>,
    journal: Option<Journal>,
}

impl OutputHub {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(OutputHubState {
                next_sequence: 0,
                capacity,
                bytes: 0,
                history: VecDeque::new(),
                subscribers: Vec::new(),
                journal: None,
            })),
        }
    }

    pub fn with_journal(journal: Journal) -> Self {
        let hub = Self::new(0);
        hub.attach_journal(journal);
        hub
    }

    pub fn attach_journal(&self, journal: Journal) {
        self.inner.lock().expect("output hub lock poisoned").journal = Some(journal);
    }

    pub fn subscribe(&self) -> mpsc::Receiver<OutputChunk> {
        let (tx, rx) = mpsc::channel();
        self.inner
            .lock()
            .expect("output hub lock poisoned")
            .subscribers
            .push(tx);
        rx
    }

    pub fn snapshot(&self) -> Vec<OutputChunk> {
        self.inner
            .lock()
            .expect("output hub lock poisoned")
            .history
            .iter()
            .cloned()
            .collect()
    }

    pub fn cursor(&self) -> OutputCursor {
        OutputCursor(
            self.inner
                .lock()
                .expect("output hub lock poisoned")
                .next_sequence,
        )
    }

    pub fn replay_from(&self, cursor: OutputCursor) -> OutputReplay {
        let state = self.inner.lock().expect("output hub lock poisoned");
        let oldest = state
            .history
            .front()
            .map(|chunk| chunk.sequence)
            .unwrap_or(state.next_sequence);
        let start = cursor.0.max(oldest);
        OutputReplay {
            chunks: state
                .history
                .iter()
                .filter(|chunk| chunk.sequence >= start)
                .cloned()
                .collect(),
            next: OutputCursor(state.next_sequence),
            truncated: cursor.0 < oldest,
        }
    }

    fn publish(&self, stream: OutputStream, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut state = self.inner.lock().expect("output hub lock poisoned");
        let chunk = if let Some(journal) = &state.journal {
            match journal.append(stream, data) {
                Ok(chunk) => chunk,
                Err(_) => return,
            }
        } else {
            OutputChunk {
                sequence: state.next_sequence,
                stream,
                data,
            }
        };
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.bytes = state.bytes.saturating_add(chunk.data.len());
        state.history.push_back(chunk.clone());
        while state.bytes > state.capacity {
            let Some(removed) = state.history.pop_front() else {
                break;
            };
            state.bytes = state.bytes.saturating_sub(removed.data.len());
        }
        state
            .subscribers
            .retain(|subscriber| subscriber.send(chunk.clone()).is_ok());
    }
}

#[derive(Clone)]
pub struct ServiceManager {
    next_id: Arc<AtomicU64>,
    services: Arc<Mutex<HashMap<ServiceId, ManagedService>>>,
    events: mpsc::Sender<ServiceEvent>,
    journal_root: PathBuf,
}

struct ManagedService {
    state: ServiceState,
    process: ProcessSession,
    spec: ServiceSpec,
    started_at: Instant,
    journal: Journal,
}

enum ProcessSession {
    Pty(PtySession),
    Pipe(PipeSession),
}

impl ProcessSession {
    fn kind(&self) -> ServiceKind {
        match self {
            Self::Pty(_) => ServiceKind::Pty,
            Self::Pipe(_) => ServiceKind::Pipe,
        }
    }

    fn pid(&self) -> u32 {
        match self {
            Self::Pty(p) => p.pid(),
            Self::Pipe(p) => p.pid,
        }
    }
    fn output(&self) -> OutputHub {
        match self {
            Self::Pty(p) => p.output(),
            Self::Pipe(p) => p.output.clone(),
        }
    }
    fn write_input(&self, data: &[u8]) -> Result<(), Error> {
        match self {
            Self::Pty(p) => p.write_input(data),
            Self::Pipe(p) => p.write_input(data),
        }
    }
    fn resize(&self, rows: u16, cols: u16) -> Result<(), Error> {
        match self {
            Self::Pty(p) => p.resize(rows, cols),
            Self::Pipe(_) => {
                let _ = (rows, cols);
                Err(Error::NotPtyService(ServiceId(0)))
            }
        }
    }
    fn signal(&self, signal: i32) -> Result<(), Error> {
        match self {
            Self::Pty(p) => p.signal(signal),
            Self::Pipe(p) => p.signal(signal),
        }
    }
}

struct PipeSession {
    pid: u32,
    stdin: Arc<Mutex<std::process::ChildStdin>>,
    output: OutputHub,
}

impl PipeSession {
    fn spawn(spec: &ServiceSpec) -> Result<Self, Error> {
        if spec.command.as_os_str().is_empty() {
            return Err(Error::EmptyCommand);
        }
        let mut command = Command::new(&spec.command);
        command
            .args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    if unsafe { libc::setpgid(0, 0) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn()?;
        let pid = child.id();
        let output = OutputHub::new(spec.output_capacity);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr"))?;
        let out = output.clone();
        thread::Builder::new()
            .name(format!("pipe-stdout-{pid}"))
            .spawn(move || read_pipe(stdout, out, OutputStream::Stdout))
            .map_err(Error::Io)?;
        let out = output.clone();
        thread::Builder::new()
            .name(format!("pipe-stderr-{pid}"))
            .spawn(move || read_pipe(stderr, out, OutputStream::Stderr))
            .map_err(Error::Io)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing stdin"))?;
        // The manager reaps children with waitpid, so Child must not also reap.
        drop(child);
        Ok(Self {
            pid,
            stdin: Arc::new(Mutex::new(stdin)),
            output,
        })
    }

    fn write_input(&self, data: &[u8]) -> Result<(), Error> {
        self.stdin
            .lock()
            .expect("stdin lock poisoned")
            .write_all(data)
            .map_err(Error::Io)
    }

    fn signal(&self, signal: i32) -> Result<(), Error> {
        let result = unsafe { libc::kill(-(self.pid as libc::pid_t), signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }
}

fn read_pipe<R: Read>(mut reader: R, output: OutputHub, stream: OutputStream) {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(size) => output.publish(stream, buffer[..size].to_vec()),
        }
    }
}

pub struct ServiceManagerHandle {
    pub events: mpsc::Receiver<ServiceEvent>,
}

impl ServiceManager {
    pub fn new() -> (Self, ServiceManagerHandle) {
        let (events, event_rx) = mpsc::channel();
        (
            Self {
                next_id: Arc::new(AtomicU64::new(1)),
                services: Arc::new(Mutex::new(HashMap::new())),
                events,
                journal_root: JournalPath::runtime(ServiceId(0))
                    .0
                    .parent()
                    .unwrap_or(Path::new("/tmp"))
                    .to_path_buf(),
            },
            ServiceManagerHandle { events: event_rx },
        )
    }

    pub fn with_journal_root(root: impl Into<PathBuf>) -> (Self, ServiceManagerHandle) {
        let (manager, handle) = Self::new();
        let mut manager = manager;
        manager.journal_root = root.into();
        (manager, handle)
    }

    pub fn spawn_pty(&self, spec: ServiceSpec) -> Result<ServiceId, Error> {
        self.spawn_session(spec.clone(), ProcessSession::Pty(PtySession::spawn(&spec)?))
    }

    /// Spawn without a controlling terminal. stdout and stderr are journaled
    /// independently, making this suitable for workers and nested managers.
    pub fn spawn(&self, spec: ServiceSpec) -> Result<ServiceId, Error> {
        self.spawn_session(
            spec.clone(),
            ProcessSession::Pipe(PipeSession::spawn(&spec)?),
        )
    }

    fn spawn_session(
        &self,
        spec: ServiceSpec,
        process: ProcessSession,
    ) -> Result<ServiceId, Error> {
        let id = ServiceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let pid = process.pid();
        let output = process.output();
        let journal = Journal::open(
            JournalPath::under_root(self.journal_root.clone(), id)
                .path()
                .to_path_buf(),
            spec.output_capacity,
        )?;
        output.attach_journal(journal.clone());
        let event_tx = self.events.clone();
        let output_rx = output.subscribe();
        let output_events = event_tx.clone();
        thread::Builder::new()
            .name(format!("service-output-{id:?}"))
            .spawn(move || {
                while let Ok(chunk) = output_rx.recv() {
                    let _ = output_events.send(ServiceEvent::Output { id, chunk });
                }
            })
            .map_err(Error::Io)?;

        self.services
            .lock()
            .expect("service manager lock poisoned")
            .insert(
                id,
                ManagedService {
                    state: ServiceState::Running,
                    process,
                    spec,
                    started_at: Instant::now(),
                    journal,
                },
            );

        let services = Arc::clone(&self.services);
        let state_events = self.events.clone();
        let wait_pid = pid;
        thread::Builder::new()
            .name(format!("service-wait-{id:?}"))
            .spawn(move || {
                let state = wait_for_pid(wait_pid);
                if let Ok(mut services) = services.lock() {
                    if let Some(service) = services.get_mut(&id) {
                        service.state = state;
                    }
                }
                let _ = state_events.send(ServiceEvent::StateChanged { id, state });
            })
            .map_err(Error::Io)?;

        let _ = self.events.send(ServiceEvent::Started { id, pid });
        let _ = self.events.send(ServiceEvent::StateChanged {
            id,
            state: ServiceState::Running,
        });
        Ok(id)
    }

    pub fn list(&self) -> Vec<ServiceInfo> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let mut result = services
            .iter()
            .map(|(&id, service)| ServiceInfo {
                id,
                pid: service.process.pid(),
                state: service.state,
                command: service.spec.command.clone(),
                args: service.spec.args.clone(),
                uptime: service.started_at.elapsed(),
                ownership: service.spec.ownership.clone(),
                kind: service.process.kind(),
            })
            .collect::<Vec<_>>();
        result.sort_by_key(|service| service.id);
        result
    }

    pub fn state(&self, id: ServiceId) -> Result<ServiceState, Error> {
        self.services
            .lock()
            .expect("service manager lock poisoned")
            .get(&id)
            .map(|service| service.state)
            .ok_or(Error::UnknownService(id))
    }

    pub fn output(&self, id: ServiceId) -> Result<OutputHub, Error> {
        self.services
            .lock()
            .expect("service manager lock poisoned")
            .get(&id)
            .map(|service| service.process.output())
            .ok_or(Error::UnknownService(id))
    }

    pub fn journal_path(&self, id: ServiceId) -> Result<JournalPath, Error> {
        self.services
            .lock()
            .expect("service manager lock poisoned")
            .get(&id)
            .map(|service| service.journal.path())
            .ok_or(Error::UnknownService(id))
    }

    pub fn journal_replay(
        &self,
        id: ServiceId,
        cursor: OutputCursor,
    ) -> Result<OutputReplay, Error> {
        self.services
            .lock()
            .expect("service manager lock poisoned")
            .get(&id)
            .map(|service| service.journal.replay_from(cursor))
            .ok_or(Error::UnknownService(id))
    }

    pub fn write_input(&self, id: ServiceId, data: &[u8]) -> Result<(), Error> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get(&id).ok_or(Error::UnknownService(id))?;
        service.process.write_input(data)
    }

    pub fn resize(&self, id: ServiceId, rows: u16, cols: u16) -> Result<(), Error> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get(&id).ok_or(Error::UnknownService(id))?;
        match &service.process {
            ProcessSession::Pty(pty) => pty.resize(rows, cols),
            ProcessSession::Pipe(_) => Err(Error::NotPtyService(id)),
        }
    }

    pub fn terminate(&self, id: ServiceId) -> Result<(), Error> {
        let mut services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get_mut(&id).ok_or(Error::UnknownService(id))?;
        service.state = ServiceState::Terminating;
        let _ = self.events.send(ServiceEvent::StateChanged {
            id,
            state: ServiceState::Terminating,
        });
        service.process.signal(libc::SIGTERM)
    }

    /// Send a signal to the whole process group, not just the leader.
    pub fn signal(&self, id: ServiceId, signal: i32) -> Result<(), Error> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get(&id).ok_or(Error::UnknownService(id))?;
        service.process.signal(signal)
    }

    pub fn ownership(&self, id: ServiceId) -> Result<Ownership, Error> {
        self.services
            .lock()
            .expect("service manager lock poisoned")
            .get(&id)
            .map(|service| service.spec.ownership.clone())
            .ok_or(Error::UnknownService(id))
    }
}

pub struct PtySession {
    pid: u32,
    master: Arc<Mutex<File>>,
    output: OutputHub,
}

impl PtySession {
    pub fn spawn(spec: &ServiceSpec) -> Result<Self, Error> {
        if spec.command.as_os_str().is_empty() {
            return Err(Error::EmptyCommand);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            return Err(Error::UnsupportedPlatform);
        }
        #[cfg(target_os = "linux")]
        {
            let master = open_ptmx()?;
            let slave = unsafe { libc::ptsname(master.as_raw_fd()) };
            if slave.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            let slave_path = unsafe { CStr::from_ptr(slave) }.to_owned();
            let command = CString::new(spec.command.as_os_str().as_encoded_bytes())?;
            let args = spec
                .args
                .iter()
                .map(|arg| CString::new(arg.as_bytes()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut argv = Vec::with_capacity(args.len() + 2);
            argv.push(command.clone());
            argv.extend(args);
            let mut argv_ptrs = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
            argv_ptrs.push(std::ptr::null());

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if pid == 0 {
                unsafe {
                    libc::setsid();
                    libc::close(master.as_raw_fd());
                    let slave_fd = libc::open(slave_path.as_ptr(), libc::O_RDWR);
                    if slave_fd >= 0 {
                        libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                        libc::dup2(slave_fd, libc::STDIN_FILENO);
                        libc::dup2(slave_fd, libc::STDOUT_FILENO);
                        libc::dup2(slave_fd, libc::STDERR_FILENO);
                        if slave_fd > libc::STDERR_FILENO {
                            libc::close(slave_fd);
                        }
                    }
                    libc::ioctl(
                        master.as_raw_fd(),
                        libc::TIOCSWINSZ,
                        &libc::winsize {
                            ws_row: spec.rows.max(1),
                            ws_col: spec.cols.max(1),
                            ws_xpixel: 0,
                            ws_ypixel: 0,
                        },
                    );
                    libc::execvp(command.as_ptr(), argv_ptrs.as_ptr());
                    libc::_exit(127);
                }
            }

            let master_file = unsafe { File::from_raw_fd(master.into_raw_fd()) };
            let master = Arc::new(Mutex::new(master_file));
            let output = OutputHub::new(spec.output_capacity);
            let reader_master = master.lock().expect("PTY lock poisoned").try_clone()?;
            let reader_output = output.clone();
            thread::Builder::new()
                .name(format!("pty-reader-{pid}"))
                .spawn(move || read_pty(reader_master, reader_output))
                .map_err(Error::Io)?;

            Ok(Self {
                pid: pid as u32,
                master,
                output,
            })
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn output(&self) -> OutputHub {
        self.output.clone()
    }

    pub fn write_input(&self, data: &[u8]) -> Result<(), Error> {
        self.master
            .lock()
            .expect("PTY lock poisoned")
            .write_all(data)
            .map_err(Error::Io)
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), Error> {
        let size = libc::winsize {
            ws_row: rows.max(1),
            ws_col: cols.max(1),
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let result = unsafe {
            libc::ioctl(
                self.master.lock().expect("PTY lock poisoned").as_raw_fd(),
                libc::TIOCSWINSZ,
                &size,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    pub fn signal(&self, signal: i32) -> Result<(), Error> {
        let result = unsafe { libc::kill(-(self.pid as libc::pid_t), signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }
}

fn read_pty(mut reader: File, output: OutputHub) {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(size) => output.publish(OutputStream::Pty, buffer[..size].to_vec()),
        }
    }
}

fn wait_for_pid(pid: u32) -> ServiceState {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    if result < 0 {
        return ServiceState::Signaled(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    if unsafe { libc::WIFEXITED(status) } {
        ServiceState::Exited(unsafe { libc::WEXITSTATUS(status) })
    } else if unsafe { libc::WIFSIGNALED(status) } {
        ServiceState::Signaled(unsafe { libc::WTERMSIG(status) })
    } else {
        ServiceState::Signaled(-1)
    }
}

#[cfg(target_os = "linux")]
fn open_ptmx() -> Result<OwnedFd, Error> {
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::grantpt(fd.as_raw_fd()) } != 0
        || unsafe { libc::unlockpt(fd.as_raw_fd()) } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_hub_replays_and_broadcasts() {
        let hub = OutputHub::new(16);
        let rx = hub.subscribe();
        hub.publish(OutputStream::Pty, b"hello".to_vec());
        assert_eq!(rx.recv().unwrap().data, b"hello");
        assert_eq!(hub.snapshot()[0].data, b"hello");
        let replay = hub.replay_from(OutputCursor(0));
        assert_eq!(replay.chunks.len(), 1);
        assert_eq!(replay.next, OutputCursor(1));
    }

    #[test]
    fn journal_recovers_tail_and_replays_bounded_records() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target/service-mgr-journal-test");
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("events.journal");
        let journal = Journal::open(&path, 30).unwrap();
        journal
            .append(OutputStream::Stdout, b"one".to_vec())
            .unwrap();
        journal
            .append(OutputStream::Stderr, b"two".to_vec())
            .unwrap();
        drop(journal);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0x08, 0, 0]).unwrap();
        drop(file);
        let journal = Journal::open(&path, 30).unwrap();
        let replay = journal.replay_from(OutputCursor(0));
        assert!(replay.truncated);
        assert_eq!(replay.chunks.len(), 1);
        assert_eq!(replay.chunks[0].data, b"two");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pty_service_reports_output_and_exit() {
        let (manager, handle) = ServiceManager::new();
        let mut spec = ServiceSpec::new("/bin/echo");
        spec.args.push("hello".to_string());
        let id = manager.spawn_pty(spec).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut saw_output = false;
        let mut saw_exit = false;
        while std::time::Instant::now() < deadline && !saw_exit {
            match handle
                .events
                .recv_timeout(std::time::Duration::from_millis(100))
                .unwrap()
            {
                ServiceEvent::Output {
                    id: event_id,
                    chunk,
                } if event_id == id => {
                    saw_output |= chunk.data.windows(5).any(|window| window == b"hello");
                }
                ServiceEvent::StateChanged {
                    id: event_id,
                    state: ServiceState::Exited(0),
                } if event_id == id => saw_exit = true,
                _ => {}
            }
        }
        assert!(saw_output);
        assert!(saw_exit);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pipe_service_reports_stdout_and_exit() {
        let (manager, handle) = ServiceManager::new();
        let mut spec = ServiceSpec::new("/bin/sh");
        spec.args = vec!["-c".into(), "printf pipe-output".into()];
        let id = manager.spawn(spec).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_output = false;
        let mut saw_exit = false;
        while Instant::now() < deadline && !saw_exit {
            if let Ok(event) = handle.events.recv_timeout(Duration::from_millis(100)) {
                match event {
                    ServiceEvent::Output {
                        id: event_id,
                        chunk,
                    } if event_id == id => {
                        saw_output |= chunk.stream == OutputStream::Stdout
                            && chunk.data.windows(4).any(|window| window == b"pipe");
                    }
                    ServiceEvent::StateChanged {
                        id: event_id,
                        state: ServiceState::Exited(0),
                    } if event_id == id => saw_exit = true,
                    _ => {}
                }
            }
        }
        assert!(saw_output);
        assert!(saw_exit);
    }
}
