//! Small Linux service supervision primitives.
//!
//! The crate deliberately does not know about nsproxy profiles or namespaces.
//! It owns service identity, PTY lifetime, output replay, and lifecycle events.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, NulError};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChunk {
    pub sequence: u64,
    pub stream: OutputStream,
    pub data: Vec<u8>,
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
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub id: ServiceId,
    pub pid: u32,
    pub state: ServiceState,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub uptime: Duration,
}

impl ServiceSpec {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            rows: 24,
            cols: 80,
            output_capacity: 256 * 1024,
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
            })),
        }
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

    fn publish(&self, stream: OutputStream, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut state = self.inner.lock().expect("output hub lock poisoned");
        let chunk = OutputChunk {
            sequence: state.next_sequence,
            stream,
            data,
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
}

struct ManagedService {
    state: ServiceState,
    pty: PtySession,
    spec: ServiceSpec,
    started_at: Instant,
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
            },
            ServiceManagerHandle { events: event_rx },
        )
    }

    pub fn spawn_pty(&self, spec: ServiceSpec) -> Result<ServiceId, Error> {
        let id = ServiceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let pty = PtySession::spawn(&spec)?;
        let pid = pty.pid();
        let output = pty.output();
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
                    pty,
                    spec,
                    started_at: Instant::now(),
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
        Ok(id)
    }

    pub fn list(&self) -> Vec<ServiceInfo> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let mut result = services
            .iter()
            .map(|(&id, service)| ServiceInfo {
                id,
                pid: service.pty.pid(),
                state: service.state,
                command: service.spec.command.clone(),
                args: service.spec.args.clone(),
                uptime: service.started_at.elapsed(),
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
            .map(|service| service.pty.output())
            .ok_or(Error::UnknownService(id))
    }

    pub fn write_input(&self, id: ServiceId, data: &[u8]) -> Result<(), Error> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get(&id).ok_or(Error::UnknownService(id))?;
        service.pty.write_input(data)
    }

    pub fn resize(&self, id: ServiceId, rows: u16, cols: u16) -> Result<(), Error> {
        let services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get(&id).ok_or(Error::UnknownService(id))?;
        service.pty.resize(rows, cols)
    }

    pub fn terminate(&self, id: ServiceId) -> Result<(), Error> {
        let mut services = self.services.lock().expect("service manager lock poisoned");
        let service = services.get_mut(&id).ok_or(Error::UnknownService(id))?;
        service.state = ServiceState::Terminating;
        let _ = self.events.send(ServiceEvent::StateChanged {
            id,
            state: ServiceState::Terminating,
        });
        service.pty.signal(libc::SIGTERM)
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
}
