//! Diagnostics communication protocol for nsproxy TUN performance monitoring.
//!
//! tun2socks5 creates a UNIX listener at `/nsp3/{profile}/tun_diag.sock`,
//! and the EGUI viewer connects to it to display a rolling log of events.
//!
//! The wire protocol is newline-delimited JSON (`DiagEvent` per line).

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::broadcast,
};
use tracing::{debug, error, info, warn};

pub mod summary;

// ── Wire protocol types ──────────────────────────────────────────────

/// Microsecond-precision wall-clock timestamp (µs since UNIX epoch).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Self(d.as_micros() as u64)
    }

    pub fn elapsed_since(&self, earlier: &Timestamp) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }
}

/// Unique connection identifier assigned in the accept loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// The kind of stream accepted from the TUN device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
    Udp,
}

/// How a connection is being handled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnRoute {
    /// Routed through the SOCKS5/HTTP proxy.
    Proxied { dest: String },
    /// NAT'd directly by the TUN device.
    Nat { dest: String },
    /// Direct connection (no proxy configured).
    Direct { dest: String },
    /// DNS query (handled, over-tcp, or direct).
    Dns { query: String, strategy: String },
    /// File serving.
    FileServe { root: String },
    /// Connection dropped/blocked by routing policy.
    Unreachable,
}

/// A single diagnostic event emitted by tun2socks5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiagEvent {
    /// A new stream was accepted from ip_stack.accept().
    Accept {
        id: ConnId,
        ts: Timestamp,
        kind: StreamKind,
        src: String,
        dst: String,
    },
    /// How long the main loop body took to dispatch this connection (µs).
    /// Emitted once at the end of each loop iteration.
    Dispatched {
        id: ConnId,
        dispatch_us: u64,
    },
    /// Routing decision made for this connection.
    Route {
        id: ConnId,
        ts: Timestamp,
        route: ConnRoute,
    },
    /// Connection to the proxy/remote server established.
    Connected {
        id: ConnId,
        ts: Timestamp,
    },
    /// Connection finished (successfully or with error).
    Finished {
        id: ConnId,
        ts: Timestamp,
        error: Option<String>,
        bytes_up: u64,
        bytes_down: u64,
    },
    /// DNS resolution via VirtDNS.
    DnsResolved {
        id: ConnId,
        ts: Timestamp,
        domain: String,
        result: String,
    },
    /// DNS query received (raw UDP handled by VirtDNS).
    DnsQuery {
        id: ConnId,
        ts: Timestamp,
        query: String,
    },
    /// Acceptor loop waiting for new connection (before ip_stack.accept()).
    Wait {
        id: ConnId,
        ts: Timestamp,
    },
    /// Wait was terminated and connection accepted.
    WaitEnded {
        id: ConnId,
        ts: Timestamp,
    },
}

// ── Server (tun2socks5 side) ─────────────────────────────────────────

/// Broadcaster that tun2socks5 uses to emit events.
/// Connected EGUI clients each get a broadcast receiver.
#[derive(Clone)]
pub struct DiagServer {
    tx: broadcast::Sender<Arc<String>>,
}

/// Capacity of the broadcast channel (rolling window for slow readers).
const BROADCAST_CAP: usize = 4096;

impl DiagServer {
    /// Create a new `DiagServer` and spawn the UNIX listener task.
    /// The socket is created at `sock_path`. If the file already exists it is removed.
    /// The socket and its parent directory are made world-accessible (0o777 / 0o666)
    /// so that a non-root EGUI viewer can connect.
    pub async fn start(sock_path: &Path) -> Result<Self> {
        // Ensure parent directory exists and is world-accessible
        if let Some(parent) = sock_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).await
                .unwrap_or_else(|e| warn!("diag: could not chmod parent dir: {}", e));
        }
        // Remove stale socket
        let _ = tokio::fs::remove_file(sock_path).await;

        let listener = UnixListener::bind(sock_path)?;

        // Make the socket world-read/writable so non-root clients can connect
        tokio::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o666)).await?;

        info!("diag: listening on {:?} (mode 0666)", sock_path);

        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        let server = DiagServer { tx: tx.clone() };

        // Spawn acceptor
        let tx2 = tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        info!("diag: client connected");
                        let rx = tx2.subscribe();
                        tokio::spawn(serve_client(stream, rx));
                    }
                    Err(e) => {
                        error!("diag: accept error: {}", e);
                    }
                }
            }
        });

        Ok(server)
    }

    /// Emit a diagnostic event. Non-blocking; if no clients are connected the
    /// event is silently dropped.
    pub fn emit(&self, event: DiagEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.tx.send(Arc::new(json));
        }
    }

    /// Returns a no-op stub that silently discards all events.
    pub fn noop() -> Self {
        let (tx, _) = broadcast::channel(1);
        DiagServer { tx }
    }
}

/// Serve a single connected EGUI client: forward broadcast events as newline-delimited JSON.
async fn serve_client(mut stream: UnixStream, mut rx: broadcast::Receiver<Arc<String>>) {
    loop {
        match rx.recv().await {
            Ok(line) => {
                let mut buf = line.as_bytes().to_vec();
                buf.push(b'\n');
                if stream.write_all(&buf).await.is_err() {
                    debug!("diag: client disconnected (write)");
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("diag: client lagged, dropped {} events", n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("diag: broadcast closed");
                return;
            }
        }
    }
}

// ── Client helpers (for the EGUI viewer) ─────────────────────────────

/// Connect to a running tun2socks5 diag socket and yield events.
pub async fn connect(sock_path: &Path) -> Result<DiagEventStream> {
    let stream = UnixStream::connect(sock_path).await?;
    Ok(DiagEventStream {
        reader: BufReader::new(stream),
    })
}

pub struct DiagEventStream {
    reader: BufReader<UnixStream>,
}

impl DiagEventStream {
    /// Read the next event from the stream. Returns `None` on EOF.
    pub async fn next(&mut self) -> Result<Option<DiagEvent>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let event: DiagEvent = serde_json::from_str(line.trim())?;
        Ok(Some(event))
    }
}

// ── Convenience: socket path derivation ──────────────────────────────

/// Derive the canonical diag socket path for a named instance.
/// `/nsp3/{name}/tun_diag.sock`
pub fn diag_sock_path(instance_name: &str) -> PathBuf {
    PathBuf::from("/nsp3").join(instance_name).join("tun_diag.sock")
}

// ── Atomic connection-id generator ───────────────────────────────────

static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn next_conn_id() -> ConnId {
    ConnId(NEXT_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}
