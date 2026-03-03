//! Diagnostics communication protocol for nsproxy TUN performance monitoring.
//!
//! tun2socks5 creates a UNIX listener at `/nsp3/{profile}/tun_diag.sock`,
//! and the EGUI viewer connects to it to display a rolling log of events.
//!
//! ## Wire protocol — length-prefixed bincode frames
//!
//! Each message is sent as:
//! ```text
//! [ u32 LE payload_length ][ bincode-encoded message ]
//! ```
//! Server → client carries [`DiagEvent`]; client → server carries [`ControlCommand`].

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use nsproxy_common::routing::{ProxyID, RoutingResovled};
pub use nsproxy_common::stats::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc},
};
use tracing::{debug, error, info, warn};

pub mod summary;

// ── Wire protocol types ──────────────────────────────────────────────



/// Unique connection identifier assigned in the accept loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// The kind of stream accepted from the TUN device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
    Udp,
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
    /// From .accept to the end of the loop body, which includes routing and spawning the proxy task.
    /// Should be very fast
    Dispatched {
        id: ConnId,
        dispatch_us: u64,
    },
    /// Routing decision made for this connection.
    Route {
        id: ConnId,
        ts: Timestamp,
        route: RoutingResovled,
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
        bytes_up: f32,
        bytes_down: f32,
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
    /// HotConfig reload completed (from file watcher or direct request).
    HotConfigReloaded {
        ts: Timestamp,
        ok: bool,
        changed: bool,
        source: String,
        error: Option<String>,
    },
    /// Snapshot of the current HotConfig (JSON text) or the error reason.
    HotConfigSnapshot {
        ts: Timestamp,
        ok: bool,
        content: Option<String>,
        error: Option<String>,
    },
    /// Current DNS state snapshot.
    DnsState {
        ts: Timestamp,
        state: DnsState,
    },
    /// Current routing selection snapshot.
    RoutingState {
        ts: Timestamp,
        state: RoutingState,
    },
    /// Per-proxy uplink stats snapshot.
    UplinkStatsSnapshot {
        ts: Timestamp,
        stats: std::collections::HashMap<ProxyID, nsproxy_common::stats::ProxyStats>,
    },
}

// ── Control commands (client → server) ─────────────────────────────

/// Commands that a connected EGUI client may send back to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlCommand {
    /// Reload all uplink proxy configurations.
    ReloadUplink,
    /// Re-read hot.json from disk and apply it.
    ReloadHotConfig,
    /// Replace the active routing function with `simple_routing(proxy_id)`.
    SetSimpleRouting {
        proxy_id: nsproxy_common::routing::ProxyID,
    },
    /// Request current DNS state snapshot.
    QueryDnsState,
    /// Request current routing selection snapshot.
    QueryRoutingState,
    /// Request current hotconfig content snapshot.
    QueryHotConfig,
    /// Apply a new HotConfig JSON payload.
    ApplyHotConfig {
        content: String,
    },
    /// Request per-proxy uplink stats from the running hub.
    QueryUplinkStats,
    /// Clear all accumulated uplink stats data.
    ClearStats,
}

/// Snapshot of DNS state derived from the VirtDNS handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsState {
    pub aaaa_only: bool,
    pub domain_count: usize,
    pub ip4_count: usize,
    pub ip6_count: usize,
}

/// Snapshot of current routing selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingState {
    pub selected_proxy: Option<ProxyID>,
}

// ── Server (tun2socks5 side) ─────────────────────────────────────────

/// Broadcaster that tun2socks5 uses to emit events.
/// Connected EGUI clients each get a broadcast receiver.
#[derive(Clone)]
pub struct DiagServer {
    /// Pre-encoded bincode frames (len-prefix + payload) ready to write.
    tx: broadcast::Sender<Arc<Vec<u8>>>,
    cmd_tx: mpsc::Sender<ControlCommand>,
}

/// Capacity of the broadcast channel (rolling window for slow readers).
const BROADCAST_CAP: usize = 4096;
/// Capacity of the control-command mpsc channel.
const CMD_CAP: usize = 64;

impl DiagServer {
    /// Create a new `DiagServer` and spawn the UNIX listener task.
    /// The socket is created at `sock_path`. If the file already exists it is removed.
    /// The socket and its parent directory are made world-accessible (0o777 / 0o666)
    /// so that a non-root EGUI viewer can connect.
    ///
    /// Returns `(server, cmd_rx)`.  Poll `cmd_rx` to receive [`ControlCommand`]s sent
    /// by any connected client.
    pub async fn start(sock_path: &Path) -> Result<(Self, mpsc::Receiver<ControlCommand>)> {
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
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CAP);
        let server = DiagServer { tx: tx.clone(), cmd_tx: cmd_tx.clone() };

        // Spawn acceptor
        let tx2 = tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        info!("diag: client connected");
                        let rx = tx2.subscribe();
                        tokio::spawn(serve_client(stream, rx, cmd_tx.clone()));
                    }
                    Err(e) => {
                        error!("diag: accept error: {}", e);
                    }
                }
            }
        });

        Ok((server, cmd_rx))
    }

    /// Emit a diagnostic event. Non-blocking; if no clients are connected the
    /// event is silently dropped.
    pub fn emit(&self, event: DiagEvent) {
        if let Ok(frame) = encode_frame(&event) {
            let _ = self.tx.send(Arc::new(frame));
        } else {
            warn!("diag: failed to encode event: {:?}", event);
        }
    }

    /// Returns a no-op stub that silently discards all events and commands.
    pub fn noop() -> Self {
        let (tx, _) = broadcast::channel(1);
        let (cmd_tx, _) = mpsc::channel(1);
        DiagServer { tx, cmd_tx }
    }
}

/// Serve a single connected EGUI client.
///
/// - **Server → client**: write pre-encoded bincode frames from the broadcast channel.
/// - **Client → server**: read bincode-framed [`ControlCommand`]s and forward to `cmd_tx`.
async fn serve_client(
    stream: UnixStream,
    mut rx: broadcast::Receiver<Arc<Vec<u8>>>,
    cmd_tx: mpsc::Sender<ControlCommand>,
) {
    let (mut read_half, mut write_half) = stream.into_split();

    loop {
        tokio::select! {
            // Outbound: server-emitted event → client
            result = rx.recv() => {
                match result {
                    Ok(frame) => {
                        if write_half.write_all(&frame).await.is_err() {
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
            // Inbound: client-sent control command → server
            result = read_frame::<ControlCommand, _>(&mut read_half) => {
                match result {
                    Ok(Some(cmd)) => {
                        debug!("diag: received control command: {:?}", cmd);
                        if cmd_tx.send(cmd).await.is_err() {
                            debug!("diag: command receiver dropped");
                        }
                    }
                    Ok(None) => {
                        debug!("diag: client disconnected (read EOF)");
                        return;
                    }
                    Err(e) => {
                        debug!("diag: client read error: {}", e);
                        return;
                    }
                }
            }
        }
    }
}

// ── Binary framing helpers (u32 LE length-prefix + bincode) ──────────

/// Encode `val` as a length-prefixed bincode frame.
fn encode_frame<T: Serialize>(val: &T) -> Result<Vec<u8>> {
    let payload = bincode::serialize(val)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Read one length-prefixed bincode frame from `reader`.
/// Returns `Ok(None)` on clean EOF.
async fn read_frame<T, R>(reader: &mut R) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(bincode::deserialize(&payload)?))
}

// ── Client helpers (for the EGUI viewer) ─────────────────────────────

/// Connect to a running tun2socks5 diag socket.
pub async fn connect(sock_path: &Path) -> Result<DiagEventStream> {
    let stream = UnixStream::connect(sock_path).await?;
    let (read_half, write_half) = stream.into_split();
    Ok(DiagEventStream { read_half, write_half })
}

pub struct DiagEventStream {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl DiagEventStream {
    /// Read the next [`DiagEvent`] from the stream. Returns `None` on EOF.
    pub async fn next(&mut self) -> Result<Option<DiagEvent>> {
        read_frame(&mut self.read_half).await
    }

    /// Send a [`ControlCommand`] to the server.
    pub async fn send_cmd(&mut self, cmd: &ControlCommand) -> Result<()> {
        let frame = encode_frame(cmd)?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    /// Split the stream into independent reader and writer halves so both
    /// directions can be used concurrently.
    pub fn split(self) -> (DiagEventReader, DiagEventWriter) {
        (
            DiagEventReader {
                read_half: self.read_half,
            },
            DiagEventWriter {
                write_half: self.write_half,
            },
        )
    }
}

/// Owned reader half of a diag connection.
pub struct DiagEventReader {
    read_half: tokio::net::unix::OwnedReadHalf,
}

impl DiagEventReader {
    /// Read the next [`DiagEvent`] from the reader. Returns `None` on EOF.
    pub async fn next(&mut self) -> Result<Option<DiagEvent>> {
        read_frame(&mut self.read_half).await
    }
}

/// Owned writer half of a diag connection.
pub struct DiagEventWriter {
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl DiagEventWriter {
    /// Send a [`ControlCommand`] on the writer.
    pub async fn send_cmd(&mut self, cmd: &ControlCommand) -> Result<()> {
        let frame = encode_frame(cmd)?;
        self.write_half.write_all(&frame).await?;
        Ok(())
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
