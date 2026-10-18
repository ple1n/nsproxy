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
    collections::{BTreeMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream as StdUnixStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, SystemTime},
};

use anyhow::{bail, Result};
pub use nsproxy_common::stats::Timestamp;
use nsproxy_common::{
    routing::{ProxyID, RoutingResovled},
    state_paths,
    stats::{HostRouteHost, HostRouteMetric, ObservedRoute},
    ExactNS, NSFrom, PidPath, UniqueFile,
};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, oneshot},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::Layer;

pub mod history;
pub mod personal;
pub mod summary;

// ── Wire protocol types ──────────────────────────────────────────────

/// Unique connection identifier assigned in the accept loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    Dispatched { id: ConnId, dispatch_us: u64 },
    /// Routing decision made for this connection.
    Route {
        id: ConnId,
        ts: Timestamp,
        route: RoutingResovled,
    },
    /// Connection to the proxy/remote server established.
    Connected { id: ConnId, ts: Timestamp },
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
    Wait { id: ConnId, ts: Timestamp },
    /// Wait was terminated and connection accepted.
    WaitEnded { id: ConnId, ts: Timestamp },
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
    DnsState { ts: Timestamp, state: DnsState },
    /// Current routing selection snapshot.
    RoutingState { ts: Timestamp, state: RoutingState },
    /// Per-proxy uplink stats snapshot.
    UplinkStatsSnapshot {
        ts: Timestamp,
        stats: std::collections::HashMap<ProxyID, nsproxy_common::stats::ProxyStats>,
    },
    /// A tracing log record forwarded from the running process.
    Log(LogEntry),
    /// Historical log entries from the server-side ring buffer.
    /// Sent in response to `ControlCommand::QueryRecentLogs`.
    RecentLogs(Vec<LogEntry>),
    /// Historical diag events from the server-side ring buffer.
    /// Sent in response to `ControlCommand::QueryRecentDiagEvents`.
    RecentDiagEvents(Vec<DiagEvent>),
    /// Snapshot of the current live connection-tracking state.
    /// Sent in response to [`ControlCommand::QueryConnsState`].
    ConnsStateSnapshot { ts: Timestamp, state: ConnsState },
    /// Full snapshot of serve-computed host/route performance estimates.
    HostRouteStatsSnapshot {
        ts: Timestamp,
        stats: Vec<HostRouteMetric>,
    },
    /// Incremental update for one host/route performance estimate.
    HostRouteStatsUpdated {
        ts: Timestamp,
        stat: HostRouteMetric,
    },
    /// Connection entries removed from the server-side retention window.
    ConnectionsExpired { ts: Timestamp, ids: Vec<ConnId> },
    /// One route attempt failed while the connection may still be retried.
    AttemptFailed {
        id: ConnId,
        ts: Timestamp,
        error: String,
    },
    /// Connection intentionally closed by a user action.
    Killed { id: ConnId, ts: Timestamp },
    /// SOCKS5 UDP ASSOCIATE or BIND endpoint status change.
    SocksEndpointStateChanged {
        ts: Timestamp,
        op: SocksOpKind,
        proxy_addr: std::net::SocketAddr,
        status: SocksEndpointStatus,
    },
    /// Periodic or event-driven stats for the SOCKS endpoint.
    SocksEndpointStats {
        ts: Timestamp,
        op: SocksOpKind,
        proxy_addr: std::net::SocketAddr,
        active_flows: usize,
        pkts_tx: u64,
        pkts_rx_datagrams: u64,
        pkts_rx: u64,
        pkts_rx_source_rejected: u64,
        pkts_rx_parse_errors: u64,
        pkts_rx_unmatched: u64,
        pkts_rx_delivery_dropped: u64,
        pkts_rx_queued: u64,
        bytes_tx: u64,
        bytes_rx: u64,
    },
}

/// Kind of SOCKS operation establishing an external listener or relay.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SocksOpKind {
    UdpAssociate,
    Bind,
}

/// Lifecycle and address state for a SOCKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SocksEndpointStatus {
    Connecting,
    Active {
        raw_bnd: WireAddress,
        effective_bnd: std::net::SocketAddr,
        relay_local_addr: Option<std::net::SocketAddr>,
    },
    Reconnecting {
        reason: String,
    },
    Closed {
        reason: String,
    },
}

/// Snapshot report of a SOCKS endpoint's state and metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocksEndpointReport {
    pub op: SocksOpKind,
    pub proxy_addr: std::net::SocketAddr,
    pub status: SocksEndpointStatus,
    pub active_flows: usize,
    pub pkts_tx: u64,
    pub pkts_rx_datagrams: u64,
    pub pkts_rx: u64,
    pub pkts_rx_source_rejected: u64,
    pub pkts_rx_parse_errors: u64,
    pub pkts_rx_unmatched: u64,
    pub pkts_rx_delivery_dropped: u64,
    pub pkts_rx_queued: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub updated_at: Timestamp,
}

/// A single tracing log record, usable across multiple transport protocols.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct LogField {
    pub name: String,
    pub value: String,
}

/// A single tracing log record, usable across multiple transport protocols.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct LogEntry {
    pub ts: Timestamp,
    /// Tracing level string: "TRACE", "DEBUG", "INFO", "WARN", or "ERROR".
    pub level: String,
    /// The tracing target (usually the module path).
    pub target: String,
    /// The formatted log message.
    pub message: String,
    /// Additional structured fields attached to the tracing event.
    #[serde(default)]
    pub fields: Vec<LogField>,
}

// ── Control commands (client → server) ─────────────────────────────

/// Commands that a connected EGUI client may send back to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlCommand {
    /// Request the serving process to shut down.
    Shutdown,
    /// Reload all uplink proxy configurations.
    ReloadUplink,
    /// Re-read hot.json from disk and apply it.
    ReloadHotConfig,
    /// Replace the active routing function with `simple_routing(proxy_id)`.
    SetSimpleRouting {
        proxy_id: nsproxy_common::routing::ProxyID,
    },
    /// Route all traffic through a named user-owned proxy group.
    SetGroupRouting { group_id: String },
    /// Route all traffic without a proxy, independently of the no-route state.
    SetNoProxyRouting,
    /// Request current DNS state snapshot.
    QueryDnsState,
    /// Request current routing selection snapshot.
    QueryRoutingState,
    /// Request current hotconfig content snapshot.
    QueryHotConfig,
    /// Apply a new HotConfig JSON payload.
    ApplyHotConfig { content: String },
    /// Request per-proxy uplink stats from the running hub.
    QueryUplinkStats,
    /// Clear all accumulated uplink stats data.
    ClearStats,
    /// Request the most-recent `limit` log entries from the server-side ring buffer.
    /// The server responds with `DiagEvent::RecentLogs`.
    QueryRecentLogs { limit: usize },
    /// Request the most-recent `limit` diag events from the server-side ring buffer.
    /// The server responds immediately with `DiagEvent::RecentDiagEvents`.
    QueryRecentDiagEvents { limit: usize },
    /// Enable or disable live connection tracking in the server.
    /// Mirrors [`DiagServer::track_conns`] at runtime.
    SetTrackConns { enabled: bool },
    /// Reset the live connection-tracking state (clears both `active` and `pending`).
    ResetConnsState,
    /// Request a full snapshot of the current live connection-tracking state.
    /// The server responds with [`DiagEvent::ConnsStateSnapshot`].
    /// Intended for infrequent polling; prefer consuming live events via
    /// [`ConnsState::apply_event`] for real-time client-side reconstruction.
    QueryConnsState,
    /// Request serve-computed per-target, per-route performance estimates.
    QueryHostRouteStats,
    /// Set or replace a routing-key override and persist it through `sp serve`.
    SetHostRoute {
        key: nsproxy_common::routing::RoutingKey,
        decision: RoutingResovled,
    },
    /// Close all active TCP and UDP connections for a host.
    KillHostConnections { host: HostRouteHost },
}

/// Request sent to the global privileged `sp daemon` service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDaemonRequest {
    pub op_id: u64,
    pub op: RootDaemonOp,
}

/// Supported privileged maintenance operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootDaemonOp {
    Ping,
    Stop,
    InitializeBasisNamespace,
    CreateDirAll {
        path: PathBuf,
    },
    ReadFile {
        path: PathBuf,
    },
    WriteFile {
        path: PathBuf,
        content: Vec<u8>,
        create_parent: bool,
    },
    ImportClashGroup {
        group_id: String,
        path: PathBuf,
        replace: bool,
    },
    CreateProfile {
        name: String,
        profile_content: String,
        hot_content: Option<String>,
    },
    WriteHotConfig {
        profile: String,
        content: String,
    },
}

/// Response emitted by the global privileged `sp daemon` service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDaemonEvent {
    pub op_id: u64,
    pub result: RootDaemonResult,
}

/// Root-daemon wire request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootDaemonWireRequest {
    Stable(StableRequest),
    Unstable(RootDaemonRequest),
    QueryRecentLogs { limit: usize },
}

/// Root-daemon wire event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootDaemonWireEvent {
    Stable(StableEvent),
    Unstable(RootDaemonEvent),
    Log(LogEntry),
    RecentLogs(Vec<LogEntry>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootDaemonResult {
    Pong {
        version: String,
    },
    ReadFile {
        content: String,
        path: PathBuf,
    },
    NamespaceInitialized {
        current: nsproxy_common::ProfileNamespaces,
        basis_ns: nsproxy_common::ProfileNamespaces,
        initialized: bool,
    },
    Ok {
        message: String,
        profile: Option<String>,
        path: Option<PathBuf>,
    },
    Error {
        message: String,
        profile: Option<String>,
        path: Option<PathBuf>,
    },
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
    #[serde(default)]
    pub selected_group: Option<String>,
    #[serde(default)]
    pub no_proxy: bool,
}

/// Logical protocol channel carried over the framed Unix stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolChannel {
    Diag,
    Up,
    Daemon,
    Control,
}

/// Mandatory pre-frame exchanged before any protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolHandshake {
    pub channel: ProtocolChannel,
    pub version: String,
    pub netns: UniqueFile,
    pub self_pid: u32,
}

static PROTOCOL_VERSION: OnceLock<String> = OnceLock::new();
static PROTOCOL_LENIENT: AtomicBool = AtomicBool::new(false);

/// Set this process' protocol build identity. Must be called before opening any protocol sockets.
pub fn set_protocol_version(version: impl Into<String>) {
    let _ = PROTOCOL_VERSION.set(version.into());
}

/// Control whether protocol build-hash mismatches are advisory instead of fatal.
pub fn set_protocol_lenient(lenient: bool) {
    PROTOCOL_LENIENT.store(lenient, Ordering::Relaxed);
}

/// Current process protocol build identity used during handshakes.
pub fn protocol_version() -> &'static str {
    PROTOCOL_VERSION
        .get()
        .map(String::as_str)
        .unwrap_or("unknown:0")
}

/// Whether version mismatches should be tolerated by this process' clients.
pub fn protocol_lenient() -> bool {
    PROTOCOL_LENIENT.load(Ordering::Relaxed)
}

pub fn protocol_mismatch_message(local: &str, remote: &str) -> String {
    format!("build hash mismatch: local={}, remote={}", local, remote)
}

fn local_handshake(channel: ProtocolChannel) -> Result<ProtocolHandshake> {
    Ok(ProtocolHandshake {
        channel,
        version: protocol_version().to_string(),
        netns: ExactNS::from_source((PidPath::Selfproc, "net"))?.unique,
        self_pid: std::process::id(),
    })
}

async fn write_handshake(stream: &mut UnixStream, channel: ProtocolChannel) -> Result<()> {
    let frame = encode_frame(&local_handshake(channel)?)?;
    stream.write_all(&frame).await?;
    Ok(())
}

async fn read_handshake(
    stream: &mut UnixStream,
    expected_channel: ProtocolChannel,
) -> Result<ProtocolHandshake> {
    let Some(remote) = read_frame::<ProtocolHandshake, _>(stream).await? else {
        bail!("peer closed before protocol handshake");
    };
    if remote.channel != expected_channel {
        bail!(
            "protocol channel mismatch: expected {:?}, got {:?}",
            expected_channel,
            remote.channel
        );
    }
    Ok(remote)
}

/// Client-side handshake: send local identity first, then validate server identity.
pub async fn handshake_client(
    stream: &mut UnixStream,
    channel: ProtocolChannel,
) -> Result<ProtocolHandshake> {
    write_handshake(stream, channel.clone()).await?;
    read_handshake(stream, channel).await
}

/// Server-side handshake: validate client identity first, then send local identity.
pub async fn handshake_server(
    stream: &mut UnixStream,
    channel: ProtocolChannel,
) -> Result<ProtocolHandshake> {
    read_handshake(stream, channel.clone()).await?;
    write_handshake(stream, channel.clone()).await?;
    // The server's own handshake is the identity returned to its client.
    Ok(local_handshake(channel)?)
}

// ── Control socket (reversed-role connections) ────────────────────────
//
// When the UI passes `--control-socket` to a spawned process, the process
// connects TO the UI's socket instead of the UI connecting to the process.
// The first frame sent by the connecting process is a `ControlSocketGreeting`
// so the UI knows which profile and protocol type to use.  After the greeting,
// the wire format is identical to the normal socket protocols (just with the
// connection direction reversed).

/// First frame sent by a spawned process over the UI control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlSocketGreeting {
    /// The `sp up` daemon is connecting; subsequent frames are `DaemonEvent` / `DaemonRequest`.
    UpDaemon { name: String },
    /// The `sp serve` process is connecting; subsequent frames are `DiagEvent` / `ControlCommand`.
    ServeDaemon { name: String },
    /// The global privileged `sp daemon` is connecting; subsequent frames are
    /// `RootDaemonEvent` / `RootDaemonRequest`.
    RootDaemon,
}

/// Encode a [`ControlSocketGreeting`] as a length-prefixed bincode frame ready to write.
pub fn encode_control_greeting(greeting: &ControlSocketGreeting) -> Result<Vec<u8>> {
    encode_frame(greeting)
}

/// Read a [`ControlSocketGreeting`] from the *unsplit* stream.  Returns `None` on clean EOF.
pub async fn read_control_greeting(
    stream: &mut UnixStream,
) -> Result<Option<ControlSocketGreeting>> {
    read_frame(stream).await
}

/// Perform control-socket client-side handshake.
pub async fn control_handshake_client(stream: &mut UnixStream) -> Result<()> {
    handshake_client(stream, ProtocolChannel::Control)
        .await
        .map(|_| ())
}

/// Perform control-socket server-side handshake.
pub async fn control_handshake_server(stream: &mut UnixStream) -> Result<()> {
    handshake_server(stream, ProtocolChannel::Control)
        .await
        .map(|_| ())
}

// ── Connection-tracking types ────────────────────────────────────────

/// Per-destination routing-decision counters for active connections.
///
/// The inner map key is the routing resolution chosen for that connection;
/// the value is the number of currently-active connections using that route.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnsSummary(pub BTreeMap<RoutingResovled, u64>);

// ── Connection-tracking types ────────────────────────────────────────

/// A single tracked connection entry retained in [`ConnsState`].
///
/// Entries are created on [`DiagEvent::Accept`] and updated inline as subsequent
/// events arrive.  Finished entries (where `finished_at` is `Some`) are retained
/// for [`DiagServer::conn_persist`] before being garbage-collected by a
/// [`ConnsActor`] GC tick.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnPhase {
    Accepted,
    Routing,
    Connected,
    DnsResolved,
    DnsFailed,
    Finished,
    Failed,
    RouteExhausted,
    RouteRejected,
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnTransitionKind {
    Accepted,
    Dispatched { dispatch_us: u64 },
    Route(RoutingResovled),
    Connected,
    AttemptFailed { error: String },
    DnsResolved { domain: String, result: String },
    Finished { error: Option<String> },
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnTransition {
    pub ts: Timestamp,
    pub kind: ConnTransitionKind,
}

const MAX_CONN_TRANSITIONS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnEntry {
    /// Transport protocol reported when the stream was accepted.
    pub kind: StreamKind,
    /// Resolved destination address.
    pub dst: WireAddress,
    /// Most recent non-drop routing decision; a later Drop does not hide the useful route.
    pub route: Option<RoutingResovled>,
    /// Current summarized lifecycle state.
    pub phase: ConnPhase,
    /// Recent state transitions in timestamp order.
    pub history: Vec<ConnTransition>,
    /// True when old transitions were trimmed to keep each entry bounded.
    pub history_truncated: bool,
    /// Timestamp when the connection was accepted.
    pub accepted_at: Timestamp,
    /// Timestamp when the upstream connection was established.
    pub connected_at: Option<Timestamp>,
    /// Timestamp when the connection finished; `None` means still active.
    pub finished_at: Option<Timestamp>,
    /// Error string if the connection finished with an error.
    pub error: Option<String>,
    /// Bytes transferred upstream (set on [`DiagEvent::Finished`]).
    pub bytes_up: Option<f32>,
    /// Bytes transferred downstream (set on [`DiagEvent::Finished`]).
    pub bytes_down: Option<f32>,
}

impl ConnEntry {
    fn push_transition(&mut self, ts: Timestamp, kind: ConnTransitionKind) {
        if self.history.len() == MAX_CONN_TRANSITIONS {
            self.history.remove(0);
            self.history_truncated = true;
        }
        self.history.push(ConnTransition { ts, kind });
    }
}

/// Live connection-tracking state owned by [`ConnsActor`] and delivered to
/// clients as a snapshot in response to [`ControlCommand::QueryConnsState`].
///
/// All connections — pending setup, active, and recently-finished — are stored
/// in a single flat map keyed by [`ConnId`].  Finished entries are retained for
/// [`DiagServer::conn_persist`] and then evicted by the actor's GC timer.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConnsState {
    /// All tracked connections (pending, active, and recently-finished).
    pub conns: BTreeMap<ConnId, Arc<ConnEntry>>,
}

impl ConnsState {
    fn entry_mut(&mut self, id: &ConnId) -> Option<&mut ConnEntry> {
        self.conns.get_mut(id).map(Arc::make_mut)
    }

    /// Apply a single [`DiagEvent`] to this state.
    ///
    /// Called both server-side (inside [`ConnsActor`]) and client-side
    /// (in the supervisor) to keep a local reconstruction up-to-date.
    pub fn apply_event(&mut self, event: &DiagEvent) {
        match event {
            DiagEvent::Accept {
                id, dst, ts, kind, ..
            } => {
                if let Ok(addr) = WireAddress::try_from(dst.as_str()) {
                    let mut entry = ConnEntry {
                        kind: kind.clone(),
                        dst: addr,
                        route: None,
                        phase: ConnPhase::Accepted,
                        history: Vec::new(),
                        history_truncated: false,
                        accepted_at: *ts,
                        connected_at: None,
                        finished_at: None,
                        error: None,
                        bytes_up: None,
                        bytes_down: None,
                    };
                    entry.push_transition(*ts, ConnTransitionKind::Accepted);
                    self.conns.insert(*id, Arc::new(entry));
                }
            }
            DiagEvent::Route { id, ts, route } => {
                if let Some(entry) = self.entry_mut(id) {
                    entry.push_transition(*ts, ConnTransitionKind::Route(route.clone()));
                    match route {
                        RoutingResovled::Drop(nsproxy_common::routing::DropReason::MaxRetry) => {
                            entry.phase = ConnPhase::RouteExhausted;
                        }
                        RoutingResovled::Drop(nsproxy_common::routing::DropReason::Preprocess(
                            _,
                        )) => {
                            entry.phase = ConnPhase::RouteRejected;
                        }
                        _ => {
                            entry.phase = ConnPhase::Routing;
                            entry.route = Some(route.clone());
                        }
                    }
                }
            }
            DiagEvent::Connected { id, ts } => {
                if let Some(entry) = self.entry_mut(id) {
                    entry.connected_at = Some(*ts);
                    entry.phase = ConnPhase::Connected;
                    entry.push_transition(*ts, ConnTransitionKind::Connected);
                }
            }
            DiagEvent::AttemptFailed { id, ts, error } => {
                if let Some(entry) = self.entry_mut(id) {
                    entry.phase = ConnPhase::Routing;
                    entry.push_transition(
                        *ts,
                        ConnTransitionKind::AttemptFailed {
                            error: error.clone(),
                        },
                    );
                }
            }
            DiagEvent::DnsResolved {
                id,
                ts,
                domain,
                result,
            } => {
                // DNS connections are handled internally; mark as finished so they
                // enter the persistence window rather than accumulating as active.
                if let Some(entry) = self.entry_mut(id) {
                    if entry.finished_at.is_none() {
                        entry.finished_at = Some(*ts);
                    }
                    entry.phase = if result.starts_with("err:") {
                        ConnPhase::DnsFailed
                    } else {
                        ConnPhase::DnsResolved
                    };
                    entry.push_transition(
                        *ts,
                        ConnTransitionKind::DnsResolved {
                            domain: domain.clone(),
                            result: result.clone(),
                        },
                    );
                }
            }
            DiagEvent::Finished {
                id,
                ts,
                error,
                bytes_up,
                bytes_down,
                ..
            } => {
                if let Some(entry) = self.entry_mut(id) {
                    entry.finished_at = Some(*ts);
                    entry.error = error.clone();
                    entry.bytes_up = Some(*bytes_up);
                    entry.bytes_down = Some(*bytes_down);
                    entry.phase = if error.is_some() {
                        ConnPhase::Failed
                    } else {
                        ConnPhase::Finished
                    };
                    entry.push_transition(
                        *ts,
                        ConnTransitionKind::Finished {
                            error: error.clone(),
                        },
                    );
                }
            }
            DiagEvent::Killed { id, ts } => {
                if let Some(entry) = self.entry_mut(id) {
                    entry.finished_at = Some(*ts);
                    entry.error = None;
                    entry.phase = ConnPhase::Killed;
                    entry.push_transition(*ts, ConnTransitionKind::Killed);
                }
            }
            DiagEvent::Dispatched { id, dispatch_us } => {
                if let Some(entry) = self.entry_mut(id) {
                    let ts = Timestamp(entry.accepted_at.0.saturating_add(*dispatch_us));
                    entry.push_transition(
                        ts,
                        ConnTransitionKind::Dispatched {
                            dispatch_us: *dispatch_us,
                        },
                    );
                }
            }
            DiagEvent::ConnectionsExpired { ids, .. } => {
                for id in ids {
                    self.conns.remove(id);
                }
            }
            _ => {}
        }
    }

    /// Clear all tracked connections.
    pub fn reset(&mut self) {
        self.conns.clear();
    }

    /// Remove finished entries whose age exceeds `max_age`.
    /// Active (unfinished) entries are never removed by this method.
    pub fn gc(&mut self, max_age: Duration) -> Vec<ConnId> {
        let now_us = Timestamp::now().0;
        let max_age_us = max_age.as_micros() as u64;
        let mut expired = Vec::new();
        self.conns.retain(|id, entry| {
            let retain = entry
                .finished_at
                .map(|ts| now_us.saturating_sub(ts.0) < max_age_us)
                .unwrap_or(true);
            if !retain {
                expired.push(*id);
            }
            retain
        });
        expired
    }
}

// ── ConnsActor ───────────────────────────────────────────────────────

/// Command sent to the [`ConnsActor`] task.
pub enum ConnsCmd {
    /// Apply a diag event to the tracked connection state.
    Event(DiagEvent),
    /// Clear all tracked connections.
    Reset,
    /// Request a snapshot; the response is sent on the provided oneshot channel.
    Query(oneshot::Sender<ConnsState>),
    /// Change how long completed entries remain in the state.
    SetPersist {
        conn_persist: Duration,
        response: oneshot::Sender<()>,
    },
}

/// How often the actor checks for stale finished entries to garbage-collect.
const GC_INTERVAL: Duration = Duration::from_secs(5);

/// Async actor that exclusively owns [`ConnsState`] and drives its GC loop.
///
/// All mutation goes through the [`mpsc`] channel so there is no shared-mutex
/// contention on the hot emit path.
struct ConnsActor {
    state: ConnsState,
    conn_persist: Duration,
    rx: mpsc::Receiver<ConnsCmd>,
    expired_tx: mpsc::Sender<Vec<ConnId>>,
}

impl ConnsActor {
    /// Spawn the actor task and return its command sender.
    fn spawn(conn_persist: Duration) -> (mpsc::Sender<ConnsCmd>, mpsc::Receiver<Vec<ConnId>>) {
        let (tx, rx) = mpsc::channel(256);
        let (expired_tx, expired_rx) = mpsc::channel(64);
        tokio::spawn(
            Self {
                state: ConnsState::default(),
                conn_persist,
                rx,
                expired_tx,
            }
            .run(),
        );
        (tx, expired_rx)
    }

    async fn run(mut self) {
        let mut gc_interval = tokio::time::interval(GC_INTERVAL);
        gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = gc_interval.tick() => {
                    let expired = self.state.gc(self.conn_persist);
                    if !expired.is_empty() && self.expired_tx.send(expired).await.is_err() {
                        break;
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Some(ConnsCmd::Event(ev)) => {
                            let terminal = matches!(
                                &ev,
                                DiagEvent::Finished { .. } | DiagEvent::DnsResolved { .. }
                            );
                            self.state.apply_event(&ev);
                            if terminal && self.conn_persist.is_zero() {
                                let expired = self.state.gc(self.conn_persist);
                                if !expired.is_empty() && self.expired_tx.send(expired).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(ConnsCmd::Reset) => self.state.reset(),
                        Some(ConnsCmd::Query(resp)) => {
                            let _ = resp.send(self.state.clone());
                        }
                        Some(ConnsCmd::SetPersist { conn_persist, response }) => {
                            self.conn_persist = conn_persist;
                            let expired = self.state.gc(self.conn_persist);
                            if !expired.is_empty() && self.expired_tx.send(expired).await.is_err() {
                                break;
                            }
                            let _ = response.send(());
                        }
                        None => break, // all senders dropped — shut down
                    }
                }
            }
        }
    }
}

// ── Server (tun2socks5 side) ─────────────────────────────────────────

/// Broadcaster that tun2socks5 uses to emit events.
/// Connected EGUI clients each get a broadcast receiver.
#[derive(Clone)]
pub struct DiagServer {
    /// Pre-encoded bincode frames (len-prefix + payload) ready to write.
    tx: broadcast::Sender<Arc<Vec<u8>>>,
    cmd_tx: mpsc::Sender<ControlCommand>,
    /// Rolling ring buffer of the most-recent [`DIAG_EVENT_RING_CAP`] emitted events.
    event_ring: Arc<Mutex<VecDeque<DiagEvent>>>,
    /// Latest SOCKS endpoint report, replayed to clients that connect after
    /// the lifecycle event was emitted.
    socks_endpoint: Arc<Mutex<Option<SocksEndpointReport>>>,
    /// Channel to the [`ConnsActor`] that owns connection-tracking state.
    conns_tx: mpsc::Sender<ConnsCmd>,
    /// When `false`, all connection-tracking logic in [`Self::emit`] is skipped.
    /// Shared across clones; may be toggled at runtime via [`Self::set_track_conns`]
    /// or the [`ControlCommand::SetTrackConns`] wire command.
    track_conns: Arc<AtomicBool>,
    /// Initial duration for finished-entry retention. The live value may be changed
    /// through [`Self::set_conn_persist`].
    pub conn_persist: Duration,
}

/// Capacity of the broadcast channel (rolling window for slow readers).
const BROADCAST_CAP: usize = 4096;
/// Capacity of the control-command mpsc channel.
const CMD_CAP: usize = 64;
/// Number of [`DiagEvent`]s retained in the server-side ring buffer.
pub const DIAG_EVENT_RING_CAP: usize = 50;
/// Default value of [`DiagServer::track_conns`] when created via [`DiagServer::start`] or [`DiagServer::noop`].
pub const DEFAULT_TRACK_CONNS: bool = true;
/// Default duration finished connection entries are retained before GC.
pub const DEFAULT_CONN_PERSIST: Duration = Duration::from_secs(300);

impl DiagServer {
    /// Create a new `DiagServer` and spawn the UNIX listener task.
    /// The socket is created at `sock_path`. If the file already exists it is removed.
    /// The socket and its parent directory are made world-accessible (0o777 / 0o666)
    /// so that a non-root EGUI viewer can connect.
    ///
    /// `conn_persist` controls how long finished connection entries are retained
    /// before the [`ConnsActor`] GC tick removes them.  Pass [`DEFAULT_CONN_PERSIST`]
    /// for the default 300-second window.
    ///
    /// Returns `(server, cmd_rx)`.  Poll `cmd_rx` to receive [`ControlCommand`]s sent
    /// by any connected client.
    pub async fn start(
        sock_path: &Path,
        conn_persist: Duration,
    ) -> Result<(Self, mpsc::Receiver<ControlCommand>)> {
        // Ensure parent directory exists and is world-accessible
        if let Some(parent) = sock_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                .await
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
        let event_ring: Arc<Mutex<VecDeque<DiagEvent>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(DIAG_EVENT_RING_CAP)));
        let socks_endpoint = Arc::new(Mutex::new(None));
        let track_conns = Arc::new(AtomicBool::new(DEFAULT_TRACK_CONNS));
        let (conns_tx, mut expired_rx) = ConnsActor::spawn(conn_persist);
        let server = DiagServer {
            tx: tx.clone(),
            cmd_tx: cmd_tx.clone(),
            event_ring: event_ring.clone(),
            socks_endpoint: socks_endpoint.clone(),
            conns_tx: conns_tx.clone(),
            track_conns: track_conns.clone(),
            conn_persist,
        };

        let expiry_server = server.clone();
        tokio::spawn(async move {
            while let Some(ids) = expired_rx.recv().await {
                expiry_server.emit(DiagEvent::ConnectionsExpired {
                    ts: Timestamp::now(),
                    ids,
                });
            }
        });

        // Spawn acceptor
        let tx2 = tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _addr)) => {
                        if let Err(e) = handshake_server(&mut stream, ProtocolChannel::Diag).await {
                            warn!("diag: handshake failed: {}", e);
                            continue;
                        }
                        info!("diag: client connected");
                        let rx = tx2.subscribe();
                        tokio::spawn(serve_client(
                            stream,
                            rx,
                            cmd_tx.clone(),
                            event_ring.clone(),
                            socks_endpoint.clone(),
                            track_conns.clone(),
                            conns_tx.clone(),
                        ));
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
    ///
    /// The event is also appended to the internal ring buffer (capped at
    /// [`DIAG_EVENT_RING_CAP`]) and, when [`Self::track_conns`] is `true`,
    /// forwarded to the [`ConnsActor`] for live connection-tracking.
    pub fn emit(&self, event: DiagEvent) {
        history::record_diag_event(&event);
        self.update_socks_endpoint(&event);
        // 1. Push to the rolling ring buffer.
        if !matches!(
            event,
            DiagEvent::HostRouteStatsSnapshot { .. }
                | DiagEvent::HostRouteStatsUpdated { .. }
                | DiagEvent::ConnectionsExpired { .. }
        ) {
            if let Ok(mut ring) = self.event_ring.lock() {
                if ring.len() >= DIAG_EVENT_RING_CAP {
                    ring.pop_front();
                }
                ring.push_back(event.clone());
            }
        }
        // 2. Forward to the ConnsActor (fire-and-forget; never blocks the caller).
        if self.track_conns.load(Ordering::Relaxed) {
            let _ = self.conns_tx.try_send(ConnsCmd::Event(event.clone()));
        }
        // 3. Broadcast pre-encoded frame to connected clients.
        if let Ok(frame) = encode_frame(&event) {
            let _ = self.tx.send(Arc::new(frame));
        } else {
            warn!("diag: failed to encode event: {:?}", event);
        }
    }

    /// Emit a forwarded log entry that originated in another process.
    ///
    /// Unlike [`Self::emit`] with `DiagEvent::Log`, this also appends the entry to the
    /// process-local log ring so `QueryRecentLogs` can replay logs that arrived before
    /// any client was attached.
    pub fn emit_forwarded_log(&self, entry: LogEntry) {
        push_log_ring(&entry);
        self.emit(DiagEvent::Log(entry));
    }

    /// Get the current value of the connection-tracking flag.
    pub fn track_conns(&self) -> bool {
        self.track_conns.load(Ordering::Relaxed)
    }

    /// Set the connection-tracking flag. Takes effect immediately across all clones.
    pub fn set_track_conns(&self, enabled: bool) {
        self.track_conns.store(enabled, Ordering::Relaxed);
    }

    /// Change the finished-connection retention window immediately.
    pub async fn set_conn_persist(&self, conn_persist: Duration) -> Result<()> {
        let (response, response_rx) = oneshot::channel();
        self.conns_tx
            .send(ConnsCmd::SetPersist {
                conn_persist,
                response,
            })
            .await
            .map_err(|_| anyhow::anyhow!("connection tracking actor has stopped"))?;
        response_rx
            .await
            .map_err(|_| anyhow::anyhow!("connection tracking actor dropped retention update"))
    }

    /// Install this server's broadcast channel as the process-global serve log sink.
    ///
    /// After calling this, [`DiagTracingLayer`] will forward all log records from tasks
    /// that are *not* running inside a [`DiagServer::scope`] to this server's diag socket
    /// as [`DiagEvent::Log`] frames.  Call once after [`DiagServer::start`] in `sp serve`.
    pub fn install_as_global(&self) {
        let _ = SERVE_LOG_TX.set(self.tx.clone());
    }

    /// Returns a no-op stub that silently discards all events and commands.
    pub fn noop() -> Self {
        let (tx, _) = broadcast::channel(1);
        let (cmd_tx, _) = mpsc::channel(1);
        let (conns_tx, _) = mpsc::channel(1); // no receiver — messages are dropped
        DiagServer {
            tx,
            cmd_tx,
            event_ring: Arc::new(Mutex::new(VecDeque::new())),
            socks_endpoint: Arc::new(Mutex::new(None)),
            conns_tx,
            track_conns: Arc::new(AtomicBool::new(DEFAULT_TRACK_CONNS)),
            conn_persist: DEFAULT_CONN_PERSIST,
        }
    }

    /// Register a reversed-role connection as a diag client.
    ///
    /// In the normal flow the UI connects to the server's socket; with a reversed
    /// connection the spawned process connected to the UI's control socket.  From
    /// the wire perspective the roles are identical — the server still broadcasts
    /// `DiagEvent` frames and the client still sends `ControlCommand` frames — so
    /// we can reuse `serve_client` unchanged.
    pub fn add_reversed_client(&self, stream: UnixStream) {
        let rx = self.tx.subscribe();
        let cmd_tx = self.cmd_tx.clone();
        let ring = self.event_ring.clone();
        let socks_endpoint = self.socks_endpoint.clone();
        let track_conns = self.track_conns.clone();
        let conns_tx = self.conns_tx.clone();
        tokio::spawn(serve_client(
            stream,
            rx,
            cmd_tx,
            ring,
            socks_endpoint,
            track_conns,
            conns_tx,
        ));
    }

    /// Run `fut` inside a task-local scope so that all `tracing` log records
    /// emitted during its execution are forwarded to this server's diag socket.
    ///
    /// Use this to wrap the top-level async block of a profile's serve task:
    /// ```ignore
    /// rt.block_on(diag_srv.scope(async move { ... }))
    /// ```
    pub fn scope<F: std::future::Future>(
        &self,
        fut: F,
    ) -> impl std::future::Future<Output = F::Output> {
        TASK_DIAG.scope(Some(self.tx.clone()), fut)
    }

    fn update_socks_endpoint(&self, event: &DiagEvent) {
        let Ok(mut current) = self.socks_endpoint.lock() else {
            return;
        };
        match event {
            DiagEvent::SocksEndpointStateChanged {
                ts,
                op,
                proxy_addr,
                status,
            } => {
                let report = current.get_or_insert_with(|| SocksEndpointReport {
                    op: *op,
                    proxy_addr: *proxy_addr,
                    status: status.clone(),
                    active_flows: 0,
                    pkts_tx: 0,
                    pkts_rx_datagrams: 0,
                    pkts_rx: 0,
                    pkts_rx_source_rejected: 0,
                    pkts_rx_parse_errors: 0,
                    pkts_rx_unmatched: 0,
                    pkts_rx_delivery_dropped: 0,
                    pkts_rx_queued: 0,
                    bytes_tx: 0,
                    bytes_rx: 0,
                    updated_at: *ts,
                });
                report.op = *op;
                report.proxy_addr = *proxy_addr;
                report.status = status.clone();
                report.updated_at = *ts;
            }
            DiagEvent::SocksEndpointStats {
                ts,
                op,
                proxy_addr,
                active_flows,
                pkts_tx,
                pkts_rx_datagrams,
                pkts_rx,
                pkts_rx_source_rejected,
                pkts_rx_parse_errors,
                pkts_rx_unmatched,
                pkts_rx_delivery_dropped,
                pkts_rx_queued,
                bytes_tx,
                bytes_rx,
            } => {
                let report = current.get_or_insert_with(|| SocksEndpointReport {
                    op: *op,
                    proxy_addr: *proxy_addr,
                    status: SocksEndpointStatus::Connecting,
                    active_flows: *active_flows,
                    pkts_tx: *pkts_tx,
                    pkts_rx_datagrams: *pkts_rx_datagrams,
                    pkts_rx: *pkts_rx,
                    pkts_rx_source_rejected: *pkts_rx_source_rejected,
                    pkts_rx_parse_errors: *pkts_rx_parse_errors,
                    pkts_rx_unmatched: *pkts_rx_unmatched,
                    pkts_rx_delivery_dropped: *pkts_rx_delivery_dropped,
                    pkts_rx_queued: *pkts_rx_queued,
                    bytes_tx: *bytes_tx,
                    bytes_rx: *bytes_rx,
                    updated_at: *ts,
                });
                report.op = *op;
                report.proxy_addr = *proxy_addr;
                report.active_flows = *active_flows;
                report.pkts_tx = *pkts_tx;
                report.pkts_rx_datagrams = *pkts_rx_datagrams;
                report.pkts_rx = *pkts_rx;
                report.pkts_rx_source_rejected = *pkts_rx_source_rejected;
                report.pkts_rx_parse_errors = *pkts_rx_parse_errors;
                report.pkts_rx_unmatched = *pkts_rx_unmatched;
                report.pkts_rx_delivery_dropped = *pkts_rx_delivery_dropped;
                report.pkts_rx_queued = *pkts_rx_queued;
                report.bytes_tx = *bytes_tx;
                report.bytes_rx = *bytes_rx;
                report.updated_at = *ts;
            }
            _ => {}
        }
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
    event_ring: Arc<Mutex<VecDeque<DiagEvent>>>,
    socks_endpoint: Arc<Mutex<Option<SocksEndpointReport>>>,
    track_conns: Arc<AtomicBool>,
    conns_tx: mpsc::Sender<ConnsCmd>,
) {
    let (mut read_half, mut write_half) = stream.into_split();

    // Lifecycle events are broadcast-only, so a client that connects after
    // startup would otherwise never learn that the endpoint exists. Replay
    // the retained report before entering the live event loop.
    let endpoint = socks_endpoint.lock().ok().and_then(|report| report.clone());
    if let Some(report) = endpoint {
        let state = DiagEvent::SocksEndpointStateChanged {
            ts: report.updated_at,
            op: report.op,
            proxy_addr: report.proxy_addr,
            status: report.status,
        };
        let stats = DiagEvent::SocksEndpointStats {
            ts: report.updated_at,
            op: report.op,
            proxy_addr: report.proxy_addr,
            active_flows: report.active_flows,
            pkts_tx: report.pkts_tx,
            pkts_rx_datagrams: report.pkts_rx_datagrams,
            pkts_rx: report.pkts_rx,
            pkts_rx_source_rejected: report.pkts_rx_source_rejected,
            pkts_rx_parse_errors: report.pkts_rx_parse_errors,
            pkts_rx_unmatched: report.pkts_rx_unmatched,
            pkts_rx_delivery_dropped: report.pkts_rx_delivery_dropped,
            pkts_rx_queued: report.pkts_rx_queued,
            bytes_tx: report.bytes_tx,
            bytes_rx: report.bytes_rx,
        };
        for event in [state, stats] {
            if let Ok(frame) = encode_frame(&event) {
                if write_half.write_all(&frame).await.is_err() {
                    return;
                }
            }
        }
    }

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
                    Ok(Some(ControlCommand::QueryRecentDiagEvents { limit })) => {
                        // Handled directly here; do not forward to the application.
                        let events: Vec<DiagEvent> = match event_ring.lock() {
                            Ok(guard) => {
                                let skip = guard.len().saturating_sub(limit);
                                guard.iter().skip(skip).cloned().collect()
                            }
                            Err(_) => vec![],
                        };
                        if let Ok(frame) = encode_frame(&DiagEvent::RecentDiagEvents(events)) {
                            if write_half.write_all(&frame).await.is_err() {
                                debug!("diag: client disconnected (write response)");
                                return;
                            }
                        }
                    }
                    Ok(Some(ControlCommand::SetTrackConns { enabled })) => {
                        track_conns.store(enabled, Ordering::Relaxed);
                        debug!("diag: track_conns set to {}", enabled);
                    }
                    Ok(Some(ControlCommand::ResetConnsState)) => {
                        let _ = conns_tx.send(ConnsCmd::Reset).await;
                        debug!("diag: conns state reset");
                    }
                    Ok(Some(ControlCommand::QueryConnsState)) => {
                        let (resp_tx, resp_rx) = oneshot::channel();
                        if conns_tx.send(ConnsCmd::Query(resp_tx)).await.is_ok() {
                            if let Ok(state) = resp_rx.await {
                                let event = DiagEvent::ConnsStateSnapshot {
                                    ts: Timestamp::now(),
                                    state,
                                };
                                if let Ok(frame) = encode_frame(&event) {
                                    if write_half.write_all(&frame).await.is_err() {
                                        debug!("diag: client disconnected (write conns snapshot)");
                                        return;
                                    }
                                }
                            }
                        }
                    }
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
    let (stream, _) = connect_with_identity(sock_path).await?;
    Ok(stream)
}

/// Connect to a diagnostic socket and return the server's network namespace identity.
pub async fn connect_with_identity(
    sock_path: &Path,
) -> Result<(DiagEventStream, ProtocolHandshake)> {
    let mut stream = UnixStream::connect(sock_path).await?;
    let handshake = handshake_client(&mut stream, ProtocolChannel::Diag).await?;
    Ok((DiagEventStream::from_stream(stream), handshake))
}

pub struct DiagEventStream {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl std::fmt::Debug for DiagEventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiagEventStream").finish_non_exhaustive()
    }
}

impl DiagEventStream {
    /// Construct from an already-established stream (reversed connection).
    pub fn from_stream(stream: UnixStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        DiagEventStream {
            read_half,
            write_half,
        }
    }
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
    PathBuf::from("/nsp3")
        .join(instance_name)
        .join("tun_diag.sock")
}

/// Derive the canonical `sp up` daemon socket path for a named instance.
/// `/nsp3/{name}/up.sock`
pub fn up_sock_path(instance_name: &str) -> PathBuf {
    PathBuf::from("/nsp3").join(instance_name).join("up.sock")
}

/// Derive the canonical global privileged daemon socket path.
pub fn root_daemon_sock_path() -> PathBuf {
    state_paths::persist_root().join("daemon.sock")
}

// ── Task-local diag sender + tracing layer ────────────────────────────

tokio::task_local! {
    /// When set, tracing log records are forwarded to this broadcast sender,
    /// which corresponds to the `DiagServer` for the currently-active profile.
    /// Use [`DiagServer::scope`] to install it for a given async scope.
    static TASK_DIAG: Option<broadcast::Sender<Arc<Vec<u8>>>>;
}

/// Global broadcast channel for the `sp up` daemon's log forwarding.
/// Initialised once by [`init_up_log_broadcast`] when the up daemon starts.
/// [`DiagTracingLayer`] forwards log records here whenever no per-task diag scope is active.
static UP_LOG_TX: std::sync::OnceLock<broadcast::Sender<Arc<Vec<u8>>>> = std::sync::OnceLock::new();

/// Global broadcast channel for the `sp daemon` log forwarding.
/// Initialised once by [`init_root_daemon_log_broadcast`] when the privileged daemon starts.
static ROOT_DAEMON_LOG_TX: std::sync::OnceLock<broadcast::Sender<Arc<Vec<u8>>>> =
    std::sync::OnceLock::new();

/// Global broadcast channel for the `sp serve` diag log forwarding.
/// Installed once via [`DiagServer::install_as_global`] after the diag server is created.
/// [`DiagTracingLayer`] forwards log records here (as [`DiagEvent::Log`] frames) for tasks
/// that are not running inside a [`DiagServer::scope`].
static SERVE_LOG_TX: std::sync::OnceLock<broadcast::Sender<Arc<Vec<u8>>>> =
    std::sync::OnceLock::new();

/// Child-process log forward sink used by forked helpers that cannot emit directly to UI.
///
/// When installed, [`DiagTracingLayer`] serializes each [`LogEntry`] and writes it to this
/// stream. The parent process can decode and relay those entries into the normal diag path.
static CHILD_LOG_FORWARD: OnceLock<Arc<Mutex<StdUnixStream>>> = OnceLock::new();

/// Per-process file-backed log ring state.
///
/// This mirrors the in-memory ring buffer to a JSONL file under the global persist root so the
/// last emitted breadcrumbs survive socket-path failures and abrupt process death.
static FILE_LOG_RING: OnceLock<Arc<Mutex<FileLogRingState>>> = OnceLock::new();

const FILE_LOG_COMPACT_INTERVAL: usize = 128;

struct FileLogRingState {
    path: PathBuf,
    approx_entries: usize,
    writes_since_compact: usize,
}

/// Initialise the global up-daemon log broadcast channel.
/// Safe to call multiple times; only the first call takes effect.
pub fn init_up_log_broadcast() {
    let (tx, _) = broadcast::channel(1024);
    let _ = UP_LOG_TX.set(tx);
}

/// Initialise the global root-daemon log broadcast channel.
/// Safe to call multiple times; only the first call takes effect.
pub fn init_root_daemon_log_broadcast() {
    let (tx, _) = broadcast::channel(1024);
    let _ = ROOT_DAEMON_LOG_TX.set(tx);
}

/// Install a child-process log forward stream.
///
/// Intended for forked serve children: the child writes framed [`LogEntry`] payloads to this
/// stream and the parent relays them as ordinary diag log events.
pub fn install_child_log_forward(stream: StdUnixStream) {
    let _ = CHILD_LOG_FORWARD.set(Arc::new(Mutex::new(stream)));
}

/// Enable the per-process file-backed log ring for the current process.
///
/// The sink is intentionally per-process and low-complexity: each log entry is appended to a
/// JSONL file, and the file is periodically compacted back to the in-memory ring snapshot.
pub fn enable_process_log_file(process_label: &str) -> Result<PathBuf> {
    let path = state_paths::process_log_file(process_label, std::process::id());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;

    let state = Arc::new(Mutex::new(FileLogRingState {
        path: path.clone(),
        approx_entries: 0,
        writes_since_compact: 0,
    }));

    match FILE_LOG_RING.set(state) {
        Ok(()) => Ok(path),
        Err(_) => current_process_log_path()
            .ok_or_else(|| anyhow::anyhow!("process log file sink already configured")),
    }
}

/// Return the current process file-backed log path when enabled.
pub fn current_process_log_path() -> Option<PathBuf> {
    FILE_LOG_RING
        .get()
        .and_then(|state| state.lock().ok().map(|guard| guard.path.clone()))
}

/// Subscribe to the up-daemon log broadcast, receiving pre-encoded `DaemonEvent::Log` frames.
/// Returns `None` if [`init_up_log_broadcast`] has not been called yet.
pub fn subscribe_up_logs() -> Option<broadcast::Receiver<Arc<Vec<u8>>>> {
    UP_LOG_TX.get().map(|tx| tx.subscribe())
}

/// Subscribe to the root-daemon log broadcast, receiving pre-encoded
/// [`RootDaemonWireEvent::Log`] frames.
pub fn subscribe_root_daemon_logs() -> Option<broadcast::Receiver<Arc<Vec<u8>>>> {
    ROOT_DAEMON_LOG_TX.get().map(|tx| tx.subscribe())
}

// ── In-process log ring buffer ────────────────────────────────────────

/// Maximum number of `LogEntry` items retained in the per-process ring buffer.
pub const LOG_RING_CAP: usize = 2000;

/// The per-process log ring buffer. Shared by all paths (`sp serve` and `sp up` each run in
/// their own process and therefore have their own instance).
static LOG_RING: std::sync::OnceLock<Arc<Mutex<VecDeque<LogEntry>>>> = std::sync::OnceLock::new();

fn log_ring() -> &'static Arc<Mutex<VecDeque<LogEntry>>> {
    LOG_RING.get_or_init(|| Arc::new(Mutex::new(VecDeque::with_capacity(LOG_RING_CAP))))
}

/// Append a log entry to the in-process ring buffer.
/// The oldest entry is discarded when the buffer reaches `LOG_RING_CAP`.
fn push_log_ring(entry: &LogEntry) {
    if history::is_enabled() {
        history::record_log(entry);
        return;
    }
    if let Ok(mut guard) = log_ring().lock() {
        if history::is_enabled() {
            drop(guard);
            history::record_log(entry);
            return;
        }
        if guard.len() >= LOG_RING_CAP {
            guard.pop_front();
        }
        guard.push_back(entry.clone());
    }
}

/// Query the in-process ring buffer, returning up to `limit` most-recent entries (oldest first).
///
/// Use this to serve `ControlCommand::QueryRecentLogs` / `DaemonRequest::QueryRecentLogs`.
pub fn query_recent_logs(limit: usize) -> Vec<LogEntry> {
    if let Some(entries) = history::query_recent_logs(limit) {
        if !entries.is_empty() {
            return entries;
        }
    }
    match log_ring().lock() {
        Ok(guard) if !guard.is_empty() => {
            let skip = guard.len().saturating_sub(limit);
            guard.iter().skip(skip).cloned().collect()
        }
        Ok(_) | Err(_) => query_recent_file_logs(limit),
    }
}

/// A [`tracing_subscriber::Layer`] that forwards every log record to the
/// per-task [`DiagServer`] installed via [`DiagServer::scope`].
///
/// Register once at subscriber init; it is a no-op when no task-local is set.
pub struct DiagTracingLayer;

impl<S> Layer<S> for DiagTracingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Collect the rendered message and flat structured fields from the event once.
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry {
            ts: Timestamp::now(),
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        };

        // Always push to the in-process ring buffer so clients can query history.
        push_log_ring(&entry);
        sync_file_log_ring(&entry);

        // Forked children can forward log entries to their parent, which then re-emits them
        // through the normal diag/UI path.
        if let Some(forward) = CHILD_LOG_FORWARD.get() {
            if let Ok(frame) = encode_frame(&entry) {
                if let Ok(mut stream) = forward.lock() {
                    let _ = stream.write_all(&frame);
                }
            }
            return;
        }

        // Forward to the per-task diag socket when inside a serve scope.
        let sent_to_diag = TASK_DIAG
            .try_with(|opt| {
                if let Some(tx) = opt.as_ref() {
                    if let Ok(frame) = encode_frame(&DiagEvent::Log(entry.clone())) {
                        let _ = tx.send(Arc::new(frame));
                        return true;
                    }
                }
                false
            })
            .unwrap_or(false);

        // Outside a diag scope, forward to the serve-global channel when in a serve process,
        // otherwise fall back to the root daemon or up daemon broadcast channels.
        if !sent_to_diag {
            if let Some(tx) = SERVE_LOG_TX.get() {
                if let Ok(frame) = encode_frame(&DiagEvent::Log(entry)) {
                    let _ = tx.send(Arc::new(frame));
                }
            } else if let Some(tx) = ROOT_DAEMON_LOG_TX.get() {
                if let Ok(frame) = encode_frame(&RootDaemonWireEvent::Log(entry)) {
                    let _ = tx.send(Arc::new(frame));
                }
            } else if let Some(tx) = UP_LOG_TX.get() {
                if let Ok(frame) = encode_frame(&UpWireEvent::Unstable(DaemonEvent::Log(entry))) {
                    let _ = tx.send(Arc::new(frame));
                }
            }
        }
    }
}

/// `tracing::field::Visit` impl that keeps the rendered log message plus flat fields.
#[derive(Default)]
struct LogVisitor {
    message: String,
    fields: Vec<LogField>,
}

impl LogVisitor {
    fn record_rendered(&mut self, field: &tracing::field::Field, value: String) {
        if field.name() == "message" {
            self.message = value;
            return;
        }

        self.fields.push(LogField {
            name: field.name().to_owned(),
            value,
        });
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record_rendered(field, value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_rendered(field, value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_rendered(field, value.to_string());
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.record_rendered(field, value.to_string());
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.record_rendered(field, value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_rendered(field, value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_rendered(field, value.to_owned());
    }

    fn record_bytes(&mut self, field: &tracing::field::Field, value: &[u8]) {
        self.record_rendered(field, format!("{:?}", value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.record_rendered(field, value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_rendered(field, format!("{:?}", value));
    }
}

fn append_file_log_entry(path: &Path, entry: &LogEntry) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, entry)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn snapshot_log_ring() -> Vec<LogEntry> {
    if let Some(mut entries) = history::snapshot_logs() {
        if entries.len() > LOG_RING_CAP {
            entries.drain(..entries.len() - LOG_RING_CAP);
        }
        return entries;
    }
    match log_ring().lock() {
        Ok(guard) => guard.iter().cloned().collect(),
        Err(_) => Vec::new(),
    }
}

fn rewrite_file_log_snapshot(path: &Path, snapshot: &[LogEntry]) -> Result<()> {
    let tmp_path = path.with_extension("jsonl.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        for entry in snapshot {
            serde_json::to_writer(&mut file, entry)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
    }
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn compact_file_log_ring() {
    let snapshot = snapshot_log_ring();
    if let Some(file_ring) = FILE_LOG_RING.get() {
        if let Ok(mut state) = file_ring.lock() {
            if rewrite_file_log_snapshot(&state.path, &snapshot).is_ok() {
                state.approx_entries = snapshot.len();
                state.writes_since_compact = 0;
            }
        }
    }
}

fn sync_file_log_ring(entry: &LogEntry) {
    let mut should_compact = false;

    if let Some(file_ring) = FILE_LOG_RING.get() {
        if let Ok(mut state) = file_ring.lock() {
            if append_file_log_entry(&state.path, entry).is_ok() {
                state.approx_entries = state.approx_entries.saturating_add(1);
                state.writes_since_compact = state.writes_since_compact.saturating_add(1);
                should_compact = state.approx_entries > LOG_RING_CAP
                    || state.writes_since_compact >= FILE_LOG_COMPACT_INTERVAL;
            }
        }
    }

    if should_compact {
        compact_file_log_ring();
    }
}

fn query_recent_file_logs(limit: usize) -> Vec<LogEntry> {
    let Some(path) = current_process_log_path() else {
        return vec![];
    };

    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };

    let mut entries = content
        .lines()
        .filter_map(|line| serde_json::from_str::<LogEntry>(line).ok())
        .collect::<Vec<_>>();
    let skip = entries.len().saturating_sub(limit);
    entries.drain(0..skip);
    entries
}

// ── Atomic connection-id generator ───────────────────────────────────

static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn next_conn_id() -> ConnId {
    ConnId(NEXT_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

/// Exact process spawn arguments sent over the `sp up` daemon wire protocol.
/// This struct must stay deterministic and avoid runtime inference.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SpawnArgs {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub exec: Option<String>,
    pub cwd: Option<PathBuf>,
    pub gids: Vec<u32>,
    /// args[0] should be executable name
    pub args: Vec<String>,
    /// Optional process output ring buffer limit.
    /// For PTY mode this is retained bytes; for output mode this is retained log entries.
    /// `None` means use the daemon default for that mode.
    pub ringbuf_size: Option<u32>,
    /// Configured application name when this is an on-demand Actions launch.
    #[serde(default)]
    pub application: Option<String>,
    pub ns: NamespaceSpawn,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceSpawn {
    /// The namespace of parent process of a container `sp up` daemon
    #[default]
    Outside,
    /// Inside the associated container. Enters all associated kernel namespaces.
    Inside,
    // Other namespaces are currently not supported.
}

impl SpawnArgs {
    pub fn exec_program_hint(&self) -> Option<String> {
        self.exec.clone()
    }

    pub fn shell_cwd_hint(&self) -> Option<PathBuf> {
        self.cwd.clone()
    }
}

// ── Per-process stdout/stderr capture ────────────────────────────────

/// Maximum number of raw log lines retained per managed process.
pub const RAW_LOG_RING_CAP: usize = 2000;

/// Which output stream a captured line originated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawLogKind {
    Stdout,
    Stderr,
}

/// A single line of raw stdout/stderr output from a managed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLog {
    pub ts: Timestamp,
    pub kind: RawLogKind,
    pub content: String,
}

// ── `sp up` daemon protocol (controller ↔ parent process) ───────────

/// Requests sent to the `sp up` daemon from controller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Spawn a new child process with given preferences
    Spawn {
        args: SpawnArgs,
    },
    /// Spawn `nsproxy` with a bincode-encoded `Cli` payload.
    /// The receiver should pass it via inheritable fd and invoke `sp <fd>`.
    SpawnCli {
        cli_bincode: Vec<u8>,
        ns: NamespaceSpawn,
    },
    /// Spawn a new child process connected to a PTY.
    SpawnPty {
        args: SpawnArgs,
    },
    /// Attach this client connection to PTY output stream for `task_pgid`.
    AttachPty {
        task_pgid: u32,
    },
    /// Detach this client connection from PTY output stream for `task_pgid`.
    DetachPty {
        task_pgid: u32,
    },
    /// Write raw bytes to a PTY child's stdin.
    PtyInput {
        task_pgid: u32,
        data: Vec<u8>,
    },
    /// Notify PTY resize in character cells.
    PtyResize {
        task_pgid: u32,
        cols: u16,
        rows: u16,
    },
    /// Request current process list snapshot
    GetProcessList,
    /// Kill a managed task by its process group id.
    Kill {
        task_pgid: u32,
    },
    /// Ping the daemon and expect a Pong response (useful for liveness checks)
    Ping,
    /// Ensure the profile-scoped private D-Bus daemon is running.
    EnsureDbus,
    Stop,
    /// Request the most-recent `limit` log entries from the up-daemon ring buffer.
    /// The server responds immediately with `DaemonEvent::RecentLogs`.
    QueryRecentLogs {
        limit: usize,
    },
    /// Request the most-recent `limit` raw stdout/stderr lines captured from the managed task `task_pgid`.
    /// The server responds immediately with `DaemonEvent::RawLogs`.
    QueryRawLogs {
        task_pgid: u32,
        limit: usize,
        after_seq: Option<u64>,
    },
    Personal(personal::PersonalDaemonRequest),
}

/// Stable control requests available across protocol versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StableRequest {
    /// Liveness probe independent of version-specific protocol.
    Ping,
    /// Ask the target up daemon to stop gracefully.
    GracefulShutdown,
    /// Request access to the version-specific protocol and advertise the caller build identity.
    Upgrade { build_tree_hash: String },
}

/// Up-daemon wire request envelope.
///
/// `Stable` is the long-lived control plane. `Unstable` carries version-specific
/// request payloads that are only valid after an accepted upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpWireRequest {
    Stable(StableRequest),
    Unstable(DaemonRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpawnCliKind {
    Serve,
    Dbus,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnCliType {
    pub cli_bincode: Vec<u8>,
    pub kind: SpawnCliKind,
}

/// Snapshot of all managed processes transmitted on state change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonEvent {
    /// Managed task was spawned.
    Spawned {
        task_pgid: u32,
    },
    /// Managed task exited.
    ProcessExit {
        task_pgid: u32,
    },
    /// Snapshot of all managed tasks (live and dead)
    ProcessListSnapshot(ProcessListSnapshot),
    /// Error response
    Error {
        msg: String,
    },
    /// Response to Ping
    Pong,
    /// Daemon process stopping
    Stopping,
    /// A tracing log record forwarded from the running `sp up` process.
    Log(LogEntry),
    /// Historical log entries from the up-daemon ring buffer.
    /// Sent in response to `DaemonRequest::QueryRecentLogs`.
    RecentLogs(Vec<LogEntry>),
    /// Raw stdout/stderr lines captured from a managed task.
    /// Sent in response to `DaemonRequest::QueryRawLogs`.
    RawLogs {
        task_pgid: u32,
        reset: bool,
        start_seq: u64,
        next_seq: u64,
        logs: Vec<RawLog>,
    },
    /// Raw PTY bytes for a managed PTY child.
    PtyOutput {
        task_pgid: u32,
        data: Vec<u8>,
    },
    /// Initial PTY scrollback bytes sent on successful attach.
    PtyScrollback {
        task_pgid: u32,
        data: Vec<u8>,
    },
    Personal(personal::PersonalDaemonEvent),
}

/// Stable control responses available across protocol versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StableEvent {
    Pong,
    ShuttingDown,
    /// Version-specific protocol is available; `build_tree_hash` reports the responder identity.
    UpgradeAccepted {
        build_tree_hash: String,
    },
    /// Version-specific protocol is unavailable for reasons other than a build-hash mismatch.
    UpgradeRejected {
        msg: String,
    },
    Error {
        msg: String,
    },
}

/// Up-daemon wire event envelope.
///
/// `Stable` is always available after handshake. `Unstable` carries version-specific
/// event payloads emitted after upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpWireEvent {
    Stable(StableEvent),
    Unstable(DaemonEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ProcessStatus {
    Alive,
    Terminating,
    Killed,
    #[default]
    Vacant,
}

/// Information about a spawned process (may be dead)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub meta: SpawnedEntry,
    pub spawned_at: SystemTime,
    /// Managed-task identity. Every tracked task is its own process-group leader.
    pub task_pgid: u32,
    pub status: ProcessStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpawnedEntry {
    Args(SpawnArgs),
    Cli(SpawnCliType),
    Pty(SpawnArgs),
}

/// Snapshot of the process list sent in `DaemonEvent::ProcessListSnapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListSnapshot {
    /// Managed tasks keyed by task process-group id.
    pub procs: BTreeMap<u32, ProcessEntry>,
    /// `sp serve` task pgid in `procs`
    pub serve: u32,
}

/// In-memory snapshot of all managed tasks (task pgid -> entry)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessList {
    pub processes: BTreeMap<u32, ProcessEntry>,
}

pub struct UpDaemonStream {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
}

pub struct RootDaemonStream {
    read_half: tokio::net::unix::OwnedReadHalf,
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl std::fmt::Debug for RootDaemonStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootDaemonStream").finish_non_exhaustive()
    }
}

pub struct RootDaemonReader {
    read_half: tokio::net::unix::OwnedReadHalf,
}

impl RootDaemonReader {
    pub async fn next_event(&mut self) -> Result<Option<RootDaemonEvent>> {
        match read_frame::<RootDaemonWireEvent, _>(&mut self.read_half).await? {
            Some(RootDaemonWireEvent::Unstable(event)) => Ok(Some(event)),
            Some(RootDaemonWireEvent::Stable(StableEvent::Error { msg })) => {
                bail!("root daemon stable protocol error: {}", msg)
            }
            Some(other) => bail!("unexpected root daemon wire event: {:?}", other),
            None => Ok(None),
        }
    }

    pub async fn next_wire_event(&mut self) -> Result<Option<RootDaemonWireEvent>> {
        read_frame(&mut self.read_half).await
    }
}

pub struct RootDaemonWriter {
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl RootDaemonWriter {
    pub async fn send_request(&mut self, req: &RootDaemonRequest) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::Unstable(req.clone()))?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_stable_request(&mut self, req: &StableRequest) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::Stable(req.clone()))?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_query_recent_logs(&mut self, limit: usize) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::QueryRecentLogs { limit })?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }
}

pub async fn connect_root_daemon(sock_path: &Path) -> Result<RootDaemonStream> {
    let mut stream = UnixStream::connect(sock_path).await?;
    handshake_client(&mut stream, ProtocolChannel::Daemon).await?;
    Ok(RootDaemonStream::from_stream(stream))
}

impl RootDaemonStream {
    pub fn from_stream(stream: UnixStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        RootDaemonStream {
            read_half,
            write_half,
        }
    }

    pub async fn next_event(&mut self) -> Result<Option<RootDaemonEvent>> {
        match read_frame::<RootDaemonWireEvent, _>(&mut self.read_half).await? {
            Some(RootDaemonWireEvent::Unstable(event)) => Ok(Some(event)),
            Some(RootDaemonWireEvent::Stable(StableEvent::Error { msg })) => {
                bail!("root daemon stable protocol error: {}", msg)
            }
            Some(other) => bail!("unexpected root daemon wire event: {:?}", other),
            None => Ok(None),
        }
    }

    pub async fn send_request(&mut self, req: &RootDaemonRequest) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::Unstable(req.clone()))?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    pub async fn next_wire_event(&mut self) -> Result<Option<RootDaemonWireEvent>> {
        read_frame(&mut self.read_half).await
    }

    pub async fn send_stable_request(&mut self, req: &StableRequest) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::Stable(req.clone()))?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_query_recent_logs(&mut self, limit: usize) -> Result<()> {
        let frame = encode_frame(&RootDaemonWireRequest::QueryRecentLogs { limit })?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    pub fn split(self) -> (RootDaemonReader, RootDaemonWriter) {
        (
            RootDaemonReader {
                read_half: self.read_half,
            },
            RootDaemonWriter {
                write_half: self.write_half,
            },
        )
    }
}

impl std::fmt::Debug for UpDaemonStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpDaemonStream").finish_non_exhaustive()
    }
}

pub struct UpDaemonReader {
    read_half: tokio::net::unix::OwnedReadHalf,
}

impl UpDaemonReader {
    pub async fn next_event(&mut self) -> Result<Option<UpWireEvent>> {
        read_frame(&mut self.read_half).await
    }
}

pub struct UpDaemonWriter {
    write_half: tokio::net::unix::OwnedWriteHalf,
}

impl UpDaemonWriter {
    pub async fn send_request(&mut self, req: &UpWireRequest) -> Result<()> {
        let frame = encode_frame(req)?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    /// Ergonomic helper for version-specific requests.
    pub async fn send_unstable_request(&mut self, req: &DaemonRequest) -> Result<()> {
        self.send_request(&UpWireRequest::Unstable(req.clone()))
            .await
    }

    /// Ergonomic helper for stable control requests.
    pub async fn send_stable_request(&mut self, req: &StableRequest) -> Result<()> {
        self.send_request(&UpWireRequest::Stable(req.clone())).await
    }
}

pub async fn connect_up_daemon(sock_path: &Path) -> Result<UpDaemonStream> {
    let mut stream = connect_up_daemon_stable(sock_path).await?;
    let local_hash = protocol_version().to_string();
    stream
        .send_request(&UpWireRequest::Stable(StableRequest::Upgrade {
            build_tree_hash: local_hash.clone(),
        }))
        .await?;
    match stream.next_event().await? {
        Some(UpWireEvent::Stable(StableEvent::UpgradeAccepted { build_tree_hash })) => {
            if build_tree_hash == local_hash {
                Ok(stream)
            } else if protocol_lenient() {
                warn!(
                    local_hash = %local_hash,
                    remote_hash = %build_tree_hash,
                    "continuing after up-daemon protocol version mismatch"
                );
                Ok(stream)
            } else {
                bail!(
                    "up daemon protocol version mismatch: {}",
                    protocol_mismatch_message(&local_hash, &build_tree_hash)
                )
            }
        }
        Some(UpWireEvent::Stable(StableEvent::UpgradeRejected { msg })) => {
            bail!("up daemon protocol upgrade rejected: {}", msg)
        }
        Some(UpWireEvent::Stable(StableEvent::Error { msg })) => {
            bail!("up daemon stable protocol error: {}", msg)
        }
        Some(UpWireEvent::Unstable(DaemonEvent::Error { msg })) => {
            bail!("up daemon protocol error: {}", msg)
        }
        Some(other) => bail!("unexpected upgrade response from up daemon: {:?}", other),
        None => bail!("up daemon closed during protocol upgrade"),
    }
}

/// Connect to an up daemon using only handshake + stable protocol.
pub async fn connect_up_daemon_stable(sock_path: &Path) -> Result<UpDaemonStream> {
    let mut stream = UnixStream::connect(sock_path).await?;
    handshake_client(&mut stream, ProtocolChannel::Up).await?;
    Ok(UpDaemonStream::from_stream(stream))
}

impl UpDaemonStream {
    /// Construct from an already-established stream (e.g. a reversed connection where
    /// the remote end connected to us rather than us connecting to it).
    pub fn from_stream(stream: UnixStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        UpDaemonStream {
            read_half,
            write_half,
        }
    }
}

impl UpDaemonStream {
    pub async fn next_event(&mut self) -> Result<Option<UpWireEvent>> {
        read_frame(&mut self.read_half).await
    }

    pub async fn send_request(&mut self, req: &UpWireRequest) -> Result<()> {
        let frame = encode_frame(req)?;
        self.write_half.write_all(&frame).await?;
        Ok(())
    }

    /// Ergonomic helper for version-specific requests.
    pub async fn send_unstable_request(&mut self, req: &DaemonRequest) -> Result<()> {
        self.send_request(&UpWireRequest::Unstable(req.clone()))
            .await
    }

    /// Ergonomic helper for stable control requests.
    pub async fn send_stable_request(&mut self, req: &StableRequest) -> Result<()> {
        self.send_request(&UpWireRequest::Stable(req.clone())).await
    }

    pub fn split(self) -> (UpDaemonReader, UpDaemonWriter) {
        (
            UpDaemonReader {
                read_half: self.read_half,
            },
            UpDaemonWriter {
                write_half: self.write_half,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_protocol_survives_live_updates_and_snapshots() {
        for kind in [StreamKind::Tcp, StreamKind::Udp] {
            let id = ConnId(1);
            let ts = Timestamp::now();
            let mut state = ConnsState::default();
            state.apply_event(&DiagEvent::Accept {
                id,
                ts,
                kind: kind.clone(),
                src: "127.0.0.1:50000".to_string(),
                dst: "127.0.0.1:443".to_string(),
            });
            state.apply_event(&DiagEvent::Connected { id, ts });
            assert_eq!(state.conns[&id].kind, kind);

            let snapshot = DiagEvent::ConnsStateSnapshot { ts, state };
            let encoded = bincode::serialize(&snapshot).unwrap();
            let decoded: DiagEvent = bincode::deserialize(&encoded).unwrap();
            let DiagEvent::ConnsStateSnapshot { state, .. } = decoded else {
                panic!("expected connection snapshot");
            };
            assert_eq!(state.conns[&id].kind, kind);
        }
    }

    #[test]
    fn connection_history_keeps_useful_route_and_expires_finished_entries() {
        let id = ConnId(7);
        let ts = Timestamp::now();
        let no_proxy_address: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut state = ConnsState::default();

        state.apply_event(&DiagEvent::Accept {
            id,
            ts,
            kind: StreamKind::Tcp,
            src: "127.0.0.1:50000".to_string(),
            dst: no_proxy_address.to_string(),
        });
        state.apply_event(&DiagEvent::Route {
            id,
            ts,
            route: RoutingResovled::NoProxy(no_proxy_address),
        });
        state.apply_event(&DiagEvent::AttemptFailed {
            id,
            ts,
            error: "transient route failure".to_string(),
        });
        assert_eq!(state.conns.get(&id).unwrap().finished_at, None);
        state.apply_event(&DiagEvent::Route {
            id,
            ts,
            route: RoutingResovled::Drop(nsproxy_common::routing::DropReason::MaxRetry),
        });
        assert_eq!(
            state.conns.get(&id).unwrap().phase,
            ConnPhase::RouteExhausted
        );
        state.apply_event(&DiagEvent::Finished {
            id,
            ts,
            error: Some("route dropped".to_string()),
            bytes_up: 0.0,
            bytes_down: 0.0,
        });

        let entry = state.conns.get(&id).unwrap();
        assert_eq!(entry.phase, ConnPhase::Failed);
        assert_eq!(
            entry.route,
            Some(RoutingResovled::NoProxy(no_proxy_address))
        );
        assert_eq!(entry.history.len(), 5);

        let snapshot = DiagEvent::ConnsStateSnapshot {
            ts,
            state: state.clone(),
        };
        let encoded = bincode::serialize(&snapshot).unwrap();
        let decoded: DiagEvent = bincode::deserialize(&encoded).unwrap();
        assert!(matches!(decoded, DiagEvent::ConnsStateSnapshot { .. }));

        assert_eq!(state.gc(Duration::ZERO), vec![id]);
        assert!(!state.conns.contains_key(&id));
    }

    #[test]
    fn connection_expiry_events_remove_client_rows() {
        let id = ConnId(8);
        let ts = Timestamp::now();
        let mut state = ConnsState::default();
        state.apply_event(&DiagEvent::Accept {
            id,
            ts,
            kind: StreamKind::Udp,
            src: "127.0.0.1:50000".to_string(),
            dst: "127.0.0.1:53".to_string(),
        });

        state.apply_event(&DiagEvent::ConnectionsExpired { ts, ids: vec![id] });
        assert!(!state.conns.contains_key(&id));
    }

    #[test]
    fn killed_connections_have_a_distinct_terminal_phase() {
        let id = ConnId(9);
        let ts = Timestamp::now();
        let mut state = ConnsState::default();
        state.apply_event(&DiagEvent::Accept {
            id,
            ts,
            kind: StreamKind::Tcp,
            src: "127.0.0.1:50000".to_string(),
            dst: "example.com:443".to_string(),
        });

        state.apply_event(&DiagEvent::Killed { id, ts });

        let entry = state.conns.get(&id).unwrap();
        assert_eq!(entry.phase, ConnPhase::Killed);
        assert_eq!(entry.finished_at, Some(ts));
        assert_eq!(entry.error, None);
        assert!(matches!(
            entry.history.last().map(|transition| &transition.kind),
            Some(ConnTransitionKind::Killed)
        ));
    }

    #[test]
    fn host_route_metrics_round_trip_over_the_diag_protocol() {
        let target = WireAddress::DomainAddress("packages.example".to_string(), 443);
        let event = DiagEvent::HostRouteStatsUpdated {
            ts: Timestamp::now(),
            stat: HostRouteMetric {
                key: nsproxy_common::stats::HostRouteKey::new(
                    target.clone(),
                    nsproxy_common::stats::ObservedRoute::NoProxy,
                ),
                observed_at: Timestamp::now(),
                last_observed: Some(Timestamp::now()),
                connect_latency_ms: Some(100.0),
                connect_success_rate: Some(1.0),
                upload_bytes_per_sec: Some(2_000_000.0),
                download_bytes_per_sec: Some(1_000_000.0),
                upload_rate_summary: Some(nsproxy_common::stats::TransferRateSummary {
                    average_bytes_per_sec: 2_000_000.0,
                    min_bytes_per_sec: 2_000_000.0,
                    max_bytes_per_sec: 2_000_000.0,
                    sample_count: 1,
                }),
                download_rate_summary: Some(nsproxy_common::stats::TransferRateSummary {
                    average_bytes_per_sec: 1_000_000.0,
                    min_bytes_per_sec: 1_000_000.0,
                    max_bytes_per_sec: 1_000_000.0,
                    sample_count: 1,
                }),
                upload_sample: Some(nsproxy_common::stats::TransferRateSample {
                    bytes: 2_000_000,
                    duration_micros: 1_000_000,
                    data_span_micros: 1_000_000,
                    event_count: 32,
                    observed_at: Timestamp::now(),
                }),
                download_sample: None,
                udp_upload_bytes_per_sec: Some(500_000.0),
                udp_download_bytes_per_sec: None,
                udp_upload_rate_summary: Some(nsproxy_common::stats::TransferRateSummary {
                    average_bytes_per_sec: 500_000.0,
                    min_bytes_per_sec: 500_000.0,
                    max_bytes_per_sec: 500_000.0,
                    sample_count: 1,
                }),
                udp_download_rate_summary: None,
                udp_upload_sample: Some(nsproxy_common::stats::TransferRateSample {
                    bytes: 500_000,
                    duration_micros: 1_000_000,
                    data_span_micros: 1_000_000,
                    event_count: 10,
                    observed_at: Timestamp::now(),
                }),
                udp_download_sample: None,
            },
        };

        let encoded = bincode::serialize(&event).unwrap();
        let decoded: DiagEvent = bincode::deserialize(&encoded).unwrap();
        let DiagEvent::HostRouteStatsUpdated { stat, .. } = decoded else {
            panic!("decoded the wrong event variant");
        };
        assert_eq!(stat.key.target, target);
        assert_eq!(stat.connect_latency_ms, Some(100.0));
        assert_eq!(stat.download_bytes_per_sec, Some(1_000_000.0));
        assert_eq!(stat.upload_sample.unwrap().event_count, 32);
        assert_eq!(stat.udp_upload_bytes_per_sec, Some(500_000.0));
        assert_eq!(stat.udp_upload_sample.unwrap().event_count, 10);
    }

    #[tokio::test]
    async fn connection_retention_can_be_reduced_at_runtime() {
        let (tx, mut expired_rx) = ConnsActor::spawn(Duration::from_secs(3600));
        let id = ConnId(9);
        let ts = Timestamp::now();
        tx.send(ConnsCmd::Event(DiagEvent::Accept {
            id,
            ts,
            kind: StreamKind::Tcp,
            src: "127.0.0.1:50000".to_string(),
            dst: "127.0.0.1:443".to_string(),
        }))
        .await
        .unwrap();
        tx.send(ConnsCmd::Event(DiagEvent::Finished {
            id,
            ts,
            error: None,
            bytes_up: 0.0,
            bytes_down: 0.0,
        }))
        .await
        .unwrap();

        let (response, response_rx) = oneshot::channel();
        tx.send(ConnsCmd::SetPersist {
            conn_persist: Duration::ZERO,
            response,
        })
        .await
        .unwrap();
        response_rx.await.unwrap();

        let expired = tokio::time::timeout(Duration::from_secs(1), expired_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired, vec![id]);
    }

    #[test]
    fn socks_endpoint_events_round_trip_over_bincode() {
        use std::net::SocketAddr;
        let proxy_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let effective_bnd: SocketAddr = "1.2.3.4:45240".parse().unwrap();
        let relay_local: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let state_event = DiagEvent::SocksEndpointStateChanged {
            ts: Timestamp::now(),
            op: SocksOpKind::UdpAssociate,
            proxy_addr,
            status: SocksEndpointStatus::Active {
                raw_bnd: WireAddress::SocketAddress(effective_bnd),
                effective_bnd,
                relay_local_addr: Some(relay_local),
            },
        };

        let encoded = bincode::serialize(&state_event).unwrap();
        let decoded: DiagEvent = bincode::deserialize(&encoded).unwrap();
        match decoded {
            DiagEvent::SocksEndpointStateChanged {
                op,
                proxy_addr: p,
                status:
                    SocksEndpointStatus::Active {
                        raw_bnd,
                        effective_bnd: eff,
                        relay_local_addr,
                    },
                ..
            } => {
                assert_eq!(op, SocksOpKind::UdpAssociate);
                assert_eq!(p, proxy_addr);
                assert_eq!(eff, effective_bnd);
                assert_eq!(relay_local_addr, Some(relay_local));
                assert_eq!(raw_bnd, WireAddress::SocketAddress(effective_bnd));
            }
            _ => panic!("wrong decoded event variant"),
        }

        let stats_event = DiagEvent::SocksEndpointStats {
            ts: Timestamp::now(),
            op: SocksOpKind::UdpAssociate,
            proxy_addr,
            active_flows: 3,
            pkts_tx: 10,
            pkts_rx_datagrams: 11,
            pkts_rx: 8,
            pkts_rx_source_rejected: 1,
            pkts_rx_parse_errors: 1,
            pkts_rx_unmatched: 0,
            pkts_rx_delivery_dropped: 0,
            pkts_rx_queued: 8,
            bytes_tx: 1024,
            bytes_rx: 800,
        };
        let encoded = bincode::serialize(&stats_event).unwrap();
        let decoded: DiagEvent = bincode::deserialize(&encoded).unwrap();
        match decoded {
            DiagEvent::SocksEndpointStats {
                active_flows,
                pkts_tx,
                pkts_rx_datagrams,
                pkts_rx,
                pkts_rx_parse_errors,
                ..
            } => {
                assert_eq!(active_flows, 3);
                assert_eq!(pkts_tx, 10);
                assert_eq!(pkts_rx_datagrams, 11);
                assert_eq!(pkts_rx, 8);
                assert_eq!(pkts_rx_parse_errors, 1);
            }
            _ => panic!("wrong decoded stats event variant"),
        }
    }

    #[tokio::test]
    async fn late_clients_receive_current_socks_endpoint_report() {
        let server = DiagServer::noop();
        let ts = Timestamp::now();
        let proxy_addr = "127.0.0.1:1080".parse().unwrap();
        server.emit(DiagEvent::SocksEndpointStateChanged {
            ts,
            op: SocksOpKind::UdpAssociate,
            proxy_addr,
            status: SocksEndpointStatus::Active {
                raw_bnd: WireAddress::SocketAddress("0.0.0.0:53000".parse().unwrap()),
                effective_bnd: "127.0.0.1:53000".parse().unwrap(),
                relay_local_addr: Some("0.0.0.0:41000".parse().unwrap()),
            },
        });
        server.emit(DiagEvent::SocksEndpointStats {
            ts,
            op: SocksOpKind::UdpAssociate,
            proxy_addr,
            active_flows: 2,
            pkts_tx: 3,
            pkts_rx_datagrams: 4,
            pkts_rx: 4,
            pkts_rx_source_rejected: 0,
            pkts_rx_parse_errors: 0,
            pkts_rx_unmatched: 0,
            pkts_rx_delivery_dropped: 0,
            pkts_rx_queued: 4,
            bytes_tx: 5,
            bytes_rx: 6,
        });

        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        server.add_reversed_client(server_stream);

        let first: DiagEvent = read_frame(&mut client_stream).await.unwrap().unwrap();
        let second: DiagEvent = read_frame(&mut client_stream).await.unwrap().unwrap();
        assert!(matches!(
            first,
            DiagEvent::SocksEndpointStateChanged {
                status: SocksEndpointStatus::Active { .. },
                ..
            }
        ));
        assert!(matches!(
            second,
            DiagEvent::SocksEndpointStats {
                active_flows: 2,
                bytes_rx: 6,
                ..
            }
        ));
    }
}
