//! Bounded in-memory history and the `sp serve` HTTP query endpoint.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{bail, Result};
use nsproxy_common::routing::{RoutingProtocol, RoutingResovled};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};

use crate::{log_ring, ConnId, DiagEvent, LogEntry, StreamKind, Timestamp};

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

static HISTORY: OnceLock<Mutex<History>> = OnceLock::new();
static LIVE_EVENTS: OnceLock<tokio::sync::broadcast::Sender<LiveEvent>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct VirtualIpMapping {
    pub ip: IpAddr,
    pub domain: String,
    pub valid_from: Timestamp,
    pub valid_until: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionActivity {
    pub id: ConnId,
    pub kind: Option<StreamKind>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub accepted_at: Option<Timestamp>,
    pub connected_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub error: Option<String>,
    pub bytes_up: Option<f32>,
    pub bytes_down: Option<f32>,
    pub history_incomplete: bool,
    pub events: Vec<DiagEvent>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RouteQuery {
    pub dst: IpAddr,
    pub src: IpAddr,
    pub port: u16,
    pub protocol: RoutingProtocol,
}

pub type RouteQueryFuture =
    Pin<Box<dyn Future<Output = std::result::Result<RoutingResovled, String>> + Send>>;
pub type RouteQueryHandler = Arc<dyn Fn(RouteQuery) -> RouteQueryFuture + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum LiveEvent {
    Log(LogEntry),
    Activity(DiagEvent),
    Gap,
}

#[derive(Debug)]
enum Entry {
    Log(LogEntry),
    Mapping(VirtualIpMapping),
    Activity { ts: Timestamp, event: DiagEvent },
}

impl Entry {
    fn timestamp(&self) -> Timestamp {
        match self {
            Self::Log(log) => log.ts,
            Self::Mapping(mapping) => mapping.valid_from,
            Self::Activity { ts, .. } => *ts,
        }
    }

    fn estimated_bytes(&self) -> usize {
        match self {
            Self::Log(log) => {
                std::mem::size_of::<Self>()
                    + log.target.capacity()
                    + log.level.capacity()
                    + log.message.capacity()
                    + log.fields.capacity() * std::mem::size_of::<crate::LogField>()
                    + log
                        .fields
                        .iter()
                        .map(|field| field.name.capacity() + field.value.capacity())
                        .sum::<usize>()
            }
            Self::Mapping(mapping) => std::mem::size_of::<Self>() + mapping.domain.capacity(),
            Self::Activity { event, .. } => {
                let serialized = serde_json::to_vec(event).unwrap_or_default();
                std::mem::size_of::<Self>() + serialized.len()
            }
        }
    }

    fn is_active_mapping(&self) -> bool {
        matches!(
            self,
            Self::Mapping(VirtualIpMapping {
                valid_until: None,
                ..
            })
        )
    }
}

#[derive(Debug)]
struct History {
    entries: VecDeque<Entry>,
    max_bytes: usize,
    used_bytes: usize,
    started_at: Timestamp,
    logs_started_at: Timestamp,
    mappings_started_at: Timestamp,
    activities_started_at: Timestamp,
    logs_evicted_through: Option<Timestamp>,
    mappings_evicted_through: Option<Timestamp>,
    mapping_history_incomplete_since: Option<Timestamp>,
    activities_evicted_through: Option<Timestamp>,
}

impl History {
    fn new(max_bytes: usize) -> Self {
        let started_at = Timestamp::now();
        Self {
            entries: VecDeque::new(),
            max_bytes,
            used_bytes: 0,
            started_at,
            logs_started_at: started_at,
            mappings_started_at: started_at,
            activities_started_at: started_at,
            logs_evicted_through: None,
            mappings_evicted_through: None,
            mapping_history_incomplete_since: None,
            activities_evicted_through: None,
        }
    }

    fn insert(&mut self, entry: Entry) {
        let size = entry.estimated_bytes();
        if size > self.max_bytes {
            self.note_eviction(&entry);
            return;
        }

        while self.used_bytes.saturating_add(size) > self.max_bytes {
            let Some(index) = self
                .entries
                .iter()
                .position(|existing| !existing.is_active_mapping())
                .or_else(|| (!self.entries.is_empty()).then_some(0))
            else {
                break;
            };
            let evicted = self.entries.remove(index).expect("selected history entry");
            self.used_bytes = self.used_bytes.saturating_sub(evicted.estimated_bytes());
            self.note_eviction(&evicted);
        }

        if self.used_bytes.saturating_add(size) <= self.max_bytes {
            self.used_bytes += size;
            self.entries.push_back(entry);
        } else {
            self.note_eviction(&entry);
        }
    }

    fn note_eviction(&mut self, entry: &Entry) {
        let ts = entry.timestamp();
        match entry {
            Entry::Log(_) => {
                self.logs_evicted_through = Some(
                    self.logs_evicted_through
                        .map_or(ts, |previous| previous.max(ts)),
                );
            }
            Entry::Mapping(mapping) => {
                let end = mapping.valid_until.unwrap_or(ts);
                self.mappings_evicted_through = Some(
                    self.mappings_evicted_through
                        .map_or(end, |previous| previous.max(end)),
                );
                if mapping.valid_until.is_none() {
                    self.mapping_history_incomplete_since = Some(
                        self.mapping_history_incomplete_since
                            .map_or(mapping.valid_from, |previous| {
                                previous.min(mapping.valid_from)
                            }),
                    );
                }
            }
            Entry::Activity { .. } => {
                self.activities_evicted_through = Some(
                    self.activities_evicted_through
                        .map_or(ts, |previous| previous.max(ts)),
                );
            }
        }
    }

    fn query_logs(&self, from: Timestamp, to: Timestamp) -> Result<Vec<LogEntry>, String> {
        self.query_logs_page(from, to, 0, usize::MAX)
            .map(|(logs, _)| logs)
    }

    fn query_logs_page(
        &self,
        from: Timestamp,
        to: Timestamp,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<LogEntry>, usize), String> {
        if from > to {
            return Err("`from_us` must be less than or equal to `to_us`".into());
        }
        if from < self.logs_started_at
            || self
                .logs_evicted_through
                .is_some_and(|evicted| from <= evicted)
        {
            return Err(
                "requested range is outside retained in-memory history; look up persisted files if configured"
                    .into(),
            );
        }
        let mut logs: Vec<_> = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Log(log) if from <= log.ts && log.ts <= to => Some(log),
                _ => None,
            })
            .collect();
        logs.sort_by_key(|log| log.ts);
        let total = logs.len();
        let page = logs.into_iter().skip(offset).take(limit).cloned().collect();
        Ok((page, total))
    }

    fn mapping_at(&self, ip: IpAddr, at: Timestamp) -> Result<Option<VirtualIpMapping>, String> {
        if at < self.mappings_started_at
            || self
                .mappings_evicted_through
                .is_some_and(|evicted| at < evicted)
            || self
                .mapping_history_incomplete_since
                .is_some_and(|incomplete| at >= incomplete)
        {
            return Err(
                "requested mapping is outside complete in-memory history; look up persisted files if configured"
                    .into(),
            );
        }
        Ok(self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Mapping(mapping)
                    if mapping.ip == ip
                        && mapping.valid_from <= at
                        && mapping.valid_until.is_none_or(|until| at < until) =>
                {
                    Some(mapping.clone())
                }
                _ => None,
            })
            .max_by_key(|mapping| mapping.valid_from))
    }

    fn connections(
        &self,
        age_seconds: u64,
        ip_filter: Option<IpAddr>,
    ) -> (Vec<ConnectionActivity>, Timestamp, bool) {
        let cutoff = Timestamp(
            Timestamp::now()
                .0
                .saturating_sub(age_seconds.saturating_mul(1_000_000)),
        );
        let available_from = Timestamp(
            self.activities_evicted_through.map_or(
                self.activities_started_at.0,
                |evicted| evicted.0.saturating_add(1).max(self.activities_started_at.0),
            ),
        );
        let history_partial = cutoff < available_from;

        let mut connections = BTreeMap::<ConnId, ConnectionActivity>::new();
        for entry in &self.entries {
            let Entry::Activity { ts, event } = entry else {
                continue;
            };
            let Some(id) = connection_id(event) else {
                continue;
            };
            let connection = connections.entry(id).or_insert_with(|| ConnectionActivity {
                id,
                kind: None,
                src: None,
                dst: None,
                accepted_at: None,
                connected_at: None,
                finished_at: None,
                error: None,
                bytes_up: None,
                bytes_down: None,
                history_incomplete: false,
                events: Vec::new(),
            });
            match event {
                DiagEvent::Accept {
                    kind, src, dst, ts, ..
                } => {
                    connection.kind = Some(kind.clone());
                    connection.src = Some(src.clone());
                    connection.dst = Some(dst.clone());
                    connection.accepted_at = Some(*ts);
                }
                DiagEvent::Connected { ts, .. } => connection.connected_at = Some(*ts),
                DiagEvent::Finished {
                    ts,
                    error,
                    bytes_up,
                    bytes_down,
                    ..
                } => {
                    connection.finished_at = Some(*ts);
                    connection.error = error.clone();
                    connection.bytes_up = Some(*bytes_up);
                    connection.bytes_down = Some(*bytes_down);
                }
                _ => {}
            }
            connection.events.push(event.clone());
            let _ = ts;
        }

        let mut result: Vec<_> = connections
            .into_values()
            .filter(|connection| {
                connection
                    .finished_at
                    .is_none_or(|finished| finished >= cutoff)
            })
            .filter(|connection| {
                ip_filter.is_none_or(|ip| {
                    let needle = ip.to_string();
                    connection
                        .src
                        .as_ref()
                        .is_some_and(|value| value.contains(&needle))
                        || connection
                            .dst
                            .as_ref()
                            .is_some_and(|value| value.contains(&needle))
                        || serde_json::to_string(&connection.events)
                            .is_ok_and(|value| value.contains(&needle))
                })
            })
            .collect();
        for connection in &mut result {
            connection.history_incomplete = connection.accepted_at.is_none();
            connection.events.sort_by_key(event_timestamp);
        }
        result.sort_by_key(|connection| {
            connection
                .finished_at
                .or(connection.connected_at)
                .or(connection.accepted_at)
        });
        (result, available_from, history_partial)
    }
}

fn event_timestamp(event: &DiagEvent) -> Timestamp {
    match event {
        DiagEvent::Accept { ts, .. }
        | DiagEvent::Route { ts, .. }
        | DiagEvent::Connected { ts, .. }
        | DiagEvent::Finished { ts, .. }
        | DiagEvent::DnsResolved { ts, .. }
        | DiagEvent::DnsQuery { ts, .. }
        | DiagEvent::Wait { ts, .. }
        | DiagEvent::WaitEnded { ts, .. } => *ts,
        DiagEvent::Dispatched { .. } => Timestamp::now(),
        _ => Timestamp::now(),
    }
}

fn connection_id(event: &DiagEvent) -> Option<ConnId> {
    match event {
        DiagEvent::Accept { id, .. }
        | DiagEvent::Dispatched { id, .. }
        | DiagEvent::Route { id, .. }
        | DiagEvent::Connected { id, .. }
        | DiagEvent::Finished { id, .. }
        | DiagEvent::DnsResolved { id, .. }
        | DiagEvent::DnsQuery { id, .. }
        | DiagEvent::Wait { id, .. }
        | DiagEvent::WaitEnded { id, .. } => Some(*id),
        _ => None,
    }
}

fn history() -> Option<&'static Mutex<History>> {
    HISTORY.get()
}

/// Enable serve history with one shared byte budget for logs and IP mappings.
pub fn init(max_bytes: usize) -> Result<()> {
    if max_bytes < 1024 {
        bail!("history storage limit must be at least 1024 bytes");
    }
    let (live_tx, _) = tokio::sync::broadcast::channel(4096);
    let _ = LIVE_EVENTS.set(live_tx);
    let mut legacy_logs = log_ring()
        .lock()
        .map_err(|_| anyhow::anyhow!("log ring lock poisoned while enabling history"))?;
    let initial_logs = legacy_logs.iter().cloned().collect::<Vec<_>>();
    let store = HISTORY.get_or_init(|| {
        let mut history = History::new(max_bytes);
        if let Some(first) = initial_logs.first() {
            history.logs_started_at = first.ts;
        }
        for log in &initial_logs {
            history.insert(Entry::Log(log.clone()));
        }
        Mutex::new(history)
    });
    legacy_logs.clear();
    drop(legacy_logs);
    let mut store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("history store lock poisoned"))?;
    store.max_bytes = max_bytes;
    while store.used_bytes > max_bytes {
        let Some(index) = store
            .entries
            .iter()
            .position(|entry| !entry.is_active_mapping())
            .or_else(|| (!store.entries.is_empty()).then_some(0))
        else {
            break;
        };
        let entry = store.entries.remove(index).expect("selected history entry");
        store.used_bytes = store.used_bytes.saturating_sub(entry.estimated_bytes());
        store.note_eviction(&entry);
    }
    Ok(())
}

pub(crate) fn record_log(entry: &LogEntry) {
    if let Some(store) = history() {
        match store.lock() {
            Ok(mut store) => store.insert(Entry::Log(entry.clone())),
            Err(_) => tracing::error!("history store lock poisoned while recording log"),
        }
        if let Some(tx) = LIVE_EVENTS.get() {
            let _ = tx.send(LiveEvent::Log(entry.clone()));
        }
    }
}

pub(crate) fn record_diag_event(event: &DiagEvent) {
    if connection_id(event).is_none() {
        return;
    }
    let Some(store) = history() else {
        return;
    };
    let ts = event_timestamp(event);
    match store.lock() {
        Ok(mut store) => store.insert(Entry::Activity {
            ts,
            event: event.clone(),
        }),
        Err(_) => tracing::error!("history store lock poisoned while recording activity"),
    }
    if let Some(tx) = LIVE_EVENTS.get() {
        let _ = tx.send(LiveEvent::Activity(event.clone()));
    }
}

fn subscribe_live_events() -> Option<tokio::sync::broadcast::Receiver<LiveEvent>> {
    LIVE_EVENTS.get().map(|tx| tx.subscribe())
}

pub(crate) fn is_enabled() -> bool {
    HISTORY.get().is_some()
}

pub(crate) fn query_recent_logs(limit: usize) -> Option<Vec<LogEntry>> {
    let store = history()?.lock().ok()?;
    Some(
        store
            .entries
            .iter()
            .rev()
            .filter_map(|entry| match entry {
                Entry::Log(log) => Some(log.clone()),
                Entry::Mapping(_) | Entry::Activity { .. } => None,
            })
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
    )
}

pub(crate) fn snapshot_logs() -> Option<Vec<LogEntry>> {
    let store = history()?.lock().ok()?;
    Some(
        store
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Log(log) => Some(log.clone()),
                Entry::Mapping(_) | Entry::Activity { .. } => None,
            })
            .collect(),
    )
}

/// Record the beginning of a virtual-IP mapping's lifetime.
pub fn record_mapping_start(ip: IpAddr, domain: &str, at: Timestamp) {
    let Some(store) = history() else {
        return;
    };
    match store.lock() {
        Ok(mut store) => {
            let sizes = store
                .entries
                .iter_mut()
                .rev()
                .find_map(|entry| match entry {
                    Entry::Mapping(mapping)
                        if mapping.ip == ip && mapping.valid_until.is_none() =>
                    {
                        let old_size = Entry::Mapping(mapping.clone()).estimated_bytes();
                        mapping.valid_until = Some(at);
                        Some((old_size, Entry::Mapping(mapping.clone()).estimated_bytes()))
                    }
                    _ => None,
                });
            if let Some((old_size, new_size)) = sizes {
                store.used_bytes = store
                    .used_bytes
                    .saturating_sub(old_size)
                    .saturating_add(new_size);
            }
            store.insert(Entry::Mapping(VirtualIpMapping {
                ip,
                domain: domain.to_owned(),
                valid_from: at,
                valid_until: None,
            }));
        }
        Err(_) => tracing::error!("history store lock poisoned while recording mapping start"),
    }
}

/// Record the end of the current virtual-IP mapping lifetime.
pub fn record_mapping_end(ip: IpAddr, domain: &str, at: Timestamp) {
    let Some(store) = history() else {
        return;
    };
    match store.lock() {
        Ok(mut store) => {
            if let Some((old_size, new_size)) =
                store
                    .entries
                    .iter_mut()
                    .rev()
                    .find_map(|entry| match entry {
                        Entry::Mapping(mapping)
                            if mapping.ip == ip
                                && mapping.domain == domain
                                && mapping.valid_until.is_none() =>
                        {
                            let old_size = Entry::Mapping(mapping.clone()).estimated_bytes();
                            mapping.valid_until = Some(at);
                            let new_size = Entry::Mapping(mapping.clone()).estimated_bytes();
                            Some((old_size, new_size))
                        }
                        _ => None,
                    })
            {
                store.used_bytes = store
                    .used_bytes
                    .saturating_sub(old_size)
                    .saturating_add(new_size);
                while store.used_bytes > store.max_bytes {
                    let Some(index) = store
                        .entries
                        .iter()
                        .position(|entry| !entry.is_active_mapping())
                    else {
                        break;
                    };
                    let entry = store.entries.remove(index).expect("selected history entry");
                    store.used_bytes = store.used_bytes.saturating_sub(entry.estimated_bytes());
                    store.note_eviction(&entry);
                }
            }
        }
        Err(_) => tracing::error!("history store lock poisoned while recording mapping end"),
    }
}

fn query_logs_page(
    from: Timestamp,
    to: Timestamp,
    offset: usize,
    limit: usize,
) -> Result<(Vec<LogEntry>, usize), String> {
    let Some(store) = history() else {
        return Err("in-memory history is not enabled for this serve process".into());
    };
    let store = store
        .lock()
        .map_err(|_| "in-memory history is temporarily unavailable".to_owned())?;
    store.query_logs_page(from, to, offset, limit)
}

fn query_mapping(ip: IpAddr, at: Timestamp) -> Result<Option<VirtualIpMapping>, String> {
    let Some(store) = history() else {
        return Err("in-memory history is not enabled for this serve process".into());
    };
    let store = store
        .lock()
        .map_err(|_| "in-memory history is temporarily unavailable".to_owned())?;
    store.mapping_at(ip, at)
}

fn query_connections(
    age_seconds: u64,
    ip_filter: Option<IpAddr>,
) -> Result<ConnectionsResponse, String> {
    let Some(store) = history() else {
        return Err("in-memory history is not enabled for this serve process".into());
    };
    let store = store
        .lock()
        .map_err(|_| "in-memory history is temporarily unavailable".to_owned())?;
    let (connections, available_from, history_partial) =
        store.connections(age_seconds, ip_filter);
    Ok(ConnectionsResponse {
        connections,
        available_from,
        requested_age_seconds: age_seconds,
        history_partial,
    })
}

#[derive(Serialize)]
struct ConnectionsResponse {
    connections: Vec<ConnectionActivity>,
    available_from: Timestamp,
    requested_age_seconds: u64,
    history_partial: bool,
}

#[derive(Serialize)]
struct HistoryStatus {
    started_at: Timestamp,
    log_oldest_available: Timestamp,
    mapping_oldest_available: Timestamp,
    activity_oldest_available: Timestamp,
    used_bytes: usize,
    max_bytes: usize,
    log_count: usize,
    mapping_count: usize,
    activity_event_count: usize,
}

fn history_status() -> Result<HistoryStatus, String> {
    let Some(store) = history() else {
        return Err("in-memory history is not enabled for this serve process".into());
    };
    let store = store
        .lock()
        .map_err(|_| "in-memory history is temporarily unavailable".to_owned())?;
    let mut status = HistoryStatus {
        started_at: store.started_at,
        log_oldest_available: Timestamp(
            store.logs_evicted_through.map_or(store.logs_started_at.0, |ts| {
                ts.0.saturating_add(1).max(store.logs_started_at.0)
            }),
        ),
        mapping_oldest_available: Timestamp(
            store.mappings_evicted_through.map_or(store.mappings_started_at.0, |ts| {
                ts.0.saturating_add(1).max(store.mappings_started_at.0)
            }),
        ),
        activity_oldest_available: Timestamp(
            store.activities_evicted_through.map_or(store.activities_started_at.0, |ts| {
                ts.0.saturating_add(1).max(store.activities_started_at.0)
            }),
        ),
        used_bytes: store.used_bytes,
        max_bytes: store.max_bytes,
        log_count: 0,
        mapping_count: 0,
        activity_event_count: 0,
    };
    for entry in &store.entries {
        match entry {
            Entry::Log(_) => status.log_count += 1,
            Entry::Mapping(_) => status.mapping_count += 1,
            Entry::Activity { .. } => status.activity_event_count += 1,
        }
    }
    Ok(status)
}

#[derive(Serialize)]
struct LogsResponse {
    logs: Vec<LogEntry>,
    total: usize,
    offset: usize,
    limit: usize,
}

#[derive(Serialize)]
struct MappingResponse {
    mapping: VirtualIpMapping,
}

#[derive(Serialize)]
struct RouteQueryResponse {
    query: RouteQuery,
    route: RoutingResovled,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

/// Start the HTTP/JSON history server on the address configured for `sp serve`.
pub async fn start_server(
    listener: std::net::TcpListener,
    route_query_handler: RouteQueryHandler,
) -> Result<()> {
    let listener = TcpListener::from_std(listener)?;
    let bound_addr = listener.local_addr()?;
    tracing::info!(%bound_addr, "history query HTTP endpoint listening");
    let clients = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let Ok(permit) = clients.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "history query connection limit reached");
                        drop(stream);
                        continue;
                    };
                    let route_query_handler = route_query_handler.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_client(stream, route_query_handler).await {
                            tracing::debug!(%peer, %error, "history query client failed");
                        }
                    });
                }
                Err(error) => tracing::error!(%error, "history query listener accept failed"),
            }
        }
    });
    Ok(())
}

async fn handle_client(
    mut stream: TcpStream,
    route_query_handler: RouteQueryHandler,
) -> Result<()> {
    let request = timeout(REQUEST_TIMEOUT, read_request(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("HTTP request timed out"))??;
    if request_method(&request) != Some("GET") {
        let (status, body) = json_error(405, "only GET is supported");
        return write_http_response(
            &mut stream,
            status,
            "Method Not Allowed",
            "application/json",
            &body,
        )
        .await;
    }
    let path = request_path(&request);
    if path == Some("/v1/stream") {
        return stream_live_events(stream).await;
    }
    if let Some((content_type, body)) = static_asset(path, WEB_ASSETS, WEB_UI_BUNDLED) {
        return write_http_response(&mut stream, 200, "OK", content_type, body).await;
    }
    let (status, body) = route_request(&request, Some(&route_query_handler)).await;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write_http_response(&mut stream, status, reason, "application/json", &body).await
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

fn static_asset<'a>(
    path: Option<&str>,
    assets: &'a [(&'static str, &'static [u8])],
    web_ui_bundled: bool,
) -> Option<(&'static str, &'a [u8])> {
    let path = path?;
    if path.starts_with("/v1/") {
        return None;
    }
    if !web_ui_bundled && !matches!(path, "/" | "/index.html") {
        return None;
    }
    let asset_path = match path {
        "/" | "/index.html" => "index.html",
        path if path.starts_with("/assets/") => &path[1..],
        _ => "index.html",
    };
    let (_, bytes) = assets.iter().find(|(name, _)| *name == asset_path)?;
    let content_type = match asset_path.rsplit('.').next().unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((content_type, bytes))
}

async fn stream_live_events(mut stream: TcpStream) -> Result<()> {
    let Some(mut events) = subscribe_live_events() else {
        let (status, body) = json_error(503, "live event stream is not enabled");
        let response = format!(
            "HTTP/1.1 {status} Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        return Ok(());
    };
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
        )
        .await?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            event = events.recv() => {
                let event = match event {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => LiveEvent::Gap,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let payload = serde_json::to_string(&event)?;
                stream.write_all(b"data: ").await?;
                stream.write_all(payload.as_bytes()).await?;
                stream.write_all(b"\n\n").await?;
                stream.flush().await?;
            }
            _ = heartbeat.tick() => {
                stream.write_all(b": keep-alive\n\n").await?;
                stream.flush().await?;
            }
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<String> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("client closed before sending HTTP headers");
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > MAX_REQUEST_BYTES {
            bail!("HTTP headers exceed size limit");
        }
    }
    String::from_utf8(request).map_err(Into::into)
}

async fn route_request(
    request: &str,
    route_query_handler: Option<&RouteQueryHandler>,
) -> (u16, Vec<u8>) {
    let Some(line) = request.lines().next() else {
        return json_error(400, "missing HTTP request line");
    };
    let mut parts = line.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return json_error(400, "malformed HTTP request line");
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return json_error(400, "unsupported HTTP version");
    }
    if method != "GET" {
        return json_error(405, "only GET is supported");
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = parse_query(query);
    match path {
        "/v1/history" => match history_status() {
            Ok(status) => json_response(200, &status),
            Err(error) => json_error(503, &error),
        },
        "/v1/logs" => {
            let Some(from) = params.get("from_us").and_then(|value| value.parse().ok()) else {
                return json_error(400, "missing or invalid `from_us` timestamp");
            };
            let Some(to) = params.get("to_us").and_then(|value| value.parse().ok()) else {
                return json_error(400, "missing or invalid `to_us` timestamp");
            };
            let limit = match params
                .get("limit")
                .map(|value| value.parse::<usize>())
                .transpose()
            {
                Ok(Some(limit)) if (1..=5000).contains(&limit) => limit,
                Ok(None) => 1000,
                Ok(Some(_)) => return json_error(400, "`limit` must be between 1 and 5000"),
                Err(_) => return json_error(400, "invalid `limit`"),
            };
            let offset = match params
                .get("offset")
                .map(|value| value.parse::<usize>())
                .transpose()
            {
                Ok(Some(offset)) => offset,
                Ok(None) => 0,
                Err(_) => return json_error(400, "invalid `offset`"),
            };
            match query_logs_page(Timestamp(from), Timestamp(to), offset, limit) {
                Ok((logs, total)) => json_response(
                    200,
                    &LogsResponse {
                        logs,
                        total,
                        offset,
                        limit,
                    },
                ),
                Err(error) if error.starts_with("`from_us`") => json_error(400, &error),
                Err(error) => json_error(410, &error),
            }
        }
        "/v1/connections" => {
            let age_seconds = match params
                .get("age_seconds")
                .map(|value| value.parse::<u64>())
                .transpose()
            {
                Ok(Some(age)) => age,
                Ok(None) => 60,
                Err(_) => return json_error(400, "invalid `age_seconds`"),
            };
            let ip = match params.get("ip") {
                Some(value) => match value.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => return json_error(400, "invalid `ip` address"),
                },
                None => None,
            };
            match query_connections(age_seconds, ip) {
                Ok(connections) => json_response(200, &connections),
                Err(error) => json_error(410, &error),
            }
        }
        "/v1/route" => {
            let query = match parse_route_query(&params) {
                Ok(query) => query,
                Err(error) => return json_error(400, &error),
            };
            let Some(handler) = route_query_handler else {
                return json_error(503, "router route-query API is unavailable");
            };
            match handler(query).await {
                Ok(route) => json_response(200, &RouteQueryResponse { query, route }),
                Err(error) => json_error(500, &format!("route lookup failed: {error}")),
            }
        }
        _ if path.starts_with("/v1/virtual-ips/") => {
            let ip = match path["/v1/virtual-ips/".len()..].parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return json_error(400, "invalid IP address"),
            };
            let Some(at) = params.get("at_us").and_then(|value| value.parse().ok()) else {
                return json_error(400, "missing or invalid `at_us` timestamp");
            };
            match query_mapping(ip, Timestamp(at)) {
                Ok(Some(mapping)) => json_response(200, &MappingResponse { mapping }),
                Ok(None) => json_error(404, "no virtual-IP mapping at that timestamp"),
                Err(error) => json_error(410, &error),
            }
        }
        _ => json_error(404, "unknown endpoint"),
    }
}

fn parse_route_query(
    params: &std::collections::HashMap<&str, &str>,
) -> std::result::Result<RouteQuery, String> {
    let dst = params
        .get("dst")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "missing or invalid `dst` IP address".to_owned())?;
    let src = params
        .get("src")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "missing or invalid `src` IP address".to_owned())?;
    let port = params
        .get("port")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| "missing or invalid `port` (must be 1-65535)".to_owned())?;
    let protocol = match params.get("protocol").copied() {
        Some("tcp") => RoutingProtocol::Tcp,
        Some("udp") => RoutingProtocol::Udp,
        Some(_) => return Err("`protocol` must be `tcp` or `udp`".to_owned()),
        None => return Err("missing `protocol` (`tcp` or `udp`)".to_owned()),
    };

    Ok(RouteQuery {
        dst,
        src,
        port,
        protocol,
    })
}

fn request_path(request: &str) -> Option<&str> {
    let line = request.lines().next()?;
    let mut parts = line.split_ascii_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    Some(target.split_once('?').map_or(target, |(path, _)| path))
}

fn request_method(request: &str) -> Option<&str> {
    request.lines().next()?.split_ascii_whitespace().next()
}

fn parse_query(query: &str) -> std::collections::HashMap<&str, &str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect()
}

fn json_response<T: Serialize>(status: u16, response: &T) -> (u16, Vec<u8>) {
    match serde_json::to_vec(response) {
        Ok(body) => (status, body),
        Err(error) => json_error(500, &format!("failed to serialize response: {error}")),
    }
}

fn json_error(status: u16, message: &str) -> (u16, Vec<u8>) {
    let message = message.to_owned();
    let response = ErrorResponse { error: &message };
    match serde_json::to_vec(&response) {
        Ok(body) => (status, body),
        Err(_) => (status, b"{\"error\":\"request failed\"}".to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log(ts: u64, message: &str) -> LogEntry {
        LogEntry {
            ts: Timestamp(ts),
            level: "INFO".into(),
            target: "test".into(),
            message: message.into(),
            fields: vec![],
        }
    }

    #[test]
    fn time_range_returns_inclusive_matches() {
        let mut history = History::new(1024 * 1024);
        history.logs_started_at = Timestamp(0);
        history.insert(Entry::Log(test_log(10, "before")));
        history.insert(Entry::Log(test_log(30, "after")));
        history.insert(Entry::Log(test_log(20, "match")));
        let (logs, total) = history
            .query_logs_page(Timestamp(10), Timestamp(30), 1, 1)
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "match");
    }

    #[test]
    fn memory_budget_evicts_old_entries_and_reports_gaps() {
        let mut history = History::new(256);
        history.logs_started_at = Timestamp(0);
        history.insert(Entry::Log(test_log(10, &"x".repeat(256))));
        history.insert(Entry::Log(test_log(30, "after")));
        assert!(history.used_bytes <= history.max_bytes);
        assert!(history.query_logs(Timestamp(10), Timestamp(30)).is_err());
    }

    #[test]
    fn mapping_lookup_respects_lifetime_boundaries() {
        let ip = "198.18.0.5".parse().unwrap();
        let mut history = History::new(1024 * 1024);
        history.mappings_started_at = Timestamp(0);
        history.insert(Entry::Mapping(VirtualIpMapping {
            ip,
            domain: "old.example".into(),
            valid_from: Timestamp(10),
            valid_until: Some(Timestamp(20)),
        }));
        history.insert(Entry::Mapping(VirtualIpMapping {
            ip,
            domain: "new.example".into(),
            valid_from: Timestamp(20),
            valid_until: None,
        }));
        assert_eq!(
            history
                .mapping_at(ip, Timestamp(19))
                .unwrap()
                .unwrap()
                .domain,
            "old.example"
        );
        assert_eq!(
            history
                .mapping_at(ip, Timestamp(20))
                .unwrap()
                .unwrap()
                .domain,
            "new.example"
        );
        assert_eq!(
            history
                .mapping_at(ip, Timestamp(30))
                .unwrap()
                .unwrap()
                .domain,
            "new.example"
        );
    }

    #[test]
    fn connection_activity_includes_live_and_recent_closed_flows() {
        let now = Timestamp::now();
        let ip = "198.18.0.5".parse().unwrap();
        let id = ConnId(7);
        let mut history = History::new(1024 * 1024);
        history.activities_started_at = Timestamp(0);
        history.insert(Entry::Activity {
            ts: now,
            event: DiagEvent::Accept {
                id,
                ts: now,
                kind: StreamKind::Udp,
                src: "198.18.0.2:1234".into(),
                dst: "198.18.0.5:53".into(),
            },
        });
        history.insert(Entry::Activity {
            ts: now,
            event: DiagEvent::Finished {
                id,
                ts: now,
                error: None,
                bytes_up: 12.0,
                bytes_down: 34.0,
            },
        });

        let (result, available_from, history_partial) = history.connections(60, Some(ip));
        assert_eq!(available_from, Timestamp(0));
        assert!(!history_partial);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, Some(StreamKind::Udp));
        assert_eq!(result[0].finished_at, Some(now));
        assert_eq!(result[0].events.len(), 2);
    }

    #[test]
    fn each_history_kind_reports_its_own_coverage_start() {
        let history = History::new(1024);
        let before_start = Timestamp(history.started_at.0.saturating_sub(1));

        assert!(history.query_logs(before_start, before_start).is_err());
        assert!(history.mapping_at(
            "198.18.0.5".parse().unwrap(),
            before_start
        ).is_err());

        let (_, available_from, partial) = history.connections(60, None);
        assert_eq!(available_from, history.activities_started_at);
        assert!(partial);
    }

    #[tokio::test]
    async fn route_requires_explicit_timestamp_range() {
        let (status, body) = route_request(
            "GET /v1/logs HTTP/1.1\r\nHost: localhost\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 400);
        assert!(String::from_utf8(body).unwrap().contains("from_us"));
    }

    #[test]
    fn parses_router_route_query_context() {
        let params = [
            ("dst", "198.18.0.23"),
            ("src", "198.18.0.1"),
            ("port", "123"),
            ("protocol", "udp"),
        ]
        .into_iter()
        .collect();
        let query = parse_route_query(&params).unwrap();

        assert_eq!(query.dst, "198.18.0.23".parse::<IpAddr>().unwrap());
        assert_eq!(query.src, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(query.port, 123);
        assert_eq!(query.protocol, RoutingProtocol::Udp);
    }

    #[test]
    fn router_route_query_requires_source_and_protocol_fields() {
        let params = [("dst", "198.18.0.23"), ("port", "123")]
            .into_iter()
            .collect();

        assert!(parse_route_query(&params).is_err());
    }

    #[tokio::test]
    async fn route_endpoint_returns_the_router_decision() {
        let handler: RouteQueryHandler = Arc::new(|query| {
            Box::pin(async move {
                Ok(RoutingResovled::Direct(SocketAddr::new(query.dst, query.port)))
            }) as RouteQueryFuture
        });
        let request = "GET /v1/route?dst=192.0.2.8&src=192.0.2.1&port=123&protocol=udp HTTP/1.1\r\nHost: localhost\r\n\r\n";

        assert!(static_asset(Some("/v1/route"), &[], false).is_none());
        let (status, body) = route_request(request, Some(&handler)).await;
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, 200);
        assert_eq!(response["query"]["port"], 123);
        assert!(response["route"].get("Direct").is_some());
    }

    #[test]
    fn missing_web_ui_serves_instructions_but_not_missing_assets() {
        let instructions = b"Enable the web console in the build script.";
        let fallback = [("index.html", instructions.as_slice())];

        assert_eq!(
            static_asset(Some("/"), &fallback, false).unwrap().1,
            instructions
        );
        assert_eq!(
            static_asset(Some("/index.html"), &fallback, false)
                .unwrap()
                .1,
            instructions
        );
        assert!(static_asset(Some("/assets/app.js"), &fallback, false).is_none());
    }

    #[test]
    fn bundled_web_ui_keeps_spa_fallback_behavior() {
        let index = b"app";
        let assets = [("index.html", index.as_slice())];

        assert_eq!(
            static_asset(Some("/client-route"), &assets, true).unwrap().1,
            index
        );
    }
}
