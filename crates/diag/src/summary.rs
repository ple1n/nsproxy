use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use crate::{ConnId, DiagEvent, Timestamp};

#[derive(Debug, Clone)]
pub struct ConnStats {
    pub id: ConnId,
    pub kind: String,
    pub src: String,
    pub dst: String,
    pub route: String,
    pub accept_ts: Timestamp,
    pub dispatch_us: u64,
    pub connected_ts: Option<Timestamp>,
    pub finished_ts: Option<Timestamp>,
    pub error: Option<String>,
    pub bytes_up: f32,
    pub bytes_down: f32,
    pub dns_query: Option<String>,
    pub dns_response: Option<String>,
    pub dns_resolved_ts: Option<Timestamp>,
}

impl ConnStats {
    pub fn connect_latency(&self) -> Option<Duration> {
        self.connected_ts
            .map(|c| c.elapsed_since(self.accept_ts))
    }

    pub fn total_duration(&self) -> Option<Duration> {
        self.finished_ts
            .map(|f| f.elapsed_since(self.accept_ts))
    }

    pub fn dns_resolve_latency(&self) -> Option<Duration> {
        self.dns_resolved_ts
            .map(|r| r.elapsed_since(self.accept_ts))
    }

    pub fn is_dns(&self) -> bool {
        self.dns_query.is_some()
    }
}

#[derive(Debug, Default)]
pub struct LoopStats {
    pub recent: VecDeque<u64>,
    pub max_window: usize,
}

impl LoopStats {
    pub fn new(window: usize) -> Self {
        Self {
            recent: VecDeque::with_capacity(window),
            max_window: window,
        }
    }

    pub fn push(&mut self, accept_us: u64) {
        if self.recent.len() >= self.max_window {
            self.recent.pop_front();
        }
        self.recent.push_back(accept_us);
    }

    pub fn avg_us(&self) -> f64 {
        if self.recent.is_empty() {
            return 0.0;
        }
        self.recent.iter().sum::<u64>() as f64 / self.recent.len() as f64
    }

    pub fn max_us(&self) -> u64 {
        self.recent.iter().copied().max().unwrap_or(0)
    }

    pub fn min_us(&self) -> u64 {
        self.recent.iter().copied().min().unwrap_or(0)
    }
}

pub fn format_duration_us(us: f64) -> String {
    let secs = us / 1_000_000.0;
    if us < 1_000.0 {
        format!("{:.0}µs", us)
    } else if us < 1_000_000.0 {
        format!("{:.1}ms", us / 1_000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        let m = (secs / 60.0).floor();
        let s = secs - m * 60.0;
        format!("{:.0}m{:.0}s", m, s)
    } else {
        let h = (secs / 3600.0).floor();
        let rem = secs - h * 3600.0;
        let m = (rem / 60.0).floor();
        format!("{:.0}h{:.0}m", h, m)
    }
}

#[derive(Debug, Default)]
pub struct DiagAccumulator {
    pub conns: HashMap<ConnId, ConnStats>,
    pub conn_order: VecDeque<ConnId>,
    pub loop_stats: LoopStats,
    pub max_conns: usize,
}

impl DiagAccumulator {
    pub fn new(max_conns: usize, loop_window: usize) -> Self {
        Self {
            conns: HashMap::new(),
            conn_order: VecDeque::new(),
            loop_stats: LoopStats::new(loop_window),
            max_conns,
        }
    }

    pub fn ingest(&mut self, event: &DiagEvent) {
        match event {
            DiagEvent::Accept { id, ts, kind, src, dst } => {
                let stats = ConnStats {
                    id: *id,
                    kind: format!("{:?}", kind),
                    src: src.clone(),
                    dst: dst.clone(),
                    route: String::new(),
                    accept_ts: *ts,
                    dispatch_us: 0,
                    connected_ts: None,
                    finished_ts: None,
                    error: None,
                    bytes_up: 0.0,
                    bytes_down: 0.0,
                    dns_query: None,
                    dns_response: None,
                    dns_resolved_ts: None,
                };
                self.conns.insert(*id, stats);
                self.conn_order.push_back(*id);
                // Prune oldest
                while self.conn_order.len() > self.max_conns {
                    if let Some(old) = self.conn_order.pop_front() {
                        self.conns.remove(&old);
                    }
                }
            }
            DiagEvent::Route { id, route, .. } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.route = format!("{:?}", route);
                }
            }
            DiagEvent::Connected { id, ts } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.connected_ts = Some(*ts);
                }
            }
            DiagEvent::Finished { id, ts, error, bytes_up, bytes_down } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.finished_ts = Some(*ts);
                    c.error = error.clone();
                    c.bytes_up = *bytes_up;
                    c.bytes_down = *bytes_down;
                }
            }
            DiagEvent::Dispatched { id, dispatch_us } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.dispatch_us = *dispatch_us;
                }
                self.loop_stats.push(*dispatch_us);
            }
            DiagEvent::DnsResolved { id, ts, domain, result, .. } => {
                if let Some(c) = self.conns.get_mut(id) {
                    if c.dns_query.is_none() {
                        c.dns_query = Some(domain.clone());
                    }
                    c.dns_response = Some(result.clone());
                    c.dns_resolved_ts = Some(*ts);
                }
            }
            DiagEvent::DnsQuery { id, query, .. } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.dns_query = Some(query.clone());
                }
            }
            DiagEvent::Wait { id, ts } => {
                let stats = ConnStats {
                    id: *id,
                    kind: "Wait".to_string(),
                    src: String::new(),
                    dst: String::new(),
                    route: "acceptor".to_string(),
                    accept_ts: *ts,
                    dispatch_us: 0,
                    connected_ts: None,
                    finished_ts: None,
                    error: None,
                    bytes_up: 0.0,
                    bytes_down: 0.0,
                    dns_query: None,
                    dns_response: None,
                    dns_resolved_ts: None,
                };
                self.conns.insert(*id, stats);
                self.conn_order.push_back(*id);
                while self.conn_order.len() > self.max_conns {
                    if let Some(old) = self.conn_order.pop_front() {
                        self.conns.remove(&old);
                    }
                }
            }
            DiagEvent::WaitEnded { id, ts } => {
                if let Some(c) = self.conns.get_mut(id) {
                    c.finished_ts = Some(*ts);
                    let wait_us = ts.elapsed_since(c.accept_ts).as_micros() as u64;
                    c.dispatch_us = wait_us;
                    c.route = "acceptor: resumed".to_string();
                }
            }
            DiagEvent::HotConfigReloaded { .. }
            | DiagEvent::HotConfigSnapshot { .. }
            | DiagEvent::DnsState { .. }
            | DiagEvent::RoutingState { .. }
            | DiagEvent::UplinkStatsSnapshot { .. } => {}
        }
    }
}