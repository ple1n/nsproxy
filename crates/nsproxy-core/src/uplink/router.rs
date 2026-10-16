use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use bytes::BytesMut;
use diag::{ConnId, ControlCommand, DiagEvent, DiagServer, StreamKind, Timestamp, next_conn_id};
use futures::SinkExt;
use ipstack::{
    IpStack, IpStackConfig, TUNDev,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, tcp::TcpConfig},
};
use nsproxy_common::routing::{
    DropReason, ProxyID, RoutingContext, RoutingDecision, RoutingProtocol, RoutingResovled, VDNSRES,
};
use nsproxy_common::stats::{
    HostRouteHost, ObservedRoute, TransferRateSample, TransferRateTracker,
};
use socks5_impl::protocol::WireAddress;
use tokio::sync::mpsc;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    sync::{RwLock, watch},
    time,
};
use tracing::{debug, error, info, trace, warn};
use tun2socks5::dns::{VirtDNSAsync, VirtDNSHandle};

use crate::{
    HotConfig,
    uplink::{UplinkHub, UplinkProxy, uplink_proxy_default_udp_expected},
};

// based off crates/tun2socks5/src/lib.rs

const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, Copy)]
enum RelaySide {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy)]
enum RelayOp {
    Copy,
    Shutdown,
}

#[derive(Debug)]
struct TcpRelayOutcome {
    bytes_up: u128,
    bytes_down: u128,
}

#[derive(Debug)]
enum RelayError {
    Io {
        flow: &'static str,
        from: RelaySide,
        to: RelaySide,
        op: RelayOp,
        source: std::io::Error,
    },
    StatsChannelClosed { flow: &'static str },
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Io {
                flow,
                from,
                to,
                op,
                source,
            } => {
                let from = match from {
                    RelaySide::Left => "left",
                    RelaySide::Right => "right",
                };
                let to = match to {
                    RelaySide::Left => "left",
                    RelaySide::Right => "right",
                };
                let op = match op {
                    RelayOp::Copy => "copy",
                    RelayOp::Shutdown => "shutdown",
                };
                write!(f, "{} {}", flow, source)
            }
            RelayError::StatsChannelClosed { flow } => {
                write!(f, "{flow} rate-statistics channel closed")
            }
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::Io { source, .. } => Some(source),
            RelayError::StatsChannelClosed { .. } => None,
        }
    }
}

/// Main TUN packet router with dynamic proxy/routing configuration
pub struct Router {
    /// Central hub for proxy management and routing decisions (exposed for direct access)
    pub uplink: Arc<RwLock<UplinkHub>>,
    /// TUN device for reading/writing packets
    tun: TUNDev,
    /// IP stack for TCP/UDP stream handling
    stack: IpStack,
    /// Virtual DNS handler for IP allocation and domain mapping
    dns: VirtDNSAsync,
    /// Diagnostic monitoring server
    diag: DiagServer,
    /// Receiver for control commands sent by connected EGUI clients.
    /// Take with [`Router::take_cmd_rx`] to drive a command-handling loop.
    pub cmd_rx: Option<mpsc::Receiver<ControlCommand>>,
    /// Channel for serving files over TCP
    file_server_tx: Option<flume::Sender<(PathBuf, IpStackTcpStream)>>,
    /// Explicit name mappings etc
    conf: Arc<watch::Receiver<HotConfig>>,
    host_connections: HostConnectionControl,
}

#[derive(Clone, Default)]
pub struct HostConnectionControl {
    inner: Arc<Mutex<HashMap<HostRouteHost, HashMap<ConnId, watch::Sender<bool>>>>>,
}

impl HostConnectionControl {
    pub fn kill_host(&self, host: &HostRouteHost) -> usize {
        let senders = match self.inner.lock() {
            Ok(connections) => connections
                .get(host)
                .map(|connections| connections.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
            Err(err) => {
                error!("host connection registry lock poisoned: {err}");
                return 0;
            }
        };
        senders
            .into_iter()
            .filter(|sender| sender.send(true).is_ok())
            .count()
    }

    fn register(
        &self,
        host: HostRouteHost,
        id: ConnId,
        sender: watch::Sender<bool>,
    ) -> Result<()> {
        let mut connections = self
            .inner
            .lock()
            .map_err(|err| anyhow::anyhow!("host connection registry lock poisoned: {err}"))?;
        connections.entry(host).or_default().insert(id, sender);
        Ok(())
    }

    fn unregister(&self, id: ConnId) -> Result<()> {
        let mut connections = self
            .inner
            .lock()
            .map_err(|err| anyhow::anyhow!("host connection registry lock poisoned: {err}"))?;
        connections.retain(|_, host_connections| {
            host_connections.remove(&id);
            !host_connections.is_empty()
        });
        Ok(())
    }
}

pub struct RouterConfig {
    pub mtu: u16,
    pub packet_info: bool,
    pub udp_timeout: Duration,
    pub diag_sock: Option<PathBuf>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            packet_info: false,
            udp_timeout: Duration::from_mins(10),
            diag_sock: None,
        }
    }
}

impl Router {
    /// Create a new router with the given configuration
    pub fn new(
        tun: TUNDev,
        config: RouterConfig,
        uplink: UplinkHub,
        file_server_tx: Option<flume::Sender<(PathBuf, IpStackTcpStream)>>,
        conf: Arc<watch::Receiver<HotConfig>>,
    ) -> Result<Self> {
        let dns = VirtDNSAsync::default(65535)?;

        let mut tcp_config = TcpConfig::default();
        tcp_config.timeout = Duration::from_hours(6);

        let stack_config = IpStackConfig {
            mtu: config.mtu,
            packet_information: config.packet_info,
            udp_timeout: config.udp_timeout,
            tcp_config: Arc::new(tcp_config),
        };

        let stack = IpStack::new(stack_config, tun.clone());

        Ok(Self {
            uplink: Arc::new(RwLock::new(uplink)),
            tun,
            stack,
            dns,
            diag: DiagServer::noop(),
            cmd_rx: None,
            file_server_tx,
            conf,
            host_connections: HostConnectionControl::default(),
        })
    }

    pub fn host_connection_control(&self) -> HostConnectionControl {
        self.host_connections.clone()
    }

    /// Get a handle to the DNS system for external configuration
    pub fn dns_handle(&self) -> VirtDNSHandle {
        self.dns.handle.clone()
    }

    /// Initialize diagnostic monitoring.
    /// After calling this, use [`Router::take_cmd_rx`] to obtain the control-command receiver.
    pub async fn init_diag(&mut self, sock_path: &PathBuf) -> Result<()> {
        let initial_persist = Duration::from_secs(
            u64::from(self.conf.borrow().diag_conn_persist_secs),
        );
        match DiagServer::start(sock_path.as_path(), initial_persist).await {
            Ok((srv, cmd_rx)) => {
                info!("diag server started at {:?}", sock_path);
                self.diag = srv.clone();
                self.cmd_rx = Some(cmd_rx);
                let mut conf = (*self.conf).clone();
                tokio::spawn(async move {
                    while conf.changed().await.is_ok() {
                        let persist = Duration::from_secs(
                            u64::from(conf.borrow().diag_conn_persist_secs),
                        );
                        if let Err(err) = srv.set_conn_persist(persist).await {
                            warn!("failed to update diagnostic connection retention: {err}");
                            break;
                        }
                    }
                });
                Ok(())
            }
            Err(e) => {
                warn!("diag server failed to start: {}, continuing without", e);
                Ok(())
            }
        }
    }

    /// Clone the diagnostic server handle for emitting events externally.
    pub fn diag_handle(&self) -> DiagServer {
        self.diag.clone()
    }

    /// Take the control-command receiver out of the router.
    /// Returns `None` if diag was not started or already taken.
    pub fn take_cmd_rx(&mut self) -> Option<mpsc::Receiver<ControlCommand>> {
        self.cmd_rx.take()
    }

    /// Get read access to the uplink hub for inspection
    pub async fn uplink(&self) -> tokio::sync::RwLockReadGuard<'_, UplinkHub> {
        self.uplink.read().await
    }

    /// Get write access to the uplink hub for dynamic updates
    pub async fn uplink_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, UplinkHub> {
        self.uplink.write().await
    }

    /// Add a proxy to the router dynamically
    pub async fn add_proxy(&self, id: ProxyID, proxy: UplinkProxy) {
        let mut uplink = self.uplink.write().await;
        uplink.add_proxy(id, proxy);
    }

    /// Update the routing function dynamically
    pub async fn set_routing(&self, routing_fn: crate::uplink::RoutingFunction) {
        let mut uplink = self.uplink.write().await;
        uplink.set_routing(routing_fn);
    }

    /// Main accept loop - processes all incoming TUN connections
    pub async fn run(mut self) -> Result<()> {
        info!("Router started, entering main loop");

        let mut stats_tick = time::interval(Duration::from_secs(60));
        stats_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        // consume the first immediate tick
        stats_tick.tick().await;

        loop {
            let wait_id = next_conn_id();
            self.diag.emit(DiagEvent::Wait {
                id: wait_id,
                ts: Timestamp::now(),
            });

            tokio::select! {
                _ = stats_tick.tick() => {
                    if let Err(e) = self.uplink.write().await.save_stats() {
                        warn!("periodic stats save failed: {e}");
                    }
                    self.diag.emit(DiagEvent::WaitEnded { id: wait_id, ts: Timestamp::now() });
                    continue;
                }
                result = self.stack.accept() => {
                    let stream = result?;
                    self.diag.emit(DiagEvent::WaitEnded {
                        id: wait_id,
                        ts: Timestamp::now(),
                    });
                    match stream {
                        IpStackStream::Tcp(tcp) => {
                            self.handle_tcp(tcp).await;
                        }
                        IpStackStream::Udp(udp) => {
                            self.handle_udp(udp).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_tcp(&self, tcp: IpStackTcpStream) {
        let conn_id = next_conn_id();
        let local = tcp.local_addr();
        let peer = tcp.peer_addr();

        self.diag.emit(DiagEvent::Accept {
            id: conn_id,
            ts: Timestamp::now(),
            kind: StreamKind::Tcp,
            src: local.to_string(),
            dst: peer.to_string(),
        });

        let uplink = self.uplink.clone();
        let dns_handle = self.dns.handle.clone();
        let diag = self.diag.clone();
        let file_tx = self.file_server_tx.clone();
        let conf = self.conf.clone();
        let host_connections = self.host_connections.clone();
        let (kill_tx, mut kill_rx) = watch::channel(false);

        tokio::spawn(async move {
            tokio::select! {
                result = Self::handle_tcp_inner(
                    tcp,
                    uplink,
                    dns_handle,
                    diag.clone(),
                    conn_id,
                    file_tx,
                    conf,
                    host_connections.clone(),
                    kill_tx,
                ) => {
                    if let Err(e) = result {
                        error!("Drop TCP connection {:?} {:?}", conn_id, e);
                        diag.emit(DiagEvent::Finished {
                            id: conn_id,
                            ts: Timestamp::now(),
                            error: Some(format!("{:?}", e)),
                            bytes_up: 0.0,
                            bytes_down: 0.0,
                        });
                    }
                }
                changed = kill_rx.changed() => {
                    if changed.is_ok() && *kill_rx.borrow() {
                        diag.emit(DiagEvent::Killed {
                            id: conn_id,
                            ts: Timestamp::now(),
                        });
                    }
                }
            }
            if let Err(err) = host_connections.unregister(conn_id) {
                error!("failed to unregister TCP connection {:?}: {err}", conn_id);
            }
        });
    }

    async fn handle_tcp_inner(
        mut tcp: IpStackTcpStream,
        uplink: Arc<RwLock<UplinkHub>>,
        dns_handle: VirtDNSHandle,
        diag: DiagServer,
        conn_id: ConnId,
        file_tx: Option<flume::Sender<(PathBuf, IpStackTcpStream)>>,
        conf: Arc<watch::Receiver<HotConfig>>,
        host_connections: HostConnectionControl,
        kill_tx: watch::Sender<bool>,
    ) -> Result<()> {
        let peer = tcp.peer_addr();
        let local = tcp.local_addr();

        let dns_result = dns_handle.preprocess(peer);

        let mut ctx = RoutingContext {
            target_ip: peer.ip(),
            target_port: peer.port(),
            source_ip: local.ip(),
            protocol: RoutingProtocol::Tcp,
            tried_proxies: Default::default(),
            attempt_num: 0,
            dns: dns_result,
        };
        let stats_target = match &ctx.dns {
            VDNSRES::Opine(RoutingDecision::HostOverProxy(domain)) => {
                WireAddress::DomainAddress(domain.clone(), peer.port())
            }
            _ => WireAddress::SocketAddress(peer),
        };
        host_connections.register(
            HostRouteHost::from_wire_address(&stats_target),
            conn_id,
            kill_tx,
        )?;

        loop {
            let decision = {
                let hub = uplink.read().await;
                hub.route(&ctx)
            };

            diag.emit(DiagEvent::Route {
                id: conn_id,
                ts: Timestamp::now(),
                route: decision.clone(),
            });
            let decision = match decision {
                RoutingResovled::NoProxyDomain { host, port } => {
                    RoutingResovled::NoProxy(Self::resolve_direct_domain(&host, port).await?)
                }
                decision => decision,
            };

            match decision {
                RoutingResovled::NoProxy(addr) | RoutingResovled::NATByTUN(addr) => {
                    warn!("direct conn to {}", &addr);
                    Self::tcp_direct(
                        tcp,
                        addr,
                        diag,
                        conn_id,
                        uplink.clone(),
                        stats_target.clone(),
                    )
                    .await?;
                    break;
                }
                RoutingResovled::NoProxyDomain { .. } => {
                    bail!("direct domain route was not resolved");
                }
                RoutingResovled::Drop(reason) => {
                    warn!("{}: {:?}", peer, reason);
                    diag.emit(DiagEvent::Finished {
                        id: conn_id,
                        ts: Timestamp::now(),
                        error: Some(format!("route dropped: {reason:?}")),
                        bytes_up: 0.0,
                        bytes_down: 0.0,
                    });
                    break;
                }
                RoutingResovled::ProxyResovled { target, id } => {
                    let proxy_clone = {
                        let hub = uplink.read().await;
                        match hub.get_proxy(&id) {
                            Some(UplinkProxy::Trojan(p)) => {
                                Ok(Some(UplinkProxy::Trojan(p.clone())))
                            }
                            Some(UplinkProxy::Remote(p)) => {
                                Ok(Some(UplinkProxy::Remote(p.clone())))
                            }
                            Some(UplinkProxy::File(path)) => {
                                if let Some(tx) = &file_tx {
                                    tx.send_async((path.clone(), tcp)).await?;
                                    return Ok(());
                                } else {
                                    bail!(
                                        "file proxy route requested but file server channel is unavailable"
                                    )
                                }
                            }
                            Some(UplinkProxy::Geph) => {
                                bail!("proxy {:?} (geph) is not supported yet", id)
                            }
                            None => Err(anyhow::anyhow!("proxy {:?} not found", id)),
                        }
                    };

                    let proxy = match proxy_clone {
                        Ok(Some(p)) => p,
                        Ok(None) => unreachable!(),
                        Err(e) => {
                            warn!("proxy {:?} lookup failed for {peer}: {e:?}, retrying", id);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

                    use crate::uplink::proxy_adapters::{
                        ProxyConnection, RemoteAdapter, TrojanAdapter,
                    };

                    let expected_udp = uplink_proxy_default_udp_expected(&proxy);

                    let connect_start = std::time::Instant::now();

                    let conn_result = match &proxy {
                        UplinkProxy::Trojan(p) => {
                            TrojanAdapter::connect_tcp(p, target.clone(), p.server_addr.ip()).await
                        }
                        UplinkProxy::Remote(p) => {
                            RemoteAdapter::connect_tcp(p, target.clone()).await
                        }
                        _ => unreachable!(),
                    };

                    let mut conn = match conn_result {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("proxy {:?} connect failed for {peer}: {e:?}, retrying", id);
                            let connect_latency = connect_start.elapsed();
                            let metric = {
                                let mut hub = uplink.write().await;
                                let stats = hub.stats.entry(id.clone()).or_default();
                                stats.set_expected_udp_default(expected_udp);
                                stats.record_attempt(false);
                                hub.record_host_route_attempt(
                                    stats_target.clone(),
                                    ObservedRoute::Proxy(id.clone()),
                                    connect_latency,
                                    false,
                                )
                            };
                            diag.emit(DiagEvent::HostRouteStatsUpdated {
                                ts: metric.observed_at,
                                stat: metric,
                            });
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

                    let connect_latency = connect_start.elapsed();
                    let latency_ms = connect_latency.as_millis() as u64;

                    let proxy_stream = match conn {
                        ProxyConnection::Tcp(ref mut stream) => stream.as_mut(),
                        ProxyConnection::Udp(_) => {
                            bail!("udp proxy tunnel cannot serve tcp stream")
                        }
                    };

                    diag.emit(DiagEvent::Connected {
                        id: conn_id,
                        ts: Timestamp::now(),
                    });

                    let metric = uplink.write().await.record_host_route_attempt(
                        stats_target.clone(),
                        ObservedRoute::Proxy(id.clone()),
                        connect_latency,
                        true,
                    );
                    diag.emit(DiagEvent::HostRouteStatsUpdated {
                        ts: metric.observed_at,
                        stat: metric,
                    });

                    {
                        let mut hub = uplink.write().await;
                        let s = hub.stats.entry(id.clone()).or_default();
                        s.set_expected_udp_default(expected_udp);
                        s.record_latency_ms(latency_ms);
                    }

                    match Self::relay_tcp_with_cause(
                        &mut tcp,
                        proxy_stream,
                        "tun->proxy",
                        "proxy->tun",
                        stats_target.clone(),
                        ObservedRoute::Proxy(id.clone()),
                        uplink.clone(),
                        diag.clone(),
                    )
                    .await
                    {
                        Ok(relay) => {
                            {
                                let mut hub = uplink.write().await;
                                let s = hub.stats.entry(id.clone()).or_default();
                                s.set_expected_udp_default(expected_udp);
                                s.record_attempt(true);
                                s.record_traffic(relay.bytes_up, relay.bytes_down);
                            };
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: relay.bytes_up as f32,
                                bytes_down: relay.bytes_down as f32,
                            });
                            break;
                        }
                        Err(relay_err) => {
                            info!(
                                "proxy {:?} relay failed for {peer}: {relay_err:?}, retrying",
                                id
                            );
                            {
                                let mut hub = uplink.write().await;
                                let stats = hub.stats.entry(id.clone()).or_default();
                                stats.set_expected_udp_default(expected_udp);
                                stats.record_attempt(false);
                            }
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::AttemptFailed {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: relay_err.to_string(),
                            });
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn wire_to_host_port(addr: &WireAddress) -> (String, u16) {
        match addr {
            WireAddress::SocketAddress(sock) => (sock.ip().to_string(), sock.port()),
            WireAddress::DomainAddress(host, port) => (host.clone(), *port),
        }
    }

    async fn resolve_direct_domain(host: &str, port: u16) -> Result<SocketAddr> {
        lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {host}:{port}"))
    }

    /// Relay UDP datagrams between an IpStackUdpStream (TUN side) and a UdpLike tunnel.
    /// Returns (bytes_up, bytes_down) on clean termination.
    async fn relay_udp(
        tunnel: &mut dyn crate::uplink::proxy_adapters::UdpLike,
        udp: &mut IpStackUdpStream,
        target: WireAddress,
        stats_target: WireAddress,
        route: ObservedRoute,
        uplink: Arc<RwLock<UplinkHub>>,
        diag: DiagServer,
    ) -> Result<(u128, u128)> {
        use tokio::io::AsyncReadExt;

        let mut bytes_up: u128 = 0;
        let mut bytes_down: u128 = 0;
        let mut buf = vec![0u8; 65535];
        let transfer_start = Instant::now();
        let mut upload_tracker = TransferRateTracker::default();
        let mut download_tracker = TransferRateTracker::default();
        let mut last_rate_update = Duration::ZERO;

        loop {
            tokio::select! {
                // TUN -> tunnel (upstream)
                result = udp.read(&mut buf) => {
                    let Some(n) = Self::udp_read_result(result)? else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    // The TUN peer may be a synthetic DNS address; send to the routed destination.
                    tunnel.send_to(&buf[..n], target.clone()).await
                        .map_err(|e| anyhow::anyhow!("UDP send_to failed: {}", e))?;
                    bytes_up += n as u128;
                    upload_tracker.record(n as u128, transfer_start.elapsed());
                }
                // tunnel -> TUN (downstream)
                result = tunnel.recv_from() => {
                    let pkt = result.map_err(|e| anyhow::anyhow!("UDP recv_from failed: {}", e))?;
                    let n = pkt.data.len();
                    udp.write_all(&pkt.data).await?;
                    bytes_down += n as u128;
                    download_tracker.record(n as u128, transfer_start.elapsed());
                }
            }

            let elapsed = transfer_start.elapsed();
            if elapsed.saturating_sub(last_rate_update) >= Duration::from_secs(1) {
                let observed_at = Timestamp::now();
                let upload_sample = upload_tracker.sample(observed_at, elapsed);
                let download_sample = download_tracker.sample(observed_at, elapsed);
                if upload_sample.is_some() || download_sample.is_some() {
                    Self::publish_udp_rate_samples(
                        &uplink,
                        &diag,
                        &stats_target,
                        &route,
                        upload_sample,
                        download_sample,
                    )
                    .await;
                    last_rate_update = elapsed;
                }
            }
        }

        let observed_at = Timestamp::now();
        Self::publish_udp_rate_samples(
            &uplink,
            &diag,
            &stats_target,
            &route,
            upload_tracker.sample(observed_at, transfer_start.elapsed()),
            download_tracker.sample(observed_at, transfer_start.elapsed()),
        )
        .await;
        Ok((bytes_up, bytes_down))
    }

    fn udp_read_result(result: std::io::Result<usize>) -> std::io::Result<Option<usize>> {
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            // IpStackUdpStream uses TimedOut to signal expiry after UDP inactivity.
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn publish_udp_rate_samples(
        uplink: &Arc<RwLock<UplinkHub>>,
        diag: &DiagServer,
        stats_target: &WireAddress,
        route: &ObservedRoute,
        upload_sample: Option<TransferRateSample>,
        download_sample: Option<TransferRateSample>,
    ) {
        if upload_sample.is_none() && download_sample.is_none() {
            return;
        }

        let metric = uplink.write().await.record_host_route_udp_transfer_samples(
            stats_target.clone(),
            route.clone(),
            upload_sample,
            download_sample,
        );
        diag.emit(DiagEvent::HostRouteStatsUpdated {
            ts: metric.observed_at,
            stat: metric,
        });
    }

    async fn publish_tcp_rate_sample(
        uplink: &Arc<RwLock<UplinkHub>>,
        diag: &DiagServer,
        stats_target: &WireAddress,
        route: &ObservedRoute,
        sample: TransferRateSample,
        upload: bool,
    ) {
        let (upload_sample, download_sample) = if upload {
            (Some(sample), None)
        } else {
            (None, Some(sample))
        };
        let metric = uplink.write().await.record_host_route_transfer_samples(
            stats_target.clone(),
            route.clone(),
            upload_sample,
            download_sample,
        );
        diag.emit(DiagEvent::HostRouteStatsUpdated {
            ts: metric.observed_at,
            stat: metric,
        });
    }

    async fn relay_tcp_with_cause<A, B>(
        left: &mut A,
        right: &mut B,
        left_to_right_flow: &'static str,
        right_to_left_flow: &'static str,
        stats_target: WireAddress,
        route: ObservedRoute,
        uplink: Arc<RwLock<UplinkHub>>,
        diag: DiagServer,
    ) -> std::result::Result<TcpRelayOutcome, RelayError>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let (upload_rate_tx, mut upload_rate_rx) = mpsc::channel(8);
        let (download_rate_tx, mut download_rate_rx) = mpsc::channel(8);
        let relay = Self::relay_tcp_copy(
            left,
            right,
            left_to_right_flow,
            right_to_left_flow,
            upload_rate_tx,
            download_rate_tx,
        );
        tokio::pin!(relay);

        let mut relay_result = None;
        let mut upload_closed = false;
        let mut download_closed = false;
        loop {
            tokio::select! {
                biased;
                result = &mut relay, if relay_result.is_none() => {
                    relay_result = Some(result);
                }
                sample = upload_rate_rx.recv(), if !upload_closed => {
                    if let Some(sample) = sample {
                        Self::publish_tcp_rate_sample(
                            &uplink,
                            &diag,
                            &stats_target,
                            &route,
                            sample,
                            true,
                        )
                        .await;
                    } else {
                        upload_closed = true;
                    }
                }
                sample = download_rate_rx.recv(), if !download_closed => {
                    if let Some(sample) = sample {
                        Self::publish_tcp_rate_sample(
                            &uplink,
                            &diag,
                            &stats_target,
                            &route,
                            sample,
                            false,
                        )
                        .await;
                    } else {
                        download_closed = true;
                    }
                }
            }

            if relay_result.is_some() && upload_closed && download_closed {
                if let Some(result) = relay_result.take() {
                    return result;
                }
            }
        }
    }

    async fn relay_tcp_copy<A, B>(
        left: &mut A,
        right: &mut B,
        left_to_right_flow: &'static str,
        right_to_left_flow: &'static str,
        upload_rate_tx: mpsc::Sender<TransferRateSample>,
        download_rate_tx: mpsc::Sender<TransferRateSample>,
    ) -> std::result::Result<TcpRelayOutcome, RelayError>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let (mut left_read, mut left_write) = tokio::io::split(left);
        let (mut right_read, mut right_write) = tokio::io::split(right);
        let transfer_start = Instant::now();
        let mut upload_tracker = TransferRateTracker::default();
        let mut download_tracker = TransferRateTracker::default();

        let up = async {
            Self::relay_tcp_direction(
                &mut left_read,
                &mut right_write,
                RelaySide::Left,
                RelaySide::Right,
                left_to_right_flow,
                transfer_start,
                &mut upload_tracker,
                upload_rate_tx,
            )
            .await
        };

        let down = async {
            Self::relay_tcp_direction(
                &mut right_read,
                &mut left_write,
                RelaySide::Right,
                RelaySide::Left,
                right_to_left_flow,
                transfer_start,
                &mut download_tracker,
                download_rate_tx,
            )
            .await
        };

        let (bytes_up, bytes_down) = tokio::try_join!(up, down)?;
        Ok(TcpRelayOutcome {
            bytes_up,
            bytes_down,
        })
    }

    async fn relay_tcp_direction<R, W>(
        reader: &mut R,
        writer: &mut W,
        from: RelaySide,
        to: RelaySide,
        flow: &'static str,
        transfer_start: Instant,
        rate_tracker: &mut TransferRateTracker,
        rate_updates: mpsc::Sender<TransferRateSample>,
    ) -> std::result::Result<u128, RelayError>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut buffer = [0u8; 8192];
        let mut copied = 0u128;
        let mut last_rate_update = Duration::ZERO;

        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|source| RelayError::Io {
                    flow,
                    from,
                    to,
                    op: RelayOp::Copy,
                    source,
                })?;
            if read == 0 {
                break;
            }

            let mut written = 0;
            while written < read {
                let n = writer
                    .write(&buffer[written..read])
                    .await
                    .map_err(|source| RelayError::Io {
                        flow,
                        from,
                        to,
                        op: RelayOp::Copy,
                        source,
                    })?;
                if n == 0 {
                    return Err(RelayError::Io {
                        flow,
                        from,
                        to,
                        op: RelayOp::Copy,
                        source: std::io::Error::from(std::io::ErrorKind::WriteZero),
                    });
                }

                written += n;
                copied += n as u128;
                let elapsed = transfer_start.elapsed();
                rate_tracker.record(n as u128, elapsed);
                if elapsed.saturating_sub(last_rate_update) >= Duration::from_secs(1) {
                    if let Some(sample) = rate_tracker.sample(Timestamp::now(), elapsed) {
                        rate_updates
                            .send(sample)
                            .await
                            .map_err(|_| RelayError::StatsChannelClosed { flow })?;
                        last_rate_update = elapsed;
                    }
                }
            }
        }

        if let Some(sample) =
            rate_tracker.sample(Timestamp::now(), transfer_start.elapsed())
        {
            rate_updates
                .send(sample)
                .await
                .map_err(|_| RelayError::StatsChannelClosed { flow })?;
        }

        if let Err(source) = writer.shutdown().await {
            if source.kind() != std::io::ErrorKind::BrokenPipe
                && source.kind() != std::io::ErrorKind::ConnectionReset
            {
                return Err(RelayError::Io {
                    flow,
                    from,
                    to,
                    op: RelayOp::Shutdown,
                    source,
                });
            }
        }
        Ok(copied)
    }

    async fn tcp_direct(
        mut tcp: IpStackTcpStream,
        target: SocketAddr,
        diag: DiagServer,
        conn_id: ConnId,
        uplink: Arc<RwLock<UplinkHub>>,
        stats_target: WireAddress,
    ) -> Result<()> {
        let connect_start = std::time::Instant::now();
        let mut remote = match TcpStream::connect(target).await {
            Ok(remote) => remote,
            Err(error) => {
                let metric = uplink.write().await.record_host_route_attempt(
                    stats_target,
                    ObservedRoute::NoProxy,
                    connect_start.elapsed(),
                    false,
                );
                diag.emit(DiagEvent::HostRouteStatsUpdated {
                    ts: metric.observed_at,
                    stat: metric,
                });
                return Err(error.into());
            }
        };
        let connect_latency = connect_start.elapsed();
        let metric = uplink.write().await.record_host_route_attempt(
            stats_target.clone(),
            ObservedRoute::NoProxy,
            connect_latency,
            true,
        );
        diag.emit(DiagEvent::HostRouteStatsUpdated {
            ts: metric.observed_at,
            stat: metric,
        });
        diag.emit(DiagEvent::Connected {
            id: conn_id.clone(),
            ts: Timestamp::now(),
        });

        match Self::relay_tcp_with_cause(
            &mut tcp,
            &mut remote,
            "tun->direct",
            "direct->tun",
            stats_target.clone(),
            ObservedRoute::NoProxy,
            uplink.clone(),
            diag.clone(),
        )
        .await
        {
            Ok(relay) => {
                diag.emit(DiagEvent::Finished {
                    id: conn_id.clone(),
                    ts: Timestamp::now(),
                    error: None,
                    bytes_up: relay.bytes_up as f32,
                    bytes_down: relay.bytes_down as f32,
                });
                debug!(
                    "TCP {:?} done: {} up, {} down",
                    conn_id, relay.bytes_up, relay.bytes_down
                );
                Ok(())
            }
            Err(relay_err) => Err(anyhow::Error::new(relay_err)),
        }
    }

    async fn handle_udp(&self, udp: IpStackUdpStream) {
        let conn_id = next_conn_id();
        let local = udp.local_addr();
        let peer = udp.peer_addr();

        self.diag.emit(DiagEvent::Accept {
            id: conn_id,
            ts: Timestamp::now(),
            kind: StreamKind::Udp,
            src: local.to_string(),
            dst: peer.to_string(),
        });

        let uplink = self.uplink.clone();
        let dns_handle = self.dns.handle.clone();
        let diag = self.diag.clone();
        let conf = self.conf.clone();
        let host_connections = self.host_connections.clone();
        let (kill_tx, mut kill_rx) = watch::channel(false);

        tokio::spawn(async move {
            tokio::select! {
                result = Self::handle_udp_inner(
                    udp,
                    uplink,
                    dns_handle,
                    diag.clone(),
                    conn_id,
                    conf,
                    host_connections.clone(),
                    kill_tx,
                ) => {
                    if let Err(e) = result {
                        error!("UDP connection {:?} error: {:?}", conn_id, e);
                        diag.emit(DiagEvent::Finished {
                            id: conn_id,
                            ts: Timestamp::now(),
                            error: Some(format!("{:?}", e)),
                            bytes_up: 0.0,
                            bytes_down: 0.0,
                        });
                    }
                }
                changed = kill_rx.changed() => {
                    if changed.is_ok() && *kill_rx.borrow() {
                        diag.emit(DiagEvent::Killed {
                            id: conn_id,
                            ts: Timestamp::now(),
                        });
                    }
                }
            }
            if let Err(err) = host_connections.unregister(conn_id) {
                error!("failed to unregister UDP connection {:?}: {err}", conn_id);
            }
        });
    }

    async fn handle_udp_inner(
        mut udp: IpStackUdpStream,
        uplink: Arc<RwLock<UplinkHub>>,
        dns_handle: VirtDNSHandle,
        diag: DiagServer,
        conn_id: ConnId,
        conf: Arc<watch::Receiver<HotConfig>>,
        host_connections: HostConnectionControl,
        kill_tx: watch::Sender<bool>,
    ) -> Result<()> {
        let peer = udp.peer_addr();
        let local = udp.local_addr();

        // Check if this is DNS traffic destined for a captured range
        if peer.port() == DNS_PORT && conf.borrow().captures_dns(local.ip()) {
            return Self::handle_dns(udp, dns_handle, diag, conn_id).await;
        }

        let dns_result = dns_handle.preprocess(peer);

        let mut ctx = RoutingContext {
            target_ip: peer.ip(),
            target_port: peer.port(),
            source_ip: local.ip(),
            protocol: RoutingProtocol::Udp,
            tried_proxies: Default::default(),
            attempt_num: 0,
            dns: dns_result,
        };
        let stats_target = match &ctx.dns {
            VDNSRES::Opine(RoutingDecision::HostOverProxy(domain)) => {
                WireAddress::DomainAddress(domain.clone(), peer.port())
            }
            _ => WireAddress::SocketAddress(peer),
        };
        host_connections.register(
            HostRouteHost::from_wire_address(&stats_target),
            conn_id,
            kill_tx,
        )?;

        loop {
            let decision = {
                let hub = uplink.read().await;
                hub.route(&ctx)
            };

            diag.emit(DiagEvent::Route {
                id: conn_id,
                ts: Timestamp::now(),
                route: decision.clone(),
            });
            let decision = match decision {
                RoutingResovled::NoProxyDomain { host, port } => {
                    RoutingResovled::NoProxy(Self::resolve_direct_domain(&host, port).await?)
                }
                decision => decision,
            };

            match decision {
                RoutingResovled::NoProxy(addr) | RoutingResovled::NATByTUN(addr) => {
                    info!("UDP {:?} -> direct to {}", conn_id, addr);
                    use crate::uplink::proxy_adapters::NoProxyAdapter;
                    let mut remote = NoProxyAdapter::connect_udp(addr).await?;
                    diag.emit(DiagEvent::Connected {
                        id: conn_id,
                        ts: Timestamp::now(),
                    });

                    match Self::relay_udp(
                        remote.as_udp_mut().unwrap(),
                        &mut udp,
                        WireAddress::SocketAddress(addr),
                        stats_target.clone(),
                        ObservedRoute::NoProxy,
                        uplink.clone(),
                        diag.clone(),
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: up as f32,
                                bytes_down: down as f32,
                            });
                            break;
                        }
                        Err(e) => {
                            info!("direct UDP relay failed for {peer}: {e:?}, retrying");
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::AttemptFailed {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: e.to_string(),
                            });
                            continue;
                        }
                    }
                }
                RoutingResovled::NoProxyDomain { .. } => {
                    bail!("direct domain route was not resolved");
                }
                RoutingResovled::Drop(reason) => {
                    info!("UDP {:?} {:?}", conn_id, reason);
                    diag.emit(DiagEvent::Finished {
                        id: conn_id,
                        ts: Timestamp::now(),
                        error: Some(format!("route dropped: {reason:?}")),
                        bytes_up: 0.0,
                        bytes_down: 0.0,
                    });
                    break;
                }
                RoutingResovled::ProxyResovled { target, id } => {
                    let proxy_clone = {
                        let hub = uplink.read().await;
                        match hub.get_proxy(&id) {
                            Some(UplinkProxy::Trojan(p)) => {
                                Ok(Some(UplinkProxy::Trojan(p.clone())))
                            }
                            Some(UplinkProxy::Remote(p)) => {
                                Ok(Some(UplinkProxy::Remote(p.clone())))
                            }
                            Some(_) => {
                                Err(anyhow::anyhow!("proxy {:?} type not supported for UDP", id))
                            }
                            None => Err(anyhow::anyhow!("proxy {:?} not found", id)),
                        }
                    };

                    let proxy = match proxy_clone {
                        Ok(Some(p)) => p,
                        Ok(None) => unreachable!(),
                        Err(e) => {
                            warn!("proxy {:?} lookup failed for {peer}: {e:?}, retrying", id);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

                    use crate::uplink::proxy_adapters::{
                        ProxyConnection, RemoteAdapter, TrojanAdapter,
                    };

                    let expected_udp = uplink_proxy_default_udp_expected(&proxy);

                    let connect_start = std::time::Instant::now();

                    let conn_result = match &proxy {
                        UplinkProxy::Trojan(p) => {
                            TrojanAdapter::connect_udp(p, target.clone(), p.server_addr.ip()).await
                        }
                        UplinkProxy::Remote(p) => RemoteAdapter::connect_udp(p).await,
                        _ => unreachable!(),
                    };

                    let mut conn = match conn_result {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("proxy {:?} connect failed for {peer}: {e:?}, retrying", id);
                            let mut hub = uplink.write().await;
                            let stats = hub.stats.entry(id.clone()).or_default();
                            stats.set_expected_udp_default(expected_udp);
                            stats.observe_udp_ability(Timestamp::now(), false);
                            stats.record_attempt(false);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

                    let latency_ms = connect_start.elapsed().as_millis() as u64;

                    let tunnel = match conn.as_udp_mut() {
                        Some(t) => t,
                        None => bail!("proxy returned TCP connection for UDP stream"),
                    };

                    diag.emit(DiagEvent::Connected {
                        id: conn_id,
                        ts: Timestamp::now(),
                    });

                    {
                        let mut hub = uplink.write().await;
                        let stats = hub.stats.entry(id.clone()).or_default();
                        stats.set_expected_udp_default(expected_udp);
                        stats.record_latency_ms(latency_ms);
                    }

                    match Self::relay_udp(
                        tunnel,
                        &mut udp,
                        target.clone(),
                        stats_target.clone(),
                        ObservedRoute::Proxy(id.clone()),
                        uplink.clone(),
                        diag.clone(),
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            {
                                let mut hub = uplink.write().await;
                                let s = hub.stats.entry(id.clone()).or_default();
                                s.set_expected_udp_default(expected_udp);
                                s.observe_udp_ability(Timestamp::now(), true);
                                s.record_attempt(true);
                                s.record_traffic(up, down);
                            }
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: up as f32,
                                bytes_down: down as f32,
                            });
                            break;
                        }
                        Err(e) => {
                            info!(
                                "proxy {:?} UDP relay failed for {peer}: {e:?}, retrying",
                                id
                            );
                            let mut hub = uplink.write().await;
                            let stats = hub.stats.entry(id.clone()).or_default();
                            stats.set_expected_udp_default(expected_udp);
                            stats.observe_udp_ability(Timestamp::now(), false);
                            stats.record_attempt(false);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: Some(e.to_string()),
                                bytes_up: 0.0,
                                bytes_down: 0.0,
                            });
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_dns(
        mut udp: IpStackUdpStream,
        dns_handle: VirtDNSHandle,
        diag: DiagServer,
        conn_id: ConnId,
    ) -> Result<()> {
        let mut pack = BytesMut::with_capacity(512);

        while udp.read_buf(&mut pack).await? > 0 {
            let query = match tun2socks5::dns::parse_data_to_dns_message(&pack, false)
                .and_then(|m| tun2socks5::dns::extract_domain_from_dns_message(&m))
            {
                Ok(q) => {
                    diag.emit(DiagEvent::DnsQuery {
                        id: conn_id,
                        ts: Timestamp::now(),
                        query: q.clone(),
                    });
                    Some(q)
                }
                Err(e) => {
                    warn!("DNS query parse error: {}", e);
                    None
                }
            };

            match dns_handle.receive_query(&pack) {
                Ok(resp) => {
                    if let Some(q) = query {
                        let result = match tun2socks5::dns::parse_data_to_dns_message(&resp, false)
                            .and_then(|m| tun2socks5::dns::extract_ipaddr_from_dns_message(&m))
                        {
                            Ok(ip) => ip.to_string(),
                            Err(e) => format!("err: {}", e),
                        };

                        diag.emit(DiagEvent::DnsResolved {
                            id: conn_id,
                            ts: Timestamp::now(),
                            domain: q,
                            result,
                        });
                    }
                    udp.write_all(&resp).await?;
                    break;
                    // Finish DNS
                }
                Err(err) => {
                    let domain = query.unwrap_or_else(|| "<parse-error>".to_string());
                    diag.emit(DiagEvent::DnsResolved {
                        id: conn_id,
                        ts: Timestamp::now(),
                        domain,
                        result: format!("err: {}", err),
                    });
                    error!("DNS error: {:?}", err);
                }
            }

            pack.clear();
        }

        Ok(())
    }

    /// Extract domain name from Virtual DNS result or HotConfig
    async fn extract_domain(
        dns_result: &VDNSRES,
        target_ip: IpAddr,
        conf: &Arc<watch::Receiver<HotConfig>>,
    ) -> Option<String> {
        let config = conf.borrow();
        for (domain, ip_str) in &config.dns {
            if let Ok(mapped_ip) = ip_str.parse::<IpAddr>() {
                if mapped_ip == target_ip {
                    return Some(domain.clone());
                }
            }
        }

        if let VDNSRES::Opine(response) = dns_result {
            match response {
                RoutingDecision::HostOverProxy(domain) => {
                    return Some(domain.clone());
                }
                _ => {}
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_idle_timeout_is_normal_relay_termination() {
        assert_eq!(
            Router::udp_read_result(Err(std::io::Error::from(
                std::io::ErrorKind::TimedOut
            )))
            .unwrap(),
            None
        );
        assert_eq!(Router::udp_read_result(Ok(12)).unwrap(), Some(12));
        assert_eq!(Router::udp_read_result(Ok(0)).unwrap(), Some(0));
        assert_eq!(
            Router::udp_read_result(Err(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset
            )))
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn host_connection_control_kills_and_unregisters_matching_connections() {
        let control = HostConnectionControl::default();
        let host = HostRouteHost::domain("example.com");
        let (sender, mut receiver) = watch::channel(false);
        control.register(host.clone(), ConnId(7), sender).unwrap();

        assert_eq!(control.kill_host(&host), 1);
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());

        control.unregister(ConnId(7)).unwrap();
        assert_eq!(control.kill_host(&host), 0);
    }

    #[test]
    fn print_relay_error_example() {
        let err = RelayError::Io {
            flow: "tun->proxy",
            from: RelaySide::Left,
            to: RelaySide::Right,
            op: RelayOp::Copy,
            source: std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset"),
        };

        println!("{}", err);
    }

    #[tokio::test]
    async fn tcp_relay_preserves_bidirectional_copy_and_half_close() {
        let (mut left, mut left_peer) = tokio::io::duplex(1024);
        let (mut right, mut right_peer) = tokio::io::duplex(1024);
        let (upload_rate_tx, mut upload_rate_rx) = mpsc::channel(8);
        let (download_rate_tx, mut download_rate_rx) = mpsc::channel(8);

        let relay = Router::relay_tcp_copy(
            &mut left,
            &mut right,
            "left->right",
            "right->left",
            upload_rate_tx,
            download_rate_tx,
        );
        let left_task = async {
            left_peer.write_all(b"request").await.unwrap();
            left_peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            left_peer.read_to_end(&mut response).await.unwrap();
            response
        };
        let right_task = async {
            right_peer.write_all(b"response").await.unwrap();
            right_peer.shutdown().await.unwrap();
            let mut request = Vec::new();
            right_peer.read_to_end(&mut request).await.unwrap();
            request
        };

        let (relay, response, request) = tokio::join!(relay, left_task, right_task);
        let relay = relay.unwrap();
        assert_eq!(relay.bytes_up, 7);
        assert_eq!(relay.bytes_down, 8);
        assert_eq!(response, b"response");
        assert_eq!(request, b"request");
        assert_eq!(upload_rate_rx.try_recv().unwrap().bytes, 7);
        assert_eq!(download_rate_rx.try_recv().unwrap().bytes, 8);
    }

    #[tokio::test]
    async fn tcp_relay_publishes_rate_samples_before_returning() {
        let (mut left, mut left_peer) = tokio::io::duplex(1024);
        let (mut right, mut right_peer) = tokio::io::duplex(1024);
        let uplink = Arc::new(RwLock::new(UplinkHub::new()));
        let target = WireAddress::DomainAddress("rates.example".to_string(), 443);
        let route = ObservedRoute::NoProxy;

        let relay = Router::relay_tcp_with_cause(
            &mut left,
            &mut right,
            "left->right",
            "right->left",
            target.clone(),
            route.clone(),
            uplink.clone(),
            DiagServer::noop(),
        );
        let left_task = async {
            for _ in 0..3 {
                left_peer.write_all(b"0123456789").await.unwrap();
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
            left_peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            left_peer.read_to_end(&mut response).await.unwrap();
        };
        let right_task = async {
            right_peer.shutdown().await.unwrap();
            let mut request = Vec::new();
            right_peer.read_to_end(&mut request).await.unwrap();
            request
        };

        let (relay, (), request) = tokio::join!(relay, left_task, right_task);
        let relay = relay.unwrap();
        assert_eq!(relay.bytes_up, 30);
        assert_eq!(request, b"012345678901234567890123456789");
        let metric = uplink
            .read()
            .await
            .host_route_metrics(Timestamp::now())
            .into_iter()
            .find(|metric| metric.key.target == target && metric.key.route == route)
            .unwrap();
        let sample = metric.upload_sample.unwrap();
        assert_eq!(sample.bytes, 30);
        assert_eq!(sample.event_count, 3);
        assert!(sample.bytes_per_sec() < 1_000_000.0);
        assert_eq!(metric.upload_rate_summary.unwrap().sample_count, 1);
    }
}
