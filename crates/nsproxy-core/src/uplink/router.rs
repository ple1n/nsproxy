use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use bytes::BytesMut;
use diag::{ConnId, DiagEvent, DiagServer, StreamKind, Timestamp, next_conn_id};
use futures::SinkExt;
use ipstack::{
    IpStack, IpStackConfig, TUNDev,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, tcp::TcpConfig},
};
use nsproxy_common::routing::{
    DropReason, ProxyID, RoutingContext, RoutingDecision, RoutingProtocol,
};
use socks5_impl::protocol::WireAddress;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
};
use tracing::{debug, error, info, trace, warn};
use tun2socks5::dns::{TUNResponse, VDNSRES, VirtDNSAsync, VirtDNSHandle};

use crate::{
    HotConfig,
    uplink::{UplinkHub, UplinkProxy},
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
enum RelayError {
    Io {
        flow: &'static str,
        from: RelaySide,
        to: RelaySide,
        op: RelayOp,
        source: std::io::Error,
    },
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
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::Io { source, .. } => Some(source),
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
    /// Channel for serving files over TCP
    file_server_tx: Option<flume::Sender<(PathBuf, IpStackTcpStream)>>,
    /// Explicit name mappings etc
    conf: Arc<RwLock<HotConfig>>,
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
        conf: Arc<RwLock<HotConfig>>,
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
            file_server_tx,
            conf,
        })
    }

    /// Get a handle to the DNS system for external configuration
    pub fn dns_handle(&self) -> VirtDNSHandle {
        self.dns.handle.clone()
    }

    /// Initialize diagnostic monitoring
    pub async fn init_diag(&mut self, sock_path: &PathBuf) -> Result<()> {
        match DiagServer::start(sock_path.as_path()).await {
            Ok(srv) => {
                info!("diag server started at {:?}", sock_path);
                self.diag = srv;
                Ok(())
            }
            Err(e) => {
                warn!("diag server failed to start: {}, continuing without", e);
                Ok(())
            }
        }
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

        loop {
            let wait_id = next_conn_id();
            self.diag.emit(DiagEvent::Wait {
                id: wait_id,
                ts: Timestamp::now(),
            });

            let stream = self.stack.accept().await?;

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

        tokio::spawn(async move {
            if let Err(e) = Self::handle_tcp_inner(
                tcp,
                uplink,
                dns_handle,
                diag.clone(),
                conn_id,
                file_tx,
                conf,
            )
            .await
            {
                error!("Drop TCP connection {:?} {:?}", conn_id, e);
                diag.emit(DiagEvent::Finished {
                    id: conn_id,
                    ts: Timestamp::now(),
                    error: Some(format!("{:?}", e)),
                    bytes_up: 0,
                    bytes_down: 0,
                });
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
        conf: Arc<RwLock<HotConfig>>,
    ) -> Result<()> {
        let peer = tcp.peer_addr();
        let local = tcp.local_addr();

        let dns_result = dns_handle.process(peer);
        let target_domain = Self::extract_domain(&dns_result, peer.ip(), &conf).await;

        let dns_decision: Option<RoutingDecision> = match &dns_result {
            VDNSRES::SpecialHandling(TUNResponse::NATByTUN(sock)) => {
                Some(RoutingDecision::NATByTUN(*sock))
            }
            VDNSRES::SpecialHandling(TUNResponse::Direct(sock)) => {
                Some(RoutingDecision::Direct(*sock))
            }
            VDNSRES::SpecialHandling(TUNResponse::Files(path)) => Some(RoutingDecision::Proxy {
                target: WireAddress::SocketAddress(peer),
                id: ProxyID::for_file(path.as_path()),
            }),
            VDNSRES::SpecialHandling(TUNResponse::Unreachable) | VDNSRES::ERR => {
                Some(RoutingDecision::Drop(DropReason::Preprocess))
            }
            _ => None,
        };

        let mut ctx = RoutingContext {
            target_domain,
            target_ip: peer.ip(),
            target_port: peer.port(),
            source_ip: local.ip(),
            protocol: RoutingProtocol::Tcp,
            tried_proxies: Default::default(),
            attempt_num: 0,
            dns: dns_decision,
        };

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

            match decision {
                RoutingDecision::Direct(addr) | RoutingDecision::NATByTUN(addr) => {
                    warn!("direct conn to {}", &addr);
                    Self::tcp_direct(tcp, addr, diag, conn_id).await?;
                    break;
                }
                RoutingDecision::Drop(reason) => {
                    warn!("{}: {:?}", peer, reason);
                    break;
                }
                RoutingDecision::Proxy { target, id } => {
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
                    let (target_host, target_port) = Self::wire_to_host_port(&target);

                    let conn_result = match &proxy {
                        UplinkProxy::Trojan(p) => {
                            TrojanAdapter::connect_tcp(
                                p,
                                &target_host,
                                target_port,
                                p.server_addr.ip(),
                            )
                            .await
                        }
                        UplinkProxy::Remote(p) => {
                            RemoteAdapter::connect_tcp(p, &target_host, target_port).await
                        }
                        _ => unreachable!(),
                    };

                    let mut conn = match conn_result {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("proxy {:?} connect failed for {peer}: {e:?}, retrying", id);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

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

                    match Self::relay_tcp_with_cause(
                        &mut tcp,
                        proxy_stream,
                        "tun->proxy",
                        "proxy->tun",
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: up,
                                bytes_down: down,
                            });
                            break;
                        }
                        Err(relay_err) => {
                            warn!(
                                "proxy {:?} relay failed for {peer}: {relay_err:?}, retrying",
                                id
                            );
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: Some(relay_err.to_string()),
                                bytes_up: 0,
                                bytes_down: 0,
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

    /// Relay UDP datagrams between an IpStackUdpStream (TUN side) and a UdpLike tunnel.
    /// Returns (bytes_up, bytes_down) on clean termination.
    async fn relay_udp(
        tunnel: &mut dyn crate::uplink::proxy_adapters::UdpLike,
        udp: &mut IpStackUdpStream,
        peer: SocketAddr,
    ) -> Result<(u64, u64)> {
        use socks5_impl::protocol::WireAddress;
        use tokio::io::AsyncReadExt;

        let dst = WireAddress::SocketAddress(peer);
        let mut bytes_up: u64 = 0;
        let mut bytes_down: u64 = 0;
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                // TUN -> tunnel (upstream)
                result = udp.read(&mut buf) => {
                    let n = result?;
                    if n == 0 {
                        break;
                    }
                    tunnel.send_to(&buf[..n], dst.clone()).await
                        .map_err(|e| anyhow::anyhow!("UDP send_to failed: {}", e))?;
                    bytes_up += n as u64;
                }
                // tunnel -> TUN (downstream)
                result = tunnel.recv_from() => {
                    let pkt = result.map_err(|e| anyhow::anyhow!("UDP recv_from failed: {}", e))?;
                    let n = pkt.data.len();
                    udp.write_all(&pkt.data).await?;
                    bytes_down += n as u64;
                }
            }
        }

        Ok((bytes_up, bytes_down))
    }

    async fn relay_tcp_with_cause<A, B>(
        left: &mut A,
        right: &mut B,
        left_to_right_flow: &'static str,
        right_to_left_flow: &'static str,
    ) -> std::result::Result<(u64, u64), RelayError>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let (mut left_read, mut left_write) = tokio::io::split(left);
        let (mut right_read, mut right_write) = tokio::io::split(right);

        let up = async {
            let copied = tokio::io::copy(&mut left_read, &mut right_write)
                .await
                .map_err(|source| RelayError::Io {
                    flow: left_to_right_flow,
                    from: RelaySide::Left,
                    to: RelaySide::Right,
                    op: RelayOp::Copy,
                    source,
                })?;
            if let Err(e) = right_write.shutdown().await {
                if e.kind() != std::io::ErrorKind::BrokenPipe
                    && e.kind() != std::io::ErrorKind::ConnectionReset
                {
                    return Err(RelayError::Io {
                        flow: left_to_right_flow,
                        from: RelaySide::Left,
                        to: RelaySide::Right,
                        op: RelayOp::Shutdown,
                        source: e,
                    });
                }
            }
            Ok::<u64, RelayError>(copied)
        };

        let down = async {
            let copied = tokio::io::copy(&mut right_read, &mut left_write)
                .await
                .map_err(|source| RelayError::Io {
                    flow: right_to_left_flow,
                    from: RelaySide::Right,
                    to: RelaySide::Left,
                    op: RelayOp::Copy,
                    source,
                })?;
            if let Err(e) = left_write.shutdown().await {
                if e.kind() != std::io::ErrorKind::BrokenPipe
                    && e.kind() != std::io::ErrorKind::ConnectionReset
                {
                    return Err(RelayError::Io {
                        flow: right_to_left_flow,
                        from: RelaySide::Right,
                        to: RelaySide::Left,
                        op: RelayOp::Shutdown,
                        source: e,
                    });
                }
            }
            Ok::<u64, RelayError>(copied)
        };

        tokio::try_join!(up, down)
    }

    async fn tcp_direct(
        mut tcp: IpStackTcpStream,
        target: SocketAddr,
        diag: DiagServer,
        conn_id: ConnId,
    ) -> Result<()> {
        let mut remote = TcpStream::connect(target).await?;

        diag.emit(DiagEvent::Connected {
            id: conn_id.clone(),
            ts: Timestamp::now(),
        });

        match Self::relay_tcp_with_cause(&mut tcp, &mut remote, "tun->direct", "direct->tun").await
        {
            Ok((up, down)) => {
                diag.emit(DiagEvent::Finished {
                    id: conn_id.clone(),
                    ts: Timestamp::now(),
                    error: None,
                    bytes_up: up,
                    bytes_down: down,
                });
                debug!("TCP {:?} done: {} up, {} down", conn_id, up, down);
                Ok(())
            }
            Err(relay_err) => {
                diag.emit(DiagEvent::Finished {
                    id: conn_id,
                    ts: Timestamp::now(),
                    error: Some(relay_err.to_string()),
                    bytes_up: 0,
                    bytes_down: 0,
                });
                Err(anyhow::Error::new(relay_err))
            }
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

        tokio::spawn(async move {
            if let Err(e) =
                Self::handle_udp_inner(udp, uplink, dns_handle, diag.clone(), conn_id, conf).await
            {
                error!("UDP connection {:?} error: {:?}", conn_id, e);
                diag.emit(DiagEvent::Finished {
                    id: conn_id,
                    ts: Timestamp::now(),
                    error: Some(format!("{:?}", e)),
                    bytes_up: 0,
                    bytes_down: 0,
                });
            }
        });
    }

    async fn handle_udp_inner(
        mut udp: IpStackUdpStream,
        uplink: Arc<RwLock<UplinkHub>>,
        dns_handle: VirtDNSHandle,
        diag: DiagServer,
        conn_id: ConnId,
        conf: Arc<RwLock<HotConfig>>,
    ) -> Result<()> {
        let peer = udp.peer_addr();
        let local = udp.local_addr();

        // Check if this is DNS traffic destined for a captured range
        if peer.port() == DNS_PORT && conf.read().await.captures_dns(local.ip()) {
            return Self::handle_dns(udp, dns_handle, diag, conn_id).await;
        }

        let dns_result = dns_handle.process(peer);
        let target_domain = Self::extract_domain(&dns_result, peer.ip(), &conf).await;

        let dns_decision: Option<RoutingDecision> = match &dns_result {
            VDNSRES::SpecialHandling(TUNResponse::NATByTUN(sock)) => {
                Some(RoutingDecision::NATByTUN(*sock))
            }
            VDNSRES::SpecialHandling(TUNResponse::Direct(sock)) => {
                Some(RoutingDecision::Direct(*sock))
            }
            VDNSRES::SpecialHandling(TUNResponse::Files(path)) => Some(RoutingDecision::Proxy {
                target: WireAddress::SocketAddress(peer),
                id: ProxyID::for_file(path.as_path()),
            }),
            VDNSRES::SpecialHandling(TUNResponse::Unreachable) | VDNSRES::ERR => {
                Some(RoutingDecision::Drop(DropReason::Preprocess))
            }
            _ => None,
        };

        let mut ctx = RoutingContext {
            target_domain,
            target_ip: peer.ip(),
            target_port: peer.port(),
            source_ip: local.ip(),
            protocol: RoutingProtocol::Udp,
            tried_proxies: Default::default(),
            attempt_num: 0,
            dns: dns_decision,
        };

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

            match decision {
                RoutingDecision::Direct(addr) | RoutingDecision::NATByTUN(addr) => {
                    info!("UDP {:?} -> direct to {}", conn_id, addr);
                    use crate::uplink::proxy_adapters::NoProxyAdapter;
                    let mut remote = NoProxyAdapter::connect_udp(addr).await?;
                    match Self::relay_udp(remote.as_udp_mut().unwrap(), &mut udp, peer).await {
                        Ok((up, down)) => {
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: up,
                                bytes_down: down,
                            });
                            break;
                        }
                        Err(e) => {
                            warn!("direct UDP relay failed for {peer}: {e:?}, retrying");
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: Some(e.to_string()),
                                bytes_up: 0,
                                bytes_down: 0,
                            });
                            continue;
                        }
                    }
                }
                RoutingDecision::Drop(reason) => {
                    info!("UDP {:?} {:?}", conn_id, reason);
                    diag.emit(DiagEvent::Finished {
                        id: conn_id,
                        ts: Timestamp::now(),
                        error: None,
                        bytes_up: 0,
                        bytes_down: 0,
                    });
                    break;
                }
                RoutingDecision::Proxy { target, id } => {
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
                    let (target_host, target_port) = Self::wire_to_host_port(&target);

                    let conn_result = match &proxy {
                        UplinkProxy::Trojan(p) => {
                            TrojanAdapter::connect_udp(
                                p,
                                &target_host,
                                target_port,
                                p.server_addr.ip(),
                            )
                            .await
                        }
                        UplinkProxy::Remote(p) => RemoteAdapter::connect_udp(p).await,
                        _ => unreachable!(),
                    };

                    let mut conn = match conn_result {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("proxy {:?} connect failed for {peer}: {e:?}, retrying", id);
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            continue;
                        }
                    };

                    let tunnel = match conn.as_udp_mut() {
                        Some(t) => t,
                        None => bail!("proxy returned TCP connection for UDP stream"),
                    };

                    diag.emit(DiagEvent::Connected {
                        id: conn_id,
                        ts: Timestamp::now(),
                    });

                    match Self::relay_udp(tunnel, &mut udp, peer).await {
                        Ok((up, down)) => {
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: None,
                                bytes_up: up,
                                bytes_down: down,
                            });
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "proxy {:?} UDP relay failed for {peer}: {e:?}, retrying",
                                id
                            );
                            ctx.tried_proxies.insert(id);
                            ctx.attempt_num += 1;
                            diag.emit(DiagEvent::Finished {
                                id: conn_id,
                                ts: Timestamp::now(),
                                error: Some(e.to_string()),
                                bytes_up: 0,
                                bytes_down: 0,
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
        conf: &Arc<RwLock<HotConfig>>,
    ) -> Option<String> {
        let config = conf.read().await;
        for (domain, ip_str) in &config.dns {
            if let Ok(mapped_ip) = ip_str.parse::<IpAddr>() {
                if mapped_ip == target_ip {
                    return Some(domain.clone());
                }
            }
        }

        if let VDNSRES::SpecialHandling(response) = dns_result {
            match response {
                TUNResponse::ProxiedHost(domain) => {
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
}
