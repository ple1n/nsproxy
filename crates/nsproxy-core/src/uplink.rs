//! # Uplink: Unified Proxy Management Framework
//!
//! This module provides a generalized framework for managing multiple proxy types and routing decisions.
//!
//! ## Key Components
//!
//! ### 1. UplinkHub
//! Central hub for managing all available proxies and routing decisions. You provide proxies and a routing function.
//!
//! ### 2. UplinkProxy
//! Enum representing different proxy types (Trojan, SOCKS5, HTTP, etc.)
//!
//! ### 3. RoutingContext & RoutingDecision
//! Simple framework exposed as a function where you can:
//! - Access target domain, IP, port, source IP, and protocol
//! - Return a routing decision: proxy to use, direct connection, or special handling
//!
//! ### 4. ProxyStream Trait
//! Unified interface that all proxies implement for stream-based communication
//!
//! ## Typical Usage Pattern
//!
//! ```ignore
//! // 1. Create a UplinkHub with custom routing logic
//! let routing = RoutingBuilder::new()
//!     .add_rule(|ctx| ctx.target_domain == Some("blocked.com".to_string()),
//!              RoutingDecision::Proxy { target: WireAddress::DomainAddress("blocked.com".into(), 443), id: ProxyID::ClashName("primary".into()) })
//!     .build();
//!
//! let mut hub = UplinkHub::with_routing(routing);
//!
//! // 2. Add proxies to the hub
//! hub.add_proxy(
//!     ProxyID::ClashName("primary".into()),
//!     UplinkProxy::Clash(trojan_proxy)
//! );
//!
//! // 3. Use the hub in main_entry
//! uplink::main_entry(device, mtu, packet_info, dns_sx, st_sx, Arc::new(hub)).await?;
//! ```
//!
//! ## Resilience & Footprint Philosophy
//! - We cache proxy server addresses to avoid repeated DNS lookups when entry points are censored
//! - We route proxy domain resolution through anonymous channels once available
//! - We never take the direct path when more secure/anonymous paths are available

// Uplink is the part of nsproxy where it acts as a client for various proxy protocols
// The apex of nsproxy's handling as a protocol client, is that it maximizes Resilience, and minimizes Footprint.
// We will cache the addresses of the proxy servers whenever possible; always assume our entry points will be censored at some point.
// We will route resolution of proxy servers' domains through anonymous channels once we have any; never take the direct path when more secure and anonymous ones are at hand.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use bimap::BiHashMap;
use nsproxy_common::routing::{
    ProxyID, ProxyNym, RoutingContext, RoutingDecision, RoutingProtocol,
};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use tracing::{info, warn};
use tun2socks5::ArgProxy;
use tun2socks5::dns::{TUNResponse, VDNSRES, VirtDNSAsync, VirtDNSHandle};

use crate::state_paths;

pub mod router;

/// Maximum number of concurrent virtual DNS entries (mirrors tun2socks5 default)
const POOL_SIZE: usize = 65_535;
const DNS_PORT: u16 = 53;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn ensure_rustls_crypto_provider() -> Result<()> {
    static TLS_PROVIDER_INIT: OnceLock<()> = OnceLock::new();

    if TLS_PROVIDER_INIT.get().is_some() || rustls::crypto::CryptoProvider::get_default().is_some()
    {
        let _ = TLS_PROVIDER_INIT.set(());
        return Ok(());
    }

    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => {
            let _ = TLS_PROVIDER_INIT.set(());
            Ok(())
        }
        Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => {
            let _ = TLS_PROVIDER_INIT.set(());
            Ok(())
        }
        Err(_) => anyhow::bail!(
            "Failed to initialize rustls CryptoProvider; call CryptoProvider::install_default() before TLS use"
        ),
    }
}

// IPs are not ever deleted here.
// Because its expected sometimes DNS servers pollute the records with junk
pub type DomainsSolved = BTreeMap<String, BTreeMap<u64, DNSResponse>>;

// Response of a single DNS packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSResponse {
    pub ips: BTreeSet<IpAddr>,
}

/// Profile is only considered usable once all domains are resolved to IPs.
/// We keep this data separately
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSolved {
    pub domains: DomainsSolved,
}

impl ProfileSolved {
    pub fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
        }
    }

    /// Add a resolved IP for a domain with current timestamp
    pub fn add_resolution(&mut self, domain: String, ips: BTreeSet<IpAddr>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.domains
            .entry(domain)
            .or_insert_with(BTreeMap::new)
            .insert(timestamp, DNSResponse { ips });
    }

    /// Get the most recent IPs for a domain
    pub fn get_latest_ips(&self, domain: &str) -> Option<&BTreeSet<IpAddr>> {
        self.domains
            .get(domain)?
            .last_key_value()
            .map(|(_, response)| &response.ips)
    }

    /// Check if all required domains are resolved
    pub fn all_resolved(&self, required_domains: &[String]) -> bool {
        required_domains
            .iter()
            .all(|domain| self.get_latest_ips(domain).is_some())
    }

    /// Load from a JSON file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        info!("Loading resolved addresses from {:?}", path);
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read solved.json from {:?}", path))?;
        info!("Read {} bytes from {:?}", content.len(), path);
        serde_json::from_str(&content).context("Failed to parse solved.json")
    }

    /// Save to a JSON file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        info!("Saving resolved addresses to {:?}", path);
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid solved.json path: {:?}", path))?;
        info!("Ensuring parent directory exists: {:?}", parent);
        std::fs::create_dir_all(parent).context("Failed to create uplink profile directory")?;
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize ProfileSolved")?;
        let bytes = content.len();
        std::fs::write(path, content)
            .context(format!("Failed to write solved.json to {:?}", path))?;
        info!("Wrote {} bytes to {:?}", bytes, path);
        Ok(())
    }
}

/// Generic DNS resolver for routing DNS queries through any proxy connection
pub mod proxy_dns {
    use super::proxy_adapters::{TcpLike, UdpLike};
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use trust_dns_proto::op::{Message, Query};
    use trust_dns_proto::rr::{Name, RecordType};
    use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

    fn build_dns_query(domain: &str) -> Result<Vec<u8>> {
        // Build DNS query
        let name = Name::from_ascii(domain).context("Invalid domain name")?;
        let query = Query::query(name, RecordType::A);

        let mut msg = Message::new();
        msg.add_query(query);
        msg.set_id(rand::random());
        msg.set_recursion_desired(true);

        msg.to_vec().context("Failed to serialize DNS query")
    }

    fn parse_dns_response(response_bytes: &[u8], domain: &str) -> Result<Vec<IpAddr>> {
        // Parse DNS response
        let response =
            Message::from_bytes(response_bytes).context("Failed to parse DNS response")?;

        let mut ips = Vec::new();
        for answer in response.answers() {
            if let Some(data) = answer.data() {
                if let Some(ip) = data.ip_addr() {
                    ips.push(ip);
                }
            }
        }

        if ips.is_empty() {
            anyhow::bail!("No IP addresses found for {}", domain);
        }

        Ok(ips)
    }

    /// DNS query over any UDP-like tunnel.
    pub async fn query_via_udp(
        tunnel: &mut (impl UdpLike + ?Sized),
        dns_server: &WireAddress,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Querying {} via {} through DNS {}",
            domain,
            tunnel.info(),
            dns_server
        );

        let query_bytes = build_dns_query(domain)?;

        // Send DNS query
        tunnel
            .send_to(&query_bytes, dns_server.clone())
            .await
            .context("Failed to send DNS query via UDP")?;

        // Receive response with timeout
        let packet = tokio::time::timeout(timeout, tunnel.recv_from())
            .await
            .context("DNS query timeout")??;

        let ips = parse_dns_response(&packet.data, domain)?;
        info!(
            "Resolved {} to {} addresses via {}",
            domain,
            ips.len(),
            tunnel.info()
        );
        Ok(ips)
    }

    /// DNS query over any TCP-like stream (RFC 1035 - 2-byte length prefix).
    pub async fn query_via_tcp(
        stream: &mut (impl TcpLike + ?Sized),
        dns_server: &WireAddress,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Querying {} via {} through DNS {}",
            domain,
            stream.info(),
            dns_server
        );

        let query_bytes = build_dns_query(domain)?;

        // DNS over TCP: send length prefix (2 bytes) + query
        let len = query_bytes.len() as u16;
        let mut buf = Vec::with_capacity(2 + query_bytes.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&query_bytes);

        tokio::time::timeout(timeout, stream.write_all(&buf))
            .await
            .context("Timeout writing DNS query")?
            .context("Failed to write DNS query via TCP")?;

        tokio::time::timeout(timeout, stream.flush())
            .await
            .context("Timeout flushing DNS query")?
            .context("Failed to flush DNS query")?;

        // Read response: first 2 bytes are length
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
            .await
            .context("Timeout reading DNS response length")?
            .context("Failed to read DNS response length")?;

        let response_len = u16::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];

        tokio::time::timeout(timeout, stream.read_exact(&mut response_buf))
            .await
            .context("Timeout reading DNS response data")?
            .context("Failed to read DNS response data")?;

        let ips = parse_dns_response(&response_buf, domain)?;
        info!(
            "Resolved {} to {} addresses via {}",
            domain,
            ips.len(),
            stream.info()
        );
        Ok(ips)
    }
}

pub mod clash;

// All uplink data is kept at /nsp3/uplink

use tokio::io::{AsyncRead, AsyncWrite};

/// Trait for a unified proxy stream interface
/// All proxy types (Trojan, SOCKS5, HTTP, etc.) implement this
pub trait ProxyStream: Send + Sync + 'static
where
    Self: AsyncRead + AsyncWrite + Unpin,
{
    /// Get information about this proxy stream
    fn info(&self) -> &str;
}

/// Type alias for the routing decision function
/// Modify this function to customize routing behavior
pub type RoutingFunction = Arc<dyn Fn(&RoutingContext) -> RoutingDecision + Send + Sync>;

/// Central hub of all resources we have
pub struct UplinkHub {
    proxies: HashMap<ProxyID, UplinkProxy>,
    routing_fn: RoutingFunction,
    proxy_nym: BiHashMap<ProxyID, ProxyNym>,
    /// Centralized Clash resolver/cache state loaded from /nsp3/clash.json
    clash: Option<clash::ClashState>,
    stats: HashMap<ProxyID, LinkStats>,
}

pub struct LinkStats {
    latency: Duration,
    latency_checked: Instant,
}

/// All proxies here should be immediately connectable without further resolution dependent on other state
pub enum UplinkProxy {
    Trojan(clash::TrojanProxy),
    Geph,
    Remote(ArgProxy),
    File(PathBuf),
}

impl std::fmt::Display for UplinkProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UplinkProxy::Trojan(t) => write!(
                f,
                "trojan {}@{}:{}",
                t.name,
                t.server_name,
                t.server_addr.port()
            ),
            UplinkProxy::Geph => write!(f, "geph"),
            UplinkProxy::Remote(arg) => write!(f, "remote {}", arg.addr),
            UplinkProxy::File(p) => write!(f, "file {}", p.display()),
        }
    }
}

impl UplinkHub {
    /// Create a new UplinkHub with a default routing function
    pub fn new() -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn: Arc::new(|ctx| {
                RoutingDecision::Direct(SocketAddr::new(ctx.target_ip, ctx.target_port))
            }),
            proxy_nym: BiHashMap::new(),
            clash: None,
            stats: HashMap::new(),
        }
    }

    /// Create a new UplinkHub with a custom routing function
    pub fn with_routing(routing_fn: RoutingFunction) -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn,
            proxy_nym: BiHashMap::new(),
            clash: None,
            stats: HashMap::new(),
        }
    }

    /// Hydrate hub from persisted state in one entrypoint:
    /// - loads centralized Clash state (`/nsp3/uplink/clash.json`)
    /// - loads all saved proxies that can be materialized from that state
    pub fn hydrate_from_persisted(&mut self) -> Result<usize> {
        let _ = self.load_clash_state()?;
        self.load_saved_proxies()
    }

    /// Load centralized Clash state from /nsp3/clash.json when not yet present.
    pub fn load_clash_state(&mut self) -> Result<&clash::ClashState> {
        if self.clash.is_none() {
            self.clash = Some(clash::ClashState::load_or_default()?);
        }
        Ok(self.clash.as_ref().expect("clash state must exist"))
    }

    /// Replace in-memory Clash state and persist it to /nsp3/clash.json.
    pub fn set_clash_state(&mut self, state: clash::ClashState) -> Result<()> {
        state.save_atomic()?;
        self.clash = Some(state);
        Ok(())
    }

    /// Add a proxy to the hub
    pub fn add_proxy(&mut self, id: ProxyID, proxy: UplinkProxy) {
        let nym = id.nym();
        self.proxy_nym.insert(id.clone(), nym);
        self.proxies.insert(id, proxy);
    }

    /// Get a proxy by ID
    pub fn get_proxy(&self, id: &ProxyID) -> Option<&UplinkProxy> {
        self.proxies.get(id)
    }

    /// Make a routing decision for the given context
    pub fn route(&self, ctx: &RoutingContext) -> RoutingDecision {
        (self.routing_fn)(ctx)
    }

    /// Set a new routing function
    pub fn set_routing(&mut self, routing_fn: RoutingFunction) {
        self.routing_fn = routing_fn;
    }

    /// Get all proxies
    pub fn all_proxies(&self) -> &HashMap<ProxyID, UplinkProxy> {
        &self.proxies
    }

    /// Get a proxy by its pseudonym (nym)
    pub fn get_proxy_by_nym(&self, nym: &ProxyNym) -> Option<(&ProxyID, &UplinkProxy)> {
        let id = self.proxy_nym.get_by_right(nym)?;
        let proxy = self.proxies.get(id)?;
        Some((id, proxy))
    }

    /// Get the nym for a proxy ID
    pub fn get_nym(&self, id: &ProxyID) -> Option<&ProxyNym> {
        self.proxy_nym.get_by_left(id)
    }

    /// Load all saved proxies across all uplink kinds
    pub fn load_saved_proxies(&mut self) -> Result<usize> {
        let uplink_root = state_paths::uplink_root();
        if !uplink_root.exists() {
            return Ok(0);
        }

        let kinds: Vec<_> = std::fs::read_dir(&uplink_root)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.path().is_dir())
            .collect();

        let mut count = 0;
        for entry in kinds {
            let kind = entry.file_name().to_string_lossy().to_string();
            match kind.as_str() {
                "clash" => {
                    count += self.load_clash_proxies()?;
                }
                _ => {
                    info!(
                        "Skipping unknown uplink kind '{}'; no loader registered",
                        kind
                    );
                }
            }
        }

        Ok(count)
    }

    /// Load all Clash proxies from saved profiles and add them to the hub
    /// This incrementally updates the hub's state with all available proxies
    pub fn load_clash_proxies(&mut self) -> Result<usize> {
        use crate::state_paths;

        let state_proxies = self.load_clash_state()?.proxies.clone();

        let uplink_dir = state_paths::uplink_dir("clash");
        if !uplink_dir.exists() {
            return Ok(0);
        }

        let profiles: Vec<_> = std::fs::read_dir(&uplink_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.path().is_dir())
            .collect();

        let mut count = 0;
        for entry in profiles {
            let profile_name = entry.file_name().to_string_lossy().to_string();
            let config_path = state_paths::uplink_profile_config("clash", &profile_name);

            if !config_path.exists() {
                warn!(
                    "Skipping profile {}: missing config ({})",
                    profile_name,
                    config_path.exists()
                );
                continue;
            }

            let profile = clash::ClashProfile::load_file(&profile_name, &config_path)?;

            // Load proxies (config entries) and add runtime proxies to hub when resolved
            let trojan_configs = profile.load_trojan_proxies()?;
            for cfg in trojan_configs {
                let resolved_ip = state_proxies
                    .get(&cfg.server)
                    .and_then(|responses| responses.last_key_value())
                    .and_then(|(_, response)| response.ips.iter().next().copied());

                if let Some(ip) = resolved_ip {
                    let runtime = clash::TrojanProxy {
                        name: cfg.name.clone(),
                        server_addr: SocketAddr::new(ip, cfg.port),
                        server_name: cfg.server.clone(),
                        password: cfg.password.clone(),
                    };
                    let id = ProxyID::ClashName(cfg.name.clone());
                    self.add_proxy(id, UplinkProxy::Trojan(runtime));
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

impl Default for UplinkHub {
    fn default() -> Self {
        Self::new()
    }
}

// ==============================================================================
// Handler Traits and Abstractions
// ==============================================================================

/// Handler for TCP connections
/// Implement this trait to customize TCP connection handling
pub trait TcpHandler: Send + Sync + 'static {
    /// Handle a TCP connection
    ///
    /// # Arguments
    /// * `addr` - The destination socket address
    /// * `stream` - The TCP stream from the client side
    /// * `routing_decision` - The routing decision from the hub
    fn handle(
        &self,
        addr: std::net::SocketAddr,
        stream: ipstack::stream::IpStackTcpStream,
        routing_decision: RoutingDecision,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;
}

/// Handler for UDP connections
pub trait UdpHandler: Send + Sync + 'static {
    /// Handle a UDP connection
    fn handle(
        &self,
        addr: std::net::SocketAddr,
        stream: ipstack::stream::IpStackUdpStream,
        routing_decision: RoutingDecision,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;
}

// ==============================================================================
// Stream Adapters for Different Proxy Types
// ==============================================================================

/// Kernel-style connection interface that supports both streaming and datagram operations
pub mod proxy_adapters {
    use super::*;
    use anyhow::Context as AnyhowContext;
    use bytes::{Buf, BufMut, BytesMut};
    use rustls::pki_types::ServerName;
    use socks5_impl::client;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::client::TlsStream;

    /// UDP packet for datagram operations
    #[derive(Debug, Clone)]
    pub struct UdpPacket {
        pub data: Vec<u8>,
        pub dst_addr: WireAddress,
    }

    /// Trait for TCP proxy streams (unified interface for Trojan, SOCKS5, unproxy, etc.)
    pub trait TcpLike: AsyncRead + AsyncWrite + Send + Sync + Unpin {
        fn info(&self) -> &str;
    }

    /// Trait for UDP proxy tunnels (unified interface for Trojan, SOCKS5, unproxy, etc)
    #[async_trait::async_trait]
    pub trait UdpLike: Send + Sync {
        async fn send_to(&mut self, data: &[u8], dst: WireAddress) -> std::io::Result<usize>;
        async fn recv_from(&mut self) -> std::io::Result<UdpPacket>;
        fn info(&self) -> &str;
    }

    /// Unified connection type that can handle both TCP streams and UDP tunnels
    pub enum ProxyConnection {
        /// TCP stream connection (Trojan, SOCKS5, etc.)
        Tcp(Box<dyn TcpLike>),
        /// UDP tunnel (Trojan, SOCKS5, etc.)
        Udp(Box<dyn UdpLike>),
    }

    impl ProxyConnection {
        /// Get connection info string
        pub fn info(&self) -> &str {
            match self {
                ProxyConnection::Tcp(conn) => conn.info(),
                ProxyConnection::Udp(conn) => conn.info(),
            }
        }

        /// Check if this connection supports datagram operations
        pub fn is_datagram(&self) -> bool {
            matches!(self, ProxyConnection::Udp(_))
        }

        /// Convert to mutable UDP tunnel reference
        pub fn as_udp_mut(&mut self) -> Option<&mut dyn UdpLike> {
            match self {
                ProxyConnection::Udp(tunnel) => Some(tunnel.as_mut()),
                _ => None,
            }
        }

        /// Convert to mutable TCP stream reference
        pub fn as_tcp_mut(&mut self) -> Option<&mut dyn TcpLike> {
            match self {
                ProxyConnection::Tcp(stream) => Some(stream.as_mut()),
                _ => None,
            }
        }
    }

    // ==============================================================================
    // Trojan Implementations
    // ==============================================================================

    /// Trojan TCP connection wrapper
    struct TrojanTcpConn {
        inner: clash::TrojanTcpStream,
        info: String,
    }

    impl TcpLike for TrojanTcpConn {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for TrojanTcpConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TrojanTcpConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Trojan UDP tunnel wrapper
    struct TrojanUdpConn {
        inner: clash::TrojanUdpTunnel,
        info: String,
    }

    #[async_trait::async_trait]
    impl UdpLike for TrojanUdpConn {
        /// Send a UDP packet through the tunnel
        /// Format: [SOCKS_ADDR][LENGTH:u16][CRLF][DATA]
        async fn send_to(&mut self, data: &[u8], dst: WireAddress) -> std::io::Result<usize> {
            let mut payload = BytesMut::new();

            // Write destination address
            match &dst {
                WireAddress::SocketAddress(addr) => {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        payload.put_u8(0x01);
                        payload.put_slice(&ipv4.octets());
                    } else if let std::net::IpAddr::V6(ipv6) = addr.ip() {
                        payload.put_u8(0x04);
                        payload.put_slice(&ipv6.octets());
                    }
                    payload.put_u16(addr.port());
                }
                WireAddress::DomainAddress(domain, port) => {
                    payload.put_u8(0x03);
                    payload.put_u8(domain.len() as u8);
                    payload.put_slice(domain.as_bytes());
                    payload.put_u16(*port);
                }
            }

            payload.put_u16(data.len() as u16);
            payload.put_slice(b"\r\n");
            payload.put_slice(data);

            self.inner.write_all(&payload).await?;
            self.inner.flush().await?;

            Ok(data.len())
        }

        /// Receive a UDP packet from the tunnel
        /// Format: [SOCKS_ADDR][LENGTH:u16][CRLF][DATA]
        async fn recv_from(&mut self) -> std::io::Result<UdpPacket> {
            let atyp = self.inner.read_u8().await?;

            let dst_addr = match atyp {
                0x01 => {
                    let mut buf = [0u8; 4];
                    self.inner.read_exact(&mut buf).await?;
                    let ip = std::net::Ipv4Addr::from(buf);
                    let port = self.inner.read_u16().await?;
                    WireAddress::SocketAddress(std::net::SocketAddr::new(ip.into(), port))
                }
                0x03 => {
                    let len = self.inner.read_u8().await?;
                    let mut domain = vec![0u8; len as usize];
                    self.inner.read_exact(&mut domain).await?;
                    let domain = String::from_utf8(domain)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    let port = self.inner.read_u16().await?;
                    WireAddress::DomainAddress(domain, port)
                }
                0x04 => {
                    let mut buf = [0u8; 16];
                    self.inner.read_exact(&mut buf).await?;
                    let ip = std::net::Ipv6Addr::from(buf);
                    let port = self.inner.read_u16().await?;
                    WireAddress::SocketAddress(std::net::SocketAddr::new(ip.into(), port))
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid address type: {}", atyp),
                    ));
                }
            };

            let data_len = self.inner.read_u16().await? as usize;

            let mut crlf = [0u8; 2];
            self.inner.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid CRLF in UDP packet",
                ));
            }

            let mut data = vec![0u8; data_len];
            self.inner.read_exact(&mut data).await?;

            Ok(UdpPacket { data, dst_addr })
        }

        fn info(&self) -> &str {
            &self.info
        }
    }

    // ==============================================================================
    // SOCKS5 Implementations
    // ==============================================================================

    /// SOCKS5 TCP connection wrapper
    struct Socks5TcpConn {
        inner: BufStream<TcpStream>,
        info: String,
    }

    impl TcpLike for Socks5TcpConn {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for Socks5TcpConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Socks5TcpConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Direct TCP connection wrapper (no proxy)
    struct DirectTcpConn {
        inner: TcpStream,
        info: String,
    }

    impl TcpLike for DirectTcpConn {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for DirectTcpConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DirectTcpConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Direct TLS connection wrapper (no proxy)
    struct DirectTlsConn {
        inner: TlsStream<TcpStream>,
        info: String,
    }

    impl TcpLike for DirectTlsConn {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for DirectTlsConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DirectTlsConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Direct UDP tunnel wrapper (no proxy)
    struct DirectUdpConn {
        socket: UdpSocket,
        info: String,
    }

    async fn resolve_wire_address(dst: &WireAddress) -> std::io::Result<SocketAddr> {
        match dst {
            WireAddress::SocketAddress(sock) => Ok(*sock),
            WireAddress::DomainAddress(host, port) => {
                warn!(
                    "Using direct tokio DNS resolve via lookup_host for {}:{}",
                    host, port
                );
                let mut iter = tokio::net::lookup_host((host.as_str(), *port)).await?;
                iter.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("No IP found for {}:{}", host, port),
                    )
                })
            }
        }
    }

    #[async_trait::async_trait]
    impl UdpLike for DirectUdpConn {
        async fn send_to(&mut self, data: &[u8], dst: WireAddress) -> std::io::Result<usize> {
            let dst_sock = resolve_wire_address(&dst).await?;
            self.socket.send_to(data, dst_sock).await
        }

        async fn recv_from(&mut self) -> std::io::Result<UdpPacket> {
            let mut buf = vec![0u8; 4096];
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok(UdpPacket {
                data: buf,
                dst_addr: WireAddress::SocketAddress(src),
            })
        }

        fn info(&self) -> &str {
            &self.info
        }
    }

    // ==============================================================================
    // TLS over TcpLike (clash-rs style)
    // ==============================================================================

    /// Global root certificate store (clash-rs style).
    /// Loaded once and reused for all TLS connections.
    static GLOBAL_ROOT_STORE: std::sync::LazyLock<Arc<rustls::RootCertStore>> =
        std::sync::LazyLock::new(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(root_store)
        });

    /// TLS client config matching clash-rs behavior:
    /// - Mozilla root CA store (`webpki_roots`) loaded globally
    /// - SNI enabled (default) for proper certificate verification
    /// - ALPN set to `["h2"]` for HTTP/2 (DoH standard)
    static TLS_CONFIG: std::sync::LazyLock<Arc<rustls::ClientConfig>> =
        std::sync::LazyLock::new(|| {
            super::ensure_rustls_crypto_provider().unwrap();

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates((*GLOBAL_ROOT_STORE).clone())
                .with_no_client_auth();

            config.alpn_protocols = vec!["h2".into()];

            Arc::new(config)
        });

    /// Custom certificate verifier that allows IP addresses as server names.
    ///
    /// This is needed because standard WebPKI verification doesn't support IP
    /// addresses in server names (returns UnsupportedNameType). When that error
    /// occurs, this verifier allows the connection to proceed while still
    /// performing all other certificate validation.
    ///
    /// Matches clash-rs's NoHostnameTlsVerifier implementation.
    #[derive(Debug)]
    struct NoHostnameTlsVerifier(Arc<rustls::client::WebPkiServerVerifier>);

    impl NoHostnameTlsVerifier {
        fn new() -> Self {
            Self(
                rustls::client::WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                    .build()
                    .unwrap(),
            )
        }
    }

    impl rustls::client::danger::ServerCertVerifier for NoHostnameTlsVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            intermediates: &[rustls::pki_types::CertificateDer<'_>],
            server_name: &rustls::pki_types::ServerName<'_>,
            ocsp_response: &[u8],
            now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            match self.0.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Err(rustls::Error::UnsupportedNameType) => {
                    warn!(
                        "Skipping TLS cert name verification for server name: {:?}",
                        server_name
                    );
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }
                other => other,
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.supported_verify_schemes()
        }
    }

    /// TLS-over-TcpLike stream wrapper.
    /// The inner stream is a `TlsStream` over a boxed `TcpLike`,
    /// so it works with any underlying transport (Trojan, SOCKS5, direct, etc.)
    struct TlsOverTcpLikeConn {
        inner: TlsStream<Box<dyn TcpLike>>,
        info: String,
    }

    impl TcpLike for TlsOverTcpLikeConn {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for TlsOverTcpLikeConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TlsOverTcpLikeConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Wrap any `TcpLike` stream in TLS using clash-rs style configuration.
    ///
    /// Uses the shared `TLS_CONFIG` which matches clash-rs behavior:
    /// - SNI enabled for proper certificate verification
    /// - h2 ALPN (required for DoH over HTTP/2)
    /// - Mozilla root CA store (loaded globally)
    /// - Custom verifier for IP literals (like clash-rs)
    ///
    /// When hostname is an IP address, uses NoHostnameTlsVerifier to allow
    /// the connection (standard PKI doesn't support IP addresses in certs).
    ///
    /// This provides perfect functional equivalence with clash-rs TLS handshake.
    pub async fn wrap_tls_for_doh(
        stream: Box<dyn TcpLike>,
        hostname: ServerName<'static>,
        info_prefix: &str,
    ) -> anyhow::Result<Box<dyn TcpLike>> {
        info!("TLS handshake with {:?}", hostname);

        // Check if hostname is an IP address by trying to parse it
        match &hostname {
            ServerName::DnsName(dns) => {
                return wrap_tls_default(stream, hostname, info_prefix).await;
            }
            ServerName::IpAddress(ip) => {
                return wrap_tls_with_custom_verifier(stream, hostname, info_prefix).await;
            }
            _ => {
                return wrap_tls_default(stream, hostname, info_prefix).await;
            }
        };
    }

    /// TLS handshake with default configuration (standard PKI verification)
    async fn wrap_tls_default(
        stream: Box<dyn TcpLike>,
        hostname: ServerName<'static>,
        info_prefix: &str,
    ) -> anyhow::Result<Box<dyn TcpLike>> {
        let mut conf = TLS_CONFIG.clone();
        let connector = TlsConnector::from(conf);

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(hostname.clone(), stream),
        )
        .await
        .context("Timeout during TLS handshake")??;

        Ok(Box::new(TlsOverTcpLikeConn {
            inner: tls_stream,
            info: format!("{}+tls", info_prefix),
        }))
    }

    /// TLS handshake with custom verifier for IP addresses
    async fn wrap_tls_with_custom_verifier(
        stream: Box<dyn TcpLike>,
        hostname: ServerName<'static>,
        info_prefix: &str,
    ) -> anyhow::Result<Box<dyn TcpLike>> {
        warn!(
            "Hostname {:?} is an IP address; using custom TLS verifier to allow connection",
            hostname
        );

        super::ensure_rustls_crypto_provider()?;

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates((*GLOBAL_ROOT_STORE).clone())
            .with_no_client_auth();

        tls_config.alpn_protocols = vec!["h2".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoHostnameTlsVerifier::new()));
        tls_config.enable_sni = true;

        let connector = TlsConnector::from(Arc::new(tls_config));

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(hostname.clone(), stream),
        )
        .await
        .context("Timeout during TLS handshake with custom verifier")??;

        Ok(Box::new(TlsOverTcpLikeConn {
            inner: tls_stream,
            info: format!("{}+tls", info_prefix),
        }))
    }

    // ==============================================================================
    // Adapters
    // ==============================================================================

    /// Adapter for creating Trojan proxy connections
    pub struct TrojanAdapter;

    impl TrojanAdapter {
        /// Create a Trojan connection
        pub async fn connect_tcp(
            proxy: &clash::TrojanProxy,
            target_host: &str,
            target_port: u16,
            resolved_ip: std::net::IpAddr,
        ) -> anyhow::Result<ProxyConnection> {
            info!(
                "Preparing Trojan connection to {}:{} via {} ({})",
                target_host, target_port, proxy.server_name, resolved_ip
            );
            let conn = proxy
                .connect_tcp(resolved_ip, target_host, target_port)
                .await?;
            match conn {
                clash::TrojanConnection::TcpConnect(stream, _target) => {
                    Ok(ProxyConnection::Tcp(Box::new(TrojanTcpConn {
                        inner: stream,
                        info: format!(
                            "trojan://{}:{}",
                            proxy.server_name,
                            proxy.server_addr.port()
                        ),
                    })))
                }
                _ => unreachable!(),
            }
        }

        /// Create a Trojan UDP tunnel explicitly (UDP ASSOCIATE)
        pub async fn connect_udp(
            proxy: &clash::TrojanProxy,
            target_host: &str,
            target_port: u16,
            resolved_ip: std::net::IpAddr,
        ) -> anyhow::Result<ProxyConnection> {
            info!(
                "Preparing Trojan UDP-associate to {}:{} via {} ({})",
                target_host, target_port, proxy.server_name, resolved_ip
            );
            let conn = proxy
                .connect_udp(resolved_ip, target_host, target_port)
                .await?;
            match conn {
                clash::TrojanConnection::UdpAssociate(tunnel, _target) => {
                    Ok(ProxyConnection::Udp(Box::new(TrojanUdpConn {
                        inner: tunnel,
                        info: format!(
                            "trojan+udp://{}:{}",
                            proxy.server_name,
                            proxy.server_addr.port()
                        ),
                    })))
                }
                _ => unreachable!(),
            }
        }
    }

    /// Adapter for creating SOCKS5/4/HTTP proxy connections
    pub struct RemoteAdapter;

    impl RemoteAdapter {
        /// Create a SOCKS5 connection
        pub async fn connect(
            proxy: &ArgProxy,
            target_host: &str,
            target_port: u16,
        ) -> anyhow::Result<ProxyConnection> {
            use tun2socks5::ProxyType;

            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    info!("Opening SOCKS5 TCP connection to proxy {}", proxy.addr);
                    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy.addr))
                        .await
                        .context("Timeout connecting to SOCKS5 proxy")??;
                    let mut stream = BufStream::new(tcp);
                    let dest = WireAddress::DomainAddress(target_host.to_string(), target_port);
                    client::connect(&mut stream, dest, proxy.credentials.clone()).await?;
                    Ok(ProxyConnection::Tcp(Box::new(Socks5TcpConn {
                        inner: stream,
                        info: format!("socks5://{}", proxy.addr),
                    })))
                }
                ProxyType::Socks4 | ProxyType::Http => {
                    anyhow::bail!("proxy type {:?} not yet supported", proxy.proxy_type)
                }
            }
        }
    }

    /// Adapter for creating direct (no-proxy) connections
    pub struct NoProxyAdapter;

    impl NoProxyAdapter {
        pub async fn connect_tcp(target: SocketAddr) -> anyhow::Result<ProxyConnection> {
            info!("Opening direct TCP connection to {}", target);
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
                .await
                .context("Timeout connecting direct TCP target")??;
            Ok(ProxyConnection::Tcp(Box::new(DirectTcpConn {
                inner: stream,
                info: format!("direct+tcp://{}", target),
            })))
        }

        pub async fn connect_udp(target: SocketAddr) -> anyhow::Result<ProxyConnection> {
            let bind_addr = if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            info!(
                "Opening direct UDP socket for target {} (bind {})",
                target, bind_addr
            );
            let socket = UdpSocket::bind(bind_addr).await?;
            Ok(ProxyConnection::Udp(Box::new(DirectUdpConn {
                socket,
                info: format!("direct+udp://{}", target),
            })))
        }

        pub async fn connect_tls(
            hostname: ServerName<'static>,
            target: SocketAddr,
        ) -> anyhow::Result<ProxyConnection> {
            info!(
                "Opening direct TLS connection to {:?} ({})",
                &hostname, target
            );
            let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
                .await
                .context("Timeout connecting direct TLS target")??;

            ensure_rustls_crypto_provider()?;

            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            tls_config.enable_sni = false;
            tls_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

            let tls_connector = TlsConnector::from(Arc::new(tls_config));

            info!("Starting direct TLS handshake with {}", target);
            let tls_stream = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                tls_connector.connect(hostname.clone(), tcp_stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(
                        "Direct TLS handshake failed for {} ({:?}): {}",
                        target, hostname, e
                    );
                    return Err(e).context("Direct TLS handshake failed");
                }
                Err(e) => {
                    warn!(
                        "Timeout during direct TLS handshake for {} ({:?}): {}",
                        target, hostname, e
                    );
                    return Err(anyhow::Error::new(e))
                        .context("Timeout during direct TLS handshake");
                }
            };

            Ok(ProxyConnection::Tcp(Box::new(DirectTlsConn {
                inner: tls_stream,
                info: format!("direct+tls://{}", target),
            })))
        }
    }

    // Backward compatibility with ProxyStream trait
    impl<T: TcpLike + ?Sized + 'static> ProxyStream for T {
        fn info(&self) -> &str {
            TcpLike::info(self)
        }
    }
}

// ==============================================================================
// Routing Framework Configuration
// ==============================================================================

/// Builder pattern for creating routing functions with custom logic
pub struct RoutingBuilder {
    rules: Vec<(
        Box<dyn Fn(&RoutingContext) -> bool + Send + Sync>,
        RoutingDecision,
    )>,
    default_decision: Option<RoutingDecision>,
}

impl RoutingBuilder {
    /// Create a new routing builder with a default direct routing
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_decision: None,
        }
    }

    /// Add a routing rule (condition -> decision)
    pub fn add_rule<F>(mut self, condition: F, decision: RoutingDecision) -> Self
    where
        F: Fn(&RoutingContext) -> bool + Send + Sync + 'static,
    {
        self.rules.push((Box::new(condition), decision));
        self
    }

    /// Set the default routing decision
    pub fn default_route(mut self, decision: RoutingDecision) -> Self {
        self.default_decision = Some(decision);
        self
    }

    /// Build the routing function
    pub fn build(self) -> RoutingFunction {
        let rules = self.rules;
        let default_decision = self.default_decision;

        Arc::new(move |ctx: &RoutingContext| -> RoutingDecision {
            for (condition, decision) in &rules {
                if condition(ctx) {
                    return decision.clone();
                }
            }
            if let Some(ref decision) = default_decision {
                decision.clone()
            } else {
                RoutingDecision::Direct(SocketAddr::new(ctx.target_ip, ctx.target_port))
            }
        })
    }
}

impl Default for RoutingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Main entry point for handling connections through the uplink
///
/// This is the refactored version that works with UplinkHub.
/// IArgs is gone — all configuration comes from the UplinkHub state.
///
/// Architecture:
/// 1. Initializes DNS and diagnostic infrastructure
/// 2. Sets up IpStack to accept connections
/// 3. For each connection, uses routing function to decide proxy
/// 4. Handles TCP and UDP separately with appropriate proxying
pub async fn main_entry(
    device: ipstack::TUNDev,
    mtu: u16,
    packet_info: bool,
    mut dns_sx: tokio::sync::mpsc::Sender<Option<VirtDNSHandle>>,
    // Streams designated for static file serving
    st_sx: flume::Sender<(PathBuf, ipstack::stream::IpStackTcpStream)>,
    hub: Arc<UplinkHub>,
    diag_sock: Option<PathBuf>,
) -> anyhow::Result<()> {
    use diag::{DiagEvent, DiagServer, StreamKind, Timestamp, next_conn_id};
    use ipstack::stream::tcp::TcpConfig;
    use ipstack::{IpStackConfig, stream::IpStackStream};
    use std::time::Duration;
    use std::time::Instant;
    use tracing::warn;

    // Phase 1: Initialize diagnostic infrastructure
    let diag = if let Some(sock) = diag_sock.as_ref() {
        match DiagServer::start(sock.as_path()).await {
            Ok(d) => d,
            Err(e) => {
                warn!("diag server failed to start: {e}");
                DiagServer::noop()
            }
        }
    } else {
        DiagServer::noop()
    };

    // Phase 2: Initialize DNS system (virtual DNS only, same as tun2socks5 default)
    let vdns = VirtDNSAsync::default(POOL_SIZE)?;
    let vh = vdns.handle.clone();

    // Phase 3: Hand off DNS handle
    let _ = dns_sx.send(Some(vh.clone())).await;

    // Phase 4: Initialize IpStack
    let conf = IpStackConfig {
        mtu,
        packet_information: packet_info,
        udp_timeout: Duration::from_secs(20),
        tcp_config: Arc::new(TcpConfig::default()),
    };
    let mut ip_stack = ipstack::IpStack::new(conf, device);

    // Phase 5: Main connection loop
    loop {
        let wait_id = next_conn_id();
        diag.emit(DiagEvent::Wait {
            id: wait_id,
            ts: Timestamp::now(),
        });

        let ip_stack_stream = ip_stack.accept().await?;
        diag.emit(DiagEvent::WaitEnded {
            id: wait_id,
            ts: Timestamp::now(),
        });

        let conn_id = next_conn_id();
        let body_start = Instant::now();

        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                diag.emit(DiagEvent::Accept {
                    id: conn_id,
                    ts: Timestamp::now(),
                    kind: StreamKind::Tcp,
                    src: tcp.local_addr().to_string(),
                    dst: tcp.peer_addr().to_string(),
                });

                let vh = vh.clone();
                let hub = hub.clone();
                let stream_sx = st_sx.clone();
                let diagc = diag.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_tcp_connection(tcp, vh, hub, stream_sx, diagc, conn_id).await
                    {
                        warn!("tcp handling error: {e:?}");
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                diag.emit(DiagEvent::Accept {
                    id: conn_id,
                    ts: Timestamp::now(),
                    kind: StreamKind::Udp,
                    src: udp.local_addr().to_string(),
                    dst: udp.peer_addr().to_string(),
                });

                let vh = vh.clone();
                let hub = hub.clone();
                let diagc = diag.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_udp_connection(udp, vh, hub, diagc, conn_id).await {
                        warn!("udp handling error: {e:?}");
                    }
                });
            }
        }

        diag.emit(DiagEvent::Dispatched {
            id: conn_id,
            dispatch_us: body_start.elapsed().as_micros() as u64,
        });
    }
}

async fn resolve_proxy_ip(host: &str) -> anyhow::Result<IpAddr> {
    warn!(
        "Using direct tokio DNS resolve via lookup_host for proxy host {}",
        host
    );
    let mut iter = tokio::net::lookup_host((host, 0)).await?;
    iter.next()
        .map(|sock| sock.ip())
        .ok_or_else(|| anyhow::anyhow!("failed to resolve proxy host {host}"))
}

fn wire_to_host_port(addr: &WireAddress) -> (String, u16) {
    match addr {
        WireAddress::SocketAddress(sock) => (sock.ip().to_string(), sock.port()),
        WireAddress::DomainAddress(host, port) => (host.clone(), *port),
    }
}

#[derive(Debug, Clone)]
struct DnsOutcome {
    target_domain: Option<String>,
    decision: Option<RoutingDecision>,
}

fn preprocess_vdns(vh: &VirtDNSHandle, dest: SocketAddr) -> DnsOutcome {
    use tun2socks5::dns::{TUNResponse, VDNSRES};

    match vh.process(dest) {
        VDNSRES::SpecialHandling(TUNResponse::ProxiedHost(host)) => DnsOutcome {
            target_domain: Some(host),
            decision: None,
        },
        VDNSRES::SpecialHandling(TUNResponse::NATByTUN(sock)) => DnsOutcome {
            target_domain: None,
            decision: Some(RoutingDecision::NATByTUN(sock)),
        },
        VDNSRES::SpecialHandling(TUNResponse::Direct(sock)) => DnsOutcome {
            target_domain: None,
            decision: Some(RoutingDecision::Direct(sock)),
        },
        VDNSRES::SpecialHandling(TUNResponse::Files(path)) => DnsOutcome {
            target_domain: None,
            decision: Some(RoutingDecision::Proxy {
                target: WireAddress::SocketAddress(dest),
                id: ProxyID::File(path),
            }),
        },
        VDNSRES::SpecialHandling(TUNResponse::Unreachable) => DnsOutcome {
            target_domain: None,
            decision: Some(RoutingDecision::Drop),
        },
        VDNSRES::SpecialHandling(TUNResponse::SpecifiedProxy(addr, proxy)) => {
            let id = ProxyID::Remote(proxy.addr);
            DnsOutcome {
                target_domain: None,
                decision: Some(RoutingDecision::Proxy { target: addr, id }),
            }
        }
        VDNSRES::NormalProxying => DnsOutcome {
            target_domain: None,
            decision: None,
        },
        VDNSRES::ERR => DnsOutcome {
            target_domain: None,
            decision: Some(RoutingDecision::Drop),
        },
    }
}

async fn handle_tcp_connection(
    tcp: ipstack::stream::IpStackTcpStream,
    vh: VirtDNSHandle,
    hub: Arc<UplinkHub>,
    stream_sx: flume::Sender<(PathBuf, ipstack::stream::IpStackTcpStream)>,
    diag: diag::DiagServer,
    conn_id: diag::ConnId,
) -> anyhow::Result<()> {
    let dest = tcp.peer_addr();
    let src = tcp.local_addr();
    let dns = preprocess_vdns(&vh, dest);

    let decision = dns.decision.unwrap_or_else(|| {
        let ctx = RoutingContext {
            target_domain: dns.target_domain.clone(),
            target_ip: dest.ip(),
            target_port: dest.port(),
            source_ip: src.ip(),
            protocol: RoutingProtocol::Tcp,
        };
        hub.route(&ctx)
    });

    diag.emit(diag::DiagEvent::Route {
        id: conn_id,
        ts: diag::Timestamp::now(),
        route: decision.clone(),
    });

    match decision {
        RoutingDecision::Direct(addr) | RoutingDecision::NATByTUN(addr) => {
            let res = handle_tcp_nat(tcp, addr).await;
            match res {
                Ok((up, down)) => {
                    diag.emit(diag::DiagEvent::Finished {
                        id: conn_id,
                        ts: diag::Timestamp::now(),
                        error: None,
                        bytes_up: up,
                        bytes_down: down,
                    });
                }
                Err(e) => {
                    diag.emit(diag::DiagEvent::Finished {
                        id: conn_id,
                        ts: diag::Timestamp::now(),
                        error: Some(format!("{e:?}")),
                        bytes_up: 0,
                        bytes_down: 0,
                    });
                    return Err(e);
                }
            }
        }
        RoutingDecision::Proxy { target, id } => match hub.get_proxy(&id) {
            Some(UplinkProxy::File(path)) => {
                let _ = stream_sx.send_async((path.clone(), tcp)).await;
            }
            Some(_) => {
                let res = handle_tcp_via_proxy(
                    tcp,
                    hub,
                    id.clone(),
                    target.clone(),
                    diag.clone(),
                    conn_id,
                )
                .await;
                if let Err(e) = &res {
                    diag.emit(diag::DiagEvent::Finished {
                        id: conn_id,
                        ts: diag::Timestamp::now(),
                        error: Some(format!("{e:?}")),
                        bytes_up: 0,
                        bytes_down: 0,
                    });
                }
                res?;
            }
            None => {
                warn!("proxy {:?} not found for {}", id, dest);
                diag.emit(diag::DiagEvent::Finished {
                    id: conn_id,
                    ts: diag::Timestamp::now(),
                    error: Some("proxy not found".into()),
                    bytes_up: 0,
                    bytes_down: 0,
                });
            }
        },
        RoutingDecision::Drop => {
            warn!("tcp unreachable for {}", dest);
            diag.emit(diag::DiagEvent::Finished {
                id: conn_id,
                ts: diag::Timestamp::now(),
                error: None,
                bytes_up: 0,
                bytes_down: 0,
            });
        }
    }

    Ok(())
}

async fn select_proxy<'a>(hub: &'a UplinkHub, id: &'a ProxyID) -> anyhow::Result<&'a UplinkProxy> {
    hub.get_proxy(id)
        .ok_or_else(|| anyhow::anyhow!("proxy {:?} not found", id))
}

async fn handle_tcp_via_proxy(
    mut tcp: ipstack::stream::IpStackTcpStream,
    hub: Arc<UplinkHub>,
    id: ProxyID,
    target: WireAddress,
    diag: diag::DiagServer,
    conn_id: diag::ConnId,
) -> anyhow::Result<()> {
    use proxy_adapters::{ProxyConnection, RemoteAdapter, TrojanAdapter};
    use tokio::io::AsyncWriteExt;

    let (target_host, target_port) = wire_to_host_port(&target);

    let mut conn = {
        let proxy = select_proxy(&hub, &id).await?;
        match proxy {
            UplinkProxy::Trojan(t) => {
                // runtime proxies already carry a resolved `server_addr`
                let ip = t.server_addr.ip();
                TrojanAdapter::connect_tcp(t, &target_host, target_port, ip).await?
            }
            UplinkProxy::Remote(arg) => {
                RemoteAdapter::connect(arg, &target_host, target_port).await?
            }
            UplinkProxy::File(path) => {
                anyhow::bail!("file proxy {:?} cannot proxy tcp", path)
            }
            _ => unimplemented!(),
        }
    };

    diag.emit(diag::DiagEvent::Connected {
        id: conn_id,
        ts: diag::Timestamp::now(),
    });

    // Extract TCP stream or fail if UDP
    let mut proxy_stream = match conn {
        ProxyConnection::Tcp(ref mut stream) => stream.as_mut(),
        ProxyConnection::Udp(_) => {
            anyhow::bail!("UDP connection cannot handle TCP stream")
        }
    };

    // Bidirectional copy
    let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
    let (mut p_rx, mut p_tx) = tokio::io::split(proxy_stream);

    let res = tokio::try_join!(
        async {
            let copied = tokio::io::copy(&mut t_rx, &mut p_tx).await?;
            p_tx.shutdown().await?;
            anyhow::Ok(copied)
        },
        async {
            let copied = tokio::io::copy(&mut p_rx, &mut t_tx).await?;
            t_tx.shutdown().await?;
            anyhow::Ok(copied)
        }
    );

    match res {
        Ok((up, down)) => {
            diag.emit(diag::DiagEvent::Finished {
                id: conn_id,
                ts: diag::Timestamp::now(),
                error: None,
                bytes_up: up,
                bytes_down: down,
            });
        }
        Err(e) => {
            diag.emit(diag::DiagEvent::Finished {
                id: conn_id,
                ts: diag::Timestamp::now(),
                error: Some(format!("{e:?}")),
                bytes_up: 0,
                bytes_down: 0,
            });
            return Err(e);
        }
    }
    Ok(())
}

async fn handle_udp_connection(
    mut udp: ipstack::stream::IpStackUdpStream,
    vh: VirtDNSHandle,
    hub: Arc<UplinkHub>,
    diag: diag::DiagServer,
    conn_id: diag::ConnId,
) -> anyhow::Result<()> {
    let dest = udp.peer_addr();
    let src = udp.local_addr();
    let dns = preprocess_vdns(&vh, dest);
    let decision = dns.decision.unwrap_or_else(|| {
        let ctx = RoutingContext {
            target_domain: dns.target_domain.clone(),
            target_ip: dest.ip(),
            target_port: dest.port(),
            source_ip: src.ip(),
            protocol: RoutingProtocol::Udp,
        };
        hub.route(&ctx)
    });

    diag.emit(diag::DiagEvent::Route {
        id: conn_id,
        ts: diag::Timestamp::now(),
        route: decision.clone(),
    });

    match decision {
        RoutingDecision::Direct(addr) | RoutingDecision::NATByTUN(addr) => {
            let res = handle_udp_nat(udp, addr).await;
            match res {
                Ok((up, down)) => {
                    diag.emit(diag::DiagEvent::Finished {
                        id: conn_id,
                        ts: diag::Timestamp::now(),
                        error: None,
                        bytes_up: up,
                        bytes_down: down,
                    });
                }
                Err(e) => {
                    diag.emit(diag::DiagEvent::Finished {
                        id: conn_id,
                        ts: diag::Timestamp::now(),
                        error: Some(format!("{e:?}")),
                        bytes_up: 0,
                        bytes_down: 0,
                    });
                    return Err(e);
                }
            }
        }
        RoutingDecision::Drop => {
            diag.emit(diag::DiagEvent::Finished {
                id: conn_id,
                ts: diag::Timestamp::now(),
                error: None,
                bytes_up: 0,
                bytes_down: 0,
            });
        }
        RoutingDecision::Proxy {
            id: ProxyID::File(_),
            ..
        } => {
            warn!("udp file serving unsupported for {}", dest);
        }
        RoutingDecision::Proxy { id, .. } => {
            warn!(
                "udp proxying not implemented for {:?}, dropping {}",
                id, dest
            );
        }
    }
    Ok(())
}

async fn handle_tcp_nat(
    mut tcp_stack: ipstack::stream::IpStackTcpStream,
    server_addr: SocketAddr,
) -> anyhow::Result<(u64, u64)> {
    info!("Opening direct TCP NAT connection to {}", server_addr);
    let mut server =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(server_addr))
            .await
            .context("Timeout connecting direct TCP NAT target")??;
    let res = tokio::io::copy_bidirectional(&mut tcp_stack, &mut server).await?;
    Ok(res)
}

async fn handle_udp_nat(
    mut udp_stack: ipstack::stream::IpStackUdpStream,
    server_addr: SocketAddr,
) -> anyhow::Result<(u64, u64)> {
    info!("Opening direct UDP NAT connection to {}", server_addr);
    let mut udp_server = udp_stream::UdpStream::connect(server_addr).await?;
    let res = tokio::io::copy_bidirectional(&mut udp_server, &mut udp_stack).await?;
    Ok(res)
}
