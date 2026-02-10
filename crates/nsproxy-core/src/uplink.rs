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
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use tun2socks5::dns::{VDNSRES, TUNResponse, VirtDNSAsync, VirtDNSHandle};
use tun2socks5::ArgProxy;
use tracing::warn;

use crate::state_paths;

/// Maximum number of concurrent virtual DNS entries (mirrors tun2socks5 default)
const POOL_SIZE: usize = 65_535;
const DNS_PORT: u16 = 53;

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
            .iter()
            .last()
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
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read solved.json from {:?}", path))?;
        serde_json::from_str(&content)
            .context("Failed to parse solved.json")
    }

    /// Save to a JSON file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        std::fs::create_dir_all(path.parent().unwrap())
            .context("Failed to create uplink profile directory")?;
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize ProfileSolved")?;
        std::fs::write(path, content)
            .context(format!("Failed to write solved.json to {:?}", path))
    }
}

pub mod clash {
    use super::*;
    use clash_bootstrap::{Bootstrapper, config::BootstrapConfig};
    use clash_config::Config;
    use bytes::BytesMut;
    use rustls::pki_types::ServerName;
    use sha2::{Sha224, Digest};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use trojan_proto::{write_request_header, AddressRef, HostRef};

    /// Clash-specific profile information
    #[derive(Debug, Clone)]
    pub struct ClashProfile {
        pub name: String,
        pub bootstrap_nameservers: Vec<String>,
        pub main_nameservers: Vec<String>,
        pub proxy_domains: Vec<String>,
    }

    /// Trojan proxy configuration
    #[derive(Debug, Clone)]
    pub struct TrojanProxy {
        pub name: String,
        pub server: String,
        pub port: u16,
        pub password: String,
    }

    impl TrojanProxy {
        /// Create a SHA-224 hash of the password (as used by Trojan protocol)
        pub fn hash_password(password: &str) -> String {
            let mut hasher = Sha224::new();
            hasher.update(password.as_bytes());
            hex::encode(hasher.finalize())
        }

        /// Create a TLS-wrapped Trojan connection
        pub async fn connect(
            &self,
            server_ip: std::net::IpAddr,
            target_host: &str,
            target_port: u16,
        ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
            // TCP connect using resolved IP
            let server_addr = SocketAddr::new(server_ip, self.port);
            let tcp_stream = TcpStream::connect(server_addr)
                .await
                .context(format!("Failed to connect to {}", server_addr))?;

            // TLS handshake
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let tls_connector = TlsConnector::from(Arc::new(tls_config));
            let server_name = ServerName::try_from(self.server.clone())
                .context("Invalid server name for TLS")?;

            let mut tls_stream = tls_connector
                .connect(server_name, tcp_stream)
                .await
                .context("TLS handshake failed")?;

            // Write Trojan protocol header
            let password_hash = Self::hash_password(&self.password);
            let mut buf = BytesMut::new();

            let address = AddressRef {
                host: HostRef::Domain(target_host.as_bytes()),
                port: target_port,
            };

            // Write the Trojan protocol request header (CONNECT command = 0x01)
            write_request_header(&mut buf, password_hash.as_bytes(), 0x01, &address)
                .map_err(|e| anyhow::anyhow!("Failed to write Trojan request header: {:?}", e))?;

            tls_stream
                .write_all(&buf)
                .await
                .context("Failed to write Trojan header")?;

            Ok(tls_stream)
        }
    }

    impl ClashProfile {
        /// Import a Clash profile from a YAML file
        pub fn import(profile_name: &str, yaml_path: &PathBuf) -> Result<Self> {
            let config = Config::try_from(yaml_path.clone())
                .context("Failed to parse Clash YAML config")?;

            let bootstrap_nameservers = config.dns.default_nameserver.clone();
            let main_nameservers = config.dns.nameserver.clone();

            let proxies = config.proxy.as_ref()
                .context("No proxies found in Clash config")?;

            let proxy_domains: Vec<String> = proxies
                .iter()
                .filter_map(|proxy| {
                    proxy.get("server")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect();

            if proxy_domains.is_empty() {
                anyhow::bail!("No proxy server domains found in config");
            }

            let profile_dir = state_paths::uplink_profile_dir("clash", profile_name);
            let dest_config = state_paths::uplink_profile_config("clash", profile_name);

            std::fs::create_dir_all(&profile_dir)
                .context("Failed to create clash profile directory")?;
            std::fs::copy(yaml_path, &dest_config)
                .context("Failed to copy config file")?;

            Ok(Self {
                name: profile_name.to_string(),
                bootstrap_nameservers,
                main_nameservers,
                proxy_domains,
            })
        }

        /// Load Trojan proxies from the config file
        pub fn load_trojan_proxies(&self) -> Result<Vec<TrojanProxy>> {
            let config_path = state_paths::uplink_profile_config("clash", &self.name);
            let config = Config::try_from(config_path)
                .context("Failed to load Clash config")?;

            let proxies = config.proxy.as_ref()
                .context("No proxies in config")?;

            let mut trojan_proxies = Vec::new();
            for proxy in proxies {
                let proxy_type = proxy.get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if proxy_type != "trojan" {
                    continue;
                }

                let name = proxy.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let server = proxy.get("server")
                    .and_then(|v| v.as_str())
                    .context("No server in trojan proxy")?
                    .to_string();

                let port = proxy.get("port")
                    .context("No port in trojan proxy")
                    .and_then(|v| {
                        if let Some(port) = v.as_u64() {
                            Ok(port as u16)
                        } else if let Some(port) = v.as_str() {
                            port.parse::<u16>()
                                .context("Invalid port string")
                        } else {
                            anyhow::bail!("Invalid port type")
                        }
                    })?;

                let password = proxy.get("password")
                    .and_then(|v| v.as_str())
                    .context("No password in trojan proxy")?
                    .to_string();

                trojan_proxies.push(TrojanProxy {
                    name,
                    server,
                    port,
                    password,
                });
            }

            if trojan_proxies.is_empty() {
                anyhow::bail!("No trojan proxies found in config");
            }

            Ok(trojan_proxies)
        }

        /// Get all domains that need to be resolved (both nameservers and proxies)
        pub fn all_domains(&self) -> Vec<String> {
            let mut domains = Vec::new();

            for ns in &self.main_nameservers {
                if let Ok(url) = url::Url::parse(ns) {
                    if let Some(host) = url.host_str() {
                        if !host.parse::<IpAddr>().is_ok() {
                            domains.push(host.to_string());
                        }
                    }
                }
            }

            domains.extend(self.proxy_domains.clone());
            domains
        }

        /// Resolve all domains using two-tier DNS resolution
        /// Returns a ProfileSolved with all resolved addresses
        pub async fn resolve_domains(&self) -> Result<ProfileSolved> {
            let mut solved = ProfileSolved::new();

            // Extract main nameserver hosts for two-tier configuration
            let main_nameserver_hosts: Vec<String> = self.main_nameservers
                .iter()
                .map(|ns| {
                    if let Ok(url) = url::Url::parse(ns) {
                        if let Some(host) = url.host_str() {
                            if let Some(port) = url.port() {
                                return format!("{}:{}", host, port);
                            }
                            return host.to_string();
                        }
                    }
                    ns.clone()
                })
                .collect();

            // Build two-tier bootstrapper
            let bootstrap_config = BootstrapConfig::with_bootstrap_and_main(
                self.bootstrap_nameservers.iter().map(|s| s.as_str()).collect(),
                main_nameserver_hosts.iter().map(|s| s.as_str()).collect(),
            )?;

            let bootstrapper = Bootstrapper::new(bootstrap_config)?;

            println!("Two-tier DNS bootstrapper created");
            println!("  Bootstrap tier: {} nameservers", self.bootstrap_nameservers.len());
            println!("  Main tier: {} nameservers", self.main_nameservers.len());

            // Step 1: Resolve main nameserver hostnames via bootstrap tier
            println!("\nResolving main nameserver hostnames...");
            for ns in &self.main_nameservers {
                if let Ok(url) = url::Url::parse(ns) {
                    if let Some(host) = url.host_str() {
                        if host.parse::<IpAddr>().is_err() {
                            match bootstrapper.resolve_all(host).await {
                                Ok(ips) => {
                                    let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                                    println!("  ✓ {} -> {} IPs", host, ip_set.len());
                                    solved.add_resolution(host.to_string(), ip_set);
                                }
                                Err(e) => {
                                    println!("  ⚠ {} -> ERROR: {}", host, e);
                                }
                            }
                        }
                    }
                }
            }

            // Step 2: Resolve proxy server domains via main tier
            println!("\nResolving proxy server domains...");
            for domain in &self.proxy_domains {
                match bootstrapper.resolve_all(domain).await {
                    Ok(ips) => {
                        let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                        println!("  ✓ {} -> {} IPs", domain, ip_set.len());
                        solved.add_resolution(domain.clone(), ip_set);
                    }
                    Err(e) => {
                        println!("  ⚠ {} -> ERROR: {}", domain, e);
                    }
                }
            }

            // Save to disk
            let solved_path = state_paths::uplink_profile_solved("clash", &self.name);
            solved.save_to_file(&solved_path)?;
            println!("\n✓ Resolved addresses saved to {:?}", solved_path);

            Ok(solved)
        }
    }
}

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

/// Context available during routing decision
#[derive(Debug, Clone)]
pub struct RoutingContext {
    /// Target domain name (if available)
    pub target_domain: Option<String>,
    /// Target IP address
    pub target_ip: std::net::IpAddr,
    /// Target port
    pub target_port: u16,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Protocol type (TCP or UDP)
    pub protocol: RoutingProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingProtocol {
    Tcp,
    Udp,
}

/// Result of routing decision — always carries a concrete target when proxying
#[derive(Clone, Debug)]
pub enum RoutingDecision {
    /// Warning: the connection is made by TUN process, which exists in SRC NS
    NATByTUN(SocketAddr),
    /// Direct connection to the given address
    Direct(SocketAddr),
    /// Route through a specific proxy identified in the UplinkHub, including full target info
    Proxy { target: WireAddress, id: ProxyID },
    Drop,
}

/// Type alias for the routing decision function
/// Modify this function to customize routing behavior
pub type RoutingFunction = Arc<dyn Fn(&RoutingContext) -> RoutingDecision + Send + Sync>;

/// Central hub of all resources we have
pub struct UplinkHub {
    proxies: HashMap<ProxyID, UplinkProxy>,
    routing_fn: RoutingFunction,
}

pub enum UplinkProxy {
    Clash(clash::TrojanProxy),
    Remote(ArgProxy),
    File(PathBuf),
}

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub enum ProxyID {
    ClashName(String),
    Remote(SocketAddr),
    File(PathBuf),
}

impl UplinkHub {
    /// Create a new UplinkHub with a default routing function
    pub fn new() -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn: Arc::new(|ctx| {
                RoutingDecision::Direct(SocketAddr::new(ctx.target_ip, ctx.target_port))
            }),
        }
    }

    /// Create a new UplinkHub with a custom routing function
    pub fn with_routing(routing_fn: RoutingFunction) -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn,
        }
    }

    /// Add a proxy to the hub
    pub fn add_proxy(&mut self, id: ProxyID, proxy: UplinkProxy) {
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

/// Converts a proxy instance into a unified stream type
pub mod proxy_adapters {
    use super::*;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufStream};
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;
    use socks5_impl::client;

    /// Adapter for Trojan proxies
    pub struct TrojanAdapter;

    /// Adapter for SOCKS5/4/HTTP proxies
    pub struct RemoteAdapter;

    struct TrojanStream {
        inner: TlsStream<TcpStream>,
        info: String,
    }

    struct RemoteStream {
        inner: BufStream<TcpStream>,
        info: String,
    }

    impl ProxyStream for TrojanStream {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl ProxyStream for RemoteStream {
        fn info(&self) -> &str {
            &self.info
        }
    }

    impl AsyncRead for TrojanStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TrojanStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl AsyncRead for RemoteStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for RemoteStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl TrojanAdapter {
        /// Create a stream for a Trojan proxy connection
        pub async fn connect(
            proxy: &clash::TrojanProxy,
            target_host: &str,
            target_port: u16,
            resolved_ip: std::net::IpAddr,
        ) -> anyhow::Result<Box<dyn ProxyStream>> {
            let stream = proxy.connect(resolved_ip, target_host, target_port).await?;
            Ok(Box::new(TrojanStream {
                inner: stream,
                info: format!("trojan://{}:{}", proxy.server, proxy.port),
            }))
        }
    }

    impl RemoteAdapter {
        /// Create a stream for a remote SOCKS/HTTP proxy connection
        pub async fn connect(
            proxy: &ArgProxy,
            target_host: &str,
            target_port: u16,
        ) -> anyhow::Result<Box<dyn ProxyStream>> {
            use tun2socks5::ProxyType;

            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    let tcp = TcpStream::connect(proxy.addr).await?;
                    let mut stream = BufStream::new(tcp);
                    let dest = WireAddress::DomainAddress(target_host.to_string(), target_port);
                    client::connect(&mut stream, dest, proxy.credentials.clone()).await?;
                    Ok(Box::new(RemoteStream {
                        inner: stream,
                        info: format!("socks5://{}", proxy.addr),
                    }))
                }
                ProxyType::Socks4 | ProxyType::Http => {
                    anyhow::bail!("proxy type {:?} not yet supported", proxy.proxy_type)
                }
            }
        }
    }
}

// ==============================================================================
// Routing Framework Configuration
// ==============================================================================

/// Builder pattern for creating routing functions with custom logic
pub struct RoutingBuilder {
    rules: Vec<(Box<dyn Fn(&RoutingContext) -> bool + Send + Sync>, RoutingDecision)>,
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
    st_sx: flume::Sender<(PathBuf, ipstack::stream::IpStackTcpStream)>,
    hub: Arc<UplinkHub>,
    diag_sock: Option<PathBuf>,
) -> anyhow::Result<()> {
    use ipstack::{IpStackConfig, stream::IpStackStream};
    use tracing::warn;
    use std::time::Duration;
    use ipstack::stream::tcp::TcpConfig;
    use diag::{DiagServer, DiagEvent, StreamKind, Timestamp, next_conn_id};
    use std::time::Instant;

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
        diag.emit(DiagEvent::Wait { id: wait_id, ts: Timestamp::now() });

        let ip_stack_stream = ip_stack.accept().await?;
        diag.emit(DiagEvent::WaitEnded { id: wait_id, ts: Timestamp::now() });

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
                    if let Err(e) = handle_tcp_connection(tcp, vh, hub, stream_sx, diagc, conn_id).await {
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
    use tun2socks5::dns::{VDNSRES, TUNResponse};

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

    let route_event = match &decision {
        RoutingDecision::Direct(addr) => diag::ConnRoute::Direct { dest: addr.to_string() },
        RoutingDecision::NATByTUN(addr) => diag::ConnRoute::Nat { dest: addr.to_string() },
        RoutingDecision::Proxy { id: ProxyID::File(path), .. } => diag::ConnRoute::FileServe { root: path.to_string_lossy().to_string() },
        RoutingDecision::Proxy { target, id } => {
            diag::ConnRoute::Proxied { dest: format!("{:?} -> {:?}", id, target) }
        }
        RoutingDecision::Drop => diag::ConnRoute::Unreachable,
    };

    diag.emit(diag::DiagEvent::Route {
        id: conn_id,
        ts: diag::Timestamp::now(),
        route: route_event,
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
        RoutingDecision::Proxy { target, id } => {
            match hub.get_proxy(&id) {
                Some(UplinkProxy::File(path)) => {
                    let _ = stream_sx.send_async((path.clone(), tcp)).await;
                }
                Some(_) => {
                    let res = handle_tcp_via_proxy(tcp, hub, id.clone(), target.clone(), diag.clone(), conn_id).await;
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
            }
        }
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
    use proxy_adapters::{RemoteAdapter, TrojanAdapter};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (target_host, target_port) = wire_to_host_port(&target);

    let stream: Box<dyn ProxyStream> = {
        let proxy = select_proxy(&hub, &id).await?;
        match proxy {
            UplinkProxy::Clash(t) => {
                let ip = resolve_proxy_ip(&t.server).await?;
                TrojanAdapter::connect(t, &target_host, target_port, ip).await?
            }
            UplinkProxy::Remote(arg) => {
                RemoteAdapter::connect(arg, &target_host, target_port).await?
            }
            UplinkProxy::File(path) => {
                anyhow::bail!("file proxy {:?} cannot proxy tcp", path)
            }
        }
    };

    let mut proxy_stream = stream;
    let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
    let (mut p_rx, mut p_tx) = tokio::io::split(proxy_stream);

    diag.emit(diag::DiagEvent::Connected { id: conn_id, ts: diag::Timestamp::now() });

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

    let route_event = match &decision {
        RoutingDecision::Direct(addr) => diag::ConnRoute::Direct { dest: addr.to_string() },
        RoutingDecision::NATByTUN(addr) => diag::ConnRoute::Nat { dest: addr.to_string() },
        RoutingDecision::Proxy { id: ProxyID::File(path), .. } => diag::ConnRoute::FileServe { root: path.to_string_lossy().to_string() },
        RoutingDecision::Proxy { target, id } => diag::ConnRoute::Proxied { dest: format!("{:?} -> {:?}", id, target) },
        RoutingDecision::Drop => diag::ConnRoute::Unreachable,
    };

    diag.emit(diag::DiagEvent::Route {
        id: conn_id,
        ts: diag::Timestamp::now(),
        route: route_event,
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
        RoutingDecision::Proxy { id: ProxyID::File(_), .. } => {
            warn!("udp file serving unsupported for {}", dest);
        }
        RoutingDecision::Proxy { id, .. } => {
            warn!("udp proxying not implemented for {:?}, dropping {}", id, dest);
        }
    }
    Ok(())
}

async fn handle_tcp_nat(mut tcp_stack: ipstack::stream::IpStackTcpStream, server_addr: SocketAddr) -> anyhow::Result<(u64, u64)> {
    let mut server = tokio::net::TcpStream::connect(server_addr).await?;
    let res = tokio::io::copy_bidirectional(&mut tcp_stack, &mut server).await?;
    Ok(res)
}

async fn handle_udp_nat(mut udp_stack: ipstack::stream::IpStackUdpStream, server_addr: SocketAddr) -> anyhow::Result<(u64, u64)> {
    let mut udp_server = udp_stream::UdpStream::connect(server_addr).await?;
    let res = tokio::io::copy_bidirectional(&mut udp_server, &mut udp_stack).await?;
    Ok(res)
}