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
use bimap::BiHashMap;
use nsproxy_common::routing::{ProxyID, ProxyNym, RoutingContext, RoutingDecision, RoutingProtocol};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use tracing::{info, warn};
use tun2socks5::ArgProxy;
use tun2socks5::dns::{TUNResponse, VDNSRES, VirtDNSAsync, VirtDNSHandle};

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
        let parent = path.parent().ok_or_else(|| anyhow::anyhow!(
            "Invalid solved.json path: {:?}",
            path
        ))?;
        info!("Ensuring parent directory exists: {:?}", parent);
        std::fs::create_dir_all(parent).context("Failed to create uplink profile directory")?;
        let content = serde_json::to_string_pretty(self).context("Failed to serialize ProfileSolved")?;
        let bytes = content.len();
        std::fs::write(path, content).context(format!("Failed to write solved.json to {:?}", path))?;
        info!("Wrote {} bytes to {:?}", bytes, path);
        Ok(())
    }
}

/// Generic DNS resolver for routing DNS queries through any proxy connection
pub mod proxy_dns {
    use super::*;
    use super::proxy_adapters::{ProxyConnection, ProxyUdpTunnel, ProxyTcpStream};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use trust_dns_proto::op::{Message, Query};
    use trust_dns_proto::rr::{Name, RecordType};
    use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

    /// DNS query through a generic proxy connection (UDP or TCP)
    pub async fn query_via_proxy(
        connection: &mut ProxyConnection,
        dns_server: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Querying {} via proxy {} through DNS {}",
            domain,
            connection.info(),
            dns_server
        );

        // Build DNS query
        let name = Name::from_ascii(domain).context("Invalid domain name")?;
        let query = Query::query(name, RecordType::A);

        let mut msg = Message::new();
        msg.add_query(query);
        msg.set_id(rand::random());
        msg.set_recursion_desired(true);

        let query_bytes = msg.to_vec().context("Failed to serialize DNS query")?;

        // Parse DNS server address
        let dns_addr: WireAddress = if let Ok(ip) = dns_server.parse::<IpAddr>() {
            WireAddress::SocketAddress(SocketAddr::new(ip, 53))
        } else {
            WireAddress::DomainAddress(dns_server.to_string(), 53)
        };

        // Send DNS query and receive response based on connection type
        let response_bytes = if connection.is_datagram() {
            // UDP DNS query
            query_udp(connection, &query_bytes, dns_addr, timeout).await?
        } else {
            // TCP DNS query (with 2-byte length prefix)
            query_tcp(connection, &query_bytes, dns_addr, timeout).await?
        };

        // Parse DNS response
        let response = Message::from_bytes(&response_bytes).context("Failed to parse DNS response")?;

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

        info!("Resolved {} to {} addresses via {}", domain, ips.len(), connection.info());
        Ok(ips)
    }

    /// Perform UDP-based DNS query
    async fn query_udp(
        connection: &mut ProxyConnection,
        query_bytes: &[u8],
        dns_addr: WireAddress,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let tunnel = connection
            .as_udp_mut()
            .context("Expected UDP connection for datagram query")?;

        // Send DNS query
        tunnel
            .send_to(query_bytes, dns_addr)
            .await
            .context("Failed to send DNS query via UDP")?;

        // Receive response with timeout
        let packet = tokio::time::timeout(timeout, tunnel.recv_from())
            .await
            .context("DNS query timeout")??;

        
        Ok(packet.data)
    }

    /// Perform TCP-based DNS query (RFC 1035 - 2-byte length prefix)
    async fn query_tcp(
        connection: &mut ProxyConnection,
        query_bytes: &[u8],
        _dns_addr: WireAddress,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let stream = connection
            .as_tcp_mut()
            .context("Expected TCP connection for stream query")?;

        // DNS over TCP: send length prefix (2 bytes) + query
        let len = query_bytes.len() as u16;
        let mut buf = Vec::with_capacity(2 + query_bytes.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(query_bytes);

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

        Ok(response_buf)
    }
}

pub mod clash {
    use super::*;
    use bytes::BytesMut;
    use clash_bootstrap::{Bootstrapper, config::BootstrapConfig};
    use clash_config::Config;
    use rustls::pki_types::ServerName;
    use sha2::{Digest, Sha224};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use trojan_proto::{AddressRef, HostRef, write_request_header};

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

    /// Supported Trojan commands for stream setup
    #[derive(Clone, Copy, Debug)]
    pub enum TrojanCommand {
        /// TCP CONNECT (0x01)
        TcpConnect,
        /// UDP ASSOCIATE (0x03)
        UdpAssociate,
    }

    impl TrojanCommand {
        fn as_code(self) -> u8 {
            match self {
                TrojanCommand::TcpConnect => 0x01,
                TrojanCommand::UdpAssociate => 0x03,
            }
        }
    }

    /// After the Trojan handshake succeeds, the connection may become:
    ///
    /// - TcpConnect: Standard TCP proxying through Trojan
    /// - UdpAssociate: UDP tunneling over TCP+TLS through Trojan
    #[derive(Debug)]
    pub enum TrojanConnection {
        /// TCP connection through Trojan (CONNECT command)
        TcpConnect(TrojanTcpStream, WireAddress),
        /// UDP tunnel through Trojan (UDP ASSOCIATE command)
        UdpAssociate(TrojanUdpTunnel, WireAddress),
    }

    /// Wrapper for a TCP connection through Trojan proxy
    #[derive(Debug)]
    pub struct TrojanTcpStream(tokio_rustls::client::TlsStream<TcpStream>);

    /// Wrapper for UDP tunneling through Trojan proxy (UDP packets over TCP+TLS)
    #[derive(Debug)]
    pub struct TrojanUdpTunnel(tokio_rustls::client::TlsStream<TcpStream>);

    impl TrojanTcpStream {
        /// Get the inner TLS stream
        pub fn into_inner(self) -> tokio_rustls::client::TlsStream<TcpStream> {
            self.0
        }

        /// Get a reference to the inner TLS stream
        pub fn inner(&self) -> &tokio_rustls::client::TlsStream<TcpStream> {
            &self.0
        }

        /// Get a mutable reference to the inner TLS stream
        pub fn inner_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<TcpStream> {
            &mut self.0
        }
    }

    impl TrojanUdpTunnel {
        /// Get the inner TLS stream
        pub fn into_inner(self) -> tokio_rustls::client::TlsStream<TcpStream> {
            self.0
        }

        /// Get a reference to the inner TLS stream
        pub fn inner(&self) -> &tokio_rustls::client::TlsStream<TcpStream> {
            &self.0
        }

        /// Get a mutable reference to the inner TLS stream
        pub fn inner_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<TcpStream> {
            &mut self.0
        }
    }

    // Implement AsyncRead/AsyncWrite for TrojanTcpStream
    impl tokio::io::AsyncRead for TrojanTcpStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for TrojanTcpStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    // Implement AsyncRead/AsyncWrite for TrojanUdpTunnel
    impl tokio::io::AsyncRead for TrojanUdpTunnel {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for TrojanUdpTunnel {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl TrojanProxy {
        /// Create a SHA-224 hash of the password (as used by Trojan protocol)
        pub fn hash_password(password: &str) -> String {
            let mut hasher = Sha224::new();
            hasher.update(password.as_bytes());
            hex::encode(hasher.finalize())
        }

        /// Create a Trojan TCP connection (CONNECT)
        pub async fn connect(
            &self,
            server_ip: std::net::IpAddr,
            target_host: &str,
            target_port: u16,
        ) -> Result<TrojanConnection> {
            let target = WireAddress::DomainAddress(target_host.to_string(), target_port);
            let stream = self
                .connect_with_command(
                    server_ip,
                    target_host,
                    target_port,
                    TrojanCommand::TcpConnect,
                )
                .await?;
            Ok(TrojanConnection::TcpConnect(
                TrojanTcpStream(stream),
                target,
            ))
        }

        /// Create a Trojan UDP tunnel (UDP ASSOCIATE)
        ///
        /// Note: This returns a TCP+TLS stream that tunnels UDP packets.
        /// This is how Trojan protocol handles UDP - it tunnels UDP datagrams
        /// over a TLS-encrypted TCP connection.
        pub async fn connect_udp(
            &self,
            server_ip: std::net::IpAddr,
            target_host: &str,
            target_port: u16,
        ) -> Result<TrojanConnection> {
            let target = WireAddress::DomainAddress(target_host.to_string(), target_port);
            let stream = self
                .connect_with_command(
                    server_ip,
                    target_host,
                    target_port,
                    TrojanCommand::UdpAssociate,
                )
                .await?;
            Ok(TrojanConnection::UdpAssociate(
                TrojanUdpTunnel(stream),
                target,
            ))
        }

        /// Create a TLS-wrapped Trojan connection using a specific command
        async fn connect_with_command(
            &self,
            server_ip: std::net::IpAddr,
            target_host: &str,
            target_port: u16,
            command: TrojanCommand,
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
            let server_name =
                ServerName::try_from(self.server.clone()).context("Invalid server name for TLS")?;

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

            // Write the Trojan protocol request header (CONNECT = 0x01, UDP ASSOCIATE = 0x03)
            write_request_header(
                &mut buf,
                password_hash.as_bytes(),
                command.as_code(),
                &address,
            )
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
            let config =
                Config::try_from(yaml_path.clone()).context("Failed to parse Clash YAML config")?;

            let bootstrap_nameservers = config.dns.default_nameserver.clone();
            let main_nameservers = config.dns.nameserver.clone();

            let proxies = config
                .proxy
                .as_ref()
                .context("No proxies found in Clash config")?;

            let proxy_domains: Vec<String> = proxies
                .iter()
                .filter_map(|proxy| {
                    proxy
                        .get("server")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect();

            if proxy_domains.is_empty() {
                anyhow::bail!("No proxy servers found in config");
            }

            let profile_dir = state_paths::uplink_profile_dir("clash", profile_name);
            let dest_config = state_paths::uplink_profile_config("clash", profile_name);

            info!("Importing Clash profile '{}' into {:?}", profile_name, profile_dir);
            info!("Ensuring profile directory exists: {:?}", profile_dir);
            std::fs::create_dir_all(&profile_dir)
                .context("Failed to create clash profile directory")?;

            // Avoid copying file onto itself when caller already provided the state config path
            let skip_copy = match (yaml_path.canonicalize(), dest_config.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => yaml_path == &dest_config,
            };
            if skip_copy {
                info!("Source and destination identical; skipping config copy for {:?}", yaml_path);
            } else {
                info!("Copying config {:?} -> {:?}", yaml_path, dest_config);
                std::fs::copy(yaml_path, &dest_config).context("Failed to copy config file")?;
            }

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
            let config = Config::try_from(config_path).context("Failed to load Clash config")?;

            let proxies = config.proxy.as_ref().context("No proxies in config")?;

            let mut trojan_proxies = Vec::new();
            for proxy in proxies {
                let proxy_type = proxy.get("type").and_then(|v| v.as_str()).unwrap_or("");

                if proxy_type != "trojan" {
                    continue;
                }

                let name = proxy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let server = proxy
                    .get("server")
                    .and_then(|v| v.as_str())
                    .context("No server in trojan proxy")?
                    .to_string();

                let port = proxy
                    .get("port")
                    .context("No port in trojan proxy")
                    .and_then(|v| {
                        if let Some(port) = v.as_u64() {
                            Ok(port as u16)
                        } else if let Some(port) = v.as_str() {
                            port.parse::<u16>().context("Invalid port string")
                        } else {
                            anyhow::bail!("Invalid port type")
                        }
                    })?;

                let password = proxy
                    .get("password")
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

        /// Resolve all domains using two-tier DNS resolution through available proxies
        /// Returns a ProfileSolved with all resolved addresses
        ///
        /// This function tethers the bootstrapping process to UplinkHub when available, utilizing all
        /// proxy resources. DNS queries are sent through SOCKS5 UDP bindings when proxies are present.
        /// If no hub is provided, falls back to direct DNS resolution for initial setup.
        pub async fn resolve_domains(&self, hub: Option<&UplinkHub>) -> Result<ProfileSolved> {
            use std::time::Duration;

            let solved_path = state_paths::uplink_profile_solved("clash", &self.name);

            // Try to load existing ProfileSolved from state file first
            if let Ok(solved) = ProfileSolved::load_from_file(&solved_path) {
                info!("Loaded existing ProfileSolved from {:?}", solved_path);
                // Check if all required domains are already resolved
                if solved.all_resolved(&self.all_domains()) {
                    info!("All domains already resolved, using cached data");
                    return Ok(solved);
                }
                info!("Some domains missing, will re-resolve");
            }

            // If hub is available, use proxy-based DNS. Otherwise, fall back to direct DNS.
            if let Some(hub) = hub {
                self.resolve_domains_via_hub(hub, &solved_path).await
            } else {
                self.resolve_domains_direct(&solved_path).await
            }
        }

        /// Resolve domains through UplinkHub proxies (preferred method when proxies are available)
        async fn resolve_domains_via_hub(
            &self,
            hub: &UplinkHub,
            solved_path: &PathBuf,
        ) -> Result<ProfileSolved> {
            use std::time::Duration;

            let mut solved = ProfileSolved::new();
            let timeout = Duration::from_secs(5);

            info!("Bootstrapping DNS through UplinkHub proxies");
            info!("  Bootstrap DNS servers: {}", self.bootstrap_nameservers.len());
            info!("  Main DNS servers: {}", self.main_nameservers.len());

            // Step 1: Resolve main nameserver hostnames via bootstrap DNS through proxies
            info!("Resolving main nameserver hostnames via proxy connections...");
            for ns in &self.main_nameservers {
                if let Ok(url) = url::Url::parse(ns) {
                    if let Some(host) = url.host_str() {
                        if host.parse::<IpAddr>().is_err() {
                            // Use any bootstrap DNS server through available proxies
                            let mut resolved = false;
                            for bootstrap_dns in &self.bootstrap_nameservers {
                                // Note: Actual implementation requires creating a ProxyConnection
                                // This is a placeholder showing the intent - caller must provide connection
                                warn!(
                                    "DNS resolution via hub requires ProxyConnection - not yet implemented: {} via {}",
                                    host, bootstrap_dns
                                );
                                // TODO: Create ProxyConnection and call proxy_dns::query_via_proxy
                            }
                            if !resolved {
                                warn!(
                                    "Could not resolve {} via any bootstrap server",
                                    host
                                );
                            }
                        }
                    }
                }
            }

            // Step 2: Resolve proxy server domains via main DNS through proxies
            info!("Resolving proxy server domains via proxy connections...");
            for domain in &self.proxy_domains {
                let mut resolved = false;

                // Extract main DNS server hosts
                for ns in &self.main_nameservers {
                    let dns_host = if let Ok(url) = url::Url::parse(ns) {
                        url.host_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| ns.clone())
                    } else {
                        ns.clone()
                    };

                    // Use resolved IP if available, otherwise use the host directly
                    let dns_server = if let Ok(ip) = dns_host.parse::<IpAddr>() {
                        ip.to_string()
                    } else if let Some(ips) = solved.get_latest_ips(&dns_host) {
                        ips.iter()
                            .next()
                            .map(|ip| ip.to_string())
                            .unwrap_or(dns_host.clone())
                    } else {
                        dns_host.clone()
                    };

                    // Note: Actual implementation requires creating a ProxyConnection
                    // This is a placeholder showing the intent - caller must provide connection
                    warn!(
                        "DNS resolution via hub requires ProxyConnection - not yet implemented: {} via {}",
                        domain, dns_server
                    );
                    // TODO: Create ProxyConnection and call proxy_dns::query_via_proxy
                }

                if !resolved {
                    warn!("Could not resolve {} via main servers", domain);
                }
            }

            // Save to disk
            solved.save_to_file(solved_path)?;
            info!("Resolved addresses saved to {:?}", solved_path);

            Ok(solved)
        }

        /// Resolve domains directly (fallback for initial setup when no proxies are available)
        async fn resolve_domains_direct(&self, solved_path: &PathBuf) -> Result<ProfileSolved> {
            let mut solved = ProfileSolved::new();

            // Extract main nameserver hosts for two-tier configuration
            let main_nameserver_hosts: Vec<String> = self
                .main_nameservers
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

            // Build two-tier bootstrapper (direct DNS)
            let bootstrap_config = BootstrapConfig::with_bootstrap_and_main(
                self.bootstrap_nameservers
                    .iter()
                    .map(|s| s.as_str())
                    .collect(),
                main_nameserver_hosts.iter().map(|s| s.as_str()).collect(),
            )?;

            let bootstrapper = Bootstrapper::new(bootstrap_config)?;

            info!("Two-tier DNS bootstrapper created (direct resolution)");
            info!("  Bootstrap tier: {} nameservers", self.bootstrap_nameservers.len());
            info!("  Main tier: {} nameservers", self.main_nameservers.len());

            // Step 1: Resolve main nameserver hostnames via bootstrap tier
            info!("Resolving main nameserver hostnames...");
            for ns in &self.main_nameservers {
                if let Ok(url) = url::Url::parse(ns) {
                    if let Some(host) = url.host_str() {
                        if host.parse::<IpAddr>().is_err() {
                            match bootstrapper.resolve_all(host).await {
                                Ok(ips) => {
                                    let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                                    info!("Resolved {} -> {} IPs", host, ip_set.len());
                                    solved.add_resolution(host.to_string(), ip_set);
                                }
                                Err(e) => {
                                    warn!("Failed to resolve {}: {}", host, e);
                                }
                            }
                        }
                    }
                }
            }

            // Step 2: Resolve proxy server domains via main tier
            info!("Resolving proxy server domains...");
            for domain in &self.proxy_domains {
                match bootstrapper.resolve_all(domain).await {
                    Ok(ips) => {
                        let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                        info!("Resolved {} -> {} IPs", domain, ip_set.len());
                        solved.add_resolution(domain.clone(), ip_set);
                    }
                    Err(e) => {
                        warn!("Failed to resolve {}: {}", domain, e);
                    }
                }
            }

            // Save to disk
            solved.save_to_file(solved_path)?;
            info!("Resolved addresses saved to {:?}", solved_path);

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

/// Type alias for the routing decision function
/// Modify this function to customize routing behavior
pub type RoutingFunction = Arc<dyn Fn(&RoutingContext) -> RoutingDecision + Send + Sync>;

/// Central hub of all resources we have
pub struct UplinkHub {
    proxies: HashMap<ProxyID, UplinkProxy>,
    routing_fn: RoutingFunction,
    proxy_nym: BiHashMap<ProxyID, ProxyNym>,
}

pub enum UplinkProxy {
    Trojan(clash::TrojanProxy),
    Geph,
    Remote(ArgProxy),
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
            proxy_nym: BiHashMap::new(),
        }
    }

    /// Create a new UplinkHub with a custom routing function
    pub fn with_routing(routing_fn: RoutingFunction) -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn,
            proxy_nym: BiHashMap::new(),
        }
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
                    info!("Skipping unknown uplink kind '{}'; no loader registered", kind);
                }
            }
        }

        Ok(count)
    }

    /// Load all Clash proxies from saved profiles and add them to the hub
    /// This incrementally updates the hub's state with all available proxies
    pub fn load_clash_proxies(&mut self) -> Result<usize> {
        use crate::state_paths;
        
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
            let solved_path = state_paths::uplink_profile_solved("clash", &profile_name);

            if !config_path.exists() || !solved_path.exists() {
                warn!(
                    "Skipping profile {}: missing config ({}) or solved ({})",
                    profile_name,
                    config_path.exists(),
                    solved_path.exists()
                );
                continue;
            }

            let profile = clash::ClashProfile::import(&profile_name, &config_path)?;
            let solved = ProfileSolved::load_from_file(&solved_path)?;

            // Load proxies and add to hub
            let trojan_proxies = profile.load_trojan_proxies()?;
            for trojan_proxy in trojan_proxies {
                // Verify that we have resolved IPs for this proxy's server
                if solved.get_latest_ips(&trojan_proxy.server).is_some() {
                    let id = ProxyID::ClashName(trojan_proxy.name.clone());
                    self.add_proxy(id, UplinkProxy::Trojan(trojan_proxy));
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
    use bytes::{Buf, BufMut, BytesMut};
    use socks5_impl::client;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream};
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    /// UDP packet for datagram operations
    #[derive(Debug, Clone)]
    pub struct UdpPacket {
        pub data: Vec<u8>,
        pub dst_addr: WireAddress,
    }

    /// Trait for TCP proxy streams (unified interface for Trojan, SOCKS5, etc.)
    pub trait ProxyTcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
        fn info(&self) -> &str;
    }

    /// Trait for UDP proxy tunnels (unified interface for Trojan, SOCKS5, etc.)
    #[async_trait::async_trait]
    pub trait ProxyUdpTunnel: Send + Sync {
        async fn send_to(&mut self, data: &[u8], dst: WireAddress) -> std::io::Result<usize>;
        async fn recv_from(&mut self) -> std::io::Result<UdpPacket>;
        fn info(&self) -> &str;
    }

    /// Unified connection type that can handle both TCP streams and UDP tunnels
    pub enum ProxyConnection {
        /// TCP stream connection (Trojan, SOCKS5, etc.)
        Tcp(Box<dyn ProxyTcpStream>),
        /// UDP tunnel (Trojan, SOCKS5, etc.)
        Udp(Box<dyn ProxyUdpTunnel>),
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
        pub fn as_udp_mut(&mut self) -> Option<&mut dyn ProxyUdpTunnel> {
            match self {
                ProxyConnection::Udp(tunnel) => Some(tunnel.as_mut()),
                _ => None,
            }
        }

        /// Convert to mutable TCP stream reference
        pub fn as_tcp_mut(&mut self) -> Option<&mut dyn ProxyTcpStream> {
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

    impl ProxyTcpStream for TrojanTcpConn {
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
    impl ProxyUdpTunnel for TrojanUdpConn {
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

    impl ProxyTcpStream for Socks5TcpConn {
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

    // ==============================================================================
    // Adapters
    // ==============================================================================

    /// Adapter for creating Trojan proxy connections
    pub struct TrojanAdapter;

    impl TrojanAdapter {
        /// Create a Trojan connection (TCP or UDP tunnel)
        pub async fn connect(
            proxy: &clash::TrojanProxy,
            target_host: &str,
            target_port: u16,
            resolved_ip: std::net::IpAddr,
        ) -> anyhow::Result<ProxyConnection> {
            let conn = proxy.connect(resolved_ip, target_host, target_port).await?;
            match conn {
                clash::TrojanConnection::TcpConnect(stream, _target) => {
                    Ok(ProxyConnection::Tcp(Box::new(TrojanTcpConn {
                        inner: stream,
                        info: format!("trojan://{}:{}", proxy.server, proxy.port),
                    })))
                }
                clash::TrojanConnection::UdpAssociate(tunnel, _target) => {
                    Ok(ProxyConnection::Udp(Box::new(TrojanUdpConn {
                        inner: tunnel,
                        info: format!("trojan+udp://{}:{}", proxy.server, proxy.port),
                    })))
                }
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
                    let tcp = TcpStream::connect(proxy.addr).await?;
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

    // Backward compatibility with ProxyStream trait
    impl<T: ProxyTcpStream + ?Sized + 'static> ProxyStream for T {
        fn info(&self) -> &str {
            ProxyTcpStream::info(self)
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
                let ip = resolve_proxy_ip(&t.server).await?;
                TrojanAdapter::connect(t, &target_host, target_port, ip).await?
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
    let mut server = tokio::net::TcpStream::connect(server_addr).await?;
    let res = tokio::io::copy_bidirectional(&mut tcp_stack, &mut server).await?;
    Ok(res)
}

async fn handle_udp_nat(
    mut udp_stack: ipstack::stream::IpStackUdpStream,
    server_addr: SocketAddr,
) -> anyhow::Result<(u64, u64)> {
    let mut udp_server = udp_stream::UdpStream::connect(server_addr).await?;
    let res = tokio::io::copy_bidirectional(&mut udp_server, &mut udp_stack).await?;
    Ok(res)
}
