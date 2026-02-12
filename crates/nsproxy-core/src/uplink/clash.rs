use super::*;
use crate::state_blueprint::PersistentState;
use bytes::BytesMut;
use clash_config::Config;
use rustls::pki_types::ServerName;
use anyhow::Context;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::ReadBuf;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use trojan_proto::{AddressRef, HostRef, write_request_header};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
// Shorter alias for the commonly used TLS stream type
type TokioTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Clash-specific profile information
#[derive(Debug, Clone)]
pub struct ClashProfile {
    pub name: String,
    pub bootstrap_nameservers: Vec<String>,
    pub main_nameservers: Vec<String>,
    pub proxy_domains: Vec<String>,
}

/// Trojan proxy configuration as read from Clash config
#[derive(Debug, Clone)]
pub struct TrojanConfig {
    pub name: String,
    /// server as provided in config (domain or IP string) - used for SNI and resolving
    pub server: String,
    pub port: u16,
    pub password: String,
}

/// Runtime Trojan proxy with resolved socket address and preserved SNI name
#[derive(Debug, Clone)]
pub struct TrojanProxy {
    pub name: String,
    /// Resolved server socket address (IP + port)
    pub server_addr: SocketAddr,
    /// Original server name (domain or IP string) for SNI and lookup
    pub server_name: String,
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
pub struct TrojanTcpStream(TokioTlsStream);

/// Wrapper for UDP tunneling through Trojan proxy (UDP packets over TCP+TLS)
#[derive(Debug)]
pub struct TrojanUdpTunnel(TokioTlsStream);

impl TrojanTcpStream {
    /// Get the inner TLS stream
    pub fn into_inner(self) -> TokioTlsStream {
        self.0
    }

    /// Get a reference to the inner TLS stream
    pub fn inner(&self) -> &TokioTlsStream {
        &self.0
    }

    /// Get a mutable reference to the inner TLS stream
    pub fn inner_mut(&mut self) -> &mut TokioTlsStream {
        &mut self.0
    }
}

impl TrojanUdpTunnel {
    /// Get the inner TLS stream
    pub fn into_inner(self) -> TokioTlsStream {
        self.0
    }

    /// Get a reference to the inner TLS stream
    pub fn inner(&self) -> &TokioTlsStream {
        &self.0
    }

    /// Get a mutable reference to the inner TLS stream
    pub fn inner_mut(&mut self) -> &mut TokioTlsStream {
        &mut self.0
    }
}

// Implement AsyncRead/AsyncWrite for TrojanTcpStream
impl tokio::io::AsyncRead for TrojanTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TrojanTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// Implement AsyncRead/AsyncWrite for TrojanUdpTunnel
impl tokio::io::AsyncRead for TrojanUdpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TrojanUdpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
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
        // TCP connect using resolved IP and the configured port from runtime proxy
        let server_addr = SocketAddr::new(server_ip, self.server_addr.port());
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
            ServerName::try_from(self.server_name.clone()).context("Invalid server name for TLS")?;

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
    pub fn load_file(profile_name: &str, yaml_path: &PathBuf) -> Result<Self> {
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

    /// Load Trojan proxies from the config file (returns config-level entries)
    pub fn load_trojan_proxies(&self) -> Result<Vec<TrojanConfig>> {
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

            trojan_proxies.push(TrojanConfig {
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

    /// Solve profile using provided `ClashState` and optional `UplinkHub`.
    /// Returns a structured report with domains and path metrics.
    pub async fn solve_file(&self, state: &mut ClashState, hub: Option<&UplinkHub>) -> Result<ResolveProfileReport> {
        state.resolve_profile(self, hub).await
    }

}

// ============================================================================
// New shared Clash state (tier1 / tier2 cache)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionTargetKind {
    ProxyDomain,
    Tier2DnsDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionPath {
    ProxyTier2,
    ProxyTier1,
    DirectTier2,
    DirectTier1,
}

pub struct ResolutionPolicy;

impl ResolutionPolicy {
    pub fn paths_for(target: ResolutionTargetKind) -> &'static [ResolutionPath] {
        match target {
            ResolutionTargetKind::ProxyDomain => &[
                ResolutionPath::ProxyTier2,
                ResolutionPath::ProxyTier1,
                ResolutionPath::DirectTier2,
            ],
            ResolutionTargetKind::Tier2DnsDomain => &[
                ResolutionPath::ProxyTier2,
                ResolutionPath::ProxyTier1,
                ResolutionPath::DirectTier2,
                ResolutionPath::DirectTier1,
            ],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionMetrics {
    pub cache_hits: usize,
    pub resolved_proxy_tier2: usize,
    pub resolved_proxy_tier1: usize,
    pub resolved_direct_tier2: usize,
    pub resolved_direct_tier1: usize,
    pub unresolved: usize,
}

impl ResolutionMetrics {
    fn mark_resolved(&mut self, path: ResolutionPath) {
        match path {
            ResolutionPath::ProxyTier2 => self.resolved_proxy_tier2 += 1,
            ResolutionPath::ProxyTier1 => self.resolved_proxy_tier1 += 1,
            ResolutionPath::DirectTier2 => self.resolved_direct_tier2 += 1,
            ResolutionPath::DirectTier1 => self.resolved_direct_tier1 += 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolveProfileReport {
    pub solved: ProfileSolved,
    pub metrics: ResolutionMetrics,
}

enum PathAttempt {
    Resolved(BTreeSet<IpAddr>),
    Skipped,
    Failed(anyhow::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClashState {
    pub schema_version: u32,
    pub tier1_nameservers: Vec<WireAddress>, // direct IP/domain nameservers
    pub tier2_nameservers: Vec<WireAddress>, 
    pub tier2_cache: DomainsSolved,
    pub proxies: DomainsSolved
}

impl ClashState {
    pub fn path() -> PathBuf {
        <Self as PersistentState>::path()
    }

    pub fn load_or_default() -> Result<Self> {
        <Self as PersistentState>::load_or_default()
    }

    pub fn save_atomic(&self) -> Result<()> {
        <Self as PersistentState>::save_atomic(self)
    }

    /// Return the newest cached tier2 nameserver-host resolution.
    pub fn get_latest_ips(&self, host: &str) -> Option<&BTreeSet<IpAddr>> {
        self.tier2_cache
            .get(host)?
            .last_key_value()
            .map(|(_, response)| &response.ips)
    }

    /// Update tier2 nameserver-host cache.
    pub fn update_cache(&mut self, host: &str, ips: BTreeSet<IpAddr>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.tier2_cache
            .entry(host.to_string())
            .or_insert_with(BTreeMap::new)
            .insert(now, DNSResponse { ips });
    }

    /// Store latest resolved proxy-domain IPs in the centralized clash state.
    pub fn add_proxy_resolution(&mut self, domain: &str, ips: BTreeSet<IpAddr>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.proxies
            .entry(domain.to_string())
            .or_insert_with(BTreeMap::new)
            .insert(now, DNSResponse { ips });
    }

    /// Get latest resolved proxy-domain IPs from centralized clash state.
    pub fn get_latest_proxy_ips(&self, domain: &str) -> Option<&BTreeSet<IpAddr>> {
        self.proxies
            .get(domain)?
            .last_key_value()
            .map(|(_, response)| &response.ips)
    }

    fn cached_for_target(&self, target: ResolutionTargetKind, domain: &str) -> Option<BTreeSet<IpAddr>> {
        let map = match target {
            ResolutionTargetKind::ProxyDomain => &self.proxies,
            ResolutionTargetKind::Tier2DnsDomain => &self.tier2_cache,
        };

        map.get(domain)
            .and_then(|responses| responses.last_key_value())
            .map(|(_, response)| response.ips.clone())
    }

    fn store_target_resolution(
        &mut self,
        target: ResolutionTargetKind,
        domain: &str,
        ips: BTreeSet<IpAddr>,
    ) {
        match target {
            ResolutionTargetKind::ProxyDomain => self.add_proxy_resolution(domain, ips),
            ResolutionTargetKind::Tier2DnsDomain => self.update_cache(domain, ips),
        }
    }

    fn parse_nameserver(raw: &str) -> Result<WireAddress> {
        if let Ok(url) = url::Url::parse(raw) {
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("URL nameserver missing host: {}", raw))?;
            let port = url.port_or_known_default().unwrap_or(53);
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(WireAddress::SocketAddress(SocketAddr::new(ip, port)));
            }
            return Ok(WireAddress::DomainAddress(host.to_string(), port));
        }

        if let Ok(sock) = raw.parse::<SocketAddr>() {
            return Ok(WireAddress::SocketAddress(sock));
        }

        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Ok(WireAddress::SocketAddress(SocketAddr::new(ip, 53)));
        }

        Ok(WireAddress::DomainAddress(raw.to_string(), 53))
    }

    fn parse_nameserver_list(values: &[String]) -> Result<Vec<WireAddress>> {
        values
            .iter()
            .map(|s| Self::parse_nameserver(s))
            .collect()
    }

    fn nameserver_query_hosts(nameservers: &[WireAddress]) -> Vec<String> {
        nameservers
            .iter()
            .map(|ns| match ns {
                WireAddress::SocketAddress(sock) => sock.ip().to_string(),
                WireAddress::DomainAddress(host, _) => host.clone(),
            })
            .collect()
    }

    fn has_proxy_resolvers(hub: &UplinkHub) -> bool {
        hub.all_proxies().values().any(|proxy| {
            matches!(proxy, UplinkProxy::Trojan(_) | UplinkProxy::Remote(_))
        })
    }

    fn wire_host_port(wire: &WireAddress) -> (String, u16) {
        match wire {
            WireAddress::SocketAddress(sock) => (sock.ip().to_string(), sock.port()),
            WireAddress::DomainAddress(host, port) => (host.clone(), *port),
        }
    }

    async fn resolve_wire_socket_addr(wire: &WireAddress) -> Result<SocketAddr> {
        match wire {
            WireAddress::SocketAddress(sock) => Ok(*sock),
            WireAddress::DomainAddress(host, port) => {
                let mut iter = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .context(format!("Failed to resolve nameserver {}:{}", host, port))?;
                iter.next()
                    .ok_or_else(|| anyhow::anyhow!("No IP found for nameserver {}:{}", host, port))
            }
        }
    }

    fn build_dns_query(domain: &str) -> Result<Vec<u8>> {
        let name = Name::from_ascii(domain).context("Invalid domain name")?;
        let query = Query::query(name, RecordType::A);

        let mut msg = Message::new();
        msg.add_query(query);
        msg.set_id(rand::random());
        msg.set_recursion_desired(true);

        msg.to_vec().context("Failed to serialize DNS query")
    }

    fn parse_dns_response(response_bytes: &[u8], domain: &str) -> Result<Vec<IpAddr>> {
        let response = Message::from_bytes(response_bytes).context("Failed to parse DNS response")?;
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

    async fn query_dns_direct_udp(
        nameserver: SocketAddr,
        query_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let bind_addr = if nameserver.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind UDP socket for DNS query")?;

        tokio::time::timeout(timeout, socket.send_to(query_bytes, nameserver))
            .await
            .context("Timeout sending UDP DNS query")?
            .context("Failed sending UDP DNS query")?;

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
            .await
            .context("Timeout receiving UDP DNS response")?
            .context("Failed receiving UDP DNS response")?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn query_dns_direct_tcp(
        nameserver: SocketAddr,
        query_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(nameserver))
            .await
            .context("Timeout connecting TCP DNS server")?
            .context("Failed connecting TCP DNS server")?;

        let len = query_bytes.len() as u16;
        let mut request = Vec::with_capacity(2 + query_bytes.len());
        request.extend_from_slice(&len.to_be_bytes());
        request.extend_from_slice(query_bytes);

        tokio::time::timeout(timeout, stream.write_all(&request))
            .await
            .context("Timeout writing TCP DNS query")?
            .context("Failed writing TCP DNS query")?;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
            .await
            .context("Timeout reading TCP DNS response length")?
            .context("Failed reading TCP DNS response length")?;

        let response_len = u16::from_be_bytes(len_buf) as usize;
        let mut response = vec![0u8; response_len];
        tokio::time::timeout(timeout, stream.read_exact(&mut response))
            .await
            .context("Timeout reading TCP DNS response body")?
            .context("Failed reading TCP DNS response body")?;

        Ok(response)
    }

    async fn query_dns_direct(nameserver: &WireAddress, domain: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
        let query_bytes = Self::build_dns_query(domain)?;
        let nameserver_addr = Self::resolve_wire_socket_addr(nameserver).await?;

        match Self::query_dns_direct_udp(nameserver_addr, &query_bytes, timeout).await {
            Ok(response) => Self::parse_dns_response(&response, domain),
            Err(udp_err) => {
                warn!(
                    "UDP DNS query failed via {} for {}: {}; trying TCP",
                    nameserver,
                    domain,
                    udp_err
                );
                let response = Self::query_dns_direct_tcp(nameserver_addr, &query_bytes, timeout).await?;
                Self::parse_dns_response(&response, domain)
            }
        }
    }

    async fn resolve_domain_direct_via(&self, domain: &str, nameservers: &[WireAddress]) -> Result<BTreeSet<IpAddr>> {
        let timeout = Duration::from_secs(8);
        let mut last_err: Option<anyhow::Error> = None;

        for nameserver in nameservers {
            match Self::query_dns_direct(nameserver, domain, timeout).await {
                Ok(ips) => return Ok(ips.into_iter().collect()),
                Err(e) => {
                    warn!("Direct DNS query failed via {} for {}: {}", nameserver, domain, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!(
            "All direct DNS queries failed for {}",
            domain
        )))
    }

    async fn resolve_domain_direct_tier2(&self, domain: &str) -> Result<BTreeSet<IpAddr>> {
        self.resolve_domain_direct_via(domain, &self.tier2_nameservers).await
    }

    async fn resolve_domain_direct_tier1(&self, domain: &str) -> Result<BTreeSet<IpAddr>> {
        self.resolve_domain_direct_via(domain, &self.tier1_nameservers).await
    }

    async fn attempt_path(
        &self,
        path: ResolutionPath,
        domain: &str,
        hub: Option<&UplinkHub>,
    ) -> PathAttempt {
        match path {
            ResolutionPath::ProxyTier2 => {
                let Some(hub) = hub else {
                    return PathAttempt::Skipped;
                };
                let proxy_tier2_servers = &self.tier2_nameservers;
                if !Self::has_proxy_resolvers(hub) || proxy_tier2_servers.is_empty() {
                    return PathAttempt::Skipped;
                }
                match Self::resolve_via_available_proxies(hub, domain, &proxy_tier2_servers).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::ProxyTier1 => {
                let Some(hub) = hub else {
                    return PathAttempt::Skipped;
                };
                let proxy_tier1_servers = &self.tier1_nameservers;
                if !Self::has_proxy_resolvers(hub) || proxy_tier1_servers.is_empty() {
                    return PathAttempt::Skipped;
                }
                match Self::resolve_via_available_proxies(hub, domain, &proxy_tier1_servers).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::DirectTier2 => {
                match self.resolve_domain_direct_tier2(domain).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::DirectTier1 => {
                match self.resolve_domain_direct_tier1(domain).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
        }
    }

    async fn resolve_target_domain(
        &mut self,
        target: ResolutionTargetKind,
        domain: &str,
        hub: Option<&UplinkHub>,
        solved: &mut ProfileSolved,
        metrics: &mut ResolutionMetrics,
    ) {
        if let Some(cached) = self.cached_for_target(target, domain) {
            metrics.cache_hits += 1;
            solved.add_resolution(domain.to_string(), cached);
            return;
        }

        for path in ResolutionPolicy::paths_for(target) {
            match self.attempt_path(
                *path,
                domain,
                hub,
            )
            .await
            {
                PathAttempt::Resolved(ip_set) => {
                    info!(
                        "Resolved {} -> {} IPs via {:?}",
                        domain,
                        ip_set.len(),
                        path
                    );
                    metrics.mark_resolved(*path);
                    solved.add_resolution(domain.to_string(), ip_set.clone());
                    self.store_target_resolution(target, domain, ip_set);
                    return;
                }
                PathAttempt::Skipped => {}
                PathAttempt::Failed(e) => {
                    warn!("Resolution path {:?} failed for {}: {}", path, domain, e);
                }
            }
        }

        metrics.unresolved += 1;
    }

    async fn resolve_via_available_proxies(
        hub: &UplinkHub,
        domain: &str,
        dns_servers: &[WireAddress],
    ) -> Result<BTreeSet<IpAddr>> {
        use super::proxy_adapters::{RemoteAdapter, TrojanAdapter};

        if dns_servers.is_empty() {
            anyhow::bail!("No DNS servers available for proxy-based resolution");
        }

        let timeout = Duration::from_secs(8);

        for proxy in hub.all_proxies().values() {
            for dns_server in dns_servers {
                let (dns_host, dns_port) = Self::wire_host_port(dns_server);
                match proxy {
                    UplinkProxy::Trojan(trojan) => {
                        let resolved_ip = trojan.server_addr.ip();
                        let mut conn = match TrojanAdapter::connect(trojan, &dns_host, dns_port, resolved_ip).await {
                            Ok(conn) => conn,
                            Err(e) => {
                                warn!(
                                    "Proxy DNS connect failed via trojan {} for server {}: {}",
                                    trojan.server_name,
                                    dns_server,
                                    e
                                );
                                continue;
                            }
                        };

                        match proxy_dns::query_via_proxy(&mut conn, dns_server, domain, timeout).await {
                            Ok(ips) => {
                                return Ok(ips.into_iter().collect());
                            }
                            Err(e) => {
                                warn!(
                                    "Proxy DNS query failed via trojan {} using {} for {}: {}",
                                    trojan.server_name,
                                    dns_server,
                                    domain,
                                    e
                                );
                            }
                        }
                    }
                    UplinkProxy::Remote(remote) => {
                        let mut conn = match RemoteAdapter::connect(remote, &dns_host, dns_port).await {
                            Ok(conn) => conn,
                            Err(e) => {
                                warn!(
                                    "Proxy DNS connect failed via remote {} for server {}: {}",
                                    remote.addr,
                                    dns_server,
                                    e
                                );
                                continue;
                            }
                        };

                        match proxy_dns::query_via_proxy(&mut conn, dns_server, domain, timeout).await {
                            Ok(ips) => {
                                return Ok(ips.into_iter().collect());
                            }
                            Err(e) => {
                                warn!(
                                    "Proxy DNS query failed via remote {} using {} for {}: {}",
                                    remote.addr,
                                    dns_server,
                                    domain,
                                    e
                                );
                            }
                        }
                    }
                    UplinkProxy::Geph | UplinkProxy::File(_) => {}
                }
            }
        }

        anyhow::bail!("All proxy-based DNS resolution attempts failed for {}", domain)
    }

    /// Resolve a profile using strategy-driven path policy.
    pub async fn resolve_profile(&mut self, profile: &ClashProfile, hub: Option<&UplinkHub>) -> Result<ResolveProfileReport> {
        // Seed tier lists if empty
        if self.tier1_nameservers.is_empty() {
            self.tier1_nameservers = Self::parse_nameserver_list(&profile.bootstrap_nameservers)
                .context("Failed to parse tier1 nameservers")?;
        }
        if self.tier2_nameservers.is_empty() {
            self.tier2_nameservers = Self::parse_nameserver_list(&profile.main_nameservers)
                .context("Failed to parse tier2 nameservers")?;
        }

        let tier2_query_hosts = Self::nameserver_query_hosts(&self.tier2_nameservers);

        info!("ClashState DNS resolver initialized (internal)");
        info!("  Bootstrap tier: {} nameservers", self.tier1_nameservers.len());
        info!("  Main tier: {} nameservers", self.tier2_nameservers.len());

        let mut solved = ProfileSolved::new();
        let mut metrics = ResolutionMetrics::default();

        // Step 1: resolve tier2 nameserver hostnames.
        for host in &tier2_query_hosts {
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            self
                .resolve_target_domain(
                    ResolutionTargetKind::Tier2DnsDomain,
                    host,
                    hub,
                    &mut solved,
                    &mut metrics,
                )
                .await;
        }

        // Step 2: resolve proxy domains.
        for domain in &profile.proxy_domains {
            self
                .resolve_target_domain(
                    ResolutionTargetKind::ProxyDomain,
                    domain,
                    hub,
                    &mut solved,
                    &mut metrics,
                )
                .await;
        }

        // Persist updated clash state
        if let Err(e) = self.save_atomic() {
            warn!("Failed to persist ClashState: {}", e);
        }

        Ok(ResolveProfileReport { solved, metrics })
    }
}

impl PersistentState for ClashState {
    const STATE_NAME: &'static str = "clash";

    fn path() -> PathBuf {
        state_paths::uplink_clash_state()
    }
}
