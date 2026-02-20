use super::*;
use crate::state_blueprint::PersistentState;
use anyhow::Context;
use bytes::BytesMut;
use clash_config::Config;
use nsproxy_common::DNSHost;
use rustls::pki_types::{DnsName, ServerName};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha224};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;
use trojan_proto::{AddressRef, HostRef, write_request_header};
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use tun2socks5::dns::{VIRT_IP, default_virtip};
// Shorter alias for the commonly used TLS stream type
type TokioTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Clash-specific profile information
/// Ephemeral
#[derive(Debug, Clone)]
pub struct ClashProfile {
    pub tier1_nameservers: BTreeMap<SocketAddr, DNSEndpoints>,
    pub tier2_nameservers: BTreeMap<String, DNSEndpoints>,
    pub proxy_domains: HashSet<String>,
    pub trojan_proxies: Vec<TrojanConfig>,
}

/// Trojan proxy configuration as read from Clash config
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
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
    pub async fn connect_tcp(
        &self,
        server_ip: std::net::IpAddr,
        dest: WireAddress,
    ) -> Result<TrojanConnection> {
        let stream = self
            .connect_with_command(
                server_ip,
                &dest,
                TrojanCommand::TcpConnect,
            )
            .await?;
        Ok(TrojanConnection::TcpConnect(
            TrojanTcpStream(stream),
            dest,
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
        dest: WireAddress,
    ) -> Result<TrojanConnection> {
        let stream = self
            .connect_with_command(
                server_ip,
                &dest,
                TrojanCommand::UdpAssociate,
            )
            .await?;
        Ok(TrojanConnection::UdpAssociate(
            TrojanUdpTunnel(stream),
            dest,
        ))
    }

    /// Create a TLS-wrapped Trojan connection using a specific command
    async fn connect_with_command(
        &self,
        server_ip: std::net::IpAddr,
        dest: &WireAddress,
        command: TrojanCommand,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        // TCP connect using resolved IP and the configured port from runtime proxy
        let server_addr = SocketAddr::new(server_ip, self.server_addr.port());
        info!(
            "Trojan TCP connection to {} for target {} ({:?})",
            server_addr, dest, command
        );
        let tcp_stream = TcpStream::connect(server_addr)
            .await
            .context(format!("Failed to connect to {}", server_addr))?;

        super::ensure_rustls_crypto_provider()?;

        // TLS handshake
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(self.server_name.clone())
            .context("Invalid server name for TLS")?;

        info!(
            "Trojan TLS handshake with {} (SNI: {})",
            server_addr, self.server_name
        );
        let mut tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        // Write Trojan protocol header
        let password_hash = Self::hash_password(&self.password);
        let mut buf = BytesMut::new();

        let (host_bytes_buf, address) = match dest {
            WireAddress::DomainAddress(host, port) => {
                let buf = host.clone().into_bytes();
                let addr = AddressRef { host: HostRef::Domain(&[]), port: *port };
                (Some(buf), addr)
            }
            WireAddress::SocketAddress(std::net::SocketAddr::V4(addr)) => {
                (None, AddressRef { host: HostRef::Ipv4(addr.ip().octets()), port: addr.port() })
            }
            WireAddress::SocketAddress(std::net::SocketAddr::V6(addr)) => {
                (None, AddressRef { host: HostRef::Ipv6(addr.ip().octets()), port: addr.port() })
            }
        };
        let address = if let Some(ref buf) = host_bytes_buf {
            AddressRef { host: HostRef::Domain(buf.as_slice()), port: address.port }
        } else {
            address
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
    pub fn load_file(yaml_path: &PathBuf) -> Result<Self> {
        let config =
            Config::try_from(yaml_path.clone()).context("Failed to parse Clash YAML config")?;

        let bootstrap_nameserver_values: HashSet<String> =
            config.dns.default_nameserver.iter().cloned().collect();
        let tier1_nameservers =
            ClashState::parse_tier1_nameserver_map(&bootstrap_nameserver_values)
                .context("Failed to parse tier1 nameservers")?;

        let mut main_nameserver_values: HashSet<String> =
            config.dns.nameserver.iter().cloned().collect();
        main_nameserver_values.extend(config.dns.fallback.iter().cloned());

        let mut tier2_nameservers: BTreeMap<String, DNSEndpoints> = BTreeMap::new();
        for raw in &main_nameserver_values {
            let (host, endpoint) = match ClashState::parse_nameserver(raw) {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!(
                        "Skipping unsupported/invalid tier2 nameserver '{}': {}",
                        raw, e
                    );
                    continue;
                }
            };
            let key = ClashState::dns_host_key(&host);
            tier2_nameservers
                .entry(key)
                .or_insert_with(BTreeMap::new)
                .insert(endpoint.proto.clone(), endpoint);
        }
        if tier2_nameservers.is_empty() {
            anyhow::bail!("No supported tier2 nameservers found after parsing config");
        }
        let proxies = config
            .proxy
            .as_ref()
            .context("No proxies found in Clash config")?;

        let proxy_domains: HashSet<String> = proxies
            .iter()
            .filter_map(|proxy| {
                proxy
                    .get("server")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();

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

        if proxy_domains.is_empty() {
            anyhow::bail!("No proxy servers found in config");
        }

        info!("Parsed Clash config from {:?}", yaml_path);

        Ok(Self {
            tier1_nameservers,
            tier2_nameservers,
            proxy_domains,
            trojan_proxies,
        })
    }

    /// Get all domains that need to be resolved (both nameservers and proxies)
    pub fn all_domains(&self) -> Vec<String> {
        let mut domains: HashSet<String> = HashSet::new();

        for host in self.tier2_nameservers.keys() {
            if host.parse::<IpAddr>().is_err() {
                domains.insert(host.clone());
            }
        }

        domains.extend(self.proxy_domains.iter().cloned());
        domains.into_iter().collect()
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
    pub fn paths_for(target: ResolutionTargetKind, direct_only: bool) -> &'static [ResolutionPath] {
        match (target, direct_only) {
            (ResolutionTargetKind::ProxyDomain, false) => &[
                ResolutionPath::ProxyTier2,
                ResolutionPath::ProxyTier1,
                ResolutionPath::DirectTier2,
            ],
            (ResolutionTargetKind::ProxyDomain, true) => &[ResolutionPath::DirectTier2],
            (ResolutionTargetKind::Tier2DnsDomain, false) => &[
                ResolutionPath::ProxyTier2,
                ResolutionPath::ProxyTier1,
                ResolutionPath::DirectTier2,
                ResolutionPath::DirectTier1,
            ],
            (ResolutionTargetKind::Tier2DnsDomain, true) => {
                &[ResolutionPath::DirectTier2, ResolutionPath::DirectTier1]
            }
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

#[derive(Debug, Clone, Copy, Default)]
pub struct AppendProfileReport {
    pub added_tier1_nameservers: usize,
    pub added_tier2_nameservers: usize,
    pub added_trojan_proxies: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub String);

impl GroupId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for GroupId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for GroupId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClashGroupState {
    pub tier1_nameservers: BTreeMap<SocketAddr, DNSEndpoints>,
    /// Host -> available endpoints
    pub tier2_nameservers: BTreeMap<String, DNSEndpoints>,
    pub tier2_cache: DomainsSolved,
}

enum PathAttempt {
    Resolved(BTreeSet<IpAddr>),
    Skipped,
    Failed(anyhow::Error),
}

mod trojan_proxy_map_serde {
    use super::*;

    pub fn serialize<S>(
        value: &BTreeMap<ProxyID, TrojanConfig>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: BTreeMap<String, &TrojanConfig> = value
            .iter()
            .map(|(id, cfg)| (hex::encode(id.0), cfg))
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<ProxyID, TrojanConfig>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = BTreeMap::<String, TrojanConfig>::deserialize(deserializer)?;
        let mut decoded = BTreeMap::new();
        for (id_hex, cfg) in encoded {
            let raw = hex::decode(&id_hex).map_err(serde::de::Error::custom)?;
            let id: [u8; 32] = raw
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid ProxyID length"))?;
            decoded.insert(ProxyID(id), cfg);
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClashState {
    pub schema_version: u32,
    pub domain_group: BTreeMap<Domain, GroupId>,
    pub groups: BTreeMap<GroupId, ClashGroupState>,
    pub proxies: DomainsSolved,
    #[serde(default, with = "trojan_proxy_map_serde")]
    pub trojan_proxies: BTreeMap<ProxyID, TrojanConfig>,
}

pub type DNSEndpoints = BTreeMap<DNSProtocol, DNSEndpoint>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DNSEndpoint {
    pub proto: DNSProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DNSProtocol {
    TLS,
    UDP,
    TCP,
    /// Subpath
    HTTPS(String),
}

impl DNSProtocol {
    fn as_key(&self) -> String {
        match self {
            DNSProtocol::TLS => "tls".to_string(),
            DNSProtocol::UDP => "udp".to_string(),
            DNSProtocol::TCP => "tcp".to_string(),
            DNSProtocol::HTTPS(path) => format!("https:{path}"),
        }
    }

    fn from_key(value: &str) -> Result<Self, String> {
        match value {
            "tls" | "TLS" => Ok(DNSProtocol::TLS),
            "udp" | "UDP" => Ok(DNSProtocol::UDP),
            "tcp" | "TCP" => Ok(DNSProtocol::TCP),
            _ => {
                if let Some(path) = value.strip_prefix("https:") {
                    return Ok(DNSProtocol::HTTPS(path.to_string()));
                }
                Err(format!("invalid DNSProtocol key: {value}"))
            }
        }
    }
}

impl Serialize for DNSProtocol {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_key())
    }
}

impl<'de> Deserialize<'de> for DNSProtocol {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_key(&value).map_err(serde::de::Error::custom)
    }
}

impl ClashState {
    fn protocol_label(proto: &DNSProtocol) -> String {
        match proto {
            DNSProtocol::UDP => "dns_over_udp".to_string(),
            DNSProtocol::TCP => "dns_over_tcp".to_string(),
            DNSProtocol::TLS => "dns_over_tls".to_string(),
            DNSProtocol::HTTPS(path) => {
                if path.is_empty() || path == "/dns-query" {
                    "dns_over_https".to_string()
                } else {
                    format!("dns_over_https:{}", path)
                }
            }
        }
    }

    fn resolver_brief(host: &DNSHost) -> String {
        match host {
            DNSHost::Tier1(sock) => format!("tier1:{}", sock.ip()),
            DNSHost::Tier2IP(sock) => format!("tier2:{}", sock.ip()),
            DNSHost::Tier2Domain {
                domain,
                socket: Some(sock),
            } => format!("tier2:{domain}@{}", sock.ip()),
            DNSHost::Tier2Domain {
                domain,
                socket: None,
            } => format!("tier2:{domain}"),
        }
    }

    fn path_label(path: ResolutionPath) -> (&'static str, &'static str) {
        match path {
            ResolutionPath::ProxyTier2 => ("true", "tier2"),
            ResolutionPath::ProxyTier1 => ("true", "tier1"),
            ResolutionPath::DirectTier2 => ("false", "tier2"),
            ResolutionPath::DirectTier1 => ("false", "tier1"),
        }
    }

    fn ips_brief(ips: &BTreeSet<IpAddr>) -> String {
        ips.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn path() -> PathBuf {
        <Self as PersistentState>::path()
    }

    pub fn load_or_default() -> Result<Self> {
        let mut m = <Self as PersistentState>::load_or_default()?;
        m.remove_private_ips();
        Ok(m)
    }

    pub fn save_atomic(&self) -> Result<()> {
        <Self as PersistentState>::save_atomic(self)
    }

    fn ensure_group_mut(&mut self, group_id: &GroupId) -> &mut ClashGroupState {
        self.groups
            .entry(group_id.clone())
            .or_insert_with(ClashGroupState::default)
    }

    fn group(&self, group_id: &GroupId) -> Result<&ClashGroupState> {
        self.groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown clash group '{}'", group_id.as_str()))
    }

    fn set_domain_group(&mut self, domain: Domain, group_id: GroupId) {
        self.domain_group.insert(domain, group_id);
    }

    pub fn group_for_domain(&self, domain: &Domain) -> Option<&GroupId> {
        self.domain_group.get(domain)
    }

    pub fn remove_private_ips(&mut self) {
        let virt = default_virtip();

        let scrub = |domains: &mut DomainsSolved| {
            domains.retain(|_, responses| {
                responses.retain(|_, response| {
                    response.ips.retain(|addr| {
                        !matches!(addr, IpAddr::V6(ip6) if virt.contains(*ip6))
                    });
                    !response.ips.is_empty()
                });
                !responses.is_empty()
            });
        };

        scrub(&mut self.proxies);
        for group in self.groups.values_mut() {
            scrub(&mut group.tier2_cache);
        }

        info!("Removed virtual DNS IPs from clash state subnet={}", VIRT_IP);
    }

    pub fn append_profile_to_group(
        &mut self,
        profile: &ClashProfile,
        group_id: GroupId,
    ) -> Result<AppendProfileReport> {
        let mut report = AppendProfileReport::default();
        let group = self.ensure_group_mut(&group_id);

        for (socket, endpoints) in &profile.tier1_nameservers {
            let current = group
                .tier1_nameservers
                .entry(*socket)
                .or_insert_with(BTreeMap::new);
            for endpoint in endpoints.values() {
                if current
                    .insert(endpoint.proto.clone(), endpoint.clone())
                    .is_none()
                {
                    report.added_tier1_nameservers += 1;
                }
            }
        }

        for (host, endpoints) in &profile.tier2_nameservers {
            let current = group
                .tier2_nameservers
                .entry(host.clone())
                .or_insert_with(BTreeMap::new);
            for endpoint in endpoints.values() {
                if current
                    .insert(endpoint.proto.clone(), endpoint.clone())
                    .is_none()
                {
                    report.added_tier2_nameservers += 1;
                }
            }
        }

        for domain in &profile.proxy_domains {
            self.set_domain_group(Domain::from(domain.clone()), group_id.clone());
        }

        for proxy in &profile.trojan_proxies {
            let unresolved =
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), proxy.port);
            let proxy_id = ProxyID::for_trojan(unresolved, &proxy.server, &proxy.password);
            if self
                .trojan_proxies
                .insert(proxy_id, proxy.clone())
                .is_none()
            {
                report.added_trojan_proxies += 1;
            }
        }

        Ok(report)
    }

    fn get_latest_ips_in_group(&self, group_id: &GroupId, host: &str) -> Option<&BTreeSet<IpAddr>> {
        self.groups
            .get(group_id)?
            .tier2_cache
            .get(&Domain::from(host))?
            .last_key_value()
            .map(|(_, response)| &response.ips)
    }

    fn update_cache_in_group(&mut self, group_id: &GroupId, host: &str, ips: BTreeSet<IpAddr>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.ensure_group_mut(group_id)
            .tier2_cache
            .entry(Domain::from(host))
            .or_insert_with(BTreeMap::new)
            .insert(now, DNSResponse { ips });
    }

    /// Return the newest cached tier2 nameserver-host resolution.
    pub fn get_latest_ips(&self, host: &str) -> Option<&BTreeSet<IpAddr>> {
        self.groups
            .values()
            .filter_map(|group| {
                group
                    .tier2_cache
                    .get(&Domain::from(host))
                    .and_then(|responses| {
                        responses
                            .last_key_value()
                            .map(|(_, response)| &response.ips)
                    })
            })
            .next()
    }

    /// Update tier2 nameserver-host cache into `default` group.
    pub fn update_cache(&mut self, host: &str, ips: BTreeSet<IpAddr>) {
        let group_id = GroupId::from("default");
        self.update_cache_in_group(&group_id, host, ips);
    }

    /// Store latest resolved proxy-domain IPs in the centralized clash state.
    pub fn add_proxy_resolution(&mut self, domain: &str, ips: BTreeSet<IpAddr>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.proxies
            .entry(Domain::from(domain))
            .or_insert_with(BTreeMap::new)
            .insert(now, DNSResponse { ips });
    }

    /// Get latest resolved proxy-domain IPs from centralized clash state.
    pub fn get_latest_proxy_ips(&self, domain: &str) -> Option<&BTreeSet<IpAddr>> {
        self.proxies
            .get(&Domain::from(domain))?
            .last_key_value()
            .map(|(_, response)| &response.ips)
    }

    fn cached_for_target(
        &self,
        group_id: &GroupId,
        target: ResolutionTargetKind,
        domain: &str,
    ) -> Option<BTreeSet<IpAddr>> {
        let map = match target {
            ResolutionTargetKind::ProxyDomain => &self.proxies,
            ResolutionTargetKind::Tier2DnsDomain => &self.groups.get(group_id)?.tier2_cache,
        };

        map.get(&Domain::from(domain))
            .and_then(|responses| responses.last_key_value())
            .map(|(_, response)| response.ips.clone())
    }

    fn store_target_resolution(
        &mut self,
        group_id: &GroupId,
        target: ResolutionTargetKind,
        domain: &str,
        ips: BTreeSet<IpAddr>,
    ) {
        match target {
            ResolutionTargetKind::ProxyDomain => self.add_proxy_resolution(domain, ips),
            ResolutionTargetKind::Tier2DnsDomain => {
                self.update_cache_in_group(group_id, domain, ips)
            }
        }
    }

    fn nameserver_url_default_port(scheme: &str) -> Option<u16> {
        match scheme {
            "https" => Some(443),
            "tls" => Some(853),
            "udp" | "tcp" | "dns" => Some(53),
            _ => None,
        }
    }

    fn parse_nameserver(raw: &str) -> Result<(DNSHost, DNSEndpoint)> {
        if let Ok(url) = url::Url::parse(raw) {
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("URL nameserver missing host: {}", raw))?;
            let port = url
                .port()
                .or_else(|| {
                    url.port_or_known_default()
                        .or_else(|| Self::nameserver_url_default_port(url.scheme()))
                })
                .unwrap_or(53);
            let proto = match url.scheme() {
                "https" => {
                    let mut subpath = if url.path().is_empty() {
                        "/dns-query".to_string()
                    } else {
                        url.path().to_string()
                    };
                    if let Some(query) = url.query() {
                        subpath.push('?');
                        subpath.push_str(query);
                    }
                    DNSProtocol::HTTPS(subpath)
                }
                "http" => anyhow::bail!(
                    "Insecure DoH URL scheme 'http' is not supported for nameserver '{}'; use https://.../dns-query",
                    raw
                ),
                _ => match url.scheme() {
                    "tls" => DNSProtocol::TLS,
                    "tcp" => DNSProtocol::TCP,
                    _ => unreachable!(),
                },
            };
            let endpoint = DNSEndpoint { proto, port };
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok((DNSHost::Tier2IP(SocketAddr::new(ip, port)), endpoint));
            }
            return Ok((
                DNSHost::Tier2Domain {
                    domain: host.to_string(),
                    socket: None,
                },
                endpoint,
            ));
        }

        if let Ok(sock) = raw.parse::<SocketAddr>() {
            return Ok((
                DNSHost::Tier2IP(sock),
                DNSEndpoint {
                    proto: DNSProtocol::UDP,
                    port: sock.port(),
                },
            ));
        }

        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Ok((
                DNSHost::Tier2IP(SocketAddr::new(ip, 53)),
                DNSEndpoint {
                    proto: DNSProtocol::UDP,
                    port: 53,
                },
            ));
        }

        Ok((
            DNSHost::Tier2Domain {
                domain: raw.to_string(),
                socket: None,
            },
            DNSEndpoint {
                proto: DNSProtocol::UDP,
                port: 53,
            },
        ))
    }

    fn parse_tier1_nameserver_map<'a, I>(values: I) -> Result<BTreeMap<SocketAddr, DNSEndpoints>>
    where
        I: IntoIterator<Item = &'a String>,
    {
        let mut map: BTreeMap<SocketAddr, DNSEndpoints> = BTreeMap::new();
        for raw in values {
            let (host, endpoint) = Self::parse_nameserver(raw)?;
            let socket = match host {
                DNSHost::Tier1(socket) | DNSHost::Tier2IP(socket) => socket,
                DNSHost::Tier2Domain {
                    socket: Some(socket),
                    ..
                } => socket,
                DNSHost::Tier2Domain { socket: None, .. } => {
                    anyhow::bail!("Tier1 nameserver must be IP/socket-form: {}", raw);
                }
            };
            map.entry(socket)
                .or_insert_with(BTreeMap::new)
                .insert(endpoint.proto.clone(), endpoint);
        }
        Ok(map)
    }

    fn has_proxy_resolvers(hub: &UplinkHub) -> bool {
        hub.all_proxies()
            .values()
            .any(|proxy| matches!(proxy, UplinkProxy::Trojan(_) | UplinkProxy::Remote(_)))
    }

    fn wire_host_port(wire: &WireAddress) -> (String, u16) {
        match wire {
            WireAddress::SocketAddress(sock) => (sock.ip().to_string(), sock.port()),
            WireAddress::DomainAddress(host, port) => (host.clone(), *port),
        }
    }

    fn dns_host_key(host: &DNSHost) -> String {
        match host {
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => sock.ip().to_string(),
            DNSHost::Tier2Domain { domain, .. } => domain.clone(),
        }
    }

    fn dns_host_to_wire_with_port(host: &DNSHost, port: u16) -> WireAddress {
        match host {
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => {
                WireAddress::SocketAddress(SocketAddr::new(sock.ip(), port))
            }
            DNSHost::Tier2Domain { domain, .. } => WireAddress::DomainAddress(domain.clone(), port),
        }
    }

    fn direct_socket_addr(host: &DNSHost, port: u16) -> Result<SocketAddr> {
        match host {
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => Ok(SocketAddr::new(sock.ip(), port)),
            DNSHost::Tier2Domain {
                socket: Some(sock), ..
            } => Ok(SocketAddr::new(sock.ip(), port)),
            DNSHost::Tier2Domain {
                domain: hostname,
                socket: None,
            } => {
                anyhow::bail!(
                    "Direct DNS resolution requires a known socket; unresolved host '{}' is not allowed",
                    hostname
                )
            }
        }
    }

    pub async fn dns_doh(
        resolver: &DNSHost,
        endpoint: &DNSEndpoint,
        doh_path: &str,
        query: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        use super::proxy_adapters::{NoProxyAdapter, wrap_tls_for_doh};
        use bytes::Bytes;
        use h2::client;
        use http::{Method, Request};
        use rustls::pki_types::{DnsName, ServerName};

        let authority = match resolver {
            DNSHost::Tier2Domain { domain, .. } => domain.clone(),
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => sock.ip().to_string(),
        };

        let path = if doh_path.is_empty() {
            "/dns-query".to_string()
        } else if doh_path.starts_with('/') {
            doh_path.to_string()
        } else {
            format!("/{doh_path}")
        };

        // Build DNS query message
        let name = Name::from_ascii(query).context("Invalid domain name")?;
        let dns_query = Query::query(name, RecordType::A);
        let mut msg = Message::new();
        msg.add_query(dns_query);
        msg.set_id(rand::random());
        msg.set_recursion_desired(true);
        let payload = msg
            .to_vec()
            .context("Failed to serialize DNS query for DoH")?;

        info!(
            "dns_doh domain={} proxied=false resolver={} authority={} path={}",
            query,
            Self::resolver_brief(resolver),
            authority,
            path
        );

        // Establish TCP connection to resolver
        let dns_server_sock = Self::direct_socket_addr(resolver, endpoint.port)?;
        let tcp_conn = NoProxyAdapter::connect_tcp(dns_server_sock).await?;

        let tcp_stream = match tcp_conn {
            super::proxy_adapters::ProxyConnection::Tcp(stream) => stream,
            _ => anyhow::bail!("Expected TCP connection for DoH"),
        };

        let use_ip = false;

        let tls_server_name = match resolver {
            DNSHost::Tier2Domain { domain, socket } => {
                if use_ip {
                    ServerName::IpAddress(socket.unwrap().ip().into())
                } else {
                    ServerName::DnsName(
                        DnsName::try_from(domain.as_str())
                            .context("Invalid TLS server name for DoH")?
                            .to_owned(),
                    )
                }
            }
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => {
                ServerName::IpAddress(sock.ip().into())
            }
        };

        let tls_stream = wrap_tls_for_doh(tcp_stream, tls_server_name, "doh").await?;

        // Perform HTTP/2 handshake
        let (mut client, h2_conn) = tokio::time::timeout(timeout, client::handshake(tls_stream))
            .await
            .context("Timeout during HTTP/2 handshake")?
            .context("HTTP/2 handshake failed")?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                warn!("HTTP/2 connection error: {}", e);
            }
        });

        // Wait for client to be ready
        let mut client = client.ready().await.context("HTTP/2 client not ready")?;

        // Build HTTP/2 request
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("host", authority)
            .header("accept", "application/dns-message")
            .header("content-type", "application/dns-message")
            .header("content-length", payload.len())
            .body(())
            .context("Failed to build HTTP/2 request")?;

        // Send request
        let (response_future, mut send_stream) = client
            .send_request(request, false)
            .context("Failed to send HTTP/2 request")?;

        // Send body
        send_stream
            .send_data(Bytes::from(payload), true)
            .context("Failed to send request body")?;

        // Wait for response
        let response = tokio::time::timeout(timeout, response_future)
            .await
            .context("Timeout waiting for DoH response")?
            .context("Failed to receive HTTP/2 response")?;

        let status = response.status();
        info!(
            "dns_query_response_status protocol=dns_over_https status={}",
            status
        );

        if !status.is_success() {
            warn!(
                "dns_query_http_error protocol=dns_over_https status={}",
                status
            );
            anyhow::bail!("dns_over_https http status={}", status);
        }

        // Get response body
        let mut body = response.into_body();
        let mut response_bytes = Vec::new();

        while let Some(chunk) = tokio::time::timeout(timeout, body.data())
            .await
            .context("Timeout reading response data")?
        {
            let chunk = chunk.context("Failed to read response chunk")?;
            response_bytes.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        info!("doh response bytes={}", response_bytes.len());

        // Parse DNS response
        let response =
            Message::from_bytes(&response_bytes).context("Failed to parse DNS response")?;

        let mut ips = Vec::new();
        for answer in response.answers() {
            if let Some(data) = answer.data() {
                if let Some(ip) = data.ip_addr() {
                    ips.push(ip);
                }
            }
        }

        info!("doh domain={} answer_count={}", query, ips.len());
        if ips.is_empty() {
            anyhow::bail!("No IP addresses found for {} via DoH", query);
        }

        Ok(ips)
    }

    pub async fn dns_dot(
        resolver: &DNSHost,
        endpoint: &DNSEndpoint,
        query: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        use super::proxy_adapters::NoProxyAdapter;

        let dns_server_sock = Self::direct_socket_addr(resolver, endpoint.port)?;
        let dns_server = WireAddress::SocketAddress(dns_server_sock);

        let tls_server_name = match resolver {
            DNSHost::Tier2Domain { domain, .. } => ServerName::DnsName(
                DnsName::try_from(domain.as_str())
                    .context("Invalid TLS server name for DNS endpoint")?
                    .to_owned(),
            ),
            DNSHost::Tier1(sock) | DNSHost::Tier2IP(sock) => {
                ServerName::IpAddress(sock.ip().into())
            }
        };

        info!(
            "DoT domain={} proxied=false resolver={} protocol={}",
            query,
            Self::resolver_brief(resolver),
            Self::protocol_label(&endpoint.proto)
        );

        let mut conn = NoProxyAdapter::connect_tls(tls_server_name, dns_server_sock).await?;
        match &mut conn {
            super::proxy_adapters::ProxyConnection::Tcp(stream) => {
                super::proxy_dns::query_via_tcp(stream.as_mut(), &dns_server, query, timeout).await
            }
            _ => anyhow::bail!("Expected TCP-capable resolver for DNS over TLS"),
        }
    }

    async fn query_dns_via_no_proxy_endpoint(
        resolver: &DNSHost,
        endpoint: DNSEndpoint,
        query: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        use super::proxy_adapters::NoProxyAdapter;

        let protocol = endpoint.proto.clone();

        match &protocol {
            DNSProtocol::HTTPS(path) => {
                return Self::dns_doh(resolver, &endpoint, path, query, timeout).await;
            }
            DNSProtocol::TLS => {
                return Self::dns_dot(resolver, &endpoint, query, timeout).await;
            }
            DNSProtocol::UDP | DNSProtocol::TCP => {}
        }

        let dns_server_sock = Self::direct_socket_addr(resolver, endpoint.port)?;
        let dns_server = WireAddress::SocketAddress(dns_server_sock);

        let mut conn = match &protocol {
            DNSProtocol::UDP => NoProxyAdapter::connect_udp(dns_server_sock).await?,
            DNSProtocol::TCP => NoProxyAdapter::connect_tcp(dns_server_sock).await?,
            DNSProtocol::TLS | DNSProtocol::HTTPS(_) => {
                unreachable!("TLS/HTTPS handled before transport setup")
            }
        };
        match (&protocol, &mut conn) {
            (DNSProtocol::UDP, super::proxy_adapters::ProxyConnection::Udp(tunnel)) => {
                super::proxy_dns::query_via_udp(tunnel.as_mut(), &dns_server, query, timeout).await
            }
            (DNSProtocol::TCP, super::proxy_adapters::ProxyConnection::Tcp(stream)) => {
                super::proxy_dns::query_via_tcp(stream.as_mut(), &dns_server, query, timeout).await
            }
            (DNSProtocol::UDP, _) => {
                anyhow::bail!("Expected UDP-capable resolver for DNS over UDP")
            }
            (DNSProtocol::TCP, _) => {
                anyhow::bail!("Expected TCP-capable resolver for DNS over TCP")
            }
            (DNSProtocol::TLS | DNSProtocol::HTTPS(_), _) => {
                unreachable!("TLS/HTTPS handled before transport query")
            }
        }
    }

    async fn query_dns_via_proxy_endpoint(
        hub: &UplinkHub,
        host: &DNSHost,
        endpoint: DNSEndpoint,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        use super::proxy_adapters::{RemoteAdapter, TrojanAdapter};

        let dns_host = Self::dns_host_key(host);
        let dns_server = Self::dns_host_to_wire_with_port(host, endpoint.port);

        for proxy in hub.all_proxies().values() {
            match proxy {
                UplinkProxy::Trojan(trojan) => {
                    let resolved_ip = trojan.server_addr.ip();
                    return match &endpoint.proto {
                        DNSProtocol::UDP => {
                            let mut conn = TrojanAdapter::connect_udp(
                                trojan,
                                dns_server.clone(),
                                resolved_ip,
                            )
                            .await?;
                            match &mut conn {
                                super::proxy_adapters::ProxyConnection::Udp(tunnel) => {
                                    super::proxy_dns::query_via_udp(
                                        tunnel.as_mut(),
                                        &dns_server,
                                        domain,
                                        timeout,
                                    )
                                    .await
                                }
                                _ => {
                                    anyhow::bail!("Expected UDP-capable resolver for DNS over UDP")
                                }
                            }
                        }
                        DNSProtocol::TCP => {
                            let mut conn = TrojanAdapter::connect_tcp(
                                trojan,
                                dns_server.clone(),
                                resolved_ip,
                            )
                            .await?;
                            match &mut conn {
                                super::proxy_adapters::ProxyConnection::Tcp(stream) => {
                                    super::proxy_dns::query_via_tcp(
                                        stream.as_mut(),
                                        &dns_server,
                                        domain,
                                        timeout,
                                    )
                                    .await
                                }
                                _ => {
                                    anyhow::bail!("Expected TCP-capable resolver for DNS over TCP")
                                }
                            }
                        }
                        DNSProtocol::TLS | DNSProtocol::HTTPS(_) => anyhow::bail!(
                            "Proxy DNS query for {:?} not implemented yet for {}",
                            endpoint.proto,
                            dns_server
                        ),
                    };
                }
                UplinkProxy::Remote(remote) => {
                    return match &endpoint.proto {
                        DNSProtocol::UDP => {
                            let mut conn =
                                RemoteAdapter::connect_tcp(remote, dns_server.clone())
                                    .await?;
                            match &mut conn {
                                super::proxy_adapters::ProxyConnection::Udp(tunnel) => {
                                    super::proxy_dns::query_via_udp(
                                        tunnel.as_mut(),
                                        &dns_server,
                                        domain,
                                        timeout,
                                    )
                                    .await
                                }
                                _ => {
                                    anyhow::bail!("Expected UDP-capable resolver for DNS over UDP")
                                }
                            }
                        }
                        DNSProtocol::TCP => {
                            let mut conn =
                                RemoteAdapter::connect_tcp(remote, dns_server.clone())
                                    .await?;
                            match &mut conn {
                                super::proxy_adapters::ProxyConnection::Tcp(stream) => {
                                    super::proxy_dns::query_via_tcp(
                                        stream.as_mut(),
                                        &dns_server,
                                        domain,
                                        timeout,
                                    )
                                    .await
                                }
                                _ => {
                                    anyhow::bail!("Expected TCP-capable resolver for DNS over TCP")
                                }
                            }
                        }
                        DNSProtocol::TLS | DNSProtocol::HTTPS(_) => anyhow::bail!(
                            "Proxy DNS query for {:?} not implemented yet for {}",
                            endpoint.proto,
                            dns_server
                        ),
                    };
                }
                UplinkProxy::Geph | UplinkProxy::File(_) => {}
            }
        }

        anyhow::bail!(
            "All proxy-based DNS resolution attempts failed for {}",
            domain
        )
    }

    async fn query_dns_via_tier2_no_proxy_endpoint(
        &self,
        group_id: &GroupId,
        dns_host: &str,
        protocol: DNSProtocol,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        let endpoint = self
            .group(group_id)?
            .tier2_nameservers
            .get(dns_host)
            .and_then(|endpoints| endpoints.get(&protocol))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing tier2 endpoint for host '{}' and protocol {:?}",
                    dns_host,
                    protocol
                )
            })?;

        if let Ok(ip) = dns_host.parse::<IpAddr>() {
            let host = DNSHost::Tier2IP(SocketAddr::new(ip, endpoint.port));
            return Self::query_dns_via_no_proxy_endpoint(&host, endpoint, domain, timeout).await;
        }

        if let Some(cached_ips) = self.get_latest_ips_in_group(group_id, dns_host) {
            if cached_ips.len() > 1 {
                info!(
                    "resolver_cache host={} ip_count={} ips={}",
                    dns_host,
                    cached_ips.len(),
                    Self::ips_brief(cached_ips)
                );
            }
            for ip in cached_ips {
                let host = DNSHost::Tier2Domain {
                    domain: dns_host.to_string(),
                    socket: Some(SocketAddr::new(*ip, endpoint.port)),
                };
                match Self::query_dns_via_no_proxy_endpoint(
                    &host,
                    endpoint.clone(),
                    domain,
                    timeout,
                )
                .await
                {
                    Ok(ips) => return Ok(ips),
                    Err(e) => {
                        warn!(
                            "dns_query_attempt_failed domain={} proxied=false tier=tier2 resolver_host={} resolver_ip={} protocol={} error={}",
                            domain,
                            dns_host,
                            ip,
                            Self::protocol_label(&endpoint.proto),
                            e
                        );
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "All IPs have been tried for DNS resolver '{}'",
            dns_host
        ))
    }

    async fn query_dns_via_tier2_proxy_endpoint(
        &self,
        group_id: &GroupId,
        hub: &UplinkHub,
        dns_host: &str,
        protocol: DNSProtocol,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        let endpoint = self
            .group(group_id)?
            .tier2_nameservers
            .get(dns_host)
            .and_then(|endpoints| endpoints.get(&protocol))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing tier2 endpoint for host '{}' and protocol {:?}",
                    dns_host,
                    protocol
                )
            })?;

        if let Ok(ip) = dns_host.parse::<IpAddr>() {
            let host = DNSHost::Tier2IP(SocketAddr::new(ip, endpoint.port));
            return Self::query_dns_via_proxy_endpoint(hub, &host, endpoint, domain, timeout).await;
        }

        if let Some(cached_ips) = self.get_latest_ips_in_group(group_id, dns_host) {
            if cached_ips.len() > 1 {
                info!(
                    "resolver_cache host={} ip_count={} ips={}",
                    dns_host,
                    cached_ips.len(),
                    Self::ips_brief(cached_ips)
                );
            }
            for ip in cached_ips {
                let host = DNSHost::Tier2Domain {
                    domain: dns_host.to_string(),
                    socket: Some(SocketAddr::new(*ip, endpoint.port)),
                };
                match Self::query_dns_via_proxy_endpoint(
                    hub,
                    &host,
                    endpoint.clone(),
                    domain,
                    timeout,
                )
                .await
                {
                    Ok(ips) => return Ok(ips),
                    Err(e) => {
                        warn!(
                            "dns_query_attempt_failed domain={} proxied=true tier=tier2 resolver_host={} resolver_ip={} protocol={} error={}",
                            domain,
                            dns_host,
                            ip,
                            Self::protocol_label(&endpoint.proto),
                            e
                        );
                    }
                }
            }
        }

        Err(anyhow::anyhow!("DNS resolution failed for '{}'", domain))
    }

    async fn query_dns_via_tier1_no_proxy_endpoint(
        &self,
        group_id: &GroupId,
        server: &SocketAddr,
        protocol: DNSProtocol,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        let endpoint = self
            .group(group_id)?
            .tier1_nameservers
            .get(server)
            .and_then(|endpoints| endpoints.get(&protocol))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing tier1 endpoint for server '{}' and protocol {:?}",
                    server,
                    protocol
                )
            })?;
        let host = DNSHost::Tier1(SocketAddr::new(server.ip(), endpoint.port));
        Self::query_dns_via_no_proxy_endpoint(&host, endpoint, domain, timeout).await
    }

    async fn query_dns_via_tier1_proxy_endpoint(
        &self,
        group_id: &GroupId,
        hub: &UplinkHub,
        server: &SocketAddr,
        protocol: DNSProtocol,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        let endpoint = self
            .group(group_id)?
            .tier1_nameservers
            .get(server)
            .and_then(|endpoints| endpoints.get(&protocol))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing tier1 endpoint for server '{}' and protocol {:?}",
                    server,
                    protocol
                )
            })?;
        let host = DNSHost::Tier1(SocketAddr::new(server.ip(), endpoint.port));
        Self::query_dns_via_proxy_endpoint(hub, &host, endpoint, domain, timeout).await
    }

    async fn resolve_domain_direct_tier2(
        &self,
        group_id: &GroupId,
        domain: &str,
    ) -> Result<BTreeSet<IpAddr>> {
        let group = self.group(group_id)?;
        let timeout = Duration::from_secs(8);

        for (hostname, endpoints) in &group.tier2_nameservers {
            for protocol in endpoints.keys().cloned() {
                match self
                    .query_dns_via_tier2_no_proxy_endpoint(
                        group_id,
                        hostname,
                        protocol.clone(),
                        domain,
                        timeout,
                    )
                    .await
                {
                    Ok(ips) => return Ok(ips.into_iter().collect()),
                    Err(e) => {
                        warn!(
                            "dns_query_failed domain={} proxied=false tier=tier2 resolver={} protocol={} error={}",
                            domain,
                            hostname,
                            Self::protocol_label(&protocol),
                            e
                        );
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "All direct DNS queries failed for {}",
            domain
        ))
    }

    async fn resolve_domain_direct_tier1(
        &self,
        group_id: &GroupId,
        domain: &str,
    ) -> Result<BTreeSet<IpAddr>> {
        let group = self.group(group_id)?;
        let timeout = Duration::from_secs(8);

        for (server, endpoints) in &group.tier1_nameservers {
            for protocol in endpoints.keys().cloned() {
                match self
                    .query_dns_via_tier1_no_proxy_endpoint(
                        group_id,
                        server,
                        protocol.clone(),
                        domain,
                        timeout,
                    )
                    .await
                {
                    Ok(ips) => return Ok(ips.into_iter().collect()),
                    Err(e) => {
                        warn!(
                            "dns_query_failed domain={} proxied=false tier=tier1 resolver={} protocol={} error={}",
                            domain,
                            server,
                            Self::protocol_label(&protocol),
                            e
                        );
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "All direct DNS queries failed for {}",
            domain
        ))
    }

    async fn attempt_path(
        &self,
        group_id: &GroupId,
        path: ResolutionPath,
        domain: &str,
        hub: Option<&UplinkHub>,
        cancel: Option<&AtomicBool>,
    ) -> PathAttempt {
        if cancel
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            return PathAttempt::Skipped;
        }

        match path {
            ResolutionPath::ProxyTier2 => {
                let Some(hub) = hub else {
                    return PathAttempt::Skipped;
                };
                if !Self::has_proxy_resolvers(hub)
                    || self
                        .groups
                        .get(group_id)
                        .map(|g| g.tier2_nameservers.is_empty())
                        .unwrap_or(true)
                {
                    return PathAttempt::Skipped;
                }
                match self
                    .resolve_via_available_tier2_proxies(group_id, hub, domain)
                    .await
                {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::ProxyTier1 => {
                let Some(hub) = hub else {
                    return PathAttempt::Skipped;
                };
                if !Self::has_proxy_resolvers(hub)
                    || self
                        .groups
                        .get(group_id)
                        .map(|g| g.tier1_nameservers.is_empty())
                        .unwrap_or(true)
                {
                    return PathAttempt::Skipped;
                }
                match self
                    .resolve_via_available_tier1_proxies(group_id, hub, domain)
                    .await
                {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::DirectTier2 => {
                match self.resolve_domain_direct_tier2(group_id, domain).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
            ResolutionPath::DirectTier1 => {
                match self.resolve_domain_direct_tier1(group_id, domain).await {
                    Ok(ips) => PathAttempt::Resolved(ips),
                    Err(e) => PathAttempt::Failed(e),
                }
            }
        }
    }

    async fn resolve_target_domain(
        &mut self,
        group_id: &GroupId,
        target: ResolutionTargetKind,
        domain: &str,
        hub: Option<&UplinkHub>,
        cancel: Option<&AtomicBool>,
        direct_only: bool,
        solved: &mut ProfileSolved,
        metrics: &mut ResolutionMetrics,
        refresh: bool,
    ) {
        if !refresh && let Some(cached) = self.cached_for_target(group_id, target, domain) {
            metrics.cache_hits += 1;
            info!("domain {} has been cached, not resolving", domain);
            solved.add_resolution(Domain::from(domain), cached);
            return;
        }

        for path in ResolutionPolicy::paths_for(target, direct_only) {
            if cancel
                .map(|flag| flag.load(Ordering::Relaxed))
                .unwrap_or(false)
            {
                warn!(
                    "Interrupt observed while resolving {}; stopping path attempts",
                    domain
                );
                return;
            }

            match self
                .attempt_path(group_id, *path, domain, hub, cancel)
                .await
            {
                PathAttempt::Resolved(ip_set) => {
                    let (proxied, tier) = Self::path_label(*path);
                    info!(
                        "domain_resolved domain={} proxied={} tier={} ip_count={} ips={}",
                        domain,
                        proxied,
                        tier,
                        ip_set.len(),
                        Self::ips_brief(&ip_set)
                    );
                    metrics.mark_resolved(*path);
                    solved.add_resolution(Domain::from(domain), ip_set.clone());
                    self.store_target_resolution(group_id, target, domain, ip_set);
                    return;
                }
                PathAttempt::Skipped => {
                    let (proxied, tier) = Self::path_label(*path);
                    info!(
                        "domain_resolution_path_skipped domain={} proxied={} tier={}",
                        domain, proxied, tier
                    );
                }
                PathAttempt::Failed(e) => {
                    let (proxied, tier) = Self::path_label(*path);
                    warn!(
                        "domain_resolution_path_failed domain={} proxied={} tier={} error={}",
                        domain, proxied, tier, e
                    );
                }
            }
        }

        metrics.unresolved += 1;
    }

    async fn resolve_via_available_tier2_proxies(
        &self,
        group_id: &GroupId,
        hub: &UplinkHub,
        domain: &str,
    ) -> Result<BTreeSet<IpAddr>> {
        let group = self.group(group_id)?;
        if group.tier2_nameservers.is_empty() {
            anyhow::bail!("No tier2 DNS servers available for proxy-based resolution");
        }

        let timeout = Duration::from_secs(8);

        for (hostname, endpoints) in &group.tier2_nameservers {
            for protocol in endpoints.keys().cloned() {
                match self
                    .query_dns_via_tier2_proxy_endpoint(
                        group_id,
                        hub,
                        hostname,
                        protocol.clone(),
                        domain,
                        timeout,
                    )
                    .await
                {
                    Ok(ips) => return Ok(ips.into_iter().collect()),
                    Err(e) => {
                        warn!(
                            "dns_query_failed domain={} proxied=true tier=tier2 resolver={} protocol={} error={}",
                            domain,
                            hostname,
                            Self::protocol_label(&protocol),
                            e
                        );
                    }
                }
            }
        }

        anyhow::bail!(
            "All proxy-based DNS resolution attempts failed for {}",
            domain
        )
    }

    async fn resolve_via_available_tier1_proxies(
        &self,
        group_id: &GroupId,
        hub: &UplinkHub,
        domain: &str,
    ) -> Result<BTreeSet<IpAddr>> {
        let group = self.group(group_id)?;
        if group.tier1_nameservers.is_empty() {
            anyhow::bail!("No tier1 DNS servers available for proxy-based resolution");
        }

        let timeout = Duration::from_secs(8);

        for (server, endpoints) in &group.tier1_nameservers {
            for protocol in endpoints.keys().cloned() {
                match self
                    .query_dns_via_tier1_proxy_endpoint(
                        group_id,
                        hub,
                        server,
                        protocol.clone(),
                        domain,
                        timeout,
                    )
                    .await
                {
                    Ok(ips) => return Ok(ips.into_iter().collect()),
                    Err(e) => {
                        warn!(
                            "dns_query_failed domain={} proxied=true tier=tier1 resolver={} protocol={} error={}",
                            domain,
                            server,
                            Self::protocol_label(&protocol),
                            e
                        );
                    }
                }
            }
        }

        anyhow::bail!(
            "All proxy-based DNS resolution attempts failed for {}",
            domain
        )
    }

    /// Prepare tier2 DNS hostnames by resolving them via tier1 DNS resolvers
    /// and storing results into `tier2_cache`.
    pub async fn prepare_tier2_dns_via_tier1(
        &mut self,
        group_id: &GroupId,
        cancel: Option<&AtomicBool>,
    ) -> Result<()> {
        warn!("prepare_tier2_dns_hosts_start");

        let group = self.group(group_id)?;

        let tier2_query_hosts: Vec<_> = group.tier2_nameservers.keys().cloned().collect();
        let mut failed_hosts = Vec::new();

        for host in tier2_query_hosts {
            if cancel
                .map(|flag| flag.load(Ordering::Relaxed))
                .unwrap_or(false)
            {
                warn!("Interrupt observed during tier2 DNS preparation");
                break;
            }

            if host.parse::<IpAddr>().is_ok() {
                continue;
            }

            if self.get_latest_ips_in_group(group_id, &host).is_some() {
                continue;
            }

            match self.resolve_domain_direct_tier1(group_id, &host).await {
                Ok(ip_set) => {
                    info!(
                        "prepare_tier2_dns_host_resolved host={} proxied=false tier=tier1 ip_count={} ips={}",
                        host,
                        ip_set.len(),
                        Self::ips_brief(&ip_set)
                    );
                    self.update_cache_in_group(group_id, &host, ip_set);
                }
                Err(e) => {
                    warn!(
                        "prepare_tier2_dns_host_failed host={} proxied=false tier=tier1 error={}",
                        host, e
                    );
                    failed_hosts.push(format!("{} ({})", host, e));
                }
            }
        }

        if !failed_hosts.is_empty() {
            anyhow::bail!(
                "Failed to prepare tier2 DNS hosts via tier1: {}",
                failed_hosts.join(", ")
            );
        }

        if let Err(e) = self.save_atomic() {
            warn!(
                "Failed to persist ClashState after tier2 preparation: {}",
                e
            );
        }

        Ok(())
    }

    pub async fn resolve_group(
        &mut self,
        group_id: &GroupId,
        hub: Option<&UplinkHub>,
        cancel: Option<&AtomicBool>,
        direct_only: bool,
        refresh: bool,
    ) -> Result<ResolveProfileReport> {
        self.prepare_tier2_dns_via_tier1(group_id, cancel).await?;

        let group = self.group(group_id)?;

        info!(
            "resolver_ready tier1_nameserver_count={} tier2_nameserver_count={}",
            group.tier1_nameservers.len(),
            group.tier2_nameservers.len()
        );

        let domains: Vec<Domain> = self
            .domain_group
            .iter()
            .filter_map(|(domain, gid)| (gid == group_id).then_some(domain.clone()))
            .collect();

        let mut solved = ProfileSolved::new();
        let mut metrics = ResolutionMetrics::default();

        for domain in domains {
            if cancel
                .map(|flag| flag.load(Ordering::Relaxed))
                .unwrap_or(false)
            {
                warn!("Interrupt observed during group resolve; stopping before next entry");
                break;
            }

            self.resolve_target_domain(
                group_id,
                ResolutionTargetKind::ProxyDomain,
                domain.as_str(),
                hub,
                cancel,
                direct_only,
                &mut solved,
                &mut metrics,
                refresh,
            )
            .await;
        }

        if let Err(e) = self.save_atomic() {
            warn!("Failed to persist ClashState: {}", e);
        }

        Ok(ResolveProfileReport { solved, metrics })
    }

    /// Resolve exactly one user-supplied domain using proxy-domain path policy.
    ///
    /// This does not persist state and does not mutate the caller's `ClashState`.
    pub async fn resolve_one_domain_no_store(
        &self,
        domain: &str,
        hub: Option<&UplinkHub>,
        cancel: Option<&AtomicBool>,
        direct_only: bool,
    ) -> Result<ResolveProfileReport> {
        let mut working = self.clone();
        let domain_key = Domain::from(domain);
        let group_id = working
            .group_for_domain(&domain_key)
            .cloned()
            .or_else(|| working.groups.keys().next().cloned())
            .unwrap_or_else(|| GroupId::from("default"));

        let group = working.group(&group_id)?;
        info!(
            "resolver_ready tier1_nameserver_count={} tier2_nameserver_count={}",
            group.tier1_nameservers.len(),
            group.tier2_nameservers.len()
        );

        let mut solved = ProfileSolved::new();
        let mut metrics = ResolutionMetrics::default();

        if cancel
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            warn!(
                "resolve_one_domain_cancelled domain={} before start=true",
                domain
            );
            return Ok(ResolveProfileReport { solved, metrics });
        }

        working
            .resolve_target_domain(
                &group_id,
                ResolutionTargetKind::ProxyDomain,
                domain,
                hub,
                cancel,
                direct_only,
                &mut solved,
                &mut metrics,
                true,
            )
            .await;

        Ok(ResolveProfileReport { solved, metrics })
    }
}

impl PersistentState for ClashState {
    const STATE_NAME: &'static str = "clash";

    fn path() -> PathBuf {
        state_paths::uplink_clash_state()
    }
}
