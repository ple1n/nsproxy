use super::*;
use bytes::BytesMut;
use clash_bootstrap::{Bootstrapper, config::BootstrapConfig};
use clash_config::Config;
use rustls::pki_types::ServerName;
use anyhow::Context;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::ReadBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
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
    /// Returns the resolved domains while persisting centralized cache/state in clash.json.
    pub async fn solve_file(&self, state: &mut ClashState, hub: Option<&UplinkHub>) -> Result<DomainsSolved> {
        let solved = state.resolve_profile(self, hub).await?;
        Ok(solved.domains)
    }

}

// ============================================================================
// New shared Clash state (tier1 / tier2 cache)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClashCacheEntry {
    pub ips: Vec<String>,
    pub updated_at: u64,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClashState {
    pub schema_version: u32,
    pub tier1_nameservers: Vec<String>, // direct IPs (or ip:port)
    pub tier2_nameservers: Vec<String>, // DoH/DoT URLs or hostnames
    pub tier2_cache: BTreeMap<String, ClashCacheEntry>,
    pub proxies: DomainsSolved
}

impl ClashState {
    pub fn path() -> PathBuf {
        state_paths::uplink_root().join("clash.json")
    }

    pub fn load_or_default() -> Result<Self> {
        let path = Self::path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .context(format!("Failed to read clash.json from {:?}", path))?;
            let st: ClashState = serde_json::from_str(&content).context("Failed to parse clash.json")?;
            Ok(st)
        } else {
            Ok(ClashState::default())
        }
    }

    pub fn save_atomic(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create uplink root dir")?;
        }
        let tmp = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self).context("Failed to serialize ClashState")?;
        std::fs::write(&tmp, content).context("Failed to write temp clash.json")?;
        std::fs::rename(&tmp, &path).context("Failed to rename clash.json temp file")?;
        Ok(())
    }

    /// Return parsed IPs for a cached host if not expired
    pub fn get_latest_ips(&self, host: &str) -> Option<Vec<IpAddr>> {
        let entry = self.tier2_cache.get(host)?;
        if let Some(ttl) = entry.ttl_seconds {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if entry.updated_at + ttl < now {
                return None;
            }
        }
        let mut out = Vec::new();
        for s in &entry.ips {
            if let Ok(ip) = s.parse::<IpAddr>() {
                out.push(ip);
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }

    /// Update cache entry for host
    pub fn update_cache(&mut self, host: &str, ips: Vec<IpAddr>, ttl_seconds: Option<u64>) {
        let ips_str: Vec<String> = ips.into_iter().map(|ip| ip.to_string()).collect();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.tier2_cache.insert(host.to_string(), ClashCacheEntry { ips: ips_str, updated_at: now, ttl_seconds });
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

    /// Resolve a profile using the two-tier approach. If `hub` is Some, proxy-based resolution
    /// may be used in future; for now it falls back to direct resolution but updates the shared cache.
    pub async fn resolve_profile(&mut self, profile: &ClashProfile, _hub: Option<&UplinkHub>) -> Result<ProfileSolved> {
        // Seed tier lists if empty
        if self.tier1_nameservers.is_empty() {
            self.tier1_nameservers = profile.bootstrap_nameservers.clone();
        }
        if self.tier2_nameservers.is_empty() {
            self.tier2_nameservers = profile.main_nameservers.clone();
        }

        // Clone tier lists to avoid borrowing `self` immutably while we mutate cache
        let tier1_nameservers = self.tier1_nameservers.clone();
        let tier2_nameservers = self.tier2_nameservers.clone();

        // Build main nameserver host strings similar to previous logic
        let main_nameserver_hosts: Vec<String> = tier2_nameservers.iter().map(|ns| {
            if let Ok(url) = url::Url::parse(ns) {
                if let Some(host) = url.host_str() {
                    if let Some(port) = url.port() {
                        return format!("{}:{}", host, port);
                    }
                    return host.to_string();
                }
            }
            ns.clone()
        }).collect();

        // Build two-tier bootstrapper (direct DNS) using tier1 (bootstrap) and tier2 (main)
        let bootstrap_config = BootstrapConfig::with_bootstrap_and_main(
            tier1_nameservers.iter().map(|s| s.as_str()).collect(),
            main_nameserver_hosts.iter().map(|s| s.as_str()).collect(),
        )?;

        let bootstrapper = Bootstrapper::new(bootstrap_config)?;

        info!("Two-tier DNS bootstrapper created (ClashState-driven)");
        info!("  Bootstrap tier: {} nameservers", self.tier1_nameservers.len());
        info!("  Main tier: {} nameservers", self.tier2_nameservers.len());

        let mut solved = ProfileSolved::new();

        // Step 1: Resolve main nameserver hostnames via bootstrap tier
        for ns in &tier2_nameservers {
            if let Ok(url) = url::Url::parse(ns) {
                if let Some(host) = url.host_str() {
                    if host.parse::<IpAddr>().is_err() {
                        match bootstrapper.resolve_all(host).await {
                            Ok(ips) => {
                                let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                                info!("Resolved {} -> {} IPs (main)", host, ip_set.len());
                                solved.add_resolution(host.to_string(), ip_set.clone());
                                // update shared cache
                                self.update_cache(host, ip_set.into_iter().collect(), None);
                            }
                            Err(e) => {
                                warn!("Failed to resolve main nameserver {}: {}", host, e);
                            }
                        }
                    }
                }
            }
        }

        // Step 2: Resolve proxy server domains via main tier
        for domain in &profile.proxy_domains {
            match bootstrapper.resolve_all(domain).await {
                Ok(ips) => {
                    let ip_set: BTreeSet<IpAddr> = ips.into_iter().collect();
                    info!("Resolved {} -> {} IPs (proxy)", domain, ip_set.len());
                    solved.add_resolution(domain.clone(), ip_set.clone());
                    self.add_proxy_resolution(domain, ip_set);
                }
                Err(e) => {
                    warn!("Failed to resolve {}: {}", domain, e);
                }
            }
        }

        // Persist updated clash state
        if let Err(e) = self.save_atomic() {
            warn!("Failed to persist ClashState: {}", e);
        }

        Ok(solved)
    }
}
