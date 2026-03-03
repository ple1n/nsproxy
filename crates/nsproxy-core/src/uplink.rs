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
//!              RoutingDecision::Proxy { target: WireAddress::DomainAddress("blocked.com".into(), 443), id: ProxyID::for_trojan("1.2.3.4:443".parse().unwrap(), "example.com", "secret") })
//!     .build();
//!
//! let mut hub = UplinkHub::with_routing(routing);
//!
//! // 2. Add proxies to the hub
//! hub.add_proxy(
//!     ProxyID::for_trojan("1.2.3.4:443".parse().unwrap(), "example.com", "secret"),
//!     UplinkProxy::Clash(trojan_proxy)
//! );
//!
//! // 3. Pass the hub to the Router
//! let mut router = Router::new(device, RouterConfig { mtu, .. }, hub, file_tx, conf);
//! router.run().await?;
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
    time::Duration,
};

use anyhow::{Context, Result};
use nsproxy_common::crdt::CRDT;
use nsproxy_common::routing::{
    DropReason, ProxyID, ProxyNym, RoutingContext, RoutingDecision, RoutingProtocol, RoutingResovled,
    VDNSRES,
};
use nsproxy_common::stats::{ChronoData, ProxyStats, Timestamp};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use tracing::{info, warn};
use tun2socks5::ArgProxy;
use tun2socks5::dns::{VirtDNSAsync, VirtDNSHandle};

use crate::{state_blueprint::PersistentState, state_paths};

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
pub type DomainsSolved = BTreeMap<Domain, BTreeMap<Timestamp, DNSResponse>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Domain(pub String);

impl Domain {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for Domain {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Domain {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.0
    }
}

impl std::ops::Deref for Domain {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

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

    pub fn add_resolution(&mut self, domain: Domain, ips: BTreeSet<IpAddr>) {
        self.domains
            .entry(domain)
            .or_default()
            .insert(Timestamp::now(), DNSResponse { ips });
    }

    /// Get the most recent IPs for a domain
    pub fn get_latest_ips(&self, domain: &str) -> Option<&BTreeSet<IpAddr>> {
        self.domains
            .get(&Domain::from(domain))?
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
pub type RoutingFunction =
    Arc<dyn Fn(&RoutingContext, &UplinkHub) -> RoutingResovled + Send + Sync>;

pub fn preferred_addr(a: WireAddress, b: WireAddress) -> WireAddress {
    match (&a, &b) {
        (WireAddress::DomainAddress(..), _) => a,
        (_, WireAddress::DomainAddress(..)) => b,
        _ => a,
    }
}

pub fn simple_routing(id: ProxyID) -> RoutingFunction {
    Arc::new(move |ctx: &RoutingContext, _hub: &UplinkHub| {
        if ctx.attempt_num > 0 {
            return RoutingResovled::Drop(DropReason::MaxRetry);
        }

        match &ctx.dns {
            // Real IP from TUN, no VirtDNS mapping — proxy using raw socket address
            VDNSRES::NormalProxying => RoutingResovled::ProxyResovled {
                target: WireAddress::SocketAddress(SocketAddr::new(ctx.target_ip, ctx.target_port)),
                id: id.clone(),
            },
            // VirtDNS decoded to a domain — use hostname so the proxy resolves it, preserving privacy
            VDNSRES::Opine(RoutingDecision::HostOverProxy(host)) => RoutingResovled::ProxyResovled {
                target: WireAddress::DomainAddress(host.clone(), ctx.target_port),
                id: id.clone(),
            },
            // VirtDNS decoded to a concrete socket — proxy to that socket directly
            VDNSRES::Opine(RoutingDecision::SocketOverProxy(sock)) => RoutingResovled::ProxyResovled {
                target: WireAddress::SocketAddress(*sock),
                id: id.clone(),
            },
            VDNSRES::Opine(RoutingDecision::NATByTUN(sock)) => RoutingResovled::NATByTUN(*sock),
            VDNSRES::Opine(RoutingDecision::Direct(sock)) => RoutingResovled::Direct(*sock),
            VDNSRES::Opine(RoutingDecision::File(path)) => RoutingResovled::ProxyResovled {
                target: WireAddress::SocketAddress(SocketAddr::new(ctx.target_ip, ctx.target_port)),
                id: ProxyID::for_file(path.as_path()),
            },
            VDNSRES::Opine(RoutingDecision::Drop(_)) | VDNSRES::ERR => {
                RoutingResovled::Drop(DropReason::Preprocess)
            }
        }
    })
}

// This struct is not directly serialized
/// Central hub of all resources we have
pub struct UplinkHub {
    pub proxies: HashMap<ProxyID, UplinkProxy>,
    routing_fn: RoutingFunction,
    /// Centralized Clash resolver/cache state loaded from /nsp3/clash.json
    pub clash: Option<clash::ClashState>,
    pub stats: HashMap<ProxyID, ProxyStats>,
    pub stats_clear: Timestamp,
    /// Map from proxy pseudonym (nym) to ProxyID for O(1) lookup
    pub nym_map: HashMap<ProxyNym, ProxyID>,
    pub found_ips: ChronoData,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteProxyState {
    pub proxies: Vec<ArgProxy>,
}

impl RemoteProxyState {
    pub fn path() -> PathBuf {
        <Self as PersistentState>::path()
    }

    pub fn load_or_default() -> Result<Self> {
        <Self as PersistentState>::load_or_default()
    }

    pub fn save_atomic(&self) -> Result<()> {
        <Self as PersistentState>::save_atomic(self)
    }

    pub fn add_proxy(&mut self, proxy: ArgProxy) -> bool {
        if self
            .proxies
            .iter()
            .any(|existing| existing.addr == proxy.addr)
        {
            return false;
        }
        self.proxies.push(proxy);
        true
    }

    pub fn remove_proxy(&mut self, nym: &ProxyNym) -> bool {
        let before = self.proxies.len();
        self.proxies.retain(|proxy| {
            let id = ProxyID::for_remote(proxy.addr);
            id.nym() != *nym
        });
        self.proxies.len() != before
    }
}

impl PersistentState for RemoteProxyState {
    const STATE_NAME: &'static str = "uplink_remote";

    fn path() -> PathBuf {
        state_paths::uplink_remote_state()
    }
}

/// All proxies here should be immediately connectable without further resolution dependent on other state
#[derive(Debug, Clone)]
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
            routing_fn: Arc::new(|_ctx: &RoutingContext, _hub: &UplinkHub| {
                RoutingResovled::Drop(DropReason::Preprocess)
            }),
            clash: None,
            stats: HashMap::new(),
            stats_clear: Timestamp::default(),
            nym_map: HashMap::new(),
            found_ips: ChronoData::default(),
        }
    }
    pub fn update_link_ttfb(&mut self, id: &ProxyID, latency: Duration) {
        self.stats
            .entry(id.clone())
            .or_default()
            .record_latency_ms(latency.as_millis() as u64);
    }

    pub fn update_link_conn_check(&mut self, id: &ProxyID, success: bool) {
        self.stats
            .entry(id.clone())
            .or_default()
            .record_attempt(success);
    }

    pub fn get_link_stats(&self, id: &ProxyID) -> Option<ProxyStats> {
        self.stats.get(id).cloned()
    }

    pub fn clear_stats(&mut self) {
        self.stats.clear();
        self.stats_clear = Timestamp::now();
    }

    /// Persist current in-memory stats to uplink/stats.json.
    /// Loads the file first and merges to preserve stats from other processes.
    pub fn save_stats(&mut self) -> Result<()> {
        let persisted = UplinkStatsState::load_or_default()?;

        // A newer clear signal was already persisted by another process.
        // Discard local pre-clear data and adopt persisted state; skip saving.
        if persisted.clear > self.stats_clear {
            self.stats = persisted.stats;
            self.stats_clear = persisted.clear;
            return Ok(());
        }

        let current = UplinkStatsState {
            stats: self.stats.clone(),
            clear: self.stats_clear,
        };
        let mut merged = persisted.merge(current);
        merged.compact_for_save();
        merged.save_atomic()?;

        // Keep in-memory copy synchronized with persisted merged state.
        self.stats = merged.stats;
        self.stats_clear = merged.clear;
        Ok(())
    }

    /// Load persisted stats from uplink/stats.json and merge into in-memory state.
    /// In-memory entries take precedence over persisted ones.
    pub fn load_stats(&mut self) -> Result<()> {
        let state = UplinkStatsState::load_or_default()?;

        if state.clear > self.stats_clear {
            self.stats = state.stats;
            self.stats_clear = state.clear;
            return Ok(());
        }

        if state.clear < self.stats_clear {
            return Ok(());
        }

        for (id, stats) in state.stats {
            self.stats.entry(id).or_insert(stats);
        }
        Ok(())
    }

    /// Create a new UplinkHub with a custom routing function
    pub fn with_routing(routing_fn: RoutingFunction) -> Self {
        Self {
            proxies: HashMap::new(),
            routing_fn,
            clash: None,
            stats: HashMap::new(),
            stats_clear: Timestamp::default(),
            nym_map: HashMap::new(),
            found_ips: ChronoData::default(),
        }
    }

    /// Hydrate hub from persisted state in one entrypoint:
    /// - loads centralized Clash state (`/nsp3/uplink/clash.json`)
    /// - loads all saved proxies that can be materialized from that state
    pub fn hydrate_from_persisted(&mut self) -> Result<usize> {
        let _ = self.load_clash_state()?;
        self.load_saved_proxies()?;
        self.load_stats()?;
        Ok(self.proxies.len())
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
        // insert into proxies and update proxynym map for fast lookup
        let nym = id.nym();
        self.nym_map.insert(nym, id.clone());
        self.proxies.insert(id, proxy);
    }

    /// Get a proxy by ID
    pub fn get_proxy(&self, id: &ProxyID) -> Option<&UplinkProxy> {
        self.proxies.get(id)
    }

    /// Make a routing decision for the given context, resolving all intermediate variants
    /// using hub state (proxy registry, etc.) into a concrete `RoutingResovled`.
    pub fn route(&self, ctx: &RoutingContext) -> RoutingResovled {
        (self.routing_fn)(ctx, self) 
    }

    /// Set a new routing function
    pub fn set_routing(&mut self, routing_fn: RoutingFunction) {
        self.routing_fn = routing_fn;
    }

    /// Get all proxies
    pub fn all_proxies(&self) -> &HashMap<ProxyID, UplinkProxy> {
        &self.proxies
    }

    // `get_proxy_by_nym` removed — use `nym_map` directly for lookups

    /// Get the nym for a proxy ID
    pub fn get_nym(&self, id: &ProxyID) -> Option<ProxyNym> {
        self.proxies.contains_key(id).then(|| id.nym())
    }

    /// Load all saved proxies across all uplink kinds
    pub fn load_saved_proxies(&mut self) -> Result<usize> {
        self.load_remote_proxies()?;
        self.load_clash_proxies()?;

        Ok(self.proxies.len())
    }

    /// Load all saved remote proxies from /nsp3/uplink/remote.json
    pub fn load_remote_proxies(&mut self) -> Result<usize> {
        let state = RemoteProxyState::load_or_default()?;
        let mut count = 0;

        for proxy in state.proxies {
            let id = ProxyID::for_remote(proxy.addr);
            self.add_proxy(id, UplinkProxy::Remote(proxy));
            count += 1;
        }

        Ok(count)
    }

    /// Export a portable snapshot of all hub state that can be serialized to JSON.
    ///
    /// The routing function is excluded — it must be re-supplied on import.
    pub fn export(&self) -> UplinkSnapshot {
        let remote_proxies: Vec<ArgProxy> = self
            .proxies
            .values()
            .filter_map(|p| {
                if let UplinkProxy::Remote(arg) = p {
                    Some(arg.clone())
                } else {
                    None
                }
            })
            .collect();

        UplinkSnapshot {
            clash: self.clash.clone(),
            remote_proxies,
            stats: self.stats.clone(),
        }
    }

    /// Build an `UplinkHub` from a previously exported [`UplinkSnapshot`].
    ///
    /// All persisted sub-states (clash, remote proxies, stats) are applied in
    /// memory.  The routing function defaults to the drop-all stub; callers
    /// should call `set_routing` or `with_routing` afterwards.
    pub fn from_snapshot(snapshot: UplinkSnapshot) -> Result<Self> {
        let mut hub = Self::new();

        if let Some(clash_state) = snapshot.clash {
            hub.clash = Some(clash_state);
        }

        for proxy in snapshot.remote_proxies {
            let id = ProxyID::for_remote(proxy.addr);
            hub.add_proxy(id, UplinkProxy::Remote(proxy));
        }

        hub.load_clash_proxies()?;

        for (id, stats) in snapshot.stats {
            hub.stats.entry(id).or_insert(stats);
        }

        Ok(hub)
    }

    /// Load all Clash proxies from centralized clash state and add them to the hub
    pub fn load_clash_proxies(&mut self) -> Result<usize> {
        let clash_state = self.load_clash_state()?.clone();
        let state_proxies = clash_state.proxies;

        let mut count = 0;
        for (_proxy_id, cfg) in clash_state.trojan_proxies {
            let resolved_ip = state_proxies
                .get(&Domain::from(cfg.server.clone()))
                .and_then(|responses| responses.last_key_value())
                .and_then(|(_, response)| response.ips.iter().next().copied());

            if let Some(ip) = resolved_ip {
                let runtime = clash::TrojanProxy {
                    name: cfg.name.clone(),
                    server_addr: SocketAddr::new(ip, cfg.port),
                    server_name: cfg.server.clone(),
                    password: cfg.password.clone(),
                };

                let id = ProxyID::for_trojan(
                    runtime.server_addr,
                    &runtime.server_name,
                    &runtime.password,
                );
                self.add_proxy(id, UplinkProxy::Trojan(runtime));
                count += 1;
            }
        }

        Ok(count)
    }
}


/// Serializable snapshot of all per-proxy link stats, stored at uplink/stats.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UplinkStatsState {
    pub stats: HashMap<ProxyID, ProxyStats>,
    #[serde(default)]
    pub clear: Timestamp,
}

impl UplinkStatsState {
    /// Compact per-proxy timeseries only when beneficial for persistence.
    /// Returns number of proxies that were simplified.
    pub fn compact_for_save(&mut self) -> usize {
        let mut simplified = 0;
        for stats in self.stats.values_mut() {
            if stats.simplify_if_needed() {
                simplified += 1;
            }
        }
        simplified
    }

    /// Clear all accumulated statistics.
    pub fn clear_all(&mut self) {
        self.stats.clear();
        self.clear = Timestamp::now();
    }
}

impl CRDT for UplinkStatsState {
    fn merge(mut self, other: Self) -> Self {
        if other.clear > self.clear {
            return other;
        }

        if other.clear < self.clear {
            return self;
        }

        for (id, stats) in other.stats {
            self.stats
                .entry(id)
                .and_modify(|e| *e = e.clone().merge(stats.clone()))
                .or_insert(stats);
        }
        self
    }
}

/// Portable, fully serializable snapshot of an `UplinkHub`.
///
/// Captures all the state that the hub is built from so it can be written to a
/// single JSON file and later restored on another machine or after a reset.
///
/// The routing function is **not** included (it is code, not data).  When
/// importing, callers should call `hydrate_from_persisted` or supply their own
/// routing function with `UplinkHub::with_routing`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UplinkSnapshot {
    /// Centralized Clash state (proxy configs, resolved IPs, …)
    pub clash: Option<clash::ClashState>,
    /// Saved remote proxies (SOCKS5 / HTTP, …)
    pub remote_proxies: Vec<ArgProxy>,
    /// Per-proxy link statistics keyed by proxy ID
    pub stats: HashMap<ProxyID, ProxyStats>,
}

impl PersistentState for UplinkStatsState {
    const STATE_NAME: &'static str = "uplink_stats";

    fn path() -> PathBuf {
        state_paths::uplink_stats_state()
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
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
        inner: TcpStream,
        info: String,
    }

    /// SOCKS5 UDP tunnel wrapper (UDP ASSOCIATE)
    struct Socks5UdpConn {
        inner: tokio::sync::Mutex<client::SocksDatagram<TcpStream>>,
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

    #[async_trait::async_trait]
    impl UdpLike for Socks5UdpConn {
        async fn send_to(&mut self, data: &[u8], dst: WireAddress) -> std::io::Result<usize> {
            let inner = self.inner.lock().await;
            inner
                .send_to(data, dst)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            Ok(data.len())
        }

        async fn recv_from(&mut self) -> std::io::Result<UdpPacket> {
            let inner = self.inner.lock().await;
            let mut buf = Vec::new();
            let (_read, src) = inner
                .recv_from(Duration::from_secs(86_400), &mut buf)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            Ok(UdpPacket {
                data: buf,
                dst_addr: src,
            })
        }

        fn info(&self) -> &str {
            &self.info
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
            dest: WireAddress,
            proxy_ip: std::net::IpAddr,
        ) -> anyhow::Result<ProxyConnection> {
            info!(
                "Trojan TCP connection to {} via {} ({})",
                dest, proxy.server_name, proxy_ip
            );
            let conn = proxy
                .connect_tcp(proxy_ip, dest)
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
            dest: WireAddress,
            resolved_ip: std::net::IpAddr,
        ) -> anyhow::Result<ProxyConnection> {
            info!(
                "Trojan UDP-associate to {} via {} ({})",
                dest, proxy.server_name, resolved_ip
            );
            let conn = proxy
                .connect_udp(resolved_ip, dest)
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
        pub async fn connect_tcp(
            proxy: &ArgProxy,
            dest: WireAddress,
        ) -> anyhow::Result<ProxyConnection> {
            use tun2socks5::ProxyType;

            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    info!("SOCKS5 TCP connection to proxy {}", proxy.addr);
                    let mut stream =
                        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy.addr))
                            .await
                            .context("Timeout connecting to SOCKS5 proxy")??;
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

        /// Create a SOCKS5 UDP tunnel via UDP ASSOCIATE
        pub async fn connect_udp(proxy: &ArgProxy) -> anyhow::Result<ProxyConnection> {
            use tun2socks5::ProxyType;

            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    info!("SOCKS5 UDP associate to proxy {}", proxy.addr);

                    let stream =
                        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy.addr))
                            .await
                            .context("Timeout connecting to SOCKS5 proxy for UDP")??;

                    let bind_addr = if proxy.addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let socket = UdpSocket::bind(bind_addr)
                        .await
                        .context("Failed to bind local UDP socket for SOCKS5 UDP associate")?;

                    let datagram = client::SocksDatagram::udp_associate(
                        stream,
                        socket,
                        proxy.credentials.clone(),
                    )
                    .await
                    .context("SOCKS5 UDP associate failed")?;

                    Ok(ProxyConnection::Udp(Box::new(Socks5UdpConn {
                        inner: tokio::sync::Mutex::new(datagram),
                        info: format!("socks5+udp://{}", proxy.addr),
                    })))
                }
                ProxyType::Socks4 | ProxyType::Http => {
                    anyhow::bail!(
                        "proxy type {:?} not yet supported for UDP",
                        proxy.proxy_type
                    )
                }
            }
        }
    }

    /// Adapter for creating direct (no-proxy) connections
    pub struct NoProxyAdapter;

    impl NoProxyAdapter {
        pub async fn connect_tcp(target: SocketAddr) -> anyhow::Result<ProxyConnection> {
            info!("Direct TCP connection to {}", target);
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
                "Direct UDP socket for target {} (bind {})",
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
            info!("Direct TLS connection to {:?} ({})", &hostname, target);
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
        RoutingResovled,
    )>,
    default_decision: Option<RoutingResovled>,
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
    pub fn add_rule<F>(mut self, condition: F, decision: RoutingResovled) -> Self
    where
        F: Fn(&RoutingContext) -> bool + Send + Sync + 'static,
    {
        self.rules.push((Box::new(condition), decision));
        self
    }

    /// Set the default routing decision
    pub fn default_route(mut self, decision: RoutingResovled) -> Self {
        self.default_decision = Some(decision);
        self
    }

    /// Build the routing function
    pub fn build(self) -> RoutingFunction {
        let rules = self.rules;
        let default_decision = self.default_decision;

        Arc::new(
            move |ctx: &RoutingContext, _hub: &UplinkHub| -> RoutingResovled {
                for (condition, decision) in &rules {
                    if condition(ctx) {
                        return decision.clone();
                    }
                }
                if let Some(ref decision) = default_decision {
                    decision.clone()
                } else {
                    RoutingResovled::Direct(SocketAddr::new(ctx.target_ip, ctx.target_port))
                }
            },
        )
    }
}

impl Default for RoutingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_uplink_stats_state_serde_with_hex_proxy_id() {
        // Create some ProxyIDs using different constructors
        let trojan_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 1080);
        let file_path = PathBuf::from("/tmp/test.sock");

        let trojan_id = ProxyID::for_trojan(trojan_addr, "example.com", "password123");
        let remote_id = ProxyID::for_remote(remote_addr);
        let file_id = ProxyID::for_file(&file_path);

        // Create ProxyStats entries
        let mut stats1 = ProxyStats::default();
        stats1.record_latency_ms(100);
        stats1.record_attempt(true);
        stats1.record_traffic(1024.0, 2048.0);

        let mut stats2 = ProxyStats::default();
        stats2.record_latency_ms(200);
        stats2.record_attempt(false);

        let mut stats3 = ProxyStats::default();
        stats3.record_traffic(512.0, 1024.0);

        // Build UplinkStatsState
        let mut state = UplinkStatsState::default();
        state.stats.insert(trojan_id.clone(), stats1);
        state.stats.insert(remote_id.clone(), stats2);
        state.stats.insert(file_id.clone(), stats3);

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state).expect("Failed to serialize");
        
        // Verify JSON structure: keys should be hex strings
        println!("Serialized JSON:\n{}", json);
        
        // Parse as generic JSON to verify keys are strings
        let json_value: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");
        let stats_obj = json_value.get("stats").expect("Missing stats field");
        let stats_map = stats_obj.as_object().expect("stats should be an object");
        
        // Verify we have 3 entries
        assert_eq!(stats_map.len(), 3, "Should have 3 proxy stats entries");
        
        // Verify keys are hex strings (64 characters for 32 bytes)
        for (key, _) in stats_map {
            assert_eq!(key.len(), 64, "ProxyID should serialize as 64-char hex string");
            assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "Key should be valid hex: {}", key);
        }

        // Deserialize back
        let deserialized: UplinkStatsState = serde_json::from_str(&json)
            .expect("Failed to deserialize");

        // Verify deserialized data
        assert_eq!(deserialized.stats.len(), 3, "Should have 3 entries after deserialization");
        assert!(deserialized.stats.contains_key(&trojan_id), "Should contain trojan proxy");
        assert!(deserialized.stats.contains_key(&remote_id), "Should contain remote proxy");
        assert!(deserialized.stats.contains_key(&file_id), "Should contain file proxy");

        // Verify stats data is preserved (check one entry in detail)
        let trojan_stats = deserialized.stats.get(&trojan_id).expect("Trojan stats missing");
        assert!(!trojan_stats.data.is_empty(), "Trojan stats should have data");
    }

    #[test]
    fn test_proxy_id_roundtrip() {
        // Test individual ProxyID serialization/deserialization
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let id = ProxyID::for_remote(addr);

        let json = serde_json::to_string(&id).expect("Failed to serialize ProxyID");
        
        // Should be a quoted hex string
        assert!(json.starts_with('"'), "Should be a JSON string");
        assert!(json.ends_with('"'), "Should be a JSON string");
        
        let hex_value = json.trim_matches('"');
        assert_eq!(hex_value.len(), 64, "Should be 64 hex characters");

        let deserialized: ProxyID = serde_json::from_str(&json)
            .expect("Failed to deserialize ProxyID");
        
        assert_eq!(id, deserialized, "ProxyID should round-trip correctly");
    }

    #[test]
    fn test_proxy_id_as_json_object_key() {
        // Demonstrate that ProxyID works as a JSON object key
        let mut map: HashMap<ProxyID, String> = HashMap::new();
        
        let id1 = ProxyID::for_remote("127.0.0.1:1080".parse().unwrap());
        let id2 = ProxyID::for_remote("127.0.0.1:1081".parse().unwrap());
        
        map.insert(id1.clone(), "proxy1".to_string());
        map.insert(id2.clone(), "proxy2".to_string());

        let json = serde_json::to_string(&map).expect("Failed to serialize map");
        
        // JSON object keys must be strings - verify it's an object, not an array
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.is_object(), "Should serialize as JSON object");
        
        let deserialized: HashMap<ProxyID, String> = serde_json::from_str(&json)
            .expect("Failed to deserialize");
        
        assert_eq!(deserialized.get(&id1), Some(&"proxy1".to_string()));
        assert_eq!(deserialized.get(&id2), Some(&"proxy2".to_string()));
    }
}
