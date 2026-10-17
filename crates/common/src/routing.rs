//! Routing decision types shared between diag and nsproxy-core

use serde::{Deserialize, Serialize};
pub use socks5_impl::protocol::WireAddress;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Context available during routing decision
/// This state is meant to be mutated and kept between retries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingContext {
    pub target_ip: std::net::IpAddr,
    pub target_port: u16,
    pub source_ip: std::net::IpAddr,
    pub protocol: RoutingProtocol,
    /// Proxies that have been tried
    pub tried_proxies: HashSet<ProxyID>,
    pub attempt_num: usize,
    /// Verdict given by DNS
    pub dns: VDNSRES,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TargetKey {
    address: IpAddr,
    port: Option<u16>,
}

impl TargetKey {
    pub fn for_final_destination(address: SocketAddr) -> Self {
        Self {
            address: address.ip(),
            port: Some(address.port()),
        }
    }

    pub fn for_any_port(address: IpAddr) -> Self {
        Self {
            address,
            port: None,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoutingKey {
    Addr(TargetKey),
    Host(String, Option<u16>),
}

impl RoutingKey {
    /// Construct a host key in lowercase fully-qualified DNS form.
    pub fn host(host: &str, port: Option<u16>) -> Self {
        Self::Host(normalize_domain(host), port)
    }
}

fn normalize_domain(domain: &str) -> String {
    let mut normalized = domain.trim().to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}

/// Canonicalize host keys and domain targets to lowercase names with a trailing dot.
/// Returns an error if normalization causes distinct keys to collide.
pub fn normalize_route_map_domains(
    route_map: &mut BTreeMap<RoutingKey, RoutingResovled>,
) -> Result<(), String> {
    let mut normalized = BTreeMap::new();
    for (key, decision) in route_map.iter() {
        let key = match key {
            RoutingKey::Host(host, port) => RoutingKey::Host(normalize_domain(host), *port),
            RoutingKey::Addr(target) => RoutingKey::Addr(target.clone()),
        };
        let mut decision = decision.clone();
        match &mut decision {
            RoutingResovled::ProxyResovled {
                target: WireAddress::DomainAddress(host, _),
                ..
            }
            | RoutingResovled::NoProxyDomain { host, .. } => {
                *host = normalize_domain(host);
            }
            _ => {}
        }
        if normalized.insert(key, decision).is_some() {
            return Err("duplicate routing key after domain normalization".to_string());
        }
    }
    *route_map = normalized;
    Ok(())
}

pub fn route_map_match<'a>(
    route_map: &'a BTreeMap<RoutingKey, RoutingResovled>,
    context: &RoutingContext,
) -> Option<&'a RoutingResovled> {
    match &context.dns {
        VDNSRES::Opine(RoutingDecision::HostOverProxy(host)) => route_map
            .get(&RoutingKey::host(host, Some(context.target_port)))
            .or_else(|| route_map.get(&RoutingKey::host(host, None))),
        VDNSRES::NormalProxying => {
            let address = SocketAddr::new(context.target_ip, context.target_port);
            route_map
                .get(&RoutingKey::Addr(TargetKey::for_final_destination(address)))
                .or_else(|| {
                    route_map.get(&RoutingKey::Addr(TargetKey::for_any_port(context.target_ip)))
                })
        }
        VDNSRES::Opine(
            RoutingDecision::SocketOverProxy(address)
            | RoutingDecision::NoProxy(address)
            | RoutingDecision::NATByTUN(address),
        ) => route_map
            .get(&RoutingKey::Addr(TargetKey::for_final_destination(*address)))
            .or_else(|| {
                route_map.get(&RoutingKey::Addr(TargetKey::for_any_port(address.ip())))
            }),
        VDNSRES::Opine(RoutingDecision::File(_) | RoutingDecision::Drop(_)) | VDNSRES::ERR => {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VDNSRES {
    Opine(RoutingDecision),
    NormalProxying,
    ERR,
}

/// Result of routing decision — always carries a concrete target when proxying
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoutingDecision {
    /// Warning: the connection is made by TUN process, which exists in SRC NS
    NATByTUN(SocketAddr),
    /// Connection made without using a proxy.
    NoProxy(SocketAddr),
    Drop(DropReason),
    // ::File can be converted to ::Proxy where ::File is represented as ProxyID::for_file(path.as_path()),
    File(PathBuf),
    HostOverProxy(String),
    SocketOverProxy(SocketAddr),
}

/// Result of routing decision — always carries a concrete target when proxying
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoutingResovled {
    /// Warning: the connection is made by TUN process, which exists in SRC NS
    NATByTUN(SocketAddr),
    /// Connection made without using a proxy.
    NoProxy(SocketAddr),
    /// Route through a specific proxy identified in the UplinkHub, including full target info
    ProxyResovled {
        target: WireAddress,
        id: ProxyID,
    },
    Drop(DropReason),
    /// No-proxy connection to a domain that must be resolved by the serve process.
    NoProxyDomain { host: String, port: u16 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    MaxRetry,
    Preprocess(Cow<'static, str>),
}

#[derive(Hash, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProxyID(pub [u8; 32]);

impl Serialize for ProxyID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ProxyID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(ProxyID(arr))
    }

}

#[cfg(test)]
mod route_map_tests {
    use super::*;

    #[test]
    fn route_map_prefers_exact_port_then_any_port() {
        let host = RoutingKey::host("Example.COM.", None);
        let exact_host = RoutingKey::host("example.com", Some(443));
        let exact_ip = RoutingKey::Addr(TargetKey::for_final_destination(
            "192.0.2.8:443".parse().unwrap(),
        ));
        let mut routes = BTreeMap::new();
        routes.insert(host, RoutingResovled::NoProxy("192.0.2.8:80".parse().unwrap()));
        routes.insert(
            exact_host,
            RoutingResovled::NoProxy("192.0.2.8:443".parse().unwrap()),
        );
        routes.insert(
            exact_ip,
            RoutingResovled::NoProxy("192.0.2.8:443".parse().unwrap()),
        );

        let context = |port, dns| RoutingContext {
            target_ip: "192.0.2.8".parse().unwrap(),
            target_port: port,
            source_ip: "192.0.2.1".parse().unwrap(),
            protocol: RoutingProtocol::Tcp,
            tried_proxies: HashSet::new(),
            attempt_num: 0,
            dns,
        };

        let host_exact = context(
            443,
            VDNSRES::Opine(RoutingDecision::HostOverProxy("example.com.".to_string())),
        );
        assert_eq!(
            route_map_match(&routes, &host_exact),
            Some(&RoutingResovled::NoProxy("192.0.2.8:443".parse().unwrap()))
        );

        let host_wildcard = context(
            8443,
            VDNSRES::Opine(RoutingDecision::HostOverProxy("example.com.".to_string())),
        );
        assert_eq!(
            route_map_match(&routes, &host_wildcard),
            Some(&RoutingResovled::NoProxy("192.0.2.8:80".parse().unwrap()))
        );

        let ip_exact = context(443, VDNSRES::NormalProxying);
        assert_eq!(
            route_map_match(&routes, &ip_exact),
            Some(&RoutingResovled::NoProxy("192.0.2.8:443".parse().unwrap()))
        );
    }

    #[test]
    fn route_map_domain_normalization_covers_keys_and_resolved_targets() {
        let mut routes = BTreeMap::new();
        routes.insert(
            RoutingKey::Host("Packages.RedHat.COM".to_string(), Some(443)),
            RoutingResovled::ProxyResovled {
                target: WireAddress::DomainAddress("Packages.RedHat.COM".to_string(), 443),
                id: ProxyID([3; 32]),
            },
        );
        routes.insert(
            RoutingKey::Host("repo.example".to_string(), None),
            RoutingResovled::NoProxyDomain {
                host: "Repo.Example".to_string(),
                port: 443,
            },
        );

        normalize_route_map_domains(&mut routes).unwrap();

        assert!(routes.contains_key(&RoutingKey::Host(
            "packages.redhat.com.".to_string(),
            Some(443)
        )));
        assert_eq!(
            routes[&RoutingKey::Host("packages.redhat.com.".to_string(), Some(443))],
            RoutingResovled::ProxyResovled {
                target: WireAddress::DomainAddress("packages.redhat.com.".to_string(), 443),
                id: ProxyID([3; 32]),
            }
        );
        assert_eq!(
            routes[&RoutingKey::Host("repo.example.".to_string(), None)],
            RoutingResovled::NoProxyDomain {
                host: "repo.example.".to_string(),
                port: 443,
            }
        );
    }

    #[test]
    fn route_map_domain_normalization_rejects_key_collisions() {
        let mut routes = BTreeMap::new();
        routes.insert(
            RoutingKey::Host("example.com".to_string(), Some(443)),
            RoutingResovled::NoProxyDomain {
                host: "example.com".to_string(),
                port: 443,
            },
        );
        routes.insert(
            RoutingKey::Host("EXAMPLE.COM.".to_string(), Some(443)),
            RoutingResovled::NoProxyDomain {
                host: "example.com.".to_string(),
                port: 443,
            },
        );
        let original = routes.clone();

        assert!(normalize_route_map_domains(&mut routes).is_err());
        assert_eq!(routes, original);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyNym(pub String);

impl ProxyNym {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProxyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nym())
    }
}

impl Debug for ProxyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nym())
    }
}

impl std::fmt::Display for ProxyNym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ProxyNym {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ProxyNym(s.to_string()))
    }
}

impl ProxyID {
    fn hash_chunks(chunks: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for chunk in chunks {
            hasher.update(&((*chunk).len() as u64).to_le_bytes());
            hasher.update(chunk);
        }
        ProxyID(*hasher.finalize().as_bytes())
    }

    pub fn for_trojan(server_addr: SocketAddr, server_name: &str, password: &str) -> Self {
        let server_addr = server_addr.to_string();
        Self::hash_chunks(&[
            b"trojan",
            server_addr.as_bytes(),
            server_name.as_bytes(),
            password.as_bytes(),
        ])
    }

    /// Create ProxyID for Trojan using domain name (preferred over resolved IP)
    /// Domain should always be used when available for stable identity across DNS changes
    pub fn for_trojan_domain(domain: &str, port: u16, password: &str) -> Self {
        let port_str = port.to_string();
        Self::hash_chunks(&[
            b"trojan",
            domain.as_bytes(),
            port_str.as_bytes(),
            password.as_bytes(),
        ])
    }

    pub fn for_remote(addr: SocketAddr) -> Self {
        let addr = addr.to_string();
        Self::hash_chunks(&[b"remote", addr.as_bytes()])
    }

    /// Create ProxyID for remote proxy using domain when available (preferred over resolved IP)
    pub fn for_remote_domain(domain: &str, port: u16) -> Self {
        let port_str = port.to_string();
        Self::hash_chunks(&[b"remote", domain.as_bytes(), port_str.as_bytes()])
    }

    pub fn for_file(path: &Path) -> Self {
        Self::hash_chunks(&[b"file", path.to_string_lossy().as_bytes()])
    }

    pub fn nym(&self) -> ProxyNym {
        ProxyNym(hex::encode(&self.0[..4]))
    }
}
