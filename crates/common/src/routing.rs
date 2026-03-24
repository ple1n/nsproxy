//! Routing decision types shared between diag and nsproxy-core

use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::SocketAddr;
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
    /// Direct connection to the given address
    Direct(SocketAddr),
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
    /// Direct connection to the given address
    Direct(SocketAddr),
    /// Route through a specific proxy identified in the UplinkHub, including full target info
    ProxyResovled {
        target: WireAddress,
        id: ProxyID,
    },
    Drop(DropReason),
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
