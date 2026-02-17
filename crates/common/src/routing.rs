//! Routing decision types shared between diag and nsproxy-core

use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use std::net::SocketAddr;
use std::path::Path;

/// Context available during routing decision
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingProtocol {
    Tcp,
    Udp,
}

/// Result of routing decision — always carries a concrete target when proxying
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoutingDecision {
    /// Warning: the connection is made by TUN process, which exists in SRC NS
    NATByTUN(SocketAddr),
    /// Direct connection to the given address
    Direct(SocketAddr),
    /// Route through a specific proxy identified in the UplinkHub, including full target info
    Proxy {
        target: WireAddress,
        id: ProxyID,
    },
    Drop,
}

#[derive(Hash, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyID(pub [u8; 32]);

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

    pub fn for_remote(addr: SocketAddr) -> Self {
        let addr = addr.to_string();
        Self::hash_chunks(&[b"remote", addr.as_bytes()])
    }

    pub fn for_file(path: &Path) -> Self {
        Self::hash_chunks(&[b"file", path.to_string_lossy().as_bytes()])
    }

    pub fn nym(&self) -> ProxyNym {
        ProxyNym(hex::encode(&self.0[..4]))
    }
}
