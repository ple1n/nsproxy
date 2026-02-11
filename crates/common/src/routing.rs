//! Routing decision types shared between diag and nsproxy-core

use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use std::net::SocketAddr;
use std::path::PathBuf;

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
pub enum ProxyID {
    ClashName(String),
    Remote(SocketAddr),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyNym(pub String);

impl ProxyNym {
    pub fn as_str(&self) -> &str {
        &self.0
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
    pub fn nym(&self) -> ProxyNym {
        // cropped blake3 hash as a nym
        let hash_input = format!("{:?}", self);
        let hash = blake3::hash(hash_input.as_bytes());
        let hash_bytes = hash.as_bytes();
        // Take first 8 bytes for a short 16-character hex nym
        ProxyNym(hex::encode(&hash_bytes[..8]))
    }
}
