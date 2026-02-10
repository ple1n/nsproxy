use std::net::{Ipv4Addr, SocketAddr};

use socks5_impl::protocol::WireAddress;

#[allow(dead_code)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Default)]
pub enum IpProtocol {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpProtocol::Tcp => write!(f, "TCP"),
            IpProtocol::Udp => write!(f, "UDP"),
            IpProtocol::Icmp => write!(f, "ICMP"),
            IpProtocol::Other(v) => write!(f, "Other({})", v),
        }
    }
}

#[derive(Hash, Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct SessionInfo {
    pub src: SocketAddr,
    pub dst: WireAddress,
    pub protocol: IpProtocol,
    id: u64,
}

impl Default for SessionInfo {
    fn default() -> Self {
        let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        let dst = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        Self::new(src, dst.into(), IpProtocol::Tcp)
    }
}

impl SessionInfo {
    pub fn new(src: SocketAddr, dst: WireAddress, protocol: IpProtocol) -> Self {
        let id = 0;
        Self { src, dst, protocol, id }
    }
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "#{} {} {} -> {}", self.id, self.protocol, self.src, self.dst)
    }
}
