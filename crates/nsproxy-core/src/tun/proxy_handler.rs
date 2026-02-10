use super::directions::{IncomingDataEvent, OutgoingDataEvent, OutgoingDirection};
use super::session_info::SessionInfo;
use std::{fmt::Debug, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[async_trait::async_trait]
pub trait ProxyHandler: Send + Sync + Debug {
    fn get_session_info(&self) -> SessionInfo;
    /// When we have received data from socks5 server, push it into the hub.
    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> anyhow::Result<()>;
    /// Remove data when it has been sent
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    /// Peek at what is being sent to socks5 server.
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
    fn data_len(&self, dir: OutgoingDirection) -> usize;
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

#[async_trait::async_trait]
pub trait ConnectionManager: Send + Sync {
    async fn new_proxy_handler(&self, info: SessionInfo, udp_associate: bool) -> anyhow::Result<Arc<Mutex<dyn ProxyHandler>>>;
    fn get_server_addr(&self) -> SocketAddr;
}
