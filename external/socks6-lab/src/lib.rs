use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use socks6::{Client, ConnectProgress, Endpoint, IdentitySelection, TcpConnector};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::{fmt, fmt::Display};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(unix)]
use socks6::UnixConnector;

pub trait AsyncProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxProxyStream = Box<dyn AsyncProxyStream>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

impl Target {
    pub fn parse(value: &str) -> Result<Self> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(Self {
                host: address.ip().to_string(),
                port: address.port(),
            });
        }
        let (host, port) = value
            .rsplit_once(':')
            .context("target must be host:port or an IP socket address")?;
        let port = port
            .parse::<u16>()
            .context("target port must be 0..65535")?;
        if host.is_empty() {
            bail!("target host must not be empty");
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    fn endpoint(&self) -> Endpoint {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => Endpoint::Socket(SocketAddr::new(ip, self.port)),
            Err(_) => Endpoint::Domain(self.host.clone(), self.port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyAddress {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ProxyAddress {
    pub fn parse(value: &str) -> Result<Self> {
        #[cfg(unix)]
        if let Some(path) = value.strip_prefix("unix://") {
            if path.is_empty() {
                bail!("Unix socket path must not be empty");
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        let address = value
            .strip_prefix("tcp://")
            .unwrap_or(value)
            .parse::<SocketAddr>()
            .context("proxy must be tcp://IP:PORT or unix:///path/to/socket")?;
        Ok(Self::Tcp(address))
    }

    pub fn connect(&self) -> Result<Client> {
        match self {
            Self::Tcp(address) => Ok(Client::from_connector(TcpConnector::new(*address))),
            #[cfg(unix)]
            Self::Unix(path) => Ok(Client::from_connector(UnixConnector::new(path.clone()))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProxyCapabilities {
    pub send_streams: bool,
    pub send_datagrams: bool,
    pub receive_streams: bool,
    pub receive_datagrams: bool,
    pub max_datagram_size: usize,
    pub description: String,
}

impl fmt::Display for ProxyCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "send-streams={} send-datagrams={} receive-streams={} receive-datagrams={} max-datagram={} B; {}",
            self.send_streams,
            self.send_datagrams,
            self.receive_streams,
            self.receive_datagrams,
            self.max_datagram_size,
            self.description
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProxyStatus {
    pub connected: bool,
    pub detail: Option<String>,
}

#[async_trait]
pub trait ProxyAdapter: Send + Sync {
    fn protocol_name(&self) -> &'static str;
    async fn capabilities(&self) -> Result<ProxyCapabilities>;
    async fn status(&self) -> Result<ProxyStatus>;
    async fn ping(&self) -> Result<()>;
    async fn open_stream(&self, target: &Target) -> Result<BoxProxyStream>;
    async fn open_stream_with_progress(
        &self,
        target: &Target,
        _on_progress: &mut (dyn FnMut(ConnectProgress) + Send),
    ) -> Result<BoxProxyStream> {
        self.open_stream(target).await
    }
    async fn open_datagrams(&self) -> Result<Box<dyn ProxyDatagramChannel>>;
}

#[async_trait]
pub trait ProxyDatagramChannel: Send + Sync {
    async fn send(&self, target: &Target, payload: Vec<u8>) -> Result<()>;
    async fn receive(&self) -> Result<Vec<u8>>;
    async fn close(&self) -> Result<()>;
}

pub async fn close_datagram_channel<T>(
    datagrams: &dyn ProxyDatagramChannel,
    operation: Result<T>,
) -> Result<T> {
    let close_result = datagrams.close().await;
    match (operation, close_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("closing datagram proxy channel"),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "also failed to close datagram proxy channel: {close_error:#}"
        ))),
    }
}

#[derive(Clone)]
pub struct Socks6Adapter {
    client: Client,
}

impl Socks6Adapter {
    pub fn new(address: &ProxyAddress) -> Result<Self> {
        Ok(Self {
            client: address.connect()?,
        })
    }
}

#[async_trait]
impl ProxyAdapter for Socks6Adapter {
    fn protocol_name(&self) -> &'static str {
        "SOCKS6"
    }

    async fn capabilities(&self) -> Result<ProxyCapabilities> {
        let capabilities = self.client.query_capabilities().await?;
        let identities = self.client.query_identities().await?;
        Ok(ProxyCapabilities {
            send_streams: identities
                .iter()
                .any(|identity| identity.capabilities.send_streams),
            send_datagrams: identities
                .iter()
                .any(|identity| identity.capabilities.send_datagrams),
            receive_streams: identities
                .iter()
                .any(|identity| identity.capabilities.receive_streams),
            receive_datagrams: identities
                .iter()
                .any(|identity| identity.capabilities.receive_datagrams),
            max_datagram_size: capabilities.max_datagram_size as usize,
            description: format!("{} ({} identities)", capabilities.server_name, identities.len()),
        })
    }

    async fn status(&self) -> Result<ProxyStatus> {
        let status = self.client.query_status().await?;
        Ok(ProxyStatus {
            connected: status.connected,
            detail: status.detail,
        })
    }

    async fn ping(&self) -> Result<()> {
        self.client.ping().await?;
        Ok(())
    }

    async fn open_stream(&self, target: &Target) -> Result<BoxProxyStream> {
        Ok(Box::new(
            self.client
                .connect_stream(target.endpoint(), IdentitySelection::Any)
                .await?,
        ))
    }

    async fn open_stream_with_progress(
        &self,
        target: &Target,
        on_progress: &mut (dyn FnMut(ConnectProgress) + Send),
    ) -> Result<BoxProxyStream> {
        Ok(Box::new(
            self.client
                .connect_stream_with_progress(target.endpoint(), IdentitySelection::Any, |event| {
                    on_progress(event)
                })
                .await?,
        ))
    }

    async fn open_datagrams(&self) -> Result<Box<dyn ProxyDatagramChannel>> {
        Ok(Box::new(Socks6Datagrams {
            channel: self.client.open_datagrams(IdentitySelection::Any).await?,
        }))
    }
}

struct Socks6Datagrams {
    channel: socks6::DatagramChannelConnection,
}

#[async_trait]
impl ProxyDatagramChannel for Socks6Datagrams {
    async fn send(&self, target: &Target, payload: Vec<u8>) -> Result<()> {
        self.channel
            .send_to(target.endpoint(), payload)
            .await
            .context("sending datagram through proxy")
    }

    async fn receive(&self) -> Result<Vec<u8>> {
        Ok(self.channel.recv_from().await?.payload)
    }

    async fn close(&self) -> Result<()> {
        self.channel.close().await.context("closing SOCKS6 datagram channel")
    }
}

pub async fn tcp_echo_check(
    adapter: &dyn ProxyAdapter,
    target: &Target,
    size: u64,
    chunk_size: usize,
) -> Result<std::time::Duration> {
    if chunk_size == 0 {
        bail!("chunk size must be greater than zero");
    }
    let stream = adapter.open_stream(target).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let started = std::time::Instant::now();
    let send = async {
        let mut remaining = size;
        let mut offset = 0u64;
        let mut buffer = vec![0u8; chunk_size];
        while remaining > 0 {
            let count = remaining.min(chunk_size as u64) as usize;
            fill_payload(&mut buffer[..count], offset);
            writer.write_all(&buffer[..count]).await?;
            remaining -= count as u64;
            offset += count as u64;
        }
        writer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let receive = async {
        let mut received = 0u64;
        let mut buffer = vec![0u8; chunk_size];
        while received < size {
            let count = (size - received).min(chunk_size as u64) as usize;
            reader.read_exact(&mut buffer[..count]).await?;
            verify_payload(&buffer[..count], received)?;
            received += count as u64;
        }
        let mut extra = [0u8; 1];
        if reader.read(&mut extra).await? != 0 {
            bail!("echo target returned more bytes than sent");
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(send, receive)?;
    Ok(started.elapsed())
}

pub async fn udp_echo_check(
    adapter: &dyn ProxyAdapter,
    target: &Target,
    size: usize,
) -> Result<std::time::Duration> {
    if size == 0 {
        bail!("datagram size must be greater than zero");
    }
    let datagrams = adapter.open_datagrams().await?;
    let started = std::time::Instant::now();
    let operation = async {
        let mut payload = vec![0; size];
        fill_payload(&mut payload, 0);
        datagrams.send(target, payload.clone()).await?;
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), datagrams.receive())
            .await
            .context("timed out waiting for UDP echo")??;
        if response != payload {
            bail!("UDP echo payload did not match");
        }
        Ok(started.elapsed())
    }
    .await;
    close_datagram_channel(datagrams.as_ref(), operation).await
}

pub async fn serve_tcp_echo(listener: tokio::net::TcpListener) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            if let Err(error) = tokio::io::copy(&mut reader, &mut writer).await {
                eprintln!("TCP echo client failed: {error}");
            }
        });
    }
}

pub async fn serve_udp_echo(socket: tokio::net::UdpSocket) -> io::Result<()> {
    let mut buffer = vec![0; 65_507];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        socket.send_to(&buffer[..length], peer).await?;
    }
}

pub fn fill_payload(buffer: &mut [u8], offset: u64) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((offset + index as u64).wrapping_mul(31).wrapping_add(17) & 0xff) as u8;
    }
}

pub fn verify_payload(buffer: &[u8], offset: u64) -> Result<()> {
    for (index, actual) in buffer.iter().enumerate() {
        let expected = ((offset + index as u64).wrapping_mul(31).wrapping_add(17) & 0xff) as u8;
        if *actual != expected {
            bail!("echo payload mismatch at byte {}", offset + index as u64);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socks6::{Server, SocketBackend};
    use std::sync::Arc;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::task::JoinSet;

    #[test]
    fn parses_targets_and_proxy_addresses() {
        assert_eq!(
            Target::parse("example.test:443").unwrap(),
            Target {
                host: "example.test".to_owned(),
                port: 443
            }
        );
        assert_eq!(
            Target::parse("[::1]:9050").unwrap(),
            Target {
                host: "::1".to_owned(),
                port: 9050
            }
        );
        assert!(ProxyAddress::parse("tcp://127.0.0.1:1086").is_ok());
        #[cfg(unix)]
        assert_eq!(
            ProxyAddress::parse("unix:///tmp/socks6.sock").unwrap(),
            ProxyAddress::Unix(PathBuf::from("/tmp/socks6.sock"))
        );
    }

    #[test]
    fn generated_payload_can_be_checked_in_chunks() {
        let mut first = [0; 31];
        let mut second = [0; 31];
        fill_payload(&mut first, 0);
        fill_payload(&mut second, 31);
        verify_payload(&first, 0).unwrap();
        verify_payload(&second, 31).unwrap();
        assert!(verify_payload(&second, 0).is_err());
    }

    #[tokio::test]
    async fn socks6_adapter_exercises_tcp_udp_and_parallel_streams() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_server = Arc::new(Server::new(SocketBackend));
        let proxy_task = tokio::spawn(proxy_server.run(proxy_listener));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = Target::parse(&tcp_listener.local_addr().unwrap().to_string()).unwrap();
        let tcp_task = tokio::spawn(serve_tcp_echo(tcp_listener));

        let udp_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = Target::parse(&udp_listener.local_addr().unwrap().to_string()).unwrap();
        let udp_task = tokio::spawn(serve_udp_echo(udp_listener));

        let adapter: Arc<dyn ProxyAdapter> =
            Arc::new(Socks6Adapter::new(&ProxyAddress::Tcp(proxy_address)).unwrap());
        let capabilities = adapter.capabilities().await.unwrap();
        assert!(capabilities.send_streams);
        assert!(capabilities.send_datagrams);
        assert!(adapter.status().await.unwrap().connected);
        adapter.ping().await.unwrap();

        tcp_echo_check(adapter.as_ref(), &tcp_target, 8 * 1024 * 1024, 64 * 1024)
            .await
            .unwrap();
        udp_echo_check(adapter.as_ref(), &udp_target, 1200)
            .await
            .unwrap();

        let mut streams = JoinSet::new();
        for _ in 0..4 {
            let adapter = Arc::clone(&adapter);
            let target = tcp_target.clone();
            streams.spawn(async move {
                tcp_echo_check(adapter.as_ref(), &target, 256 * 1024, 4096).await
            });
        }
        while let Some(result) = streams.join_next().await {
            result.unwrap().unwrap();
        }

        proxy_task.abort();
        tcp_task.abort();
        udp_task.abort();
    }
}
