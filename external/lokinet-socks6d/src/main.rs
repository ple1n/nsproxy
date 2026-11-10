use anyhow::{bail, Context};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use nsproxy_ipstack::{
    stream::{IpStackTcpStream, IpStackUdpStream},
    IpStack, IpStackConfig, IpStackHandle, PacketIo,
};
use rs_lokinet::{Config, Runtime, StreamDecision, UdpFlow};
use socks6::{
    Backend, BackendError, Capabilities, ConnectContext, ConnectProgress, Datagram,
    DatagramChannel, Endpoint, IdentityAddress, IdentityCapabilities, IdentityOffer, Server,
    ServiceStatus, MAX_DATAGRAM_SIZE,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use std::{env, fs, fs::OpenOptions};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener as LocalTcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

const UDP_PORT_START: u16 = 49_152;
const UDP_FLOW_TIMEOUT_SECS: u32 = 120;
const UDP_EVENT_CAPACITY: usize = 256;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LOKINET_STREAM_READY_TIMEOUT: Duration = Duration::from_secs(29);

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "SOCKS6 proxy socket path"
    )]
    socket: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Lokinet configuration file path"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Private Lokinet data directory"
    )]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(
            long,
            value_name = "FILE",
            help = "Copy a signed Lokinet bootstrap router-contact file"
        )]
        bootstrap_file: Option<PathBuf>,
        #[arg(
            long,
            value_name = "PATH",
            help = "Persistent Lokinet address key path (default: <data-dir>/lokinet-addr.privkey)"
        )]
        keyfile: Option<PathBuf>,
    },
}

struct Paths {
    socket: PathBuf,
    config: PathBuf,
    data_dir: PathBuf,
}

impl Paths {
    fn resolve(args: &Args) -> anyhow::Result<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .context("HOME must be set to an absolute path")?;
        let config_home = xdg_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let data_home = xdg_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        let data_dir = absolute_path(
            args.data_dir
                .clone()
                .unwrap_or_else(|| data_home.join("lokinet-socks6")),
        )?;
        let config = absolute_path(
            args.config
                .clone()
                .unwrap_or_else(|| config_home.join("lokinet-socks6/lokinet.ini")),
        )?;
        let socket = absolute_path(args.socket.clone().unwrap_or_else(|| {
            xdg_path("XDG_RUNTIME_DIR")
                .map(|path| path.join("lokinet-socks6/lokinet.socks6"))
                .unwrap_or_else(|| data_dir.join("run/lokinet.socks6"))
        }))?;
        Ok(Self {
            socket,
            config,
            data_dir,
        })
    }
}

fn parse_args() -> Args {
    let defaults = Paths::resolve(&Args {
        socket: None,
        config: None,
        data_dir: None,
        command: None,
    });
    let path_help = match defaults {
        Ok(paths) => format!(
            "Resolved default paths (unless overridden):\n  --socket {}\n  --config {}\n  --data-dir {}",
            paths.socket.display(),
            paths.config.display(),
            paths.data_dir.display()
        ),
        Err(error) => format!("Default paths could not be resolved: {error}"),
    };
    let matches = Args::command().after_help(path_help).get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

fn is_lokinet_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.ends_with(".loki") || host.ends_with(".snode")
}

fn xdg_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn absolute_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn create_private_data_dir(path: &Path) -> anyhow::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                bail!("data directory path is not a directory: {}", path.display());
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!(
                    "data directory {} is accessible by other users; restrict its permissions before using it",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating data directory {}", path.display()));
                }
            }
            let metadata = fs::metadata(path)
                .with_context(|| format!("checking data directory {}", path.display()))?;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!(
                    "data directory {} must not be accessible by other users",
                    path.display()
                );
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("checking data directory {}", path.display()));
        }
    }
    Ok(())
}

fn initialize(
    paths: &Paths,
    bootstrap_file: Option<&Path>,
    keyfile: Option<&Path>,
) -> anyhow::Result<()> {
    create_private_data_dir(&paths.data_dir)?;
    if let Some(parent) = paths.config.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }

    let keyfile = keyfile
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.data_dir.join("lokinet-addr.privkey"));
    let keyfile = absolute_path(keyfile)?;
    let keyfile = keyfile
        .to_str()
        .context("keyfile path must be valid UTF-8")?;
    if keyfile.contains('\n') || keyfile.contains('\r') {
        bail!("keyfile path must not contain newlines");
    }
    let config_contents = format!("[network]\nkeyfile={keyfile}\n");
    use std::os::unix::fs::OpenOptionsExt;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&paths.config)
    {
        Ok(mut file) => {
            file.write_all(config_contents.as_bytes())
                .with_context(|| format!("writing config {}", paths.config.display()))?;
            println!("Created config: {}", paths.config.display());
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            println!("Keeping existing config: {}", paths.config.display());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("creating config {}", paths.config.display()));
        }
    }

    if let Some(source) = bootstrap_file {
        let target = paths.data_dir.join("bootstrap.signed");
        let mut source_file = fs::File::open(source)
            .with_context(|| format!("opening bootstrap file {}", source.display()))?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(mut destination) => {
                if let Err(error) = io::copy(&mut source_file, &mut destination) {
                    let _ = fs::remove_file(&target);
                    return Err(error).with_context(|| {
                        format!("copying bootstrap file to {}", target.display())
                    });
                }
                println!("Copied bootstrap file: {}", target.display());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                println!("Keeping existing bootstrap file: {}", target.display());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", target.display()));
            }
        }
    }

    println!(
        "Start with: lokinet-socks6d --socket {} --config {} --data-dir {}",
        paths.socket.display(),
        paths.config.display(),
        paths.data_dir.display()
    );
    Ok(())
}

struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                if let Err(error) = std::fs::remove_file(&self.path) {
                    warn!(path = %self.path.display(), %error, "could not remove SOCKS6 proxy socket");
                }
            }
            Ok(_) => warn!(
                path = %self.path.display(),
                "SOCKS6 proxy socket path changed while service was running; leaving it untouched"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(path = %self.path.display(), %error, "could not inspect SOCKS6 proxy socket")
            }
        }
    }
}

#[derive(Clone)]
struct LokinetPacketIo(rs_lokinet::IpPacketIo);

impl PacketIo for LokinetPacketIo {
    fn receive<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let packet_io = self.0.clone();
            let capacity = buffer.len();
            let (packet, packet_size) = tokio::task::spawn_blocking(move || {
                let mut packet = vec![0; capacity];
                let packet_size = packet_io.receive(&mut packet, Duration::from_secs(1))?;
                Ok::<_, io::Error>((packet, packet_size))
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
            if packet_size > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Lokinet returned an oversized IP packet",
                ));
            }
            buffer[..packet_size].copy_from_slice(&packet[..packet_size]);
            Ok(packet_size)
        }
    }

    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send + 'a {
        async move { self.0.send_packet(packet) }
    }
}

#[derive(Default)]
struct UdpPortPool {
    next: u16,
    in_use: HashSet<u16>,
}

struct UdpPortLease {
    port: u16,
    pool: Arc<StdMutex<UdpPortPool>>,
}

impl Drop for UdpPortLease {
    fn drop(&mut self) {
        match self.pool.lock() {
            Ok(mut pool) => {
                pool.in_use.remove(&self.port);
            }
            Err(error) => {
                tracing::error!(%error, "Lokinet UDP port pool lock poisoned");
            }
        }
    }
}

fn reserve_udp_port(pool_ref: &Arc<StdMutex<UdpPortPool>>) -> Result<UdpPortLease, BackendError> {
    let mut pool = pool_ref
        .lock()
        .map_err(|error| BackendError::Internal(format!("UDP port pool: {error}")))?;
    let count = u32::from(u16::MAX - UDP_PORT_START) + 1;
    let start = u32::from(pool.next.saturating_sub(UDP_PORT_START));
    for offset in 0..count {
        let port = UDP_PORT_START + ((start + offset) % count) as u16;
        if pool.in_use.insert(port) {
            pool.next = if port == u16::MAX {
                UDP_PORT_START
            } else {
                port + 1
            };
            return Ok(UdpPortLease {
                port,
                pool: Arc::clone(pool_ref),
            });
        }
    }
    Err(BackendError::Unavailable(
        "no Lokinet UDP endpoint ports are available".to_owned(),
    ))
}

struct LokinetBackend {
    runtime: Arc<Runtime>,
    ip_stack: IpStackHandle,
    _ip_stack: Mutex<IpStack>,
    local_ipv4: IpAddr,
    local_ipv6: IpAddr,
    udp_ports: Arc<StdMutex<UdpPortPool>>,
}

impl LokinetBackend {
    fn new(
        runtime: Arc<Runtime>,
        ip_stack: IpStack,
        local_ipv4: IpAddr,
        local_ipv6: IpAddr,
    ) -> Self {
        let ip_stack_handle = ip_stack.handle();
        Self {
            runtime,
            ip_stack: ip_stack_handle,
            _ip_stack: Mutex::new(ip_stack),
            local_ipv4,
            local_ipv6,
            udp_ports: Arc::new(StdMutex::new(UdpPortPool {
                next: UDP_PORT_START,
                in_use: HashSet::new(),
            })),
        }
    }

    fn reserve_udp_port(&self) -> Result<UdpPortLease, BackendError> {
        reserve_udp_port(&self.udp_ports)
    }

    async fn connect_stream_inner(
        &self,
        identity: &IdentityOffer,
        target: Endpoint,
        context: Option<ConnectContext>,
    ) -> Result<socks6::BoxStream, BackendError> {
        if identity.id != "lokinet-primary" {
            return Err(BackendError::UnsupportedEndpoint(format!(
                "Lokinet identity {}",
                identity.id
            )));
        }

        // Literal IPs use the packet bridge; Lokinet names use its native stream API.
        let ip_peer = match &target {
            Endpoint::Socket(address) if address.port() != 0 => Some(*address),
            Endpoint::Domain(host, port) if *port != 0 => host
                .parse::<IpAddr>()
                .ok()
                .map(|address| SocketAddr::new(address, *port)),
            _ => None,
        };
        if let Some(peer_addr) = ip_peer {
            let local_ip = if peer_addr.is_ipv4() {
                self.local_ipv4
            } else {
                self.local_ipv6
            };
            let port = self.reserve_udp_port()?;
            let local_addr = SocketAddr::new(local_ip, port.port);
            let ip_stack = self.ip_stack.clone();
            let connect = tokio::time::timeout(
                TCP_CONNECT_TIMEOUT,
                ip_stack.connect_tcp(local_addr, peer_addr),
            );
            let result = await_or_cancel(connect, context.as_ref())
                .await
                .ok_or_else(|| BackendError::Unavailable("connection cancelled".to_owned()))?;
            let stream = result
                .map_err(|_| BackendError::ConnectFailure {
                    code: socks6::ErrorCode::Unavailable,
                    message: "timed out connecting to IP target".to_owned(),
                    phase: Some("connecting_target".to_owned()),
                    retry_after: Some(Duration::from_secs(1)),
                })?
                .map_err(|error| BackendError::Unavailable(error.to_string()))?;
            return Ok(Box::new(LokinetIpTcpStream {
                stream,
                _port: port,
            }));
        }

        let (host, port) = match target {
            Endpoint::Domain(host, port)
                if port != 0 && !host.is_empty() && is_lokinet_name(&host) =>
            {
                (host, port)
            }
            Endpoint::Service { namespace, .. } => {
                return Err(BackendError::UnsupportedEndpoint(namespace));
            }
            endpoint => {
                return Err(BackendError::UnsupportedEndpoint(format!(
                    "Lokinet SOCKS6 supports IPv4/IPv6 literals and .loki/.snode names with a port; ordinary DNS hostnames are not resolved; unsupported target {endpoint}"
                )));
            }
        };
        if host.contains('\0') {
            return Err(BackendError::InvalidEndpoint(
                "domain contains a NUL byte".to_owned(),
            ));
        }
        let host = host.trim_end_matches('.').to_owned();
        let remote = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if let Some(context) = &context {
            context
                .report_progress(
                    ConnectProgress::new("establishing_route")
                        .with_detail("Waiting for the Lokinet target connection"),
                )
                .await
                .map_err(|_| BackendError::Unavailable("connection cancelled".to_owned()))?;
        }
        let runtime = Arc::clone(&self.runtime);
        let native_stream = await_or_cancel(
            tokio::task::spawn_blocking(move || runtime.open_tcp_stream(&remote, None)),
            context.as_ref(),
        )
        .await
        .ok_or_else(|| BackendError::Unavailable("connection cancelled".to_owned()))?
        .map_err(|error| BackendError::Unavailable(format!("Lokinet stream task failed: {error}")))?
        .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        let mut cancel_guard = NativeStreamCancelGuard::new(native_stream.clone());
        let local_ip = native_stream
            .local_address()
            .parse()
            .map_err(|error| BackendError::Internal(format!("invalid local address: {error}")))?;
        let local_addr = SocketAddr::new(local_ip, native_stream.local_port());
        let connect = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(local_addr));
        let socket = await_or_cancel(connect, context.as_ref())
            .await
            .ok_or_else(|| BackendError::Unavailable("connection cancelled".to_owned()))?
            .map_err(|_| BackendError::ConnectFailure {
                code: socks6::ErrorCode::Unavailable,
                message: "timed out connecting to the local Lokinet tunnel".to_owned(),
                phase: Some("connecting_target".to_owned()),
                retry_after: Some(Duration::from_secs(1)),
            })?
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;

        let wait_stream = native_stream.clone();
        let wait = tokio::task::spawn_blocking(move || {
            wait_stream.wait_ready(LOKINET_STREAM_READY_TIMEOUT)
        });
        let readiness = if let Some(context) = &context {
            tokio::select! {
                result = wait => Some(result),
                _ = context.cancelled() => {
                    native_stream.close();
                    return Err(BackendError::Unavailable("connection cancelled".to_owned()));
                }
            }
        } else {
            Some(wait.await)
        };
        let Some(readiness) = readiness else {
            return Err(BackendError::Unavailable("connection cancelled".to_owned()));
        };
        match readiness {
            Ok(Ok(())) => {}
            Ok(Err(rs_lokinet::Error::StreamOpenFailed { phase, retryable })) => {
                return Err(BackendError::ConnectFailure {
                    code: socks6::ErrorCode::Unavailable,
                    message: format!("Lokinet stream connection failed during {phase}"),
                    phase: Some(phase),
                    retry_after: retryable.then_some(Duration::from_secs(1)),
                });
            }
            Ok(Err(rs_lokinet::Error::StreamReadyTimeout)) => {
                return Err(BackendError::ConnectFailure {
                    code: socks6::ErrorCode::Unavailable,
                    message: "timed out waiting for the Lokinet target connection".to_owned(),
                    phase: Some("connecting_target".to_owned()),
                    retry_after: Some(Duration::from_secs(1)),
                });
            }
            Ok(Err(error)) => return Err(BackendError::Unavailable(error.to_string())),
            Err(error) => return Err(BackendError::Unavailable(error.to_string())),
        }
        cancel_guard.disarm();
        Ok(Box::new(LokinetTcpStream {
            socket,
            _stream: native_stream,
        }))
    }
}

async fn await_or_cancel<T>(
    future: impl Future<Output = T>,
    context: Option<&ConnectContext>,
) -> Option<T> {
    if let Some(context) = context {
        tokio::select! {
            result = future => Some(result),
            _ = context.cancelled() => None,
        }
    } else {
        Some(future.await)
    }
}

struct LokinetTcpStream {
    socket: TcpStream,
    _stream: rs_lokinet::TcpStream,
}

struct NativeStreamCancelGuard {
    stream: rs_lokinet::TcpStream,
    armed: bool,
}

impl NativeStreamCancelGuard {
    fn new(stream: rs_lokinet::TcpStream) -> Self {
        Self {
            stream,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for NativeStreamCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.stream.close();
        }
    }
}

struct LokinetIpTcpStream {
    stream: IpStackTcpStream,
    _port: UdpPortLease,
}

struct LokinetIncomingTcpStream {
    socket: TcpStream,
    _listener: rs_lokinet::TcpListener,
}

impl AsyncRead for LokinetTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for LokinetTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl AsyncRead for LokinetIncomingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for LokinetIncomingTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl AsyncRead for LokinetIpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for LokinetIpTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

enum UdpEvent {
    Packet(UdpFlow, Vec<u8>),
    IpPacket(SocketAddr, Vec<u8>),
}

struct LokinetDatagrams {
    socket: rs_lokinet::UdpSocket,
    flows: Arc<StdMutex<HashMap<(String, u16), UdpFlow>>>,
    establish_lock: Mutex<()>,
    events: Mutex<mpsc::Receiver<UdpEvent>>,
    event_sender: mpsc::Sender<UdpEvent>,
    ip_stack: IpStackHandle,
    local_ipv4: IpAddr,
    local_ipv6: IpAddr,
    ip_flows: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    udp_ports: Arc<StdMutex<UdpPortPool>>,
    address: String,
    _port: UdpPortLease,
}

impl LokinetDatagrams {
    async fn send_ip_datagram(
        &self,
        peer_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<(), BackendError> {
        if peer_addr.port() == 0 {
            return Err(BackendError::InvalidEndpoint(
                "IP UDP destination port must be nonzero".to_owned(),
            ));
        }
        let max_payload = if peer_addr.is_ipv4() { 1472 } else { 1452 };
        if payload.len() > max_payload {
            return Err(BackendError::InvalidEndpoint(format!(
                "IP UDP payload exceeds the {max_payload}-byte packet MTU limit"
            )));
        }

        let sender = {
            let _establish_guard = self.establish_lock.lock().await;
            let mut flows = self.ip_flows.lock().await;
            if let Some(sender) = flows.get(&peer_addr) {
                if !sender.is_closed() {
                    sender.clone()
                } else {
                    flows.remove(&peer_addr);
                    self.create_ip_flow(peer_addr, &mut flows).await?
                }
            } else {
                self.create_ip_flow(peer_addr, &mut flows).await?
            }
        };
        sender
            .send(payload)
            .await
            .map_err(|_| BackendError::Unavailable("IP UDP flow has closed".to_owned()))
    }

    async fn create_ip_flow(
        &self,
        peer_addr: SocketAddr,
        flows: &mut HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    ) -> Result<mpsc::Sender<Vec<u8>>, BackendError> {
        let port = reserve_udp_port(&self.udp_ports)?;
        let local_ip = if peer_addr.is_ipv4() {
            self.local_ipv4
        } else {
            self.local_ipv6
        };
        let local_addr = SocketAddr::new(local_ip, port.port);
        let mut stream = self
            .ip_stack
            .connect_udp(local_addr, peer_addr)
            .await
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);
        let event_sender = self.event_sender.clone();
        tokio::spawn(async move {
            let _port = port;
            loop {
                tokio::select! {
                    _ = event_sender.closed() => break,
                    payload = receiver.recv() => match payload {
                        Some(payload) => {
                            if let Err(error) = stream.send_datagram(&payload) {
                                warn!(%peer_addr, %error, "could not send IP UDP datagram");
                                break;
                            }
                        }
                        None => break,
                    },
                    response = stream.recv_datagram() => match response {
                        Ok((source, payload)) => {
                            match event_sender.try_send(UdpEvent::IpPacket(source, payload)) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!(%peer_addr, "dropping IP UDP response because the SOCKS6 event queue is full");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(error) => {
                            warn!(%peer_addr, %error, "IP UDP flow ended");
                            break;
                        }
                    }
                }
            }
        });
        flows.insert(peer_addr, sender.clone());
        Ok(sender)
    }
}

#[async_trait::async_trait]
impl DatagramChannel for LokinetDatagrams {
    fn bound_endpoint(&self) -> Option<Endpoint> {
        Some(Endpoint::Domain(self.address.clone(), self._port.port))
    }

    async fn send_to(&self, endpoint: Endpoint, payload: Vec<u8>) -> Result<(), BackendError> {
        let ip_peer = match &endpoint {
            Endpoint::Socket(address) => Some(*address),
            Endpoint::Domain(host, port) => host
                .parse::<IpAddr>()
                .ok()
                .map(|address| SocketAddr::new(address, *port)),
            _ => None,
        };
        if let Some(peer_addr) = ip_peer {
            return self.send_ip_datagram(peer_addr, payload).await;
        }

        let (host, port) = match endpoint {
            Endpoint::Domain(host, port)
                if port != 0
                    && !host.is_empty()
                    && host.parse::<std::net::IpAddr>().is_err()
                    && is_lokinet_name(&host) =>
            {
                (host.trim_end_matches('.').to_owned(), port)
            }
            Endpoint::Service { namespace, .. } => {
                return Err(BackendError::UnsupportedEndpoint(namespace));
            }
            endpoint => {
                return Err(BackendError::UnsupportedEndpoint(format!(
                    "Lokinet UDP supports IPv4/IPv6 literals and .loki/.snode names with a port; ordinary DNS hostnames are not resolved; unsupported target {endpoint}"
                )));
            }
        };
        if host.contains('\0') {
            return Err(BackendError::InvalidEndpoint(
                "domain contains a NUL byte".to_owned(),
            ));
        }
        if payload.len() > MAX_DATAGRAM_SIZE {
            return Err(BackendError::InvalidEndpoint(format!(
                "UDP payload exceeds {MAX_DATAGRAM_SIZE} bytes"
            )));
        }
        let key = (host.clone(), port);
        let _establish_guard = self.establish_lock.lock().await;
        let existing_flow = self
            .flows
            .lock()
            .map_err(|error| BackendError::Internal(format!("UDP flow map: {error}")))?
            .get(&key)
            .cloned();
        let flow = if let Some(flow) = existing_flow {
            flow
        } else {
            let socket = self.socket.clone();
            let flow_host = host.clone();
            let flow = tokio::task::spawn_blocking(move || {
                socket.establish(
                    &flow_host,
                    port,
                    NonZeroU32::new(UDP_FLOW_TIMEOUT_SECS)
                        .expect("Lokinet UDP flow timeout is nonzero"),
                )
            })
            .await
            .map_err(|error| BackendError::Unavailable(error.to_string()))?
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;
            self.flows
                .lock()
                .map_err(|error| BackendError::Internal(format!("UDP flow map: {error}")))?
                .insert(key.clone(), flow.clone());
            flow
        };

        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || socket.send(&flow, &payload))
            .await
            .map_err(|error| BackendError::Unavailable(error.to_string()))?
            .map_err(|error| BackendError::Unavailable(error.to_string()))
    }

    async fn recv_from(&self) -> Result<Datagram, BackendError> {
        let mut events = self.events.lock().await;
        match events.recv().await {
            Some(UdpEvent::Packet(flow, payload)) => {
                let host = flow.remote_host().to_owned();
                let endpoint = match host.parse::<std::net::IpAddr>() {
                    Ok(address) => {
                        Endpoint::Socket(std::net::SocketAddr::new(address, flow.remote_port()))
                    }
                    Err(_) => Endpoint::Domain(host, flow.remote_port()),
                };
                Ok(Datagram { endpoint, payload })
            }
            Some(UdpEvent::IpPacket(source, payload)) => Ok(Datagram {
                endpoint: Endpoint::Socket(source),
                payload,
            }),
            None => Err(BackendError::Unavailable(
                "Lokinet datagram channel closed".to_owned(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl Backend for LokinetBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_datagram_size: MAX_DATAGRAM_SIZE as u32,
            server_name: "lokinet".to_owned(),
        }
    }

    fn identity_offers(&self) -> std::result::Result<Vec<IdentityOffer>, BackendError> {
        let address = self
            .runtime
            .address()
            .map_err(|error| BackendError::Unavailable(error.to_string()))?
            .map(IdentityAddress::Domain);
        Ok(vec![IdentityOffer {
            id: "lokinet-primary".to_owned(),
            address,
            capabilities: IdentityCapabilities {
                send_streams: true,
                send_datagrams: true,
                receive_streams: true,
                receive_datagrams: true,
            },
        }])
    }

    fn status(&self) -> ServiceStatus {
        let connected = self.runtime.is_connected();
        ServiceStatus {
            connected,
            detail: (!connected).then(|| "Lokinet is not connected yet".to_owned()),
        }
    }

    async fn connect_stream(
        &self,
        identity: &IdentityOffer,
        target: Endpoint,
    ) -> Result<socks6::BoxStream, BackendError> {
        self.connect_stream_inner(identity, target, None).await
    }

    async fn connect_stream_with_context(
        &self,
        identity: &IdentityOffer,
        target: Endpoint,
        context: ConnectContext,
    ) -> Result<socks6::BoxStream, BackendError> {
        self.connect_stream_inner(identity, target, Some(context))
            .await
    }

    async fn accept_stream(
        &self,
        identity: &IdentityOffer,
        port: u16,
    ) -> Result<(socks6::BoxStream, Endpoint), BackendError> {
        if identity.id != "lokinet-primary" {
            return Err(BackendError::UnsupportedEndpoint(format!(
                "Lokinet identity {}",
                identity.id
            )));
        }
        if port == 0 {
            return Err(BackendError::InvalidEndpoint(
                "Lokinet incoming stream port must be nonzero".to_owned(),
            ));
        }

        let listener = LocalTcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|error| {
                BackendError::Unavailable(format!(
                    "binding local listener for Lokinet port {port}: {error}"
                ))
            })?;
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        let accepting = Arc::new(AtomicBool::new(false));
        let callback_accepting = Arc::clone(&accepting);
        let runtime = Arc::clone(&self.runtime);
        let lokinet_listener = tokio::task::spawn_blocking(move || {
            runtime.listen_tcp_stream(move |remote, exposed_port| {
                if exposed_port == port
                    && callback_accepting
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    if peer_tx.send(remote.to_owned()).is_ok() {
                        StreamDecision::Accept
                    } else {
                        StreamDecision::Reject
                    }
                } else {
                    StreamDecision::Reject
                }
            })
        })
        .await
        .map_err(|error| BackendError::Unavailable(error.to_string()))?
        .map_err(|error| BackendError::Unavailable(error.to_string()))?;

        let (socket, _) = listener
            .accept()
            .await
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        let peer = peer_rx.recv().await.ok_or_else(|| {
            BackendError::Unavailable("Lokinet inbound stream closed before identification".into())
        })?;
        Ok((
            Box::new(LokinetIncomingTcpStream {
                socket,
                _listener: lokinet_listener,
            }),
            Endpoint::Service {
                namespace: "lokinet-peer".to_owned(),
                address: peer.into_bytes(),
                port: None,
            },
        ))
    }

    async fn open_datagrams(
        &self,
        identity: &IdentityOffer,
    ) -> Result<Box<dyn DatagramChannel>, BackendError> {
        if identity.id != "lokinet-primary" {
            return Err(BackendError::UnsupportedEndpoint(format!(
                "Lokinet identity {}",
                identity.id
            )));
        }
        let address = match identity.address.as_ref() {
            Some(IdentityAddress::Domain(address)) => address.clone(),
            Some(address) => {
                return Err(BackendError::UnsupportedEndpoint(format!(
                    "Lokinet identity address {address}"
                )));
            }
            None => self
                .runtime
                .address()
                .map_err(|error| BackendError::Unavailable(error.to_string()))?
                .ok_or_else(|| {
                    BackendError::Unavailable(
                        "Lokinet identity address is not available".to_owned(),
                    )
                })?,
        };
        let port = self.reserve_udp_port()?;
        let (event_tx, event_rx) = mpsc::channel(UDP_EVENT_CAPACITY);
        let flow_map = Arc::new(StdMutex::new(HashMap::new()));
        let callback_flows = Arc::clone(&flow_map);
        let callback_drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped = Arc::clone(&callback_drops);
        let runtime = Arc::clone(&self.runtime);
        let event_sender = event_tx.clone();
        let socket = tokio::task::spawn_blocking(move || {
            let packet_tx = event_tx.clone();
            runtime.bind_udp(
                port.port,
                |_| NonZeroU32::new(UDP_FLOW_TIMEOUT_SECS),
                move |flow, data| {
                    if packet_tx.try_send(UdpEvent::Packet(flow, data)).is_err() {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                },
                move |flow| match callback_flows.lock() {
                    Ok(mut flows) => {
                        flows.remove(&(flow.remote_host().to_owned(), flow.remote_port()));
                    }
                    Err(error) => {
                        tracing::error!(%error, "Lokinet UDP flow map lock poisoned");
                    }
                },
            )
        })
        .await
        .map_err(|error| BackendError::Unavailable(error.to_string()))?
        .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        Ok(Box::new(LokinetDatagrams {
            socket,
            flows: flow_map,
            establish_lock: Mutex::new(()),
            events: Mutex::new(event_rx),
            event_sender,
            ip_stack: self.ip_stack.clone(),
            local_ipv4: self.local_ipv4,
            local_ipv6: self.local_ipv6,
            ip_flows: Mutex::new(HashMap::new()),
            udp_ports: Arc::clone(&self.udp_ports),
            address,
            _port: port,
        }))
    }
}

async fn bind_socket(path: &Path) -> anyhow::Result<(UnixListener, SocketPathGuard)> {
    let parent = path
        .parent()
        .context("SOCKS6 proxy socket path must have a parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "creating SOCKS6 proxy socket directory {}",
            parent.display()
        )
    })?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            bail!("refusing to replace non-socket path {}", path.display());
        }
        match UnixStream::connect(path).await {
            Ok(_) => bail!(
                "a SOCKS6 service is already listening at {}",
                path.display()
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                let current = std::fs::symlink_metadata(path)
                    .with_context(|| format!("rechecking stale proxy socket {}", path.display()))?;
                if !current.file_type().is_socket()
                    || current.dev() != metadata.dev()
                    || current.ino() != metadata.ino()
                {
                    bail!(
                        "SOCKS6 proxy socket path changed while checking it: {}",
                        path.display()
                    );
                }
                std::fs::remove_file(path)
                    .with_context(|| format!("removing stale proxy socket {}", path.display()))?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("checking existing proxy socket {}", path.display()));
            }
        }
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding SOCKS6 proxy socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).with_context(|| {
        format!(
            "making SOCKS6 proxy socket available to local users: {}",
            path.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((
        listener,
        SocketPathGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

fn read_config(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warn!(path = %path.display(), "Lokinet config not found; starting with native defaults");
            Ok(String::new())
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = parse_args();
    let paths = Paths::resolve(&args)?;
    if let Some(Command::Init {
        bootstrap_file,
        keyfile,
    }) = args.command
    {
        return initialize(&paths, bootstrap_file.as_deref(), keyfile.as_deref());
    }

    create_private_data_dir(&paths.data_dir)?;
    let config = read_config(&paths.config)?;
    info!(
        config = %paths.config.display(),
        data_dir = %paths.data_dir.display(),
        "starting the Lokinet runtime"
    );
    let (runtime, packet_io) =
        Runtime::start_with_ip_packet_io(Config::new(config, &paths.data_dir))?;
    let local_ipv4 = runtime.ip_packet_local_address()?;
    let local_ipv6 = runtime.ip_packet_local_ipv6_address()?;
    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config
        .mtu(1500)
        .udp_timeout(Duration::from_secs(UDP_FLOW_TIMEOUT_SECS as u64));
    let ip_stack = IpStack::new_with_packet_io(ip_stack_config, LokinetPacketIo(packet_io));
    let backend = LokinetBackend::new(Arc::new(runtime), ip_stack, local_ipv4, local_ipv6);
    let (listener, _socket_guard) = bind_socket(&paths.socket).await?;
    info!(
        socket = %paths.socket.display(),
        "Lokinet SOCKS6 service ready for local users"
    );
    let server = Arc::new(Server::new(backend).with_max_connections(1024)?);

    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = server.run(listener) => result?,
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "lokinet-socks6d-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn bind_socket_creates_parent_and_grants_local_access() {
        let directory = test_directory();
        let path = directory.join("test.socks6");
        let (listener, guard) = bind_socket(&path).await.unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
        assert!(UnixStream::connect(&path).await.is_ok());

        drop(listener);
        drop(guard);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn bind_socket_refuses_to_replace_regular_files() {
        let directory = test_directory();
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("test.socks6");
        std::fs::write(&path, "keep").unwrap();

        assert!(bind_socket(&path).await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn init_creates_private_data_and_config_and_copies_bootstrap() {
        let directory = test_directory();
        let paths = Paths {
            socket: directory.join("run/lokinet.socks6"),
            config: directory.join("config/lokinet.ini"),
            data_dir: directory.join("data"),
        };
        let bootstrap = directory.join("bootstrap.signed");
        fs::create_dir_all(&directory).unwrap();
        fs::write(&bootstrap, "signed-bootstrap-data").unwrap();

        initialize(&paths, Some(&bootstrap), None).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.config).unwrap(),
            format!(
                "[network]\nkeyfile={}\n",
                paths.data_dir.join("lokinet-addr.privkey").display()
            )
        );
        assert_eq!(
            fs::read_to_string(paths.data_dir.join("bootstrap.signed")).unwrap(),
            "signed-bootstrap-data"
        );
        assert_eq!(
            fs::metadata(&paths.data_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
