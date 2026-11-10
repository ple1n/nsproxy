use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Serialize;
use socks6::{
    Backend, BackendError, BoxStream, Capabilities, ConnectContext, ConnectProgress,
    DatagramChannel, Endpoint, IdentityOffer, Server, SocketBackend,
};
use socks6_lab::{
    close_datagram_channel, serve_tcp_echo, serve_udp_echo, tcp_echo_check, udp_echo_check,
    ProxyAdapter, ProxyAddress, ProxyCapabilities, ProxyStatus, Socks6Adapter, Target,
};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::{
    io::{self, IsTerminal},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::JoinSet,
};
use tokio_rustls::TlsConnector;
use url::Url;

const DEFAULT_PROXY_LISTEN: &str = "127.0.0.1:1086";
const DEFAULT_PROXY: &str = "tcp://127.0.0.1:1086";
const DEFAULT_RESPONDER: &str = "127.0.0.1:19090";
const MAX_TRANSFER_SIZE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_TOTAL_BENCH_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PARALLEL_STREAMS: usize = 256;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Proxy requester tools for probing, client checks, benchmarks, and suites"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Probe(ProxyArgs),
    #[command(
        name = "proxy",
        alias = "serve",
        about = "Start a local SOCKS6 proxy fixture"
    )]
    Proxy {
        #[arg(long, default_value = DEFAULT_PROXY_LISTEN, value_parser = parse_socket_proxy_addr)]
        tcp: SocketAddr,
        #[arg(
            long,
            value_name = "PATH",
            help = "Also listen on this Unix-domain socket"
        )]
        unix: Option<PathBuf>,
        #[arg(
            long,
            default_value_t = 0,
            help = "Delay each outgoing TCP connection and report SOCKS6 connection progress"
        )]
        connect_delay_ms: u64,
    },
    Client {
        #[command(flatten)]
        proxy: ProxyArgs,
        #[arg(
            long,
            default_value = DEFAULT_RESPONDER,
            value_parser = parse_target,
            help = "Responder address in host:port form"
        )]
        responder: Target,
        #[arg(long, value_enum, default_value_t = ClientProtocol::Tcp)]
        protocol: ClientProtocol,
        #[arg(long, default_value = "hello from socks6-lab")]
        message: String,
    },
    #[command(name = "responder", aliases = ["echo-listen", "listen"], about = "Start TCP and UDP test responders")]
    Responder {
        #[arg(
            long,
            default_value = DEFAULT_RESPONDER,
            value_parser = parse_socket_addr,
            help = "Bind TCP and UDP responders on the same address"
        )]
        address: SocketAddr,
    },
    Bench {
        #[command(flatten)]
        proxy: ProxyArgs,
        #[arg(
            long,
            default_value = DEFAULT_RESPONDER,
            value_parser = parse_target,
            help = "Responder address in host:port form"
        )]
        responder: Target,
        #[arg(long, default_value = "1MiB", value_parser = parse_size)]
        size: u64,
        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,
        #[arg(long, default_value_t = 1, value_parser = parse_parallelism)]
        parallelism: usize,
        #[arg(long)]
        json: bool,
    },
    Suite {
        #[command(flatten)]
        proxy: ProxyArgs,
        #[arg(
            long,
            default_value = DEFAULT_RESPONDER,
            value_parser = parse_target,
            visible_alias = "tcp-target"
        )]
        tcp_responder: Option<Target>,
        #[arg(
            long,
            default_value = DEFAULT_RESPONDER,
            value_parser = parse_target,
            visible_alias = "udp-target"
        )]
        udp_responder: Option<Target>,
        #[arg(long, default_value = "1KiB,64KiB,1MiB")]
        sizes: String,
        #[arg(long, default_value = "1,4")]
        parallelism: String,
        #[arg(long, default_value_t = 1200)]
        udp_size: usize,
        #[arg(
            long,
            help = "Require at least one SOCKS6 connection-progress update before stream readiness"
        )]
        expect_connect_progress: bool,
        #[arg(long)]
        json: bool,
    },
    Lokinet {
        #[command(subcommand)]
        check: LokinetCheck,
    },
}

#[derive(Debug, Subcommand)]
enum LokinetCheck {
    #[command(about = "Check a TCP connection through a Lokinet-backed SOCKS6 proxy")]
    Tcp {
        #[arg(
            long,
            value_parser = parse_proxy_address,
            help = "SOCKS6 proxy endpoint (defaults to lokinet-socks6d's XDG-resolved socket)"
        )]
        proxy: Option<ProxyAddress>,
        #[arg(long, value_parser = parse_target, help = "Target host:port (for example, service.loki:443)")]
        target: Target,
    },
    #[command(about = "Check an HTTP(S) response through a Lokinet-backed SOCKS6 proxy")]
    Http {
        #[arg(
            long,
            value_parser = parse_proxy_address,
            help = "SOCKS6 proxy endpoint (defaults to lokinet-socks6d's XDG-resolved socket)"
        )]
        proxy: Option<ProxyAddress>,
        #[arg(
            long,
            value_name = "URL",
            help = "HTTP(S) URL to request through the proxy"
        )]
        url: String,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ClientProtocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Args)]
struct ProxyArgs {
    #[arg(
        long,
        default_value = DEFAULT_PROXY,
        value_parser = parse_proxy_address,
        help = "Proxy address under test (tcp://IP:PORT or unix:///PATH)"
    )]
    proxy: ProxyAddress,
}

fn parse_proxy_address(value: &str) -> std::result::Result<ProxyAddress, String> {
    ProxyAddress::parse(value).map_err(|error| error.to_string())
}

fn default_lokinet_socket_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("HOME must be set to an absolute path")?;
    let xdg_data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let xdg_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    Ok(lokinet_socket_path(
        &home,
        xdg_data_home.as_deref(),
        xdg_runtime_dir.as_deref(),
    ))
}

fn lokinet_socket_path(
    home: &Path,
    xdg_data_home: Option<&Path>,
    xdg_runtime_dir: Option<&Path>,
) -> PathBuf {
    let data_home = xdg_data_home
        .filter(|path| path.is_absolute())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".local/share"));
    let data_dir = data_home.join("lokinet-socks6");
    xdg_runtime_dir
        .filter(|path| path.is_absolute())
        .map(|path| path.join("lokinet-socks6/lokinet.socks6"))
        .unwrap_or_else(|| data_dir.join("run/lokinet.socks6"))
}

fn resolve_lokinet_proxy(proxy: Option<ProxyAddress>) -> Result<ProxyAddress> {
    match proxy {
        Some(proxy) => Ok(proxy),
        None => {
            #[cfg(unix)]
            {
                Ok(ProxyAddress::Unix(default_lokinet_socket_path()?))
            }
            #[cfg(not(unix))]
            {
                bail!("Lokinet SOCKS6 default socket is only supported on Unix platforms");
            }
        }
    }
}

fn parse_target(value: &str) -> std::result::Result<Target, String> {
    Target::parse(value).map_err(|error| error.to_string())
}

fn parse_socket_addr(value: &str) -> std::result::Result<SocketAddr, String> {
    value.parse().map_err(|error| format!("{error}"))
}

fn parse_socket_proxy_addr(value: &str) -> std::result::Result<SocketAddr, String> {
    value.parse().map_err(|error| format!("{error}"))
}

fn parse_parallelism(value: &str) -> std::result::Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| "parallelism must be a positive integer".to_owned())?;
    if count == 0 || count > MAX_PARALLEL_STREAMS {
        return Err(format!(
            "parallelism must be between 1 and {MAX_PARALLEL_STREAMS}"
        ));
    }
    Ok(count)
}

fn parse_parallelisms(value: &str) -> std::result::Result<Vec<usize>, String> {
    value.split(',').map(parse_parallelism).collect()
}

fn parse_sizes(value: &str) -> std::result::Result<Vec<u64>, String> {
    let sizes = value.split(',').map(parse_size).collect::<Result<Vec<_>>>();
    sizes.map_err(|error| error.to_string())
}

fn parse_size(value: &str) -> Result<u64> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number = number
        .parse::<u64>()
        .with_context(|| format!("invalid size {value:?}"))?;
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1000,
        "m" | "mb" => 1000u64.pow(2),
        "g" | "gb" => 1000u64.pow(3),
        "ki" | "kib" => 1024,
        "mi" | "mib" => 1024u64.pow(2),
        "gi" | "gib" => 1024u64.pow(3),
        _ => bail!("unsupported size unit in {value:?}; use B, KiB, MiB, or GiB"),
    };
    let size = number
        .checked_mul(multiplier)
        .context("size is too large")?;
    if size == 0 || size > MAX_TRANSFER_SIZE {
        bail!("size must be between 1 byte and 16 GiB");
    }
    Ok(size)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseState {
    Queued,
    Running,
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Serialize)]
struct SuiteRow {
    name: String,
    state: CaseState,
    detail: String,
    elapsed_ms: Option<u128>,
}

struct SuiteConfig {
    tcp_responder: Option<Target>,
    udp_responder: Option<Target>,
    sizes: Vec<u64>,
    parallelism: Vec<usize>,
    udp_size: usize,
    expect_connect_progress: bool,
}

enum SuiteMessage {
    Update(usize, SuiteRow),
    Finished,
}

#[derive(Serialize)]
struct ProbeReport {
    protocol: &'static str,
    capabilities: ProxyCapabilities,
    status: ProxyStatus,
    ping: &'static str,
}

#[derive(Serialize)]
struct BenchReport {
    protocol: &'static str,
    responder: Target,
    size_bytes_per_stream: u64,
    streams: usize,
    total_payload_bytes: u64,
    elapsed_ms: u128,
    payload_mib_per_second: f64,
    stream_elapsed_ms: Vec<u128>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    match Cli::parse().command {
        Command::Probe(args) => run_probe(args).await,
        Command::Proxy {
            tcp,
            unix,
            connect_delay_ms,
        } => run_proxy_server(tcp, unix, Duration::from_millis(connect_delay_ms)).await,
        Command::Client {
            proxy,
            responder,
            protocol,
            message,
        } => run_client(proxy, responder, protocol, message).await,
        Command::Responder { address } => run_listeners(address).await,
        Command::Bench {
            proxy,
            responder,
            size,
            chunk_size,
            parallelism,
            json,
        } => run_bench(proxy, responder, size, chunk_size, parallelism, json).await,
        Command::Suite {
            proxy,
            tcp_responder,
            udp_responder,
            sizes,
            parallelism,
            udp_size,
            expect_connect_progress,
            json,
        } => {
            run_suite_command(
                proxy,
                tcp_responder,
                udp_responder,
                parse_sizes(&sizes).map_err(|error| anyhow::anyhow!(error))?,
                parse_parallelisms(&parallelism).map_err(|error| anyhow::anyhow!(error))?,
                udp_size,
                expect_connect_progress,
                json,
            )
            .await
        }
        Command::Lokinet { check } => match check {
            LokinetCheck::Tcp { proxy, target } => {
                run_lokinet_tcp_check(resolve_lokinet_proxy(proxy)?, target).await
            }
            LokinetCheck::Http { proxy, url } => {
                run_lokinet_http_check(resolve_lokinet_proxy(proxy)?, &url).await
            }
        },
    }
}

struct DelayedSocketBackend {
    connect_delay: Duration,
}

#[async_trait]
impl Backend for DelayedSocketBackend {
    fn capabilities(&self) -> Capabilities {
        SocketBackend.capabilities()
    }

    fn identity_offers(&self) -> Result<Vec<IdentityOffer>, BackendError> {
        SocketBackend.identity_offers()
    }

    async fn connect_stream(
        &self,
        identity: &IdentityOffer,
        target: Endpoint,
    ) -> Result<BoxStream, BackendError> {
        SocketBackend.connect_stream(identity, target).await
    }

    async fn connect_stream_with_context(
        &self,
        identity: &IdentityOffer,
        target: Endpoint,
        context: ConnectContext,
    ) -> Result<BoxStream, BackendError> {
        if !self.connect_delay.is_zero() {
            context
                .report_progress(
                    ConnectProgress::new("establishing_route")
                        .with_detail("waiting for the lab-configured connection delay"),
                )
                .await
                .map_err(|_| {
                    BackendError::Unavailable("connection progress receiver closed".to_owned())
                })?;
            tokio::select! {
                _ = tokio::time::sleep(self.connect_delay) => {}
                _ = context.cancelled() => {
                    return Err(BackendError::Unavailable("connection cancelled".to_owned()));
                }
            }
        }
        SocketBackend.connect_stream(identity, target).await
    }

    async fn open_datagrams(
        &self,
        identity: &IdentityOffer,
    ) -> Result<Box<dyn DatagramChannel>, BackendError> {
        SocketBackend.open_datagrams(identity).await
    }
}

async fn run_proxy_server(
    tcp_address: SocketAddr,
    unix_path: Option<PathBuf>,
    connect_delay: Duration,
) -> Result<()> {
    if !tcp_address.ip().is_loopback() {
        eprintln!(
            "warning: the proxy server has no authentication; non-loopback TCP bind exposes it to the network"
        );
    }
    let tcp_listener = TcpListener::bind(tcp_address)
        .await
        .with_context(|| format!("binding proxy TCP listener at {tcp_address}"))?;
    let bound_tcp_address = tcp_listener
        .local_addr()
        .context("reading bound proxy TCP address")?;
    let server = Arc::new(Server::new(DelayedSocketBackend { connect_delay }));
    let mut tasks = JoinSet::new();
    tasks.spawn(Arc::clone(&server).run(tcp_listener));
    println!("SOCKS6 proxy listening on TCP {bound_tcp_address}");

    #[cfg(unix)]
    let _socket_guard = if let Some(path) = unix_path {
        let (listener, guard) = bind_proxy_unix_socket(&path)?;
        tasks.spawn(Arc::clone(&server).run(listener));
        println!("SOCKS6 proxy listening on Unix socket {}", path.display());
        Some(guard)
    } else {
        None
    };

    #[cfg(not(unix))]
    if unix_path.is_some() {
        bail!("Unix-domain proxy listeners are not supported on this platform");
    }

    let result = tokio::select! {
        result = tasks.join_next() => match result {
            Some(Ok(Ok(()))) => bail!("SOCKS6 proxy listener stopped unexpectedly"),
            Some(Ok(Err(error))) => Err(error.into()),
            Some(Err(error)) => Err(error.into()),
            None => bail!("all SOCKS6 proxy listeners stopped unexpectedly"),
        },
        result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C"),
    };
    result?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(unix)]
fn bind_proxy_unix_socket(path: &Path) -> Result<(UnixListener, UnixSocketGuard)> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating proxy socket directory {}", parent.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding proxy socket {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting proxy socket {}", path.display()))?;
    if !metadata.file_type().is_socket() {
        bail!("proxy socket path is not a socket: {}", path.display());
    }
    let guard = UnixSocketGuard {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        drop(guard);
        return Err(error)
            .with_context(|| format!("restricting proxy socket permissions {}", path.display()));
    }
    Ok((listener, guard))
}

#[cfg(unix)]
struct UnixSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                if let Err(error) = std::fs::remove_file(&self.path) {
                    eprintln!(
                        "could not remove proxy socket {}: {error}",
                        self.path.display()
                    );
                }
            }
            Ok(_) => eprintln!(
                "proxy socket path changed while running; leaving {} untouched",
                self.path.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "could not inspect proxy socket {}: {error}",
                self.path.display()
            ),
        }
    }
}

async fn run_client(
    proxy_args: ProxyArgs,
    responder: Target,
    protocol: ClientProtocol,
    message: String,
) -> Result<()> {
    let proxy = adapter(&proxy_args.proxy)?;
    match protocol {
        ClientProtocol::Tcp => {
            let mut stream = proxy.open_stream(&responder).await?;
            stream.write_all(message.as_bytes()).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            if response != message.as_bytes() {
                bail!("TCP echo response did not match the request");
            }
        }
        ClientProtocol::Udp => {
            let datagrams = proxy.open_datagrams().await?;
            let operation = async {
                datagrams
                    .send(&responder, message.as_bytes().to_vec())
                    .await?;
                let response = tokio::time::timeout(Duration::from_secs(5), datagrams.receive())
                    .await
                    .context("timed out waiting for UDP echo")??;
                if response != message.as_bytes() {
                    bail!("UDP echo response did not match the request");
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            close_datagram_channel(datagrams.as_ref(), operation).await?;
        }
    }
    println!(
        "{} responder check passed: {} bytes via {} to {}",
        match protocol {
            ClientProtocol::Tcp => "TCP",
            ClientProtocol::Udp => "UDP",
        },
        message.len(),
        proxy.protocol_name(),
        responder
    );
    Ok(())
}

async fn run_lokinet_tcp_check(proxy_address: ProxyAddress, target: Target) -> Result<()> {
    let proxy = Socks6Adapter::new(&proxy_address)?;
    let started = Instant::now();
    let _stream = tokio::time::timeout(Duration::from_secs(30), proxy.open_stream(&target))
        .await
        .context("timed out opening TCP stream through SOCKS6")?
        .with_context(|| format!("connecting to {target} through SOCKS6"))?;
    println!(
        "Lokinet TCP connection to {target} succeeded in {} ms",
        started.elapsed().as_millis()
    );
    Ok(())
}

async fn run_lokinet_http_check(proxy_address: ProxyAddress, input: &str) -> Result<()> {
    let url = Url::parse(input).context("parsing HTTP(S) URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("URL scheme must be http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URLs containing credentials are not supported");
    }
    let host = match url.host().context("HTTP(S) URL must include a host")? {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    let port = url
        .port_or_known_default()
        .context("HTTP(S) URL must specify a port")?;
    let target = Target {
        host: host.clone(),
        port,
    };
    let mut host_header = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.clone()
    };
    if url.port().is_some() {
        host_header.push(':');
        host_header.push_str(&port.to_string());
    }
    let mut request_target = url.path().to_owned();
    if let Some(query) = url.query() {
        request_target.push('?');
        request_target.push_str(query);
    }
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: socks6-lab\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );

    let proxy = Socks6Adapter::new(&proxy_address)?;
    let stream = tokio::time::timeout(Duration::from_secs(30), proxy.open_stream(&target))
        .await
        .context("timed out opening HTTP stream through SOCKS6")??;
    let status_line = if url.scheme() == "https" {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name =
            ServerName::try_from(host.clone()).context("invalid TLS server host name")?;
        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connector.connect(server_name, stream),
        )
        .await
        .context("timed out negotiating TLS through SOCKS6")??;
        http_status_line(&mut stream, &request).await?
    } else {
        let mut stream = stream;
        http_status_line(&mut stream, &request).await?
    };
    let status = parse_http_status(&status_line)?;
    println!("Lokinet HTTP check: {status_line}");
    if status >= 400 {
        bail!("HTTP endpoint returned status {status}");
    }
    Ok(())
}

async fn http_status_line<S>(stream: &mut S, request: &str) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(Duration::from_secs(30), async {
        stream.write_all(request.as_bytes()).await?;
        let mut line = Vec::with_capacity(128);
        loop {
            let mut byte = [0];
            if stream.read(&mut byte).await? == 0 {
                bail!("HTTP endpoint closed before sending a status line");
            }
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
            if line.len() >= 8192 {
                bail!("HTTP status line exceeded 8192 bytes");
            }
        }
        let line = std::str::from_utf8(&line[..line.len() - 2])
            .context("HTTP status line was not valid UTF-8")?;
        Ok(line.to_owned())
    })
    .await
    .context("timed out waiting for an HTTP status line")?
}

fn parse_http_status(status_line: &str) -> Result<u16> {
    let mut fields = status_line.split_ascii_whitespace();
    let version = fields.next().context("HTTP response has no version")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        bail!("unsupported HTTP status line version {version:?}");
    }
    let status = fields
        .next()
        .context("HTTP response has no status code")?
        .parse::<u16>()
        .context("HTTP response has an invalid status code")?;
    if !(100..=599).contains(&status) {
        bail!("HTTP response status code {status} is out of range");
    }
    Ok(status)
}

fn adapter(address: &ProxyAddress) -> Result<Arc<dyn ProxyAdapter>> {
    Ok(Arc::new(Socks6Adapter::new(address)?))
}

async fn run_probe(args: ProxyArgs) -> Result<()> {
    let proxy = adapter(&args.proxy)?;
    let capabilities = proxy.capabilities().await?;
    let status = proxy.status().await?;
    if !status.connected {
        bail!(
            "proxy reports disconnected{}",
            status
                .detail
                .as_deref()
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default()
        );
    }
    proxy.ping().await?;
    let report = ProbeReport {
        protocol: proxy.protocol_name(),
        capabilities,
        status,
        ping: "ok",
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn run_listeners(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() {
        eprintln!("warning: test responders are unauthenticated; non-loopback binds expose them to the network");
    }
    let (tcp_listener, udp_listener) = bind_responders(address).await?;
    println!(
        "TCP responder: {}",
        tcp_listener
            .local_addr()
            .context("reading TCP listener address")?
    );
    println!(
        "UDP responder: {}",
        udp_listener
            .local_addr()
            .context("reading UDP listener address")?
    );
    println!("Press Ctrl-C to stop.");
    tokio::select! {
        result = serve_tcp_echo(tcp_listener) => result.context("TCP echo listener stopped")?,
        result = serve_udp_echo(udp_listener) => result.context("UDP echo listener stopped")?,
        result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
    }
    Ok(())
}

async fn bind_responders(address: SocketAddr) -> Result<(TcpListener, UdpSocket)> {
    let tcp_listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("binding TCP responder at {address}"))?;
    let tcp_address = tcp_listener
        .local_addr()
        .context("reading bound TCP responder address")?;
    let mut udp_address = address;
    udp_address.set_port(tcp_address.port());
    let udp_listener = UdpSocket::bind(udp_address)
        .await
        .with_context(|| format!("binding UDP responder at {udp_address}"))?;
    Ok((tcp_listener, udp_listener))
}

async fn run_bench(
    proxy_args: ProxyArgs,
    responder: Target,
    size: u64,
    chunk_size: usize,
    parallelism: usize,
    json: bool,
) -> Result<()> {
    if chunk_size == 0 {
        bail!("chunk size must be greater than zero");
    }
    let proxy = adapter(&proxy_args.proxy)?;
    let report = benchmark(proxy, responder, size, chunk_size, parallelism).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_bench(&report);
    }
    Ok(())
}

async fn benchmark(
    proxy: Arc<dyn ProxyAdapter>,
    responder: Target,
    size: u64,
    chunk_size: usize,
    parallelism: usize,
) -> Result<BenchReport> {
    if parallelism == 0 || parallelism > MAX_PARALLEL_STREAMS {
        bail!("parallelism must be between 1 and {MAX_PARALLEL_STREAMS}");
    }
    if size == 0 || size > MAX_TRANSFER_SIZE {
        bail!("size must be between 1 byte and 16 GiB");
    }
    let total_bytes = size
        .checked_mul(parallelism as u64)
        .context("total benchmark byte count overflowed")?;
    if total_bytes > MAX_TOTAL_BENCH_BYTES {
        bail!("combined benchmark payload is capped at 16 GiB per run");
    }
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for _ in 0..parallelism {
        let proxy = Arc::clone(&proxy);
        let responder = responder.clone();
        tasks.spawn(
            async move { tcp_echo_check(proxy.as_ref(), &responder, size, chunk_size).await },
        );
    }
    let mut stream_elapsed_ms = Vec::with_capacity(parallelism);
    while let Some(result) = tasks.join_next().await {
        let elapsed = result.context("benchmark stream task failed to join")??;
        stream_elapsed_ms.push(elapsed.as_millis());
    }
    let elapsed = started.elapsed();
    let total_payload_bytes = size
        .checked_mul(parallelism as u64)
        .context("total benchmark byte count overflowed")?;
    let payload_mib_per_second =
        total_payload_bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
    Ok(BenchReport {
        protocol: proxy.protocol_name(),
        responder,
        size_bytes_per_stream: size,
        streams: parallelism,
        total_payload_bytes,
        elapsed_ms: elapsed.as_millis(),
        payload_mib_per_second,
        stream_elapsed_ms,
    })
}

fn print_bench(report: &BenchReport) {
    println!(
        "{} echo benchmark — {} stream(s), {} each",
        report.protocol,
        report.streams,
        human_size(report.size_bytes_per_stream)
    );
    println!("Responder: {}", report.responder);
    println!("Elapsed: {:.3}s", report.elapsed_ms as f64 / 1000.0);
    println!(
        "Aggregate payload goodput: {:.2} MiB/s",
        report.payload_mib_per_second
    );
    if report.stream_elapsed_ms.len() > 1 {
        let streams = report
            .stream_elapsed_ms
            .iter()
            .map(|elapsed| format!("{:.3}s", *elapsed as f64 / 1000.0))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Per-stream elapsed: {streams}");
    }
    println!("Note: goodput counts the payload once, not the echoed return traffic.");
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

async fn run_suite_command(
    proxy_args: ProxyArgs,
    tcp_responder: Option<Target>,
    udp_responder: Option<Target>,
    sizes: Vec<u64>,
    parallelism: Vec<usize>,
    udp_size: usize,
    expect_connect_progress: bool,
    json: bool,
) -> Result<()> {
    let proxy = adapter(&proxy_args.proxy)?;
    let config = SuiteConfig {
        tcp_responder,
        udp_responder,
        sizes,
        parallelism,
        udp_size,
        expect_connect_progress,
    };
    let rows = initial_suite_rows(&config);
    let task_rows = rows.clone();
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let task_proxy = Arc::clone(&proxy);
    let task =
        tokio::spawn(async move { execute_suite(task_proxy, config, sender, task_rows).await });

    let (mut rows, quit_before_completion) = if json || !io::stdout().is_terminal() {
        (run_suite_plain(&mut receiver, rows, json).await, false)
    } else {
        run_suite_tui(&mut receiver, rows, task.abort_handle()).await?
    };
    if quit_before_completion {
        match task.await {
            Err(error) if error.is_cancelled() => bail!("suite cancelled"),
            Err(error) => return Err(error).context("suite task failed"),
            Ok(()) => {
                while let Some(message) = receiver.recv().await {
                    match message {
                        SuiteMessage::Update(index, row) => {
                            if let Some(slot) = rows.get_mut(index) {
                                *slot = row;
                            }
                        }
                        SuiteMessage::Finished => break,
                    }
                }
            }
        }
    } else {
        task.await.context("suite task failed")?;
    }
    let failed = rows
        .iter()
        .any(|row| matches!(row.state, CaseState::Failed));
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    }
    if failed {
        bail!("suite failed");
    } else if !json {
        let passed = rows
            .iter()
            .filter(|row| matches!(row.state, CaseState::Passed))
            .count();
        let skipped = rows
            .iter()
            .filter(|row| matches!(row.state, CaseState::Skipped))
            .count();
        println!("Suite complete: {passed} passed, {skipped} skipped.");
    }
    Ok(())
}

fn initial_suite_rows(config: &SuiteConfig) -> Vec<SuiteRow> {
    let mut names = vec![
        "Negotiate capabilities".to_owned(),
        "Query service status".to_owned(),
        "Ping proxy".to_owned(),
    ];
    names.push(if config.tcp_responder.is_some() {
        "TCP echo".to_owned()
    } else {
        "TCP echo (requires --tcp-responder)".to_owned()
    });
    if config.expect_connect_progress {
        names.push(if config.tcp_responder.is_some() {
            "TCP connect progress".to_owned()
        } else {
            "TCP connect progress (requires --tcp-responder)".to_owned()
        });
    }
    names.push(if config.udp_responder.is_some() {
        "UDP echo".to_owned()
    } else {
        "UDP echo (requires --udp-responder)".to_owned()
    });
    for size in &config.sizes {
        names.push(format!("TCP stream · {}", human_size(*size)));
    }
    for count in &config.parallelism {
        names.push(format!("Parallel TCP · {count} stream(s)"));
    }
    names
        .into_iter()
        .map(|name| SuiteRow {
            name,
            state: CaseState::Queued,
            detail: String::new(),
            elapsed_ms: None,
        })
        .collect()
}

async fn execute_suite(
    proxy: Arc<dyn ProxyAdapter>,
    config: SuiteConfig,
    sender: mpsc::UnboundedSender<SuiteMessage>,
    mut rows: Vec<SuiteRow>,
) {
    let capabilities = run_case(&mut rows, 0, &sender, async {
        let capabilities = proxy.capabilities().await?;
        Ok::<_, anyhow::Error>(capabilities)
    })
    .await;

    run_case(&mut rows, 1, &sender, async {
        let status = proxy.status().await?;
        if !status.connected {
            bail!(
                "proxy reports disconnected{}",
                status
                    .detail
                    .as_deref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            );
        }
        Ok(status.detail.unwrap_or_else(|| "connected".to_owned()))
    })
    .await;

    run_case(&mut rows, 2, &sender, async {
        proxy.ping().await?;
        Ok("pong".to_owned())
    })
    .await;

    let mut index = 3;
    let tcp_supported = capabilities
        .as_ref()
        .is_some_and(|capabilities| capabilities.send_streams);
    if let Some(responder) = &config.tcp_responder {
        if tcp_supported {
            run_case(&mut rows, index, &sender, async {
                let elapsed = tcp_echo_check(proxy.as_ref(), responder, 64, 64).await?;
                Ok(format!(
                    "64-byte echo in {:.2} ms",
                    elapsed.as_secs_f64() * 1000.0
                ))
            })
            .await;
        } else {
            skip_case(
                &mut rows,
                index,
                "reliable stream sending is not offered",
                &sender,
            );
        }
    } else {
        skip_case(&mut rows, index, "no TCP responder supplied", &sender);
    }
    index += 1;

    if config.expect_connect_progress {
        if let Some(responder) = config.tcp_responder.as_ref().filter(|_| tcp_supported) {
            run_case(&mut rows, index, &sender, async {
                let mut progress = Vec::new();
                let stream = proxy
                    .open_stream_with_progress(responder, &mut |event| progress.push(event))
                    .await?;
                drop(stream);
                if progress.is_empty() {
                    bail!("proxy completed without reporting connection progress");
                }
                let phases = progress
                    .iter()
                    .map(|event| event.phase.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(format!("{} update(s): {phases}", progress.len()))
            })
            .await;
        } else if config.tcp_responder.is_none() {
            skip_case(&mut rows, index, "no TCP responder supplied", &sender);
        } else {
            skip_case(
                &mut rows,
                index,
                "reliable stream sending is not offered",
                &sender,
            );
        }
        index += 1;
    }

    if let Some(responder) = &config.udp_responder {
        if capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.send_datagrams)
        {
            run_case(&mut rows, index, &sender, async {
                let elapsed = udp_echo_check(proxy.as_ref(), responder, config.udp_size).await?;
                Ok(format!(
                    "{}-byte echo in {:.2} ms",
                    config.udp_size,
                    elapsed.as_secs_f64() * 1000.0
                ))
            })
            .await;
        } else {
            skip_case(
                &mut rows,
                index,
                "unreliable datagram sending is not offered",
                &sender,
            );
        }
    } else {
        skip_case(&mut rows, index, "no UDP responder supplied", &sender);
    }
    index += 1;

    if let Some(responder) = config.tcp_responder.as_ref().filter(|_| tcp_supported) {
        for size in &config.sizes {
            let current_size = *size;
            run_case(&mut rows, index, &sender, async {
                let elapsed =
                    tcp_echo_check(proxy.as_ref(), responder, current_size, 64 * 1024).await?;
                let rate = current_size as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
                Ok(format!(
                    "{} echoed at {:.2} MiB/s",
                    human_size(current_size),
                    rate
                ))
            })
            .await;
            index += 1;
        }
        for count in config.parallelism {
            let parallel_count = count;
            run_case(&mut rows, index, &sender, async {
                let report = benchmark(
                    Arc::clone(&proxy),
                    responder.clone(),
                    1024 * 1024,
                    64 * 1024,
                    parallel_count,
                )
                .await?;
                Ok(format!(
                    "{} streams, {:.2} MiB/s aggregate",
                    parallel_count, report.payload_mib_per_second
                ))
            })
            .await;
            index += 1;
        }
    } else {
        while index < rows.len() {
            skip_case(
                &mut rows,
                index,
                "TCP responder required for stream tests",
                &sender,
            );
            index += 1;
        }
    }
    let _ = sender.send(SuiteMessage::Finished);
}

async fn run_case<F, T>(
    rows: &mut [SuiteRow],
    index: usize,
    sender: &mpsc::UnboundedSender<SuiteMessage>,
    test: F,
) -> Option<T>
where
    F: std::future::Future<Output = Result<T>>,
    T: std::fmt::Display,
{
    rows[index].state = CaseState::Running;
    rows[index].detail = "running".to_owned();
    let _ = sender.send(SuiteMessage::Update(index, rows[index].clone()));
    let started = Instant::now();
    match test.await {
        Ok(detail) => {
            rows[index].state = CaseState::Passed;
            rows[index].detail = detail.to_string();
            rows[index].elapsed_ms = Some(started.elapsed().as_millis());
            let _ = sender.send(SuiteMessage::Update(index, rows[index].clone()));
            Some(detail)
        }
        Err(error) => {
            rows[index].state = CaseState::Failed;
            rows[index].detail = format!("{error:#}");
            rows[index].elapsed_ms = Some(started.elapsed().as_millis());
            let _ = sender.send(SuiteMessage::Update(index, rows[index].clone()));
            None
        }
    }
}

fn skip_case(
    rows: &mut [SuiteRow],
    index: usize,
    detail: &str,
    sender: &mpsc::UnboundedSender<SuiteMessage>,
) {
    rows[index].state = CaseState::Skipped;
    rows[index].detail = detail.to_owned();
    let _ = sender.send(SuiteMessage::Update(index, rows[index].clone()));
}

async fn run_suite_plain(
    receiver: &mut mpsc::UnboundedReceiver<SuiteMessage>,
    mut rows: Vec<SuiteRow>,
    quiet: bool,
) -> Vec<SuiteRow> {
    while let Some(message) = receiver.recv().await {
        match message {
            SuiteMessage::Update(index, row) => {
                if !quiet {
                    println!(
                        "{}  {} — {}",
                        state_symbol(&row.state),
                        row.name,
                        row.detail
                    );
                }
                rows[index] = row;
            }
            SuiteMessage::Finished => break,
        }
    }
    rows
}

async fn run_suite_tui(
    receiver: &mut mpsc::UnboundedReceiver<SuiteMessage>,
    mut rows: Vec<SuiteRow>,
    abort: tokio::task::AbortHandle,
) -> Result<(Vec<SuiteRow>, bool)> {
    enable_raw_mode().context("enabling terminal raw mode")?;
    let mut restore = TerminalRestore;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("opening alternate terminal screen")?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let mut selected = 0usize;
    let mut complete = false;
    let quit_before_completion;

    loop {
        while let Ok(message) = receiver.try_recv() {
            match message {
                SuiteMessage::Update(index, row) => {
                    if let Some(slot) = rows.get_mut(index) {
                        *slot = row;
                    }
                }
                SuiteMessage::Finished => complete = true,
            }
        }

        terminal.draw(|frame| draw_suite(frame, &rows, selected, complete))?;
        if event::poll(Duration::from_millis(80)).context("polling terminal input")? {
            if let Event::Key(key) = event::read().context("reading terminal input")? {
                match key.code {
                    KeyCode::Char('q') => {
                        quit_before_completion = !complete;
                        if quit_before_completion {
                            abort.abort();
                        }
                        break;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        selected = (selected + 1).min(rows.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                    }
                    _ => {}
                }
            }
        }
    }

    terminal.show_cursor()?;
    drop(terminal);
    restore.restore();
    Ok((rows, quit_before_completion))
}

struct TerminalRestore;

impl TerminalRestore {
    fn restore(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

impl Drop for TerminalRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

fn draw_suite(frame: &mut ratatui::Frame<'_>, rows: &[SuiteRow], selected: usize, complete: bool) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let passed = rows
        .iter()
        .filter(|row| matches!(row.state, CaseState::Passed))
        .count();
    let failed = rows
        .iter()
        .filter(|row| matches!(row.state, CaseState::Failed))
        .count();
    let running = rows
        .iter()
        .filter(|row| matches!(row.state, CaseState::Running))
        .count();
    let summary = Paragraph::new(Line::from(vec![
        Span::styled(
            " PROXY TEST LAB ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{passed} passed"),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        Span::styled(format!("{failed} failed"), Style::default().fg(Color::Red)),
        Span::raw("  "),
        Span::styled(
            format!("{running} running"),
            Style::default().fg(Color::Yellow),
        ),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(summary, layout[0]);

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(layout[1]);
    let items = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let color = match row.state {
                CaseState::Queued => Color::DarkGray,
                CaseState::Running => Color::Yellow,
                CaseState::Passed => Color::Green,
                CaseState::Failed => Color::Red,
                CaseState::Skipped => Color::Gray,
            };
            let selected_style = if index == selected {
                Style::default().bg(Color::Rgb(35, 44, 58)).fg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", state_symbol(&row.state)),
                    Style::default().fg(color),
                ),
                Span::styled(&row.name, selected_style),
            ]))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().bg(Color::Rgb(35, 44, 58)))
            .block(
                Block::default()
                    .title("  SUITE CHECKLIST  ")
                    .borders(Borders::RIGHT),
            ),
        panels[0],
        &mut list_state,
    );

    let detail = rows
        .get(selected)
        .map(|row| {
            let timing = row
                .elapsed_ms
                .map(|elapsed| format!("\n\nElapsed  {elapsed} ms"))
                .unwrap_or_default();
            format!(
                "{}\n\n{}\n{}",
                row.name,
                state_label(&row.state),
                row.detail
            ) + &timing
        })
        .unwrap_or_else(|| "No test selected".to_owned());
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: true })
            .block(Block::default().title("  DETAILS  ").borders(Borders::ALL)),
        panels[1],
    );
    let footer = if complete {
        "Suite complete · press q to close"
    } else {
        "↑/↓ or j/k  navigate    q  quit"
    };
    frame.render_widget(Paragraph::new(footer), layout[2]);
}

fn state_symbol(state: &CaseState) -> &'static str {
    match state {
        CaseState::Queued => "·",
        CaseState::Running => "◌",
        CaseState::Passed => "✓",
        CaseState::Failed => "✗",
        CaseState::Skipped => "–",
    }
}

fn state_label(state: &CaseState) -> &'static str {
    match state {
        CaseState::Queued => "QUEUED",
        CaseState::Running => "RUNNING",
        CaseState::Passed => "PASSED",
        CaseState::Failed => "FAILED",
        CaseState::Skipped => "SKIPPED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socks6::{Server, SocketBackend};
    use tokio::net::TcpListener;

    #[test]
    fn parses_human_sizes_and_limits() {
        assert_eq!(parse_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("10MB").unwrap(), 10_000_000);
        assert!(parse_size("0").is_err());
        assert!(parse_size("17GiB").is_err());
    }

    #[test]
    fn parses_parallelism_sweep() {
        assert_eq!(parse_parallelisms("1,4,16").unwrap(), [1, 4, 16]);
        assert!(parse_parallelisms("1,0").is_err());
        assert!(parse_parallelisms("257").is_err());
    }

    #[test]
    fn requester_commands_default_to_local_proxy_and_responder() {
        let Cli {
            command: Command::Client {
                proxy, responder, ..
            },
        } = Cli::try_parse_from(["socks6-lab", "client"]).unwrap()
        else {
            panic!("expected client command");
        };
        assert_eq!(
            proxy.proxy,
            ProxyAddress::parse(&format!("tcp://{DEFAULT_PROXY_LISTEN}")).unwrap()
        );
        assert_eq!(responder.to_string(), DEFAULT_RESPONDER);

        let Cli {
            command: Command::Bench {
                proxy, responder, ..
            },
        } = Cli::try_parse_from(["socks6-lab", "bench"]).unwrap()
        else {
            panic!("expected bench command");
        };
        assert_eq!(
            proxy.proxy,
            ProxyAddress::parse(&format!("tcp://{DEFAULT_PROXY_LISTEN}")).unwrap()
        );
        assert_eq!(responder.to_string(), DEFAULT_RESPONDER);

        let Cli {
            command:
                Command::Suite {
                    proxy,
                    tcp_responder,
                    udp_responder,
                    expect_connect_progress,
                    ..
                },
        } = Cli::try_parse_from(["socks6-lab", "suite"]).unwrap()
        else {
            panic!("expected suite command");
        };
        assert_eq!(
            proxy.proxy,
            ProxyAddress::parse(&format!("tcp://{DEFAULT_PROXY_LISTEN}")).unwrap()
        );
        assert_eq!(tcp_responder.unwrap().to_string(), DEFAULT_RESPONDER);
        assert_eq!(udp_responder.unwrap().to_string(), DEFAULT_RESPONDER);
        assert!(!expect_connect_progress);

        let Cli {
            command:
                Command::Suite {
                    expect_connect_progress,
                    ..
                },
        } = Cli::try_parse_from(["socks6-lab", "suite", "--expect-connect-progress"]).unwrap()
        else {
            panic!("expected suite command");
        };
        assert!(expect_connect_progress);
    }

    #[test]
    fn lokinet_checks_default_to_daemon_socket_and_require_targets() {
        assert!(Cli::try_parse_from(
            ["socks6-lab", "lokinet", "tcp", "--target", "peer.loki:443",]
        )
        .is_ok());
        assert!(Cli::try_parse_from([
            "socks6-lab",
            "lokinet",
            "http",
            "--url",
            "https://service.loki/",
        ])
        .is_ok());
        assert_eq!(
            resolve_lokinet_proxy(None).unwrap(),
            ProxyAddress::Unix(default_lokinet_socket_path().unwrap())
        );
        assert!(parse_http_status("HTTP/1.1 204 No Content").is_ok());
        assert!(parse_http_status("not-http").is_err());
    }

    #[test]
    fn lokinet_socket_path_matches_daemon_xdg_defaults() {
        let home = Path::new("/home/test");
        assert_eq!(
            lokinet_socket_path(home, None, None),
            Path::new("/home/test/.local/share/lokinet-socks6/run/lokinet.socks6")
        );
        assert_eq!(
            lokinet_socket_path(
                home,
                Some(Path::new("/data")),
                Some(Path::new("/run/user/1000"))
            ),
            Path::new("/run/user/1000/lokinet-socks6/lokinet.socks6")
        );
        assert_eq!(
            lokinet_socket_path(
                home,
                Some(Path::new("relative-data")),
                Some(Path::new("relative-runtime"))
            ),
            Path::new("/home/test/.local/share/lokinet-socks6/run/lokinet.socks6")
        );
    }

    #[tokio::test]
    async fn lokinet_http_check_gets_status_through_socks6() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_server = Arc::new(Server::new(SocketBackend));
        let proxy_task = tokio::spawn(proxy_server.run(proxy_listener));

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = http_listener.local_addr().unwrap();
        let http_task = tokio::spawn(async move {
            let (mut stream, _) = http_listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });

        run_lokinet_http_check(
            ProxyAddress::Tcp(proxy_address),
            &format!("http://{http_address}/health"),
        )
        .await
        .unwrap();

        http_task.await.unwrap();
        proxy_task.abort();
    }

    #[tokio::test]
    async fn tcp_and_udp_responders_share_the_same_port() {
        let (tcp, udp) = bind_responders("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    }

    #[tokio::test]
    async fn suite_runs_checks_and_parallel_benchmarks() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_server = Arc::new(Server::new(DelayedSocketBackend {
            connect_delay: Duration::from_millis(50),
        }));
        let proxy_task = tokio::spawn(proxy_server.run(proxy_listener));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_responder = Target::parse(&tcp_listener.local_addr().unwrap().to_string()).unwrap();
        let tcp_task = tokio::spawn(socks6_lab::serve_tcp_echo(tcp_listener));
        let udp_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_responder = Target::parse(&udp_listener.local_addr().unwrap().to_string()).unwrap();
        let udp_task = tokio::spawn(socks6_lab::serve_udp_echo(udp_listener));

        run_client(
            ProxyArgs {
                proxy: ProxyAddress::Tcp(proxy_address),
            },
            tcp_responder.clone(),
            ClientProtocol::Tcp,
            "tcp-client-check".to_owned(),
        )
        .await
        .unwrap();
        run_client(
            ProxyArgs {
                proxy: ProxyAddress::Tcp(proxy_address),
            },
            udp_responder.clone(),
            ClientProtocol::Udp,
            "udp-client-check".to_owned(),
        )
        .await
        .unwrap();

        let proxy: Arc<dyn ProxyAdapter> =
            Arc::new(Socks6Adapter::new(&ProxyAddress::Tcp(proxy_address)).unwrap());
        let config = SuiteConfig {
            tcp_responder: Some(tcp_responder),
            udp_responder: Some(udp_responder),
            sizes: vec![1024],
            parallelism: vec![1, 4],
            udp_size: 1200,
            expect_connect_progress: true,
        };
        let rows = initial_suite_rows(&config);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        execute_suite(proxy, config, sender, rows.clone()).await;

        let mut completed = rows;
        while let Ok(message) = receiver.try_recv() {
            if let SuiteMessage::Update(index, row) = message {
                completed[index] = row;
            }
        }
        assert!(completed
            .iter()
            .all(|row| matches!(row.state, CaseState::Passed)));
        let progress_row = completed
            .iter()
            .find(|row| row.name == "TCP connect progress")
            .expect("suite should include the requested progress check");
        assert!(progress_row.detail.contains("establishing_route"));
        assert!(progress_row.elapsed_ms.unwrap() >= 40);

        proxy_task.abort();
        tcp_task.abort();
        udp_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_unix_listener_is_private_and_cleaned_up() {
        use std::{
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        let directory = std::env::temp_dir().join(format!(
            "socks6-lab-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("test.socks6");
        let (listener, guard) = bind_proxy_unix_socket(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }
}
