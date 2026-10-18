use anyhow::{Context, Result, bail, ensure};
use socks5_impl::protocol::{
    AsyncStreamOperation, Command, Reply, Request, StreamOperation, UserKey, WireAddress,
};
use std::{
    io::Cursor,
    net::SocketAddr,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};
use tracing::{info, warn};

struct SocksResponse {
    reply: Reply,
    address: WireAddress,
}

pub async fn spawn_test_servers() -> Result<SocketAddr> {
    let tcp_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("binding localhost SOCKS5 TCP echo test server")?;
    let address = tcp_listener.local_addr()?;
    let udp_socket = UdpSocket::bind(address)
        .await
        .context("binding localhost SOCKS5 UDP echo test server on the TCP test server port")?;
    info!(transport = "tcp", operation = "bind/listen", %address, "SOCKS5 test server ready");
    info!(transport = "udp", operation = "bind", %address, "SOCKS5 test server ready");

    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((mut stream, peer)) => {
                    info!(transport = "tcp", operation = "accept", %address, %peer, "SOCKS5 test server accepted connection");
                    tokio::spawn(async move {
                        let mut buffer = [0; 8192];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) => break,
                                Ok(length) => {
                                    info!(transport = "tcp", operation = "recv", %peer, bytes = length, "SOCKS5 TCP echo received data");
                                    if let Err(error) = stream.write_all(&buffer[..length]).await {
                                        warn!("SOCKS5 TCP echo test server failed to reply: {error}");
                                        break;
                                    }
                                    info!(transport = "tcp", operation = "write", %peer, bytes = length, "SOCKS5 TCP echo sent data");
                                }
                                Err(error) => {
                                    warn!("SOCKS5 TCP echo test server failed to read: {error}");
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(error) => warn!("SOCKS5 TCP echo test server accept failed: {error}"),
            }
        }
    });
    tokio::spawn(async move {
        let mut buffer = vec![0; u16::MAX as usize];
        loop {
            match udp_socket.recv_from(&mut buffer).await {
                Ok((length, peer)) => {
                    info!(transport = "udp", operation = "recv_from", %address, %peer, bytes = length, "SOCKS5 UDP echo received datagram");
                    match udp_socket.send_to(&buffer[..length], peer).await {
                        Ok(sent) => info!(transport = "udp", operation = "send_to", %address, %peer, bytes = sent, "SOCKS5 UDP echo sent datagram"),
                        Err(error) => warn!("SOCKS5 UDP echo test server failed to reply to {peer}: {error}"),
                    }
                }
                Err(error) => warn!("SOCKS5 UDP echo test server receive failed: {error}"),
            }
        }
    });
    Ok(address)
}

pub async fn check(
    proxy: &str,
    connect_targets: &[String],
    udp_echo_target: Option<&str>,
    bind: bool,
    username: Option<&str>,
    password: Option<&str>,
    operation_timeout: Duration,
) -> Result<()> {
    let proxy = parse_endpoint(proxy).context("invalid proxy address")?;
    let auth = username.zip(password).map(|(user, pass)| UserKey::new(user, pass));
    let connect_targets = connect_targets
        .iter()
        .map(|target| parse_endpoint(target).with_context(|| format!("invalid CONNECT target '{target}'")))
        .collect::<Result<Vec<_>>>()?;
    let udp_echo_target = udp_echo_target
        .map(|target| parse_endpoint(target).with_context(|| format!("invalid UDP echo target '{target}'")))
        .transpose()?;

    println!("SOCKS5 proxy: {proxy}");
    info!(operation = "start_probe", %proxy, "SOCKS5 feature probe started");
    let mut failures = Vec::new();
    for (method, method_auth) in [(0x00, auth.as_ref()), (0x02, auth.as_ref()), (0x80, None)] {
        if let Err(error) = probe_auth_method(&proxy, method, method_auth, operation_timeout).await {
            let message = format!("authentication method {method:#04x}: {error:#}");
            eprintln!("FAIL {message}");
            failures.push(message);
        }
    }

    for target in connect_targets {
        match command(&proxy, Command::Connect, target.clone(), auth.as_ref(), operation_timeout).await {
            Ok((_, response)) => {
                print_reply("CONNECT", &target, &response);
                if response.reply != Reply::Succeeded {
                    failures.push(format!("CONNECT to {target} failed: {}", response.reply));
                }
            }
            Err(error) => {
                let message = format!("CONNECT to {target}: {error:#}");
                eprintln!("FAIL {message}");
                failures.push(message);
            }
        }
    }

    if bind {
        if let Err(error) = probe_bind(&proxy, auth.as_ref(), operation_timeout).await {
            let message = format!("BIND: {error:#}");
            eprintln!("FAIL {message}");
            failures.push(message);
        }
    } else {
        println!("SKIP BIND (pass --bind to exercise it)");
    }

    if let Some(target) = udp_echo_target {
        if let Err(error) = probe_udp(&proxy, target.clone(), auth.as_ref(), operation_timeout).await {
            let message = format!("UDP ASSOCIATE to {target}: {error:#}");
            eprintln!("FAIL {message}");
            failures.push(message);
        }
    } else {
        println!("SKIP UDP ASSOCIATE (pass --udp-echo-target HOST:PORT)");
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{} SOCKS5 probe(s) failed: {}", failures.len(), failures.join("; "))
    }
}

async fn probe_auth_method(
    proxy: &WireAddress,
    method: u8,
    auth: Option<&UserKey>,
    operation_timeout: Duration,
) -> Result<()> {
    let result = timeout(operation_timeout, async {
        let mut stream = connect_proxy(proxy).await?;
        info!(operation = "send_greeting", version = 5, method = format!("{method:#04x}"), "SOCKS5 probe sending method offer");
        stream.write_all(&[0x05, 0x01, method]).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        ensure!(response[0] == 0x05, "invalid SOCKS version in method response: {:#x}", response[0]);
        info!(operation = "read_method_selection", version = response[0], method = format!("{:#04x}", response[1]), "SOCKS5 probe received method selection");
        Ok::<_, anyhow::Error>((stream, response[1]))
    })
    .await
    .context("authentication negotiation timed out")??;

    let (mut stream, selected) = result;
    match selected {
        0xff => println!("UNSUPPORTED authentication method {method:#04x}"),
        selected if selected != method => bail!(
            "proxy selected unoffered authentication method {selected:#04x} when only {method:#04x} was offered"
        ),
        0x00 => println!("PASS authentication method: no authentication"),
        0x02 => {
            let Some(auth) = auth else {
                println!("SUPPORTED authentication method: username/password (credentials not supplied)");
                return Ok(());
            };
            timeout(operation_timeout, async {
                info!(operation = "send_rfc1929_auth", username_bytes = auth.username.len(), password_bytes = auth.password.len(), "SOCKS5 probe sending username/password credentials");
                stream.write_u8(0x01).await?;
                write_socks_string(&mut stream, &auth.username).await?;
                write_socks_string(&mut stream, &auth.password).await?;
                let mut response = [0; 2];
                stream.read_exact(&mut response).await?;
                ensure!(response[0] == 0x01, "invalid RFC 1929 auth version: {:#x}", response[0]);
                ensure!(response[1] == 0x00, "username/password authentication rejected");
                info!(operation = "read_rfc1929_auth", version = response[0], status = response[1], "SOCKS5 probe received authentication status");
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("username/password authentication timed out")??;
            println!("PASS authentication method: username/password credentials accepted");
        }
        selected => bail!("proxy selected unsupported authentication method {selected:#04x}"),
    }
    Ok(())
}

async fn command(
    proxy: &WireAddress,
    command: Command,
    target: WireAddress,
    auth: Option<&UserKey>,
    operation_timeout: Duration,
) -> Result<(TcpStream, SocksResponse)> {
    timeout(operation_timeout, async {
        let mut stream = connect_proxy(proxy).await?;
        negotiate(&mut stream, auth).await?;
        info!(operation = "send_request", ?command, atyp = ?target.get_type(), %target, "SOCKS5 probe sending command request");
        Request::new(command, target).write_to_async_stream(&mut stream).await?;
        let response = read_response(&mut stream).await?;
        Ok::<_, anyhow::Error>((stream, response))
    })
    .await
    .context("SOCKS5 command timed out")?
}

async fn negotiate(stream: &mut TcpStream, auth: Option<&UserKey>) -> Result<()> {
    if auth.is_some() {
        info!(operation = "send_greeting", version = 5, methods = "no-auth,user-password", "SOCKS5 probe sending method offer");
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        info!(operation = "send_greeting", version = 5, methods = "no-auth", "SOCKS5 probe sending method offer");
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    ensure!(method[0] == 0x05, "invalid SOCKS version in negotiation: {:#x}", method[0]);
    info!(operation = "read_method_selection", version = method[0], method = format!("{:#04x}", method[1]), "SOCKS5 proxy selected authentication method");

    match method[1] {
        0x00 => Ok(()),
        0x02 => {
            let auth = auth.context("proxy requires username/password credentials")?;
            stream.write_u8(0x01).await?;
            write_socks_string(stream, &auth.username).await?;
            write_socks_string(stream, &auth.password).await?;
            let mut result = [0; 2];
            stream.read_exact(&mut result).await?;
            ensure!(result[0] == 0x01 && result[1] == 0x00, "username/password authentication failed");
            Ok(())
        }
        0xff => bail!("proxy has no acceptable authentication method"),
        method => bail!("proxy selected unsupported authentication method {method:#04x}"),
    }
}

async fn read_response(stream: &mut TcpStream) -> Result<SocksResponse> {
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    ensure!(header[0] == 0x05, "invalid SOCKS version in reply: {:#x}", header[0]);
    ensure!(header[2] == 0x00, "nonzero reserved byte in SOCKS5 reply: {:#x}", header[2]);
    let reply = Reply::try_from(header[1])?;
    let address = WireAddress::retrieve_from_async_stream(stream).await?;
    info!(operation = "read_reply", version = header[0], ?reply, atyp = ?address.get_type(), %address, "SOCKS5 probe received command reply");
    Ok(SocksResponse { reply, address })
}

async fn probe_bind(proxy: &WireAddress, auth: Option<&UserKey>, operation_timeout: Duration) -> Result<()> {
    let request_address = WireAddress::try_from("0.0.0.0:0")?;
    let (mut control, first) = command(proxy, Command::Bind, request_address, auth, operation_timeout).await?;
    print_reply("BIND (first reply)", proxy, &first);
    if first.reply != Reply::Succeeded {
        bail!("BIND was rejected: {}", first.reply);
    }

    let peer_addr = bind_connect_address(&first.address, proxy).await?;
    info!(operation = "connect_bind_listener", %peer_addr, "SOCKS5 probe connecting to BIND relay");
    let mut peer = timeout(operation_timeout, TcpStream::connect(peer_addr))
        .await
        .context("connecting to BIND relay timed out")??;
    let second = timeout(operation_timeout, read_response(&mut control))
        .await
        .context("waiting for BIND second reply timed out")??;
    print_reply("BIND (second reply)", &peer_addr.into(), &second);
    if second.reply != Reply::Succeeded {
        bail!("BIND peer was rejected: {}", second.reply);
    }

    let request = b"sp-socks5-bind-probe";
    let response = b"sp-socks5-bind-response";
    timeout(operation_timeout, async {
        info!(operation = "write_bind_data", bytes = request.len(), "SOCKS5 probe sending data through BIND");
        control.write_all(request).await?;
        let mut received = vec![0; request.len()];
        peer.read_exact(&mut received).await?;
        ensure!(received == request, "BIND client-to-peer data mismatch");
        peer.write_all(response).await?;
        let mut received = vec![0; response.len()];
        control.read_exact(&mut received).await?;
        ensure!(received == response, "BIND peer-to-client data mismatch");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("BIND data exchange timed out")??;
    println!("PASS BIND bidirectional TCP relay");
    Ok(())
}

async fn probe_udp(
    proxy: &WireAddress,
    target: WireAddress,
    auth: Option<&UserKey>,
    operation_timeout: Duration,
) -> Result<()> {
    let local_address = match proxy {
        WireAddress::SocketAddress(SocketAddr::V6(_)) => "[::]:0",
        _ => "0.0.0.0:0",
    };
    let socket = UdpSocket::bind(local_address).await?;
    info!(operation = "bind_udp_client", local = %socket.local_addr()?, "SOCKS5 probe bound UDP client socket");
    let requested_address = if socket.local_addr()?.is_ipv4() {
        WireAddress::try_from("0.0.0.0:0")?
    } else {
        WireAddress::try_from("[::]:0")?
    };
    let (mut control, response) =
        command(proxy, Command::UdpAssociate, requested_address, auth, operation_timeout).await?;
    print_reply("UDP ASSOCIATE", proxy, &response);
    if response.reply != Reply::Succeeded {
        bail!("UDP ASSOCIATE was rejected: {}", response.reply);
    }

    let relay_addr = bind_connect_address(&response.address, proxy).await?;
    socket.connect(relay_addr).await?;
    info!(operation = "connect_udp_relay", %relay_addr, "SOCKS5 probe connected UDP socket to relay");
    let payload = b"sp-socks5-udp-probe";
    let mut packet = Vec::with_capacity(3 + target.len() + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    target.write_to_buf(&mut packet);
    packet.extend_from_slice(payload);
    info!(operation = "send_udp_request", rsv = 0, frag = 0, atyp = ?target.get_type(), destination = %target, bytes = payload.len(), "SOCKS5 probe sending UDP datagram");
    let sent = timeout(operation_timeout, socket.send(&packet))
        .await
        .context("sending UDP probe timed out")??;
    info!(operation = "send_udp_request", bytes = sent, "SOCKS5 probe sent UDP datagram");

    let mut reply = vec![0; 65_535];
    let size = timeout(operation_timeout, socket.recv(&mut reply))
        .await
        .context("waiting for UDP echo response timed out")??;
    reply.truncate(size);
    ensure!(reply.len() >= 3, "truncated SOCKS5 UDP response");
    ensure!(reply[0..2] == [0x00, 0x00], "nonzero reserved bytes in UDP response");
    ensure!(reply[2] == 0x00, "fragmented UDP response is not supported by this probe");
    let mut cursor = Cursor::new(&reply[3..]);
    let source = WireAddress::retrieve_from_stream(&mut cursor)?;
    let payload_offset = 3 + cursor.position() as usize;
    ensure!(source == target, "UDP echo source mismatch: expected {target}, received {source}");
    ensure!(reply[payload_offset..] == payload[..], "UDP echo payload mismatch");
    info!(operation = "receive_udp_reply", rsv = 0, frag = 0, atyp = ?source.get_type(), %source, bytes = reply.len() - payload_offset, "SOCKS5 probe received UDP echo reply");
    println!("PASS UDP ASSOCIATE relay and echo from {source}");

    drop(control);
    Ok(())
}

fn print_reply(operation: &str, target: &WireAddress, response: &SocksResponse) {
    if response.reply == Reply::Succeeded {
        println!("PASS {operation} to {target} (bound address {})", response.address);
    } else {
        println!("REJECTED {operation} to {target}: {}", response.reply);
    }
}

async fn connect_proxy(proxy: &WireAddress) -> Result<TcpStream> {
    let addr = lookup_host(proxy.to_string())
        .await?
        .next()
        .context("proxy address resolved to no IP addresses")?;
    info!(operation = "connect", %addr, "SOCKS5 probe connecting to proxy");
    TcpStream::connect(addr).await.context("connecting to SOCKS5 proxy failed")
}

async fn bind_connect_address(address: &WireAddress, proxy: &WireAddress) -> Result<SocketAddr> {
    let mut addresses = lookup_host(address.to_string()).await?;
    let mut addr = addresses.next().context("BIND/UDP relay address resolved to no IP addresses")?;
    if addr.ip().is_unspecified() {
        let mut proxy_addresses = lookup_host(proxy.to_string()).await?;
        let proxy_addr = proxy_addresses
            .find(|candidate| candidate.is_ipv4() == addr.is_ipv4())
            .or(lookup_host(proxy.to_string()).await?.next())
            .context("could not resolve proxy address for wildcard relay address")?;
        addr.set_ip(proxy_addr.ip());
    }
    ensure!(addr.port() != 0, "proxy returned a zero relay port");
    Ok(addr)
}

async fn write_socks_string(stream: &mut TcpStream, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(bytes.len() <= u8::MAX as usize, "SOCKS5 username/password fields may not exceed 255 bytes");
    stream.write_u8(bytes.len() as u8).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

fn parse_endpoint(value: &str) -> Result<WireAddress> {
    let endpoint = WireAddress::try_from(value).context("expected HOST:PORT or [IPv6]:PORT")?;
    ensure!(endpoint.port() != 0, "endpoint port must be nonzero");
    if let WireAddress::DomainAddress(host, _) = &endpoint {
        ensure!(!host.is_empty(), "endpoint hostname must not be empty");
        ensure!(host.len() <= u8::MAX as usize, "SOCKS5 domain names may not exceed 255 bytes");
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socks5_impl::protocol::{Reply, Response};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn optional_tcp_and_udp_test_servers_share_a_loopback_port_and_echo() {
        let address = spawn_test_servers().await.unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);

        let mut tcp_client = TcpStream::connect(address).await.unwrap();
        tcp_client.write_all(b"tcp test").await.unwrap();
        let mut tcp_response = [0; 8];
        timeout(Duration::from_secs(1), tcp_client.read_exact(&mut tcp_response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&tcp_response, b"tcp test");

        let udp_client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        udp_client.connect(address).await.unwrap();
        udp_client.send(b"udp test").await.unwrap();
        let mut response = [0; 32];
        let length = timeout(Duration::from_secs(1), udp_client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"udp test");
    }

    #[tokio::test]
    async fn udp_probe_runs_even_when_bind_is_rejected() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let udp_associate_requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&udp_associate_requests);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request_count = Arc::clone(&request_count);
                tokio::spawn(async move {
                    let mut greeting = [0; 2];
                    if stream.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0; greeting[1] as usize];
                    if stream.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    let method = if methods.contains(&0) { 0 } else { 0xff };
                    if stream.write_all(&[0x05, method]).await.is_err() || method == 0xff {
                        return;
                    }

                    let request = match Request::retrieve_from_async_stream(&mut stream).await {
                        Ok(request) => request,
                        Err(_) => return,
                    };
                    if request.command == Command::UdpAssociate {
                        request_count.fetch_add(1, Ordering::SeqCst);
                    }
                    let response = Response::new(Reply::CommandNotSupported, WireAddress::unspecified());
                    let _ = response.write_to_async_stream(&mut stream).await;
                });
            }
        });

        let result = check(
            &address.to_string(),
            &[],
            Some("127.0.0.1:9"),
            true,
            None,
            None,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("BIND"));
        assert_eq!(udp_associate_requests.load(Ordering::SeqCst), 1);
    }
}
