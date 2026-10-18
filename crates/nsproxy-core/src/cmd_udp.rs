use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use socks5_impl::protocol::WireAddress;
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{UdpSocket, lookup_host},
    time::timeout,
};
use tun2socks5::{ArgProxy, ProxyType};
use url::Url;

use crate::uplink::proxy_adapters::{ProxyConnection, RemoteAdapter};

const NTP_PACKET_LEN: usize = 48;
const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;
const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

#[derive(Debug)]
pub struct NtpProbeResult {
    pub peer: String,
    pub via_proxy: Option<String>,
    pub elapsed: Duration,
    pub leap_indicator: u8,
    pub stratum: u8,
    pub reference_id: String,
    pub server_time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct StunProbeResult {
    pub server: String,
    pub via_proxy: Option<String>,
    pub elapsed: Duration,
    pub mapped_address: SocketAddr,
}

pub async fn probe_ntp(
    target: &str,
    socks5: Option<&str>,
    timeout_duration: Duration,
) -> Result<NtpProbeResult> {
    ensure!(
        !timeout_duration.is_zero(),
        "timeout must be greater than zero"
    );

    let target_address = parse_target_address(target)?;
    let request = make_request(SystemTime::now())?;

    if let Some(socks5) = socks5 {
        let proxy = parse_socks5_proxy(socks5)?;
        let connection = timeout(timeout_duration, RemoteAdapter::connect_udp(&proxy))
            .await
            .context("timed out connecting to SOCKS5 proxy")?
            .context("failed to establish SOCKS5 UDP association")?;
        let route = connection.info().to_owned();
        let mut tunnel = match connection {
            ProxyConnection::Udp(tunnel) => tunnel,
            ProxyConnection::Tcp(_) => bail!("SOCKS5 proxy did not establish a UDP tunnel"),
        };

        let started = Instant::now();
        let packet = timeout(timeout_duration, async {
            tunnel
                .send_to(&request, target_address)
                .await
                .context("failed to send NTP request through SOCKS5")?;
            tunnel
                .recv_from()
                .await
                .context("failed to receive NTP response through SOCKS5")
        })
        .await
        .context("timed out waiting for NTP response through SOCKS5")??;

        return finish_probe(target, Some(route), started, &packet.data, &request);
    }

    let peer = resolve_target(&target_address)
        .await
        .with_context(|| format!("failed to resolve NTP target '{target}'"))?;

    let bind_addr = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind local UDP socket for {peer}"))?;
    socket
        .connect(peer)
        .await
        .with_context(|| format!("failed to connect UDP socket to {peer}"))?;

    let started = Instant::now();
    let (response, response_len) = timeout(timeout_duration, async {
        socket
            .send(&request)
            .await
            .context("failed to send NTP request")?;

        let mut response = [0; 512];
        let response_len = socket
            .recv(&mut response)
            .await
            .context("failed to receive NTP response")?;
        Ok::<_, anyhow::Error>((response, response_len))
    })
    .await
    .with_context(|| format!("timed out waiting for NTP response from {peer}"))??;

    finish_probe(
        &peer.to_string(),
        None,
        started,
        &response[..response_len],
        &request,
    )
}

pub async fn probe_stun(
    server: &str,
    socks5: Option<&str>,
    timeout_duration: Duration,
) -> Result<StunProbeResult> {
    ensure!(
        !timeout_duration.is_zero(),
        "timeout must be greater than zero"
    );

    let target_address = parse_target_address(server)?;
    let (request, transaction_id) = make_stun_request();

    if let Some(socks5) = socks5 {
        let proxy = parse_socks5_proxy(socks5)?;
        let connection = timeout(timeout_duration, RemoteAdapter::connect_udp(&proxy))
            .await
            .context("timed out connecting to SOCKS5 proxy")?
            .context("failed to establish SOCKS5 UDP association")?;
        let route = connection.info().to_owned();
        let mut tunnel = match connection {
            ProxyConnection::Udp(tunnel) => tunnel,
            ProxyConnection::Tcp(_) => bail!("SOCKS5 proxy did not establish a UDP tunnel"),
        };

        let started = Instant::now();
        let packet = timeout(timeout_duration, async {
            tunnel
                .send_to(&request, target_address)
                .await
                .context("failed to send STUN request through SOCKS5")?;
            tunnel
                .recv_from()
                .await
                .context("failed to receive STUN response through SOCKS5")
        })
        .await
        .context("timed out waiting for STUN response through SOCKS5")??;

        return finish_stun_probe(server, Some(route), started, &packet.data, &transaction_id);
    }

    let peer = resolve_target(&target_address)
        .await
        .with_context(|| format!("failed to resolve STUN server '{server}'"))?;
    let bind_addr = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind local UDP socket for {peer}"))?;
    socket
        .connect(peer)
        .await
        .with_context(|| format!("failed to connect UDP socket to {peer}"))?;

    let started = Instant::now();
    let (response, response_len) = timeout(timeout_duration, async {
        socket
            .send(&request)
            .await
            .context("failed to send STUN request")?;
        let mut response = [0; 512];
        let response_len = socket
            .recv(&mut response)
            .await
            .context("failed to receive STUN response")?;
        Ok::<_, anyhow::Error>((response, response_len))
    })
    .await
    .with_context(|| format!("timed out waiting for STUN response from {peer}"))??;

    finish_stun_probe(
        &peer.to_string(),
        None,
        started,
        &response[..response_len],
        &transaction_id,
    )
}

fn make_stun_request() -> ([u8; STUN_HEADER_LEN], [u8; 12]) {
    let transaction_id = rand::random::<[u8; 12]>();
    let mut request = [0; STUN_HEADER_LEN];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    (request, transaction_id)
}

fn finish_stun_probe(
    server: &str,
    via_proxy: Option<String>,
    started: Instant,
    response: &[u8],
    transaction_id: &[u8; 12],
) -> Result<StunProbeResult> {
    let elapsed = started.elapsed();
    let mapped_address = parse_stun_response(response, transaction_id)
        .with_context(|| format!("invalid STUN response from {server}"))?;
    Ok(StunProbeResult {
        server: server.to_owned(),
        via_proxy,
        elapsed,
        mapped_address,
    })
}

fn parse_stun_response(response: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    ensure!(
        response.len() >= STUN_HEADER_LEN,
        "response is only {} bytes; expected at least {STUN_HEADER_LEN}",
        response.len()
    );
    ensure!(
        u16::from_be_bytes(response[0..2].try_into().unwrap()) == STUN_BINDING_SUCCESS,
        "expected a STUN binding success response"
    );
    let message_len = usize::from(u16::from_be_bytes(response[2..4].try_into().unwrap()));
    ensure!(
        message_len % 4 == 0,
        "invalid STUN message length {message_len}"
    );
    ensure!(
        response.len() >= STUN_HEADER_LEN + message_len,
        "truncated STUN response"
    );
    ensure!(
        u32::from_be_bytes(response[4..8].try_into().unwrap()) == STUN_MAGIC_COOKIE,
        "invalid STUN magic cookie"
    );
    ensure!(
        &response[8..20] == transaction_id,
        "STUN response does not match this request"
    );

    let mut offset = STUN_HEADER_LEN;
    while offset < STUN_HEADER_LEN + message_len {
        ensure!(
            offset + 4 <= response.len(),
            "truncated STUN attribute header"
        );
        let attribute_type = u16::from_be_bytes(response[offset..offset + 2].try_into().unwrap());
        let attribute_len = usize::from(u16::from_be_bytes(
            response[offset + 2..offset + 4].try_into().unwrap(),
        ));
        let value_start = offset + 4;
        let value_end = value_start + attribute_len;
        ensure!(
            value_end <= STUN_HEADER_LEN + message_len,
            "truncated STUN attribute value"
        );
        if matches!(
            attribute_type,
            STUN_XOR_MAPPED_ADDRESS | STUN_MAPPED_ADDRESS
        ) {
            return parse_stun_address(
                attribute_type,
                &response[value_start..value_end],
                transaction_id,
            );
        }
        offset = value_start + (attribute_len + 3) / 4 * 4;
    }
    bail!("STUN response did not include a mapped address")
}

fn parse_stun_address(
    attribute_type: u16,
    value: &[u8],
    transaction_id: &[u8; 12],
) -> Result<SocketAddr> {
    ensure!(value.len() >= 4, "truncated STUN mapped address");
    ensure!(value[0] == 0, "invalid STUN mapped address reserved byte");
    let xor = attribute_type == STUN_XOR_MAPPED_ADDRESS;
    let port = u16::from_be_bytes(value[2..4].try_into().unwrap())
        ^ if xor {
            (STUN_MAGIC_COOKIE >> 16) as u16
        } else {
            0
        };
    let address = match value[1] {
        0x01 => {
            ensure!(value.len() == 8, "invalid STUN IPv4 mapped address length");
            let mut bytes: [u8; 4] = value[4..8].try_into().unwrap();
            if xor {
                for (byte, mask) in bytes.iter_mut().zip(STUN_MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            std::net::IpAddr::V4(bytes.into())
        }
        0x02 => {
            ensure!(value.len() == 20, "invalid STUN IPv6 mapped address length");
            let mut bytes: [u8; 16] = value[4..20].try_into().unwrap();
            if xor {
                for (byte, mask) in bytes.iter_mut().zip(
                    STUN_MAGIC_COOKIE
                        .to_be_bytes()
                        .into_iter()
                        .chain(*transaction_id),
                ) {
                    *byte ^= mask;
                }
            }
            std::net::IpAddr::V6(bytes.into())
        }
        family => bail!("unsupported STUN mapped address family {family}"),
    };
    Ok(SocketAddr::new(address, port))
}

fn finish_probe(
    target: &str,
    via_proxy: Option<String>,
    started: Instant,
    response: &[u8],
    request: &[u8; NTP_PACKET_LEN],
) -> Result<NtpProbeResult> {
    let elapsed = started.elapsed();
    let result = parse_response(response, request)
        .with_context(|| format!("invalid NTP response from {target}"))?;

    Ok(NtpProbeResult {
        peer: target.to_owned(),
        via_proxy,
        elapsed,
        leap_indicator: result.leap_indicator,
        stratum: result.stratum,
        reference_id: result.reference_id,
        server_time: result.server_time,
    })
}

fn parse_socks5_proxy(socks5: &str) -> Result<ArgProxy> {
    let url = if socks5.contains("://") {
        socks5.to_owned()
    } else {
        format!("socks5://{socks5}")
    };
    let proxy = ArgProxy::from_url(&url)
        .map_err(|err| anyhow::anyhow!("invalid SOCKS5 proxy '{socks5}': {err}"))?;
    ensure!(
        proxy.proxy_type == ProxyType::Socks5,
        "--socks5 requires a SOCKS5 proxy"
    );
    Ok(proxy)
}

fn parse_target_address(target: &str) -> Result<WireAddress> {
    if let Ok(address) = target.parse::<SocketAddr>() {
        return Ok(WireAddress::SocketAddress(address));
    }

    let url = Url::parse(&format!("udp://{target}"))
        .with_context(|| format!("invalid NTP target '{target}'; expected HOST:PORT"))?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid NTP target '{target}'; expected HOST:PORT"
    );
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("NTP target '{target}' has no host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow::anyhow!("NTP target '{target}' must include a port"))?;

    if let Ok(ip) = host.parse() {
        Ok(WireAddress::SocketAddress(SocketAddr::new(ip, port)))
    } else {
        Ok(WireAddress::DomainAddress(host.to_owned(), port))
    }
}

async fn resolve_target(target: &WireAddress) -> Result<SocketAddr> {
    match target {
        WireAddress::SocketAddress(address) => Ok(*address),
        WireAddress::DomainAddress(host, port) => lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("NTP target '{host}:{port}' resolved to no addresses")),
    }
}

struct ParsedNtpResponse {
    leap_indicator: u8,
    stratum: u8,
    reference_id: String,
    server_time: Option<DateTime<Utc>>,
}

fn make_request(now: SystemTime) -> Result<[u8; NTP_PACKET_LEN]> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    let ntp_seconds = elapsed
        .as_secs()
        .checked_add(NTP_UNIX_EPOCH_OFFSET)
        .context("system time is outside the supported NTP era")?;
    let fraction = ((u64::from(elapsed.subsec_nanos())) << 32) / 1_000_000_000;

    let mut packet = [0; NTP_PACKET_LEN];
    packet[0] = (4 << 3) | 3;
    packet[40..44].copy_from_slice(&(ntp_seconds as u32).to_be_bytes());
    packet[44..48].copy_from_slice(&(fraction as u32).to_be_bytes());
    Ok(packet)
}

fn parse_response(response: &[u8], request: &[u8; NTP_PACKET_LEN]) -> Result<ParsedNtpResponse> {
    ensure!(
        response.len() >= NTP_PACKET_LEN,
        "response is only {} bytes; expected at least {NTP_PACKET_LEN}",
        response.len()
    );

    let leap_indicator = response[0] >> 6;
    let version = (response[0] >> 3) & 0x07;
    let mode = response[0] & 0x07;
    ensure!(
        matches!(version, 3 | 4),
        "unsupported NTP version {version}"
    );
    ensure!(mode == 4, "expected NTP server mode, received mode {mode}");
    ensure!(
        response[24..32] == request[40..48],
        "response does not match this request"
    );

    let stratum = response[1];
    ensure!(stratum <= 16, "invalid NTP stratum {stratum}");
    let reference_id = String::from_utf8_lossy(&response[12..16])
        .trim()
        .to_string();
    let seconds = u32::from_be_bytes(response[40..44].try_into().unwrap());
    let fraction = u32::from_be_bytes(response[44..48].try_into().unwrap());
    let server_time = if seconds == 0 && fraction == 0 {
        None
    } else {
        let unix_seconds = i64::from(seconds) - NTP_UNIX_EPOCH_OFFSET as i64;
        let nanoseconds = ((u64::from(fraction) * 1_000_000_000) >> 32) as u32;
        DateTime::from_timestamp(unix_seconds, nanoseconds)
    };

    Ok(ParsedNtpResponse {
        leap_indicator,
        stratum,
        reference_id,
        server_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[test]
    fn request_is_ntpv4_client_packet_with_transmit_timestamp() {
        let request = make_request(SystemTime::now()).unwrap();

        assert_eq!(request.len(), NTP_PACKET_LEN);
        assert_eq!(request[0], 0x23);
        assert_ne!(&request[40..48], &[0; 8]);
    }

    #[test]
    fn parses_a_matching_ntp_server_response() {
        let request = make_request(SystemTime::now()).unwrap();
        let mut response = [0; NTP_PACKET_LEN];
        response[0] = 0x24;
        response[1] = 2;
        response[12..16].copy_from_slice(b"LOCL");
        response[24..32].copy_from_slice(&request[40..48]);
        response[40..48].copy_from_slice(&request[40..48]);

        let parsed = parse_response(&response, &request).unwrap();
        assert_eq!(parsed.stratum, 2);
        assert_eq!(parsed.reference_id, "LOCL");
        assert!(parsed.server_time.is_some());
    }

    #[test]
    fn rejects_a_response_for_another_request() {
        let request = make_request(SystemTime::now()).unwrap();
        let mut response = [0; NTP_PACKET_LEN];
        response[0] = 0x24;
        response[24..32].copy_from_slice(&[1; 8]);

        assert!(parse_response(&response, &request).is_err());
    }

    #[tokio::test]
    async fn probes_a_local_ntp_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap().to_string();
        let server_port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut request = [0; 512];
            let (len, peer) = server.recv_from(&mut request).await.unwrap();
            let mut response = [0; NTP_PACKET_LEN];
            response[0] = 0x24;
            response[1] = 2;
            response[24..32].copy_from_slice(&request[40..48]);
            let server_time = make_request(SystemTime::now()).unwrap();
            response[40..48].copy_from_slice(&server_time[40..48]);
            assert!(len >= NTP_PACKET_LEN);
            server.send_to(&response, peer).await.unwrap();
        });

        let result = probe_ntp(&target, None, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.stratum, 2);
        assert_eq!(result.peer, target);
        assert!(result.via_proxy.is_none());
        assert_ne!(server_port, 53);
    }

    #[test]
    fn parses_socks5_proxy_urls_and_bare_addresses() {
        assert_eq!(
            parse_socks5_proxy("127.0.0.1:1080").unwrap().addr,
            "127.0.0.1:1080".parse().unwrap()
        );
        assert_eq!(
            parse_socks5_proxy("socks5://user:pass@127.0.0.1:1080")
                .unwrap()
                .addr,
            "127.0.0.1:1080".parse().unwrap()
        );
    }

    #[test]
    fn parses_domain_and_ipv6_ntp_targets() {
        assert_eq!(
            parse_target_address("time.cloudflare.com:123").unwrap(),
            WireAddress::DomainAddress("time.cloudflare.com".to_owned(), 123)
        );
        assert_eq!(
            parse_target_address("[2001:db8::1]:123").unwrap(),
            WireAddress::SocketAddress("[2001:db8::1]:123".parse().unwrap())
        );
    }

    fn make_stun_response(transaction_id: [u8; 12], mapped_address: SocketAddr) -> Vec<u8> {
        let (family, address_bytes) = match mapped_address.ip() {
            std::net::IpAddr::V4(ip) => (0x01, ip.octets().to_vec()),
            std::net::IpAddr::V6(ip) => (0x02, ip.octets().to_vec()),
        };
        let mut response = vec![0; STUN_HEADER_LEN + 8 + address_bytes.len()];
        response[0..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&((8 + address_bytes.len()) as u16).to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&((4 + address_bytes.len()) as u16).to_be_bytes());
        response[25] = family;
        response[26..28].copy_from_slice(
            &(mapped_address.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
        );
        for (index, byte) in address_bytes.into_iter().enumerate() {
            let mask = if index < 4 {
                STUN_MAGIC_COOKIE.to_be_bytes()[index]
            } else {
                transaction_id[index - 4]
            };
            response[28 + index] = byte ^ mask;
        }
        response
    }

    #[test]
    fn parses_stun_xor_mapped_ipv4_and_ipv6_addresses() {
        let transaction_id = [7; 12];
        for address in [
            "203.0.113.9:45678".parse().unwrap(),
            "[2001:db8::1234]:45678".parse().unwrap(),
        ] {
            let response = make_stun_response(transaction_id, address);
            assert_eq!(
                parse_stun_response(&response, &transaction_id).unwrap(),
                address
            );
        }
    }

    #[test]
    fn rejects_stun_response_for_another_transaction() {
        let transaction_id = [7; 12];
        let response = make_stun_response(transaction_id, "203.0.113.9:45678".parse().unwrap());

        assert!(parse_stun_response(&response, &[8; 12]).is_err());
    }

    #[tokio::test]
    async fn probes_a_local_stun_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap().to_string();
        let mapped_address = "203.0.113.9:45678".parse().unwrap();

        tokio::spawn(async move {
            let mut request = [0; 512];
            let (len, peer) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(len, STUN_HEADER_LEN);
            assert_eq!(
                u16::from_be_bytes(request[0..2].try_into().unwrap()),
                STUN_BINDING_REQUEST
            );
            assert_eq!(
                u32::from_be_bytes(request[4..8].try_into().unwrap()),
                STUN_MAGIC_COOKIE
            );
            let transaction_id = request[8..20].try_into().unwrap();
            let response = make_stun_response(transaction_id, mapped_address);
            server.send_to(&response, peer).await.unwrap();
        });

        let result = probe_stun(&target, None, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.mapped_address, mapped_address);
        assert!(result.via_proxy.is_none());
    }
}
