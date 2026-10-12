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
}
