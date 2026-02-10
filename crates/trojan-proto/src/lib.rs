//! Trojan protocol parsing and serialization.
//!
//! This module provides zero-copy parsers for trojan request headers and UDP packets.
//! It is intentionally minimal and DRY: address parsing is shared by request and UDP paths.

use bytes::BytesMut;

pub const HASH_LEN: usize = 56;
pub const CRLF: &[u8; 2] = b"\r\n";

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
/// Mux command for trojan-go multiplexing extension.
pub const CMD_MUX: u8 = 0x7f;

/// Maximum UDP payload size (8 KiB, consistent with trojan-go).
pub const MAX_UDP_PAYLOAD: usize = 8 * 1024;
/// Maximum domain name length.
pub const MAX_DOMAIN_LEN: usize = 255;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidCrlf,
    InvalidCommand,
    InvalidAtyp,
    InvalidDomainLen,
    InvalidUtf8,
    /// Hash contains non-hex characters (expected lowercase a-f, 0-9).
    InvalidHashFormat,
}

/// Errors that can occur when writing protocol data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// Payload exceeds maximum allowed size (65535 bytes for UDP).
    PayloadTooLarge,
    /// Domain name exceeds maximum length (255 bytes).
    DomainTooLong,
    /// Hash must be exactly 56 bytes.
    InvalidHashLen,
}

/// Parse result for incremental parsing.
///
/// - `Complete(T)` - parsing succeeded, contains the parsed value.
/// - `Incomplete(n)` - buffer too small; `n` is the **minimum total bytes** needed
///   (not the additional bytes needed). Caller should accumulate more data and retry.
/// - `Invalid(e)` - protocol violation, connection should be rejected or redirected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult<T> {
    Complete(T),
    Incomplete(usize),
    Invalid(ParseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRef<'a> {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRef<'a> {
    pub host: HostRef<'a>,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRequest<'a> {
    pub hash: &'a [u8],
    pub command: u8,
    pub address: AddressRef<'a>,
    pub header_len: usize,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    pub address: AddressRef<'a>,
    pub length: usize,
    pub packet_len: usize,
    pub payload: &'a [u8],
}

/// Validates that the hash is a valid hex string (a-f, A-F, 0-9).
#[inline]
pub fn is_valid_hash(hash: &[u8]) -> bool {
    hash.len() == HASH_LEN && hash.iter().all(|&b| b.is_ascii_hexdigit())
}

#[inline]
pub fn parse_request(buf: &[u8]) -> ParseResult<TrojanRequest<'_>> {
    if buf.len() < HASH_LEN {
        return ParseResult::Incomplete(HASH_LEN);
    }

    let hash = &buf[..HASH_LEN];
    if !is_valid_hash(hash) {
        return ParseResult::Invalid(ParseError::InvalidHashFormat);
    }
    let mut offset = HASH_LEN;

    if let Some(res) = expect_crlf(buf, offset) {
        return res;
    }
    offset += 2;

    if buf.len() < offset + 2 {
        return ParseResult::Incomplete(offset + 2);
    }
    let command = buf[offset];
    if command != CMD_CONNECT && command != CMD_UDP_ASSOCIATE {
        return ParseResult::Invalid(ParseError::InvalidCommand);
    }
    let atyp = buf[offset + 1];
    offset += 2;

    let addr_res = parse_address(atyp, &buf[offset..]);
    let (address, addr_len) = match addr_res {
        ParseResult::Complete(v) => v,
        ParseResult::Incomplete(n) => return ParseResult::Incomplete(offset + n),
        ParseResult::Invalid(e) => return ParseResult::Invalid(e),
    };
    offset += addr_len;

    if let Some(res) = expect_crlf(buf, offset) {
        return res;
    }
    offset += 2;

    ParseResult::Complete(TrojanRequest {
        hash,
        command,
        address,
        header_len: offset,
        payload: &buf[offset..],
    })
}

#[inline]
pub fn parse_udp_packet(buf: &[u8]) -> ParseResult<UdpPacket<'_>> {
    if buf.is_empty() {
        return ParseResult::Incomplete(1);
    }
    let atyp = buf[0];
    let addr_res = parse_address(atyp, &buf[1..]);
    let (address, addr_len) = match addr_res {
        ParseResult::Complete(v) => v,
        ParseResult::Incomplete(n) => return ParseResult::Incomplete(1 + n),
        ParseResult::Invalid(e) => return ParseResult::Invalid(e),
    };

    let mut offset = 1 + addr_len;
    if buf.len() < offset + 2 {
        return ParseResult::Incomplete(offset + 2);
    }
    let length = read_u16(&buf[offset..offset + 2]) as usize;
    if buf.len() < offset + 4 {
        return ParseResult::Incomplete(offset + 4);
    }
    if &buf[offset + 2..offset + 4] != CRLF {
        return ParseResult::Invalid(ParseError::InvalidCrlf);
    }
    offset += 4;
    if buf.len() < offset + length {
        return ParseResult::Incomplete(offset + length);
    }

    ParseResult::Complete(UdpPacket {
        address,
        length,
        packet_len: offset + length,
        payload: &buf[offset..offset + length],
    })
}

/// Writes a Trojan request header to the buffer.
///
/// # Errors
/// - `InvalidHashLen` if hash is not exactly 56 bytes.
/// - `DomainTooLong` if address contains a domain longer than 255 bytes.
pub fn write_request_header(
    buf: &mut BytesMut,
    hash_hex: &[u8],
    command: u8,
    address: &AddressRef<'_>,
) -> Result<(), WriteError> {
    if hash_hex.len() != HASH_LEN {
        return Err(WriteError::InvalidHashLen);
    }
    if let HostRef::Domain(d) = &address.host
        && d.len() > MAX_DOMAIN_LEN
    {
        return Err(WriteError::DomainTooLong);
    }
    buf.extend_from_slice(hash_hex);
    buf.extend_from_slice(CRLF);
    buf.extend_from_slice(&[command, address_atyp(address)]);
    write_address_unchecked(buf, address);
    buf.extend_from_slice(CRLF);
    Ok(())
}

/// Writes a UDP packet to the buffer.
///
/// # Errors
/// - `PayloadTooLarge` if payload exceeds 65535 bytes.
/// - `DomainTooLong` if address contains a domain longer than 255 bytes.
pub fn write_udp_packet(
    buf: &mut BytesMut,
    address: &AddressRef<'_>,
    payload: &[u8],
) -> Result<(), WriteError> {
    if payload.len() > u16::MAX as usize {
        return Err(WriteError::PayloadTooLarge);
    }
    if let HostRef::Domain(d) = &address.host
        && d.len() > MAX_DOMAIN_LEN
    {
        return Err(WriteError::DomainTooLong);
    }
    buf.extend_from_slice(&[address_atyp(address)]);
    write_address_unchecked(buf, address);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(CRLF);
    buf.extend_from_slice(payload);
    Ok(())
}

#[inline]
fn expect_crlf<T>(buf: &[u8], offset: usize) -> Option<ParseResult<T>> {
    if buf.len() < offset + 2 {
        return Some(ParseResult::Incomplete(offset + 2));
    }
    if &buf[offset..offset + 2] != CRLF {
        return Some(ParseResult::Invalid(ParseError::InvalidCrlf));
    }
    None
}

#[inline]
fn parse_address<'a>(atyp: u8, buf: &'a [u8]) -> ParseResult<(AddressRef<'a>, usize)> {
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 6 {
                return ParseResult::Incomplete(6);
            }
            let host = HostRef::Ipv4([buf[0], buf[1], buf[2], buf[3]]);
            let port = read_u16(&buf[4..6]);
            ParseResult::Complete((AddressRef { host, port }, 6))
        }
        ATYP_DOMAIN => {
            if buf.is_empty() {
                return ParseResult::Incomplete(1);
            }
            let len = buf[0] as usize;
            if len == 0 {
                return ParseResult::Invalid(ParseError::InvalidDomainLen);
            }
            let need = 1 + len + 2;
            if buf.len() < need {
                return ParseResult::Incomplete(need);
            }
            let domain = &buf[1..1 + len];
            if std::str::from_utf8(domain).is_err() {
                return ParseResult::Invalid(ParseError::InvalidUtf8);
            }
            let port = read_u16(&buf[1 + len..1 + len + 2]);
            ParseResult::Complete((
                AddressRef {
                    host: HostRef::Domain(domain),
                    port,
                },
                need,
            ))
        }
        ATYP_IPV6 => {
            if buf.len() < 18 {
                return ParseResult::Incomplete(18);
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[0..16]);
            let port = read_u16(&buf[16..18]);
            ParseResult::Complete((
                AddressRef {
                    host: HostRef::Ipv6(ip),
                    port,
                },
                18,
            ))
        }
        _ => ParseResult::Invalid(ParseError::InvalidAtyp),
    }
}

/// Writes address without validation. Caller must ensure domain length <= 255.
fn write_address_unchecked(buf: &mut BytesMut, address: &AddressRef<'_>) {
    match address.host {
        HostRef::Ipv4(ip) => {
            buf.extend_from_slice(&ip);
        }
        HostRef::Ipv6(ip) => {
            buf.extend_from_slice(&ip);
        }
        HostRef::Domain(domain) => {
            debug_assert!(domain.len() <= MAX_DOMAIN_LEN);
            buf.extend_from_slice(&[domain.len() as u8]);
            buf.extend_from_slice(domain);
        }
    }
    buf.extend_from_slice(&address.port.to_be_bytes());
}

#[inline]
fn address_atyp(address: &AddressRef<'_>) -> u8 {
    match address.host {
        HostRef::Ipv4(_) => ATYP_IPV4,
        HostRef::Ipv6(_) => ATYP_IPV6,
        HostRef::Domain(_) => ATYP_DOMAIN,
    }
}

#[inline]
fn read_u16(buf: &[u8]) -> u16 {
    debug_assert!(buf.len() >= 2, "read_u16 requires at least 2 bytes");
    u16::from_be_bytes([buf[0], buf[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash() -> [u8; HASH_LEN] {
        [b'a'; HASH_LEN]
    }

    #[test]
    fn test_is_valid_hash() {
        // Valid lowercase hex
        assert!(is_valid_hash(&[b'a'; HASH_LEN]));
        assert!(is_valid_hash(
            b"0123456789abcdef0123456789abcdef0123456789abcdef01234567"
        ));

        // Uppercase should be accepted
        assert!(is_valid_hash(
            b"0123456789ABCDEF0123456789abcdef0123456789abcdef01234567"
        ));

        // Invalid: wrong length
        assert!(!is_valid_hash(&[b'a'; HASH_LEN - 1]));
        assert!(!is_valid_hash(&[b'a'; HASH_LEN + 1]));

        // Invalid: non-hex characters
        let mut invalid = [b'a'; HASH_LEN];
        invalid[0] = b'g';
        assert!(!is_valid_hash(&invalid));
    }

    #[test]
    fn parse_request_connect_ipv4() {
        let addr = AddressRef {
            host: HostRef::Ipv4([1, 2, 3, 4]),
            port: 443,
        };
        let mut buf = BytesMut::new();
        write_request_header(&mut buf, &sample_hash(), CMD_CONNECT, &addr).unwrap();
        buf.extend_from_slice(b"hello");

        let res = parse_request(&buf);
        match res {
            ParseResult::Complete(req) => {
                assert_eq!(req.command, CMD_CONNECT);
                assert_eq!(req.address, addr);
                assert_eq!(req.payload, b"hello");
            }
            _ => panic!("unexpected parse result: {:?}", res),
        }
    }

    #[test]
    fn parse_request_invalid_hash() {
        let addr = AddressRef {
            host: HostRef::Ipv4([1, 2, 3, 4]),
            port: 443,
        };
        let mut buf = BytesMut::new();
        // Use non-hex which is invalid
        let mut invalid_hash = [b'a'; HASH_LEN];
        invalid_hash[0] = b'g';
        write_request_header(&mut buf, &invalid_hash, CMD_CONNECT, &addr).unwrap();

        let res = parse_request(&buf);
        assert_eq!(res, ParseResult::Invalid(ParseError::InvalidHashFormat));
    }

    #[test]
    fn parse_request_incomplete() {
        let data = vec![b'a'; HASH_LEN - 1];
        assert_eq!(parse_request(&data), ParseResult::Incomplete(HASH_LEN));
    }

    #[test]
    fn parse_udp_packet_ipv4() {
        let addr = AddressRef {
            host: HostRef::Ipv4([8, 8, 8, 8]),
            port: 53,
        };
        let mut buf = BytesMut::new();
        write_udp_packet(&mut buf, &addr, b"ping").unwrap();
        let res = parse_udp_packet(&buf);
        match res {
            ParseResult::Complete(pkt) => {
                assert_eq!(pkt.address, addr);
                assert_eq!(pkt.payload, b"ping");
            }
            _ => panic!("unexpected parse result: {:?}", res),
        }
    }

    #[test]
    fn write_udp_packet_payload_too_large() {
        let addr = AddressRef {
            host: HostRef::Ipv4([8, 8, 8, 8]),
            port: 53,
        };
        let mut buf = BytesMut::new();
        let large_payload = vec![0u8; u16::MAX as usize + 1];
        let res = write_udp_packet(&mut buf, &addr, &large_payload);
        assert_eq!(res, Err(WriteError::PayloadTooLarge));
    }

    #[test]
    fn write_request_header_domain_too_long() {
        let long_domain = vec![b'a'; 256];
        let addr = AddressRef {
            host: HostRef::Domain(&long_domain),
            port: 443,
        };
        let mut buf = BytesMut::new();
        let res = write_request_header(&mut buf, &sample_hash(), CMD_CONNECT, &addr);
        assert_eq!(res, Err(WriteError::DomainTooLong));
    }

    #[test]
    fn write_request_header_invalid_hash_len() {
        let addr = AddressRef {
            host: HostRef::Ipv4([1, 2, 3, 4]),
            port: 443,
        };
        let mut buf = BytesMut::new();
        let short_hash = [b'a'; HASH_LEN - 1];
        let res = write_request_header(&mut buf, &short_hash, CMD_CONNECT, &addr);
        assert_eq!(res, Err(WriteError::InvalidHashLen));
    }
}
