# trojan-proto

Zero-copy parser and serializer for the [Trojan protocol](https://trojan-gfw.github.io/trojan/protocol).

## Overview

This crate handles the wire format of the Trojan protocol:

- **Request parsing** — Parse Trojan request headers (command, address, port) from raw bytes
- **UDP packet parsing** — Parse Trojan UDP relay packets with address and payload
- **Serialization** — Write request headers and UDP packets to buffers
- **Hash validation** — Verify SHA-224 password hashes

All parsers are zero-copy, borrowing from the input buffer to avoid allocations.

## Protocol Format

```text
+-----------+-----------+-----+------+----------+
| hash (56) | CRLF (2)  | CMD | ADDR | CRLF (2) |
+-----------+-----------+-----+------+----------+
```

- `hash` — 56-byte hex-encoded SHA-224 of the password
- `CMD` — `0x01` (CONNECT), `0x03` (UDP ASSOCIATE), or `0x7f` (MUX)
- `ADDR` — SOCKS5-style address: IPv4/IPv6/domain + port

## Usage

```rust
use trojan_proto::{parse_request, CMD_CONNECT};

let (request, consumed) = parse_request(buffer)?;
assert_eq!(request.command, CMD_CONNECT);
println!("Target: {}:{}", request.address.host, request.address.port);
```

## License

GPL-3.0-only
