

## nsproxy diagnostics (`diag`)

Communication protocol and EGUI viewer for real-time performance diagnostics of nsproxy's TUN proxy.

### Architecture

- **sp serve** creates a UNIX domain socket listener at `/nsp3/{instance}/tun_diag.sock`
- The EGUI viewer connects to this socket for live diagnostics. Its wire protocol is length-prefixed bincode.
- `sp serve` also exposes an HTTP/JSON history API inside the profile network namespace. It binds to `0.0.0.0:17890` by default, with no authentication; configure network access accordingly.

### History API

Timestamps are Unix-epoch microseconds. The API only queries in-memory history; when a requested range has been evicted, it returns HTTP `410 Gone` and directs the caller to persisted files if configured.

```text
GET /v1/logs?from_us=<inclusive>&to_us=<inclusive>
GET /v1/virtual-ips/<ip>?at_us=<timestamp>
GET /v1/connections?age_seconds=<window>[&ip=<address>]
GET /v1/stream
```

The log endpoint is paginated (`limit`, up to 5000, and `offset`) and returns entries in timestamp order. `/v1/history` reports current usage and separate oldest-available timestamps for logs, mappings, and connection activity. `/v1/stream` is a server-sent event stream for live logs and connection activity.

The web console accepts `from` and `to` URL parameters as RFC 3339 timestamps, including fractional seconds up to microsecond precision (for example, `/?from=2026-10-12T14%3A51%3A27.194387Z&to=2026-10-12T15%3A51%3A27.194387Z`). It also accepts `from_us` and `to_us` as Unix microseconds. Running a query updates the URL without reloading the page; browser back and forward restore earlier ranges.

The mapping response gives the domain and its validity interval (`valid_from` inclusive, `valid_until` exclusive; `null` means the mapping is still active). `404 Not Found` means no mapping existed at that time. The connections endpoint returns a `connections` array and coverage metadata; `history_partial` indicates that the requested age window begins before retained activity history. Individual records with `history_incomplete: true` are missing their original accept event. The endpoint includes active connections and completed TCP/UDP activity within the selected age window; the optional IP filter powers the log inspector.

Logs, virtual-IP mappings, and connection activity share one approximate storage budget, **64 MiB** by default. Set it with `sp serve --history-max-bytes`; set the listener using `sp serve --history-listen <address:port>`.

Example:

```sh
curl 'http://<profile-ip>:17890/v1/logs?from_us=...&to_us=...'
curl 'http://<profile-ip>:17890/v1/virtual-ips/198.18.0.5?at_us=...'
curl 'http://<profile-ip>:17890/v1/connections?age_seconds=3600'
```

### Tracked events

| Event | Description |
|---|---|
| `Accept` | New TCP/UDP stream accepted from `ip_stack.accept()` |
| `Route` | Routing decision: Proxied, NAT, Direct, DNS, FileServe |
| `Connected` | Proxy/remote connection established |
| `Finished` | Connection completed (with optional error, byte counts) |
| `LoopTick` | Main loop iteration timing (accept latency in µs) |
| `DnsResolved` | VirtDNS resolution result |

### Building the viewer

```sh
cargo build -p diag --features egui-client --bin nsp-diag
```

### Running

```sh
nsp-diag <instance-name>
# e.g. nsp-diag myprofile
```