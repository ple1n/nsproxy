

## nsproxy diagnostics (`diag`)

Communication protocol and EGUI viewer for real-time performance diagnostics of nsproxy's TUN proxy.

### Architecture

- **tun2socks5** creates a UNIX domain socket listener at `/nsp3/{instance}/tun_diag.sock`
- The EGUI viewer (`nsp-diag`) connects to this socket to display a rolling log of events
- The wire protocol is **newline-delimited JSON** (`DiagEvent` per line)
- The socket path is passed from nsproxy's `::Make` command via the `--diag-sock` argument on `IArgs`

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