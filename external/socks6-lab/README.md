# SOCKS6 Lab

`socks6-lab` is a standalone CLI and reusable Rust harness for exercising
proxy implementations. Its test runner depends on the `ProxyAdapter` interface;
protocol-specific handshake and stream behavior live in adapters. The initial
adapter supports SOCKS6 over TCP or a Unix socket.

Build or run it with Nix:

```sh
nix build .#socks6-lab
nix run .#socks6-lab -- --help
```

Or run it from this directory with Cargo:

```sh
cargo run --manifest-path external/socks6-lab/Cargo.toml -- --help
```

## Roles

- **Proxy:** the intermediary being exercised. Pass its address with
  `--proxy`; it defaults to `tcp://127.0.0.1:1086`, the local proxy fixture.
- **Requester:** this tool's `probe`, `client`, `bench`, and `suite` commands.
- **Responder:** the destination test service. Pass its address with
  `--responder` (or protocol-specific responder flags in `suite`); both default
  to `127.0.0.1:19090`, the local TCP/UDP responder.

## Manual checks

Optionally start the local SOCKS6 proxy fixture with the direct-socket backend.
It binds to loopback by default and has no authentication; non-loopback binds
should only be used on a network you control:

```sh
nix run .#socks6-lab -- proxy
```

The built-in proxy can simulate a delayed connection attempt and emit a
progress update before it opens the target stream:

```sh
nix run .#socks6-lab -- proxy --connect-delay-ms 250
```

The proxy accepts TCP requesters on `127.0.0.1:1086`. To also accept requesters
over a Unix socket:

```sh
nix run .#socks6-lab -- proxy --unix /tmp/socks6-lab.socks6
```

Start the TCP and UDP test responders on the same address and port (default
`127.0.0.1:19090`):

```sh
nix run .#socks6-lab -- responder
```

Choose a different shared bind address with `--address`, for example
`--address 127.0.0.1:20000`.

Probe a proxy's capabilities, status, and ping:

```sh
nix run .#socks6-lab -- probe --proxy tcp://127.0.0.1:1086
nix run .#socks6-lab -- probe --proxy unix:///run/example-socks6/proxy.socks6
```

The `client` requester sends one TCP or UDP request through the proxy to the
corresponding responder:

```sh
nix run .#socks6-lab -- client \
  --proxy tcp://127.0.0.1:1086 \
  --responder 127.0.0.1:19090 \
  --protocol tcp
```

Run a stream transfer benchmark through a proxy to a TCP responder:

```sh
nix run .#socks6-lab -- bench --size 1GiB --parallelism 4
```

That uses the local proxy and responder defaults. Specify either address to
override it, for example:

```sh
nix run .#socks6-lab -- bench \
  --proxy unix:///run/example-socks6/proxy.socks6 \
  --responder 127.0.0.1:19090 \
  --size 1GiB \
  --parallelism 4
```

Sizes accept bytes or `KiB`, `MiB`, and `GiB` units. Payloads are generated and
verified incrementally, so large tests use bounded memory. Benchmarks report
payload goodput (not the extra echoed return traffic), elapsed time, and
per-stream timings. Combined payload is capped at 16 GiB per benchmark.

## Feature suite

Run the interactive suite against the local proxy and responder defaults:

```sh
nix run .#socks6-lab -- suite
```

The suite checks capability negotiation, service status, ping, TCP and UDP
echo, configured stream sizes, and parallel TCP streams. In a terminal it
shows a live checklist; in non-interactive use it prints progress. `--json`
emits machine-readable results. The proxy and responder addresses can be
overridden with `--proxy`, `--tcp-responder`, and `--udp-responder`.

To require a connection-progress update before stream readiness, enable
`--expect-connect-progress`. This is intended for a proxy that reports progress
for pending connections; the lab fixture can generate a deterministic delayed
attempt with `proxy --connect-delay-ms 250`:

```sh
nix run .#socks6-lab -- suite --expect-connect-progress
```

The check opens a stream to the TCP responder and fails if the proxy returns
ready without first reporting progress.

SOCKS6 proxies advertise identity offers with independent send/receive
capabilities. Requesters may use a leased identity, request an offered
identity, or let the proxy choose. The suite uses a proxy-selected identity.
Its stream/datagram checks exercise reliable-stream and unreliable-datagram
semantics; those names do not constrain the underlying proxy transport.

The default size sweep is `1KiB,64KiB,1MiB` and the parallelism sweep is `1,4`.
Use `--sizes` and `--parallelism` to change those lists. Large transfers are
opt-in, for example `--sizes 1KiB,1MiB,1GiB`.

`curl --socks5-hostname` speaks SOCKS5, not SOCKS6, so it cannot directly test
a SOCKS6 endpoint. Use `probe` for negotiation/status/ping, `client` for a
single TCP or UDP echo request, and `suite` for the integrated TCP/UDP and
parallel-stream checks. A curl-based HTTP check would need a SOCKS5-to-SOCKS6
bridge; it would test that bridge as well as the endpoint.

The proxy and responder commands bind to loopback by default. Keep large or
parallel runs scoped to systems where you have permission to generate traffic.

## Lokinet checks

Check a reachable Lokinet service through the daemon's SOCKS6 socket:

```sh
nix run .#socks6-lab -- lokinet tcp \
  --target peer.loki:443
nix run .#socks6-lab -- lokinet http \
  --url https://service.loki/
```

By default, both commands use the same socket path as `lokinet-socks6d`:
`$XDG_RUNTIME_DIR/lokinet-socks6/lokinet.socks6`, or
`$XDG_DATA_HOME/lokinet-socks6/run/lokinet.socks6` when no absolute runtime
directory is set. `XDG_DATA_HOME` defaults to `$HOME/.local/share`. Override
the socket with `--proxy` when the daemon uses custom paths.

The TCP check confirms that a stream can be opened to the target. The HTTP
check sends a GET request and reports the HTTP status; HTTPS certificates are
verified against bundled Mozilla WebPKI roots. Targets must actually serve TCP
or HTTP(S), respectively. Use a `.loki` or `.snode` name for an overlay
service, or an IPv4/IPv6 literal for IP egress. Ordinary DNS hostnames are
unsupported, even with an exit provider configured. Public-IP egress requires
a configured Lokinet exit provider.
These checks use SOCKS6 directly; `curl --socks5-hostname` is SOCKS5 and is not
a direct test of the SOCKS6 endpoint.
