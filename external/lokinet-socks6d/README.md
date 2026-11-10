# lokinet-socks6d

`lokinet-socks6d` runs a standalone SOCKS6 endpoint backed by one Lokinet
runtime. It is an ordinary foreground executable: start it when needed and
stop it with Ctrl-C or SIGTERM. It does not start from `sp serve`.

Build it with the repository flake:

```sh
nix build .#lokinet-socks6d
./result/bin/lokinet-socks6d --help
```

The help output shows the resolved default socket, config, and data-directory
paths for the current XDG environment.

Initialize a writable instance without elevated privileges:

```sh
nix run .#lokinet-socks6d -- init --bootstrap-file ./bootstrap.signed
nix run .#lokinet-socks6d
```

`init` creates the config and data directories, configures a persistent
Lokinet address key, and optionally copies a signed bootstrap file to the data
directory. It does not overwrite existing config or bootstrap files. The
bootstrap file is Lokinet's signed router-contact list, not a private key.

By default config and data live under `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
(or their usual locations under `$HOME`); the socket uses `XDG_RUNTIME_DIR`
when available. Override these paths with `--config`, `--data-dir`, and
`--socket`. The data directory must be private because Lokinet stores key
material there. To share the socket with other local accounts, choose a socket
path in a directory they can access; the socket itself is made available to
local users.

Configure nsproxy with the same socket path. Start the daemon before applying
the sandbox to a pivot profile so nsproxy can expose the socket directory.
The daemon offers its Lokinet address as an identity for outbound reliable
streams and datagrams. `.loki`/`.snode` destinations use Lokinet's overlay
stream/datagram APIs. IPv4 and IPv6 literal destinations use an in-memory
packet bridge into Lokinet's existing packet-routing endpoint; this does not
open an OS TUN device or modify host routes. Public IP egress still requires an
exit provider configured in Lokinet; no default exit provider is shipped.
The SOCKS6 backend accepts IPv4/IPv6 literals for IP egress and `.loki` or
`.snode` names for Lokinet overlay streams. It does not resolve ordinary DNS
hostnames such as `example.com`; those requests return an explicit unsupported
target error, even when an exit provider is configured.

Overlay datagram channels expose a reachable
`<lokinet-address>:<port>` endpoint for incoming datagrams. For incoming
reliable streams, the requester selects a nonzero service port; the same
`<lokinet-address>:<port>` must be shared with the peer that will connect.

SOCKS6 stream and datagram operations describe reliable-stream and
unreliable-datagram semantics, respectively; they do not prescribe the
underlying Lokinet or carrier transport.
