# `sp` command manual

Agent-facing reference for the `sp` executable in this repository.

## Invocation rules

- Run `sp --help` against the checked-out/build-selected binary before relying on a command not listed here; the CLI is evolving.
- Global options precede the command: `-c, --conf <PATH>` selects configuration, `--state <PATH>` selects the persistent state root (default `/nsp3`; `--root` remains an alias), and `-n, --no-wrap-check` disables wrapper checks.
- Profile names resolve under `<root>/config/<profile>`. A profile normally has `profile.json`, `hot.json`, namespace metadata, and runtime files.
- Commands that change namespaces, mounts, veths, daemon state, or global state may require the privileged wrapper. The binary reports `sudo check disabled` in this development environment; do not infer that an operation succeeded from that line alone.
- Use `--help` on any command for the authoritative syntax. Do not invent `status` or `diag` subcommands; runtime diagnostics are exposed through profile state, `enter`, and the diagnostic/UI paths.
- Preserve unrelated dirty work. After source edits, validate with `./build-ui.sh` (or `./build-ui.sh --release` when release behavior matters).

## Common agent workflows

### Inspect a running profile

```fish
sp enter <profile> -s sh
sp id
cat /nsp3/config/<profile>/ns_alive.json
cat /nsp3/config/<profile>/veth_status.json
```

`sp enter` takes the profile/path as its positional target. Use `-s`, `--cwd`, `--uid`, `--gid`, `--gids`, and `--args` to control the entered process. A Pivot profile must have its sandbox applied before sandboxed entry can work.

### Start and attach a profile

```fish
sp up <profile>
sp veth --src <profile> --dst <peer> --src-ip4 <address> --dst-ip4 <address>
sp serve --profile <profile>
sp sandbox <profile>
```

`up` creates and persists namespaces. `serve` attaches the TUN/router to an already-up profile. `veth` uses namespace endpoints `this`, `default`, or a profile name; with fixed addresses, both `--src-ip4` and `--dst-ip4` must be supplied together. `sandbox` applies the profile's Pivot root and template mounts.

### Stop or reset

```fish
sp down <profile>
sp down --rm <profile>
sp clean
sp clean --veth
```

`down` tears down the keeper and namespace bind mount. `--rm` also removes profile config/runtime directories. `clean --veth` performs the default veth cleanup; inspect state before using removal commands.

### Trace hot configuration

```fish
cat /nsp3/config/<profile>/hot.json
sp enter <profile> -s sh --args -c 'cat /etc/resolv.conf'
```

`hot.json` owns `dns`, `tun`, `devs`, `mnt`/`mounts`, `locals`, `dns_capture`, `resolv_conf_dns`, `default_route`, `route_map`, `daemons`, `applications`, and `veth`. Empty `dns_capture` means capture all DNS source IPs; a disabled sentinel captures none. A `dns` entry maps a name directly to an IPv4 address and is pinned into Virtual DNS. Synthesized A/AAAA answers for virtual domains have a 300-second DNS TTL; their in-process address mappings remain subject to the virtual-DNS LRU capacity. A `tun` entry routes through TUN or a file server. Hot changes are watched and applied to the running serve process; invalid JSON is rejected and does not replace the active config.

### Route-map transfer

`sp route` imports and exports a `RoutePrefs` document containing `default_route` and a `route_map` array of concrete per-host/IP decisions. The map uses the same key/decision representation as `hot.json`; it does not contain symbolic names or proxy bindings.

```fish
sp route routes.json --apply-to <PROFILE>
sp route routes.json --apply-to <PROFILE> --replace
sp route export <PROFILE> routes.json
sp route routes.json --make-container <NAME> [--template <TEMPLATE>] [--destroy] -- <COMMAND> [ARGS...]
```

Apply merges entries by key; `--replace` clears the profile's route map first. Export refuses to overwrite an existing file unless `--force` is supplied; a directory destination receives `<PROFILE>.json`. `--make-container` creates and starts a profile with the imported map, then runs the command inside it. The new profile remains running by default; `--destroy` removes it when the command exits. Use `--help` for the current option details.

For a mapping issue, check in this order: the JSON parses as `HotConfig`; `resolv_conf_dns` inside the profile points at the intended DNS server; `dns_capture` includes the query source; `veth_status.json` says `success: true`; the target address is reachable from the profile namespace; and the serve process was running when the change was applied. The internal IPv4-only DNS forwarder preserves AAAA questions and removes AAAA records from responses, yielding a valid no-data response instead of `FORMERR`. `sp enter` is the supported namespace check.

## Command reference

### Global and utility commands

- `sp enter [OPTIONS] <TARGET>`: enter an existing profile namespace. Options: `-u/--uid`, `-g/--gid`, `-s/--shell`, `--cwd`, `--gids`, `--args`.
- `sp temp [OPTIONS] <COMMAND> [ARGS]`: create an Overlay profile named from a filesystem-safe command prefix (up to five characters) and a four-character URL-safe Base64 prefix of the current timestamp's BLAKE3 digest in the normal state root and namespace registry (so it is visible in the UI while running). It runs with `sp enter`-style options, then tears down and removes the profile and its config when it exits. Put options before the command, e.g. `sp temp -u 0 fish`.
- `sp install [DIR]`: install binaries/scripts into `DIR` (default `./install`).
- `sp completions --fish`: install fish completions under `~/.config/fish/completions`.
- `sp rm <PATH> [-r|--recurse]`: unmount a bind-mount target. With `-r` / `--recurse`, detach mounts and recursively remove the directory tree without following symlinks.
- `sp clean [--veth]`: clean runtime state; `--veth` also removes the default veth.
- `sp netlink`: print all IPv4 addresses through the netlink test path.
- `sp udp [HOST:PORT] [--socks5 HOST:PORT|URL] [--timeout-secs SECONDS]`: test UDP connectivity with an NTP request. Defaults to `time.cloudflare.com:123`; `--socks5` accepts a proxy address or a `socks5://[user:pass@]host:port` URL. Run it inside the target container to test that container's network namespace.
- `sp gen <SAVE_TO>`: generate an empty config file.
- `sp init`: record the current process namespaces as the basis namespace set.
- `sp --state <SOURCE> migrate --to <TARGET>`: stage a separate state root using top-level symlinks, preserving the source until finalization. Unix socket files are excluded. `--rm` removes an existing target through recursive unmount/removal, then stages the migration there. `--finish` removes staged links, moves source entries into the target without traversing nested symlinks, and moves legacy `<state-root>/rootfs` to global `/rootfs`. It can be combined with `--to` to stage and finalize in one operation, or run on an existing staged target. Migration and target removal check the selected root's WAL and prompt before stopping attributable active nsproxy processes.
- `sp --state <ROOT> meta processes|kill <PID>`: inspect or interactively terminate processes verified against the append-only process WAL.
- `sp id [PID]`: identify the current net namespace, or the namespace associated with `PID`.
- `sp state-tree`: print the typed persistent-state blueprint.
- `sp version`: print build identity, including source-tree BLAKE3 and build epoch.

### Network and process commands

- `sp socks5 serve <PORT> [--test-servers]`: serve the no-auth SOCKS5 proxy for escaping a container. By default it starts only the proxy; `--test-servers` additionally starts loopback TCP and UDP echo servers sharing an ephemeral port, printed at startup. Use that address with `sp socks check`'s `--connect` and `--udp-echo-target` options.
- `sp socks check <HOST:PORT>`: probe SOCKS5 authentication negotiation. Add `--connect HOST:PORT` (repeatable) to test CONNECT, `--bind` to test the two-reply BIND exchange and TCP relay, and `--udp-echo-target HOST:PORT` to test UDP ASSOCIATE against an explicit UDP echo service. `--username` and `--password` enable RFC 1929 authentication checks; `--timeout-secs` controls each network operation. Traffic tests are opt-in and only contact the proxy and endpoints named on the command line.
- `sp curl [-p/--proxy <ADDRESS>] <URL>`: issue one HTTP request, optionally through a SOCKS5 proxy.
- `sp forward <SRC> <DST>`: create a TCP forward from `SRC` to `DST`.
- `sp sudo [OPTIONS]`: execute a command with nsproxy's sudo-style environment while preserving Wayland-related context. Options: `-u/--uid`, `-g/--gid`, `-s/--shell`, `--cwd`, `--gids`, `--args`.
- `sp file <PATH>`: accept command arguments from a serialized file.

### Profile lifecycle

- `sp template [--reset] [--update] <PATH> [NAME]`: create a profile from a template. Name defaults to the template filename stem. `--reset` recreates an existing profile; `--update` updates its config without recreating directories.
- `sp clone <NAME> <FROM>`: clone an existing profile into a new profile directory.
- `sp up [OPTIONS] <PROFILE>`: create/persist the profile namespaces and keeper. Development protocol-test options are `--cmd <JSON>`, `--simulate-protocol-no-upgrade`, `--simulate-conn-close`, and `--simulate-slow-shutdown`; use them only for targeted tests.
- `sp down [--rm] <PROFILE>`: tear down the profile; `--rm` also removes config/runtime directories.
- `sp serve --profile <PROFILE> [OPTIONS]`: attach TUN/router to an up profile. Options: `--tun-name`, `--simple <NYM>`, `-n/--no-default`, `-l/--log <PATH>`, `--no-dns-capture [true|false]`, and `--internal-dns-server [true|false]`.
- `sp sandbox <PROFILE>`: enter the existing profile namespace and apply its Pivot-root sandbox/template mounts.
- `sp dbus --profile <PROFILE>`: run the private D-Bus daemon for an up profile.
- `sp veth --src <SRC> --dst <DST> [OPTIONS]`: create a veth pair between up namespaces. Options: `--veth-name`, `--src-ip4`, `--dst-ip4`, `--prefix-len` (default `30`), and `-l/--log`.

### Basis namespace

- `sp basis mount`: mount the recorded basis network namespace.
- `sp basis enter [OPTIONS]`: enter it. Supports the same command-selection options as `sp enter`: `-u/--uid`, `-g/--gid`, `-s/--shell`, `--cwd`, `--gids`, and `--args`.

### Uplink and DNS state

- `sp uplink stats`: show uplink statistics.
- `sp uplink remote add <URL>`: add a remote proxy, such as `socks5://127.0.0.1:1080`.
- `sp uplink remote remove <NYM>`: remove a saved remote proxy by nym.
- `sp uplink remote list`: list saved remote proxies.
- `sp uplink instance <NAME> test`: test a named uplink instance.
- `sp uplink geph`: enter the Geph uplink operation path; it currently has no additional CLI arguments.
- `sp uplink export <PATH>`: export all uplink hub state.
- `sp uplink import <PATH>`: import a prior uplink hub snapshot.
- `sp uplink dns-backup <PATH>`: export only the DNS backup cache.
- `sp uplink dns-import <PATH>`: import a DNS backup cache.

#### Clash operations

- `sp uplink clash config-add <GROUP_ID> <PATH>`: create a new user-owned group from a Clash YAML config; it fails if the group already exists.
- `sp uplink clash config-replace <GROUP_ID> <PATH>`: replace all imported data in an existing group from a Clash YAML config.
- `sp uplink clash list`: show imported groups and cached proxy status.
- `sp uplink clash config-explain <PATH>`: explain the two-tier DNS bootstrap for a Clash config.
- `sp uplink clash resolve [--direct] [--refresh] [--backup <PATH>]`: resolve proxies without known IPs; optionally force direct resolution, refresh state, or preload a DNS backup.
- `sp uplink clash test-resolve [--direct] <QUERY>`: test one host's DNS resolution.

## State and ownership map

- Persistent root: `/nsp3` by default; override per invocation with `--root`.
- Profile config: `/nsp3/config/<profile>/profile.json` and `hot.json`.
- Namespace metadata: `ns_alive.json`; veth results: `veth_status.json`; sandbox identity/status: `sandbox_status.json`.
- Runtime ownership: `up` creates/keeps namespaces; `serve` owns TUN, Virtual DNS, routing, and hot reload; `sandbox` owns Pivot-root setup and hot mount watching; `veth` reconciles profile network links.
- Use `agentic/runtime-state.md` for implementation ownership and `agentic/ipc-diagnostics.md` for daemon/socket/reconnection diagnostics. Use `agentic/terminal.md` for PTY and external terminal behavior.
