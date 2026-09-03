# `sp` command manual

Agent-facing reference for the `sp` executable in this repository.

## Invocation rules

- Run `sp --help` against the checked-out/build-selected binary before relying on a command not listed here; the CLI is evolving.
- Global options precede the command: `-c, --conf <PATH>` selects configuration, `-r, --root <PATH>` selects the persistent state root (default `/nsp3`), and `-n, --no-wrap-check` disables wrapper checks.
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

`hot.json` owns `dns`, `tun`, `devs`, `mnt`/`mounts`, `locals`, `dns_capture`, `resolv_conf_dns`, `route`, `daemons`, `applications`, and `veth`. Empty `dns_capture` means capture all DNS source IPs; a disabled sentinel captures none. A `dns` entry maps a name directly to an IPv4 address and is pinned into Virtual DNS. A `tun` entry routes through TUN or a file server. Hot changes are watched and applied to the running serve process; invalid JSON is rejected and does not replace the active config.

For a mapping issue, check in this order: the JSON parses as `HotConfig`; `resolv_conf_dns` inside the profile points at the intended DNS server; `dns_capture` includes the query source; `veth_status.json` says `success: true`; the target address is reachable from the profile namespace; and the serve process was running when the change was applied. `sp enter` is the supported namespace check.

## Command reference

### Global and utility commands

- `sp enter [OPTIONS] <TARGET>`: enter an existing profile namespace. Options: `-u/--uid`, `-g/--gid`, `-s/--shell`, `--cwd`, `--gids`, `--args`.
- `sp install [DIR]`: install binaries/scripts into `DIR` (default `./install`).
- `sp completions --fish`: install fish completions under `~/.config/fish/completions`.
- `sp rm <FILE>`: remove a bind-mount file.
- `sp clean [--veth]`: clean runtime state; `--veth` also removes the default veth.
- `sp netlink`: print all IPv4 addresses through the netlink test path.
- `sp gen <SAVE_TO>`: generate an empty config file.
- `sp init`: record the current process namespaces as the basis namespace set.
- `sp id [PID]`: identify the current net namespace, or the namespace associated with `PID`.
- `sp state-tree`: print the typed persistent-state blueprint.
- `sp version`: print build identity, including source-tree BLAKE3 and build epoch.

### Network and process commands

- `sp socks5 <PORT>`: serve a SOCKS5 proxy for escaping a container.
- `sp curl [-p/--proxy <ADDRESS>] <URL>`: issue one HTTP request, optionally through a SOCKS5 proxy.
- `sp forward <SRC> <DST>`: create a TCP forward from `SRC` to `DST`.
- `sp sudo [OPTIONS]`: execute a command with nsproxy's sudo-style environment while preserving Wayland-related context. Options: `-u/--uid`, `-g/--gid`, `-s/--shell`, `--cwd`, `--gids`, `--args`.
- `sp file <PATH>`: accept command arguments from a serialized file.

### Profile lifecycle

- `sp template [--reset] [--update] <PATH> [NAME]`: create a profile from a template. Name defaults to the template filename stem. `--reset` recreates an existing profile; `--update` updates its config without recreating directories.
- `sp clone <NAME> <FROM>`: clone an existing profile into a new profile directory.
- `sp up [OPTIONS] <PROFILE>`: create/persist the profile namespaces and keeper. Development protocol-test options are `--cmd <JSON>`, `--simulate-protocol-no-upgrade`, `--simulate-conn-close`, and `--simulate-slow-shutdown`; use them only for targeted tests.
- `sp down [--rm] <PROFILE>`: tear down the profile; `--rm` also removes config/runtime directories.
- `sp serve --profile <PROFILE> [OPTIONS]`: attach TUN/router to an up profile. Options: `--tun-name`, `--simple <NYM>`, `-n/--no-default`, `-l/--log <PATH>`, `--clash <PATH>`, `--no-dns-capture [true|false]`, and `--internal-dns-server [true|false]`.
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

- `sp uplink clash config-add <GROUP_ID> <PATH>`: import a Clash YAML config for a group.
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
