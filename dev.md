(agent, add concise new section if any new info is available, or modify existing section but minimize text delta)

This is a utility for system-wide, Qubes like containerization engine but built on kernel namespaces. 

The tool provides medium-effort security against casual attackers.

# coding style

maximize Kolmogorov complexity. dont write comments for what is obvious

# State handling

- All persited state are currently in json files at a state root by PERSIST_ROOT
- [PersistentState](crates/nsproxy-core/src/state_blueprint.rs#L10) is a trait that handles all state file loading saving
- command `sp state-root` prints all state visaulized on a tree. See [state_blueprint.rs](crates/nsproxy-core/src/state_blueprint.rs)
- State is centralized at one place, which is part of the philosophy of nsproxy.

`sp X` refers to commands which can be found at [MainCommand](crates/nsproxy-core/src/lib.rs#L1564). `sp` is installed to user system as a SUID symlinked binary.

PERSIST_ROOT stores all data about profiles. You should see all profiles instantiated by `ls` at PERSIST_ROOT

`sp up` launches a process for the purpose of creating a container and keeping it not GCed by kernel, [MainCommand::Up](crates/nsproxy-core/src/lib.rs#L1564)

[NsAlive](crates/common/src/lib.rs#L148) struct:
```rust
pub struct NsAlive {
    pub browser_profile: Option<String>,
    pub bind_mount: PathBuf,
    pub child_pid: Option<u32>,
}
```

keeps the pid of it

# Sandboxing modes

Two-process model: parent stays in host ns (SUID root), child enters new ns with full capabilities.

overlay mode (stable): bind-mounts layered onto real `/` inside new mount namespace

pivot mode: `pivot_root(2)` with unconditional tmpfs staging at `/tmp/nsp_sandbox_{pid}` or `/run/`. Skeleton construction: mount tmpfs, mkdir with preserved uid/gid, bind `/usr` `/etc` read-only, recreate merged-usr symlinks (`/bin -> usr/bin` etc) or bind non-merged dirs, bind `/dev` rw for tty, mount fresh proc/sys/tmp/run, apply [TemplateConfig.mounts](crates/nsproxy-core/src/lib.rs#L1065), bind `/nsp3` for state access, pivot. Better state isolation.

`sp sandbox` does pivot work exclusively, watches [HotConfig](crates/nsproxy-core/src/lib.rs#L850) for mount changes. DBus is major security vector, toggle mount in config. GUI visualizes full mount namespace tree holistically (opposed to firejail/bubblejail unix philosophy).

Instance state stored at `/nsp3/{profile}/` mounted into pivot root. User chooses state location for disk flexibility.

# State machine model 

Many things in the project follow a state machine model such as [PathExpansionState](crates/nsproxy-core/src/lib.rs#L876). A state object is kept for the sole purpose of saving amount of arguments passed per function call. 

# Async + egui 

The main state handling in ui is async primitives from flume or crossbeam or tokio, plus recving per render pass. 

Compuation within render pass is to be avoided.

## Field validation

UI shows non-blocking visual validation via colored borders (green=valid, red=invalid):

- **Paths**: Accept `@` (instance root), `~` (home), or absolute paths. Validates file existence where possible.
- **DNS domains**: Must end with `.` per RFC. Auto-normalized on blur via [normalize_domain()](crates/common/src/lib.rs#L508).
- **Ports** (locals map): Range 1-65535.
- **Chmod mode**: Octal ≤ 0o7777.
- **IPv4**: Standard format validation.

Validation is visual only - doesn't block JSON saves. Only JSON parse errors prevent saving. 

# UplinkHub

All traffic got from TUN are routed through a routing function, which can be changed freely, as a field of [UplinkHub](crates/nsproxy-core/src/uplink.rs#L429). The hub handles all affairs about uplink proxies, 

Some proxies such as Clash proxies are usually supplied in the form of domain names, which need to be resolved periodically, as service supplier may change nodes. Resolution itself should go through uplinkhub. 

`sp serve` instruments a single container. There is [DiagEvent](crates/diag/src/lib.rs#L50) infrastructure tracking all connections already. 

The GUI is built to be parallel to the CLI infra. That is the GUI should not depend on CLI and should perform many functonality through code in the GUI codebase directly. 

UplinkHub itself is not directly persistented. It's an aggregate struct built from other persisted state.

# Diag

The Diag protocol allows bidirectional communication between a controller and an nsproxy process. The protocol logs various stats about connections on the TUN, allows for commands from controller to reload config ([HotConfig](crates/nsproxy-core/src/lib.rs#L850))

## `sp up` daemon protocol

Uses length-prefixed bincode frames. Controller sends [DaemonRequest](crates/diag/src/lib.rs#L456) enum (Spawn, GetProcessList); daemon emits [DaemonEvent](crates/diag/src/lib.rs#L477) enum (Spawned, ProcessExit, ProcessListSnapshot, Error). Daemon maintains in-memory [ProcessList](crates/diag/src/lib.rs#L521) snapshot, transmits on every state change. Parent process acts as container lifecycle manager for all managed child processes.

- UI and supervisor should treat [DaemonEvent::ProcessListSnapshot](crates/diag/src/lib.rs#L477) as the source of truth for process tables.
- [DaemonRequest::SpawnCli](crates/diag/src/lib.rs#L456) { cli_bincode } can launch structured `Cli` commands via the `sp <fd>` fast-path (no string argv reconstruction).

# systemd-resolved

sysetemd has a DNS unix socket at `/run/systemd/resolve/io.systemd.Resolve`

## for overlay mode 

- `resolv.conf` alone isnt enough. `/etc/nsswitch.conf` takes precedence. 
- therefore bind mount overlay nsswitch.conf
- minimal nsswitch.conf to use only explicit DNS resolver:
  ```
  hosts: files dns
  ```
- then set `/etc/resolv.conf`:
  ```
  nameserver 100.68.0.2
  ```
- this prevents `libnss_resolve.so` from being loaded; glibc uses `libnss_dns.so` which does UDP to the configured nameserver only

## for pivot mode

- IPC isolation is irrelevant
- the socket can be hidden from the sandbox via pivot_root (new root without `/run/systemd/resolve/`)

## proxy reuse

I found that kernel reuses network namespaces of dead processes.

Therefore running `sproxy veth` consecutively results in one node with multiple veths, with some of them non existent.

# Accidental unsandboxeed process launches

One of the most common ways I leaked my IP was by launching browsers through unintended ways like opening a link or the launcher of KDE.

I tried wrapping librewolf browser with a wrapper binary and thought about kernel hooking to prevent such leaks. 

I reached a conclusion that _state isolation_ is the superior method.

That the anonymous identity is at its core, a form of secret state that should not be leaked into an uncontainerized network. 

In base system, the censor has no way to tell that I possess a secret material (state) that could identify myself as some identity.

Specifically, nsproxy should handle the environment through kernel namespaces, bind mounts, and chroot. 

In the base system, the browser launch can not leak my secret identity because the profile folder is not mounted.

Some basic anonymization. Anonymized user name, root directory paths for containers.

UplinkHub should track the IP quality of proxies. Blocked by google or not, and other sites.

# workflow


To release a new version 

```sh
./strip.sh
gh release create v2.1.0 ./release/*
```

for debugging

```sh
./testing_install.sh
. env.fish # loads ./install to $PATH
```

# What could be added

- pivot_root, wip
- automatic retries of proxy connection at nsproxy's side, which suits the case where the software does not handle connection failures well in poor network condition
- whitelist for proxy bypass
- handle leaks in basis ns

# Method

I prefer json over yaml, toml, or xml, as a person who is familiar with all of them. 

These so-called better formats are poorly readable, often ambiguous, counter-intuitive leading to reduced productivity.

# Opsec as a multi-variable optimization problem

For a long time people have pursued opsec through paranoid hardware hardening, resorting to some very niche pick of setup. 

Opsec is a multi-variable problem. It's not called a compromise between usability and anonymity. It's a maximum on the multi-variable optimization problem.

# Process architecture

For each container, there exists `sp up` process as the master process, spawning child processes. 

`sp serve` is the basic networking process, as a child process of `sp up`, which handles TUN, routing setup, and other basic things.

All other processes should be spawned through `sp up` by asking it in the `sp up` socket.

For each container currently we have 2 unix sockets:
- `sp up` daemon socket at [/nsp3/{name}/up.sock](crates/diag/src/lib.rs#L418) - created by [run_up_daemon_loop()](crates/nsproxy-core/src/bin/nsproxy.rs#L1612), uses [DaemonRequest](crates/diag/src/lib.rs#L456)/[DaemonEvent](crates/diag/src/lib.rs#L477) protocol
- `sp serve` diag socket at [/nsp3/{name}/tun_diag.sock](crates/diag/src/lib.rs#L410) - created by [DiagServer::spawn()](crates/diag/src/lib.rs#L200), uses [DiagEvent](crates/diag/src/lib.rs#L50) protocol

# Idea, a new container preset desigend for package managers etc

maximize speed/availablility instead of identity isolation.

bind mount crafted package manager configs. use overlay

# Idea, selective routing mode

- Nsproxy presents a DNS in user's main namespace
- Domains designated for proxying are resovled to TUN's IPs
- Non proxied domains get resolved with upstream DNS

make user turn off systemd-dns? and keep a resolv.conf

problems

- can not proxy raw IPs