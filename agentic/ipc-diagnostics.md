# IPC, networking, and diagnostics

Load this note for `sp up`, `sp serve`, Unix socket protocols, reconnection, routing, diagnostic state, and the UI supervisor actor. For spawn semantics, also load `agentic/runtime-state.md`.

## Core paths and protocol

- `UplinkHub` owns the proxy map and pluggable routing through `with_routing` / `set_routing` in `crates/nsproxy-core/src/uplink.rs`.
- `sp up` listens on `/nsp3/{name}/up.sock`; search `up_sock_path`, `run_up_daemon`, and `handle_up_client`.
- `sp serve` diagnostics listen on `/nsp3/{name}/tun_diag.sock`; search `diag_sock_path`, `Router::init_diag`, and `DiagServer::start`.
- Frames are bincode payloads prefixed by a little-endian `u32`. Search `encode_frame`, `read_frame`, `write_bincode_frame`, `read_bincode_frame`, and async variants in `crates/diag/src/lib.rs` and `crates/nsproxy-core/src/bin/nsproxy.rs`.
- The private session bus replaces the standard activation directories with a filtered copy in `run_container_dbus_daemon`; it blacklists only `org.freedesktop.Notifications` because Plasma's `plasma_waitforname` activation can hang on the private bus. Other standard activations, including KWallet, remain available.

## Server and client ownership

- Serve entry/probe: `cmd_serve` in `crates/nsproxy-core/src/bin/nsproxy.rs`.
- Per-diagnostic-client handling: `serve_client`, `DiagServer::emit`, `DiagServer::install_as_global` in `crates/diag/src/lib.rs`.
- Bounded historical logs, virtual-IP mapping, connection activity, SSE, and the embedded React console: `diag::history` in `crates/diag/src/history.rs`; frontend source is `crates/diag/web/`. Logs, mappings, and activity share the `--history-max-bytes` budget. `sp serve` listens inside the profile network namespace (default `0.0.0.0:17890`, unauthenticated).
- Up requests include `GetProcessList`, `Spawn`, `SpawnCli`, and `Stop`; handling is in `handle_up_client`.
- UI connection guards and loops: `ensure_up_client`, `ensure_diag_client`, `up_stream_loop`, `diag_stream_loop` in `crates/nsproxy-ui/src/supervisor.rs`.

## Event-driven bidirectional connection pattern

Both service processes and the UI can establish the active channel; core correctness must not depend on polling.

- The UI listens on `/nsp3/nsproxy-ui-{pid}.sock` through `control_socket_accept_loop`.
- `sp init` creates `/nsp3` and sets that root directory to mode `0777`, allowing an
  unprivileged UI to bind its control socket there. It does not change permissions of
  a custom `--root` directory.
- Services greet it with `ControlSocketGreeting::{UpDaemon,ServeDaemon}` via `connect_and_greet_up` / `connect_and_greet_serve`.
- UI injection paths are `InjectUpStream`, `InjectDiagStream`, and `run_injected_up_stream`.
- On UI restart, `up_client_loop` can connect to an existing daemon through `diag::connect_up_daemon`.
- When UI launches `sp up`, `Cli.control_socket` lets the daemon connect back immediately.
- Lifecycle is driven by accept/connect/stream-close events. Retry helpers (`retry_delay`, `sleep_or_cancelled`) are fallback behavior, not discovery architecture.

## Diagnostic state

- Event history: `event_ring`, `DIAG_EVENT_RING_CAP` in `crates/diag/src/lib.rs`.
- Connection actor: `ConnsState`, `ConnsSummary`, `ConnsActor`, `ConnsCmd`.
- `ConnsState` retains active TCP/UDP entries and finished entries for `HotConfig.diag_conn_persist_secs` (default 300 seconds; GC runs every five seconds, zero removes entries as soon as they finish). Retention changes are applied from the HotConfig watch channel. The server sends `ConnectionsExpired` so subscribed clients promptly remove expired rows.
- Each connection has a summarized `ConnPhase` and a bounded timestamped `ConnTransition` history. `Drop(MaxRetry)` means the retry limit was reached, not necessarily that multiple routes were exhausted; it is transient until the terminal event sets the final `Failed` or `Finished` phase. The drop does not overwrite the last useful non-drop route. `AttemptFailed` records retryable route failures without falsely finishing the connection.
- Connection tracking, its timeline, and its retention state are process-local and in-memory; they are not persisted by `sp serve`. This is distinct from the persisted aggregate per-proxy `ProxyStats` and the separate bounded `diag::history` memory budget.
- Host/route estimates are process-local. `HostRouteKey` uses the SOCKS5 `WireAddress` target, including port, and an exact `ObservedRoute` (`NoProxy` or a specific proxy). TCP connect outcomes are published immediately after each direct or proxy socket connects, so long-lived flows appear without waiting for relay completion. TCP relay rates use successful forwarded-write events; UDP rates use successfully forwarded datagrams. Each protocol and direction has a separate estimate. Samples are coalesced in 100 ms buckets over a five-second rolling window and require at least one second and three events. Qualified samples update serve-side route stats during traffic and (for TCP) on completion. The TUN NAT path also records NoProxy TCP connect outcomes and TCP/UDP directional rates, and answers `QueryHostRouteStats` from its in-memory snapshot. The denominator is the span between data events, not the connection lifetime, and latest sample evidence accompanies each serve-computed average. UDP send-side observations mean local adapter handoff, not remote receipt. `HostRouteStatsSnapshot` / `HostRouteStatsUpdated` carry estimates to clients; `QueryHostRouteStats` fetches the current snapshot.
- Route-selection commands are requests, not acknowledgements. The hot-reload service emits `RoutingState` only after applying the config; clients should not optimistically change the selected route or immediately query state after enqueueing a route command.
- `HotRoute::Group { group_id }` selects a user-owned Clash group. `SetGroupRouting` persists this route, and `RoutingState.selected_group` reports it after hot-config application. For each connection, the uplink chooses a loaded group member by highest past-hour success rate, then lowest measured latency, and retries other untried members after failures.
- `IpStackUdpStream` uses `TimedOut` to indicate normal UDP-flow expiration after its inactivity timeout. `Router::relay_udp` treats that read timeout as clean completion; other read/write/tunnel errors remain failures.
- Runtime commands: `SetTrackConns`, `ResetConnsState`, `QueryConnsState`, `QueryHostRouteStats`, and `QueryRecentDiagEvents`.
- `SetHostRoute` updates and persists a host-wide direct/proxy override through the live `sp serve` HotConfig path. `KillHostConnections` cancels active TCP and UDP flows for a `HostRouteHost`; cancellations emit a distinct `Killed` lifecycle event rather than reporting a relay failure.

## UI supervisor actor

- Actor boundary: `Supervisor`, `SupervisorCommand`, `SupervisorEvent`, `Supervisor::run`, `tokio::select!` in `crates/nsproxy-ui/src/supervisor.rs`.
- Handle/task split: `SupervisorHandle::{new,send,try_recv_snapshot}` and the watch channel.
- Main integration: `SupervisorHandle::new`, `SupervisorCommand::Init`, and `try_recv_snapshot` in `crates/nsproxy-ui/src/main.rs`.
