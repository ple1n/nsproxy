# nsproxy agent context (concise)

This project is a namespace-based containerization/runtime system with persistent profile state rooted at `/nsp3` by default, and overridable per process via `state_paths::set_persist_root`. ([PERSIST_ROOT](crates/common/src/lib.rs#L36), [state_paths::persist_root](crates/common/src/lib.rs#L46), [state_paths::set_persist_root](crates/common/src/lib.rs#L54), [Cli.root](crates/nsproxy-core/src/lib.rs#L1544))

## Core runtime model

- CLI commands are centralized in `MainCommand`, including `Up`, `Serve`, and `Sandbox` (pivot-root sandbox flow). ([MainCommand](crates/nsproxy-core/src/lib.rs#L1622), [MainCommand::Up](crates/nsproxy-core/src/lib.rs#L1691), [MainCommand::Serve](crates/nsproxy-core/src/lib.rs#L1705), [MainCommand::Sandbox](crates/nsproxy-core/src/lib.rs#L1755))
- Per-profile namespace/process metadata uses `NsAlive` (`child_pid`, `serve_pid`, `bind_mount`, optional browser profile). ([NsAlive](crates/common/src/lib.rs#L142))
- The `sp up` daemon exposes `/nsp3/{name}/up.sock` and exchanges `DaemonRequest`/`DaemonEvent` snapshots (notably `ProcessListSnapshot`). ([up_sock_path](crates/diag/src/lib.rs#L418), [DaemonRequest](crates/diag/src/lib.rs#L456), [DaemonEvent](crates/diag/src/lib.rs#L479), [run_up_daemon_loop](crates/nsproxy-core/src/bin/nsproxy.rs#L1661), [ProcessListSnapshot handling](crates/nsproxy-core/src/bin/nsproxy.rs#L1686))
- `SpawnCli { cli_bincode }` exists for structured CLI spawning via memfd/fd fast-path (`sp <fd>` style handoff). ([DaemonRequest::SpawnCli](crates/diag/src/lib.rs#L463), [CliDaemonRequest::SpawnCli](crates/nsproxy-core/src/lib.rs#L1583), [cli_to_memfd docs](crates/nsproxy-core/src/lib.rs#L1933), [daemon SpawnCli branch](crates/nsproxy-core/src/bin/nsproxy.rs#L1736))

## State + config model

- Persisted JSON state is standardized through `PersistentState`; profile/state path helpers are centralized in `state_paths`. ([PersistentState](crates/nsproxy-core/src/state_blueprint.rs#L10), [state_paths module](crates/common/src/lib.rs#L39), [profile_ns_meta](crates/common/src/lib.rs#L83))
- `HotConfig` contains DNS/TUN/dev/mount/locals + daemon fields; `TemplateConfig` contains sandbox mode, explicit mounts, chmod, env, and hot config linkage. ([HotConfig](crates/nsproxy-core/src/lib.rs#L850), [TemplateConfig](crates/nsproxy-core/src/lib.rs#L1065))
- Path expansion is stateful through `PathExpansionState` (instance root/home/chroot contexts). ([PathExpansionState](crates/nsproxy-core/src/lib.rs#L876))
- Domain normalization helper enforces trailing-dot canonicalization for non-empty inputs. ([normalize_domain](crates/common/src/lib.rs#L502))

## Sandboxing + mounts

- `SandboxMode` supports overlay/pivot semantics through template config; pivot flow is implemented in `sandbox.rs`. ([SandboxMode](crates/nsproxy-core/src/lib.rs#L1115), [TemplateConfig.sandbox_mode](crates/nsproxy-core/src/lib.rs#L1069), [sandbox module](crates/nsproxy-core/src/sandbox.rs#L1))
- Pivot flow stages a tmpfs root, builds skeleton mounts (`/usr`, `/etc`, `/dev`, `/proc`, `/sys`, `/tmp`, `/run`), applies template mounts, binds persist root, then `pivot_root`. ([pivot flow docs](crates/nsproxy-core/src/sandbox.rs#L127), [apply_mounts](crates/nsproxy-core/src/sandbox.rs#L23), [persist bind step](crates/nsproxy-core/src/sandbox.rs#L135), [pivot_root_into call](crates/nsproxy-core/src/sandbox.rs#L169))
- Current pivot staging path helper is `/tmp/nsproxy_{name}` (important if older docs mention other paths). ([pivot_root_dir](crates/common/src/lib.rs#L136))

## Networking + diagnostics

- `UplinkHub` owns proxy map + pluggable routing function (`with_routing`, `set_routing`). ([UplinkHub](crates/nsproxy-core/src/uplink.rs#L430), [with_routing](crates/nsproxy-core/src/uplink.rs#L616), [set_routing](crates/nsproxy-core/src/uplink.rs#L673))
- Tun diagnostics socket is `/nsp3/{name}/tun_diag.sock`; event stream type is `DiagEvent` with control commands and snapshots. ([diag_sock_path](crates/diag/src/lib.rs#L448), [DiagEvent](crates/diag/src/lib.rs#L51), [ControlCommand](crates/diag/src/lib.rs#L142))
- Diag protocol framing is binary length-prefixed bincode (`u32 LE len + payload`). ([encode_frame](crates/diag/src/lib.rs#L347), [read_frame](crates/diag/src/lib.rs#L357))
- Up daemon socket is `/nsp3/{name}/up.sock`. ([up_sock_path](crates/diag/src/lib.rs#L456))

## Diag protocol codepaths (index)

### Socket paths
- `diag_sock_path` → `/nsp3/{name}/tun_diag.sock` ([diag/lib.rs:448](crates/diag/src/lib.rs#L448))
- `up_sock_path` → `/nsp3/{name}/up.sock` ([diag/lib.rs:456](crates/diag/src/lib.rs#L456))

### DiagEvent variants (server→client, tun_diag.sock)
`Accept` [L54](crates/diag/src/lib.rs#L54) · `Dispatched` [L62](crates/diag/src/lib.rs#L62) · `Route` [L65](crates/diag/src/lib.rs#L65) · `Connected` [L71](crates/diag/src/lib.rs#L71) · `Finished` [L74](crates/diag/src/lib.rs#L74) · `DnsResolved` [L83](crates/diag/src/lib.rs#L83) · `DnsQuery` [L91](crates/diag/src/lib.rs#L91) · `Wait`/`WaitEnded` [L97](crates/diag/src/lib.rs#L97) · `HotConfigReloaded` [L102](crates/diag/src/lib.rs#L102) · `HotConfigSnapshot` [L110](crates/diag/src/lib.rs#L110) · `DnsState` [L118](crates/diag/src/lib.rs#L118) · `RoutingState` [L120](crates/diag/src/lib.rs#L120) · `UplinkStatsSnapshot` [L122](crates/diag/src/lib.rs#L122) · `Log` [L127](crates/diag/src/lib.rs#L127) · `RecentLogs(Vec<LogEntry>)` · `RecentDiagEvents(Vec<DiagEvent>)`

### ControlCommand variants (client→server)
`ReloadUplink` [L146](crates/diag/src/lib.rs#L146) · `ReloadHotConfig` [L148](crates/diag/src/lib.rs#L148) · `SetSimpleRouting` [L150](crates/diag/src/lib.rs#L150) · `QueryDnsState` [L155](crates/diag/src/lib.rs#L155) · `QueryRoutingState` [L157](crates/diag/src/lib.rs#L157) · `QueryHotConfig` [L159](crates/diag/src/lib.rs#L159) · `ApplyHotConfig` [L161](crates/diag/src/lib.rs#L161) · `QueryUplinkStats` [L164](crates/diag/src/lib.rs#L164) · `ClearStats` [L166](crates/diag/src/lib.rs#L166) · `QueryRecentLogs { limit }` · `QueryRecentDiagEvents { limit }` · `SetTrackConns { enabled }` · `ResetConnsState`

### DaemonRequest / DaemonEvent variants (up.sock)
- `DaemonRequest` (`Spawn`, `SpawnCli`, `GetProcessList`, `Kill`, `Ping`, `Stop`): [diag/lib.rs:599](crates/diag/src/lib.rs#L599)
- `DaemonEvent` (`Spawned`, `ProcessExit`, `ProcessListSnapshot`, `Error`, `Pong`, `Stopping`, `Log`): [diag/lib.rs:628](crates/diag/src/lib.rs#L628)

### Diag server — `sp serve` path
- `cmd_serve` entry; probes existing socket: [nsproxy.rs:1163](crates/nsproxy-core/src/bin/nsproxy.rs#L1163) (probe [L1183–1193](crates/nsproxy-core/src/bin/nsproxy.rs#L1183))
- `router.init_diag(&diag_path)` calls `DiagServer::start`, stores `(DiagServer, cmd_rx)`: [nsproxy.rs:1401](crates/nsproxy-core/src/bin/nsproxy.rs#L1401), [router.rs:179](crates/nsproxy-core/src/uplink/router.rs#L179)
- `DiagServer::start` — binds socket (chmod 0666), spawns accept loop, returns `(Self, cmd_rx)`: [diag/lib.rs:204](crates/diag/src/lib.rs#L204)
- `serve_client` — per-client `tokio::select!`: broadcasts `DiagEvent` to client, reads `ControlCommand` from client: [diag/lib.rs:294](crates/diag/src/lib.rs#L294)
- `diag_srv_scope.install_as_global()` registers diag broadcast as global log sink: [nsproxy.rs:1408](crates/nsproxy-core/src/bin/nsproxy.rs#L1408)
- `cmd_rx.recv()` dispatch loop for all `ControlCommand` variants, emitting responses via `diag_srv.emit()`: [nsproxy.rs:1414–1580](crates/nsproxy-core/src/bin/nsproxy.rs#L1414)

### Diag server — `sp up` path
- `run_up_daemon` — binds `up.sock` (chmod 0666), calls `diag::init_up_log_broadcast()`, runs accept loop: [nsproxy.rs:1699](crates/nsproxy-core/src/bin/nsproxy.rs#L1699) (spawned at [L824](crates/nsproxy-core/src/bin/nsproxy.rs#L824))
- `handle_up_client` — per-client `tokio::select!` on `read_bincode_frame_async` (inbound `DaemonRequest`) and `log_rx` broadcast (outbound `DaemonEvent::Log`): [nsproxy.rs:1745](crates/nsproxy-core/src/bin/nsproxy.rs#L1745)
- Sync CLI one-shot path (`write_bincode_frame` / `read_bincode_frame`): [nsproxy.rs:2218](crates/nsproxy-core/src/bin/nsproxy.rs#L2218) / [L2225](crates/nsproxy-core/src/bin/nsproxy.rs#L2225)
- `write_bincode_frame_async` / `read_bincode_frame_async` used in `handle_up_client`: [nsproxy.rs:2238](crates/nsproxy-core/src/bin/nsproxy.rs#L2238) / [L2249](crates/nsproxy-core/src/bin/nsproxy.rs#L2249)

### Frame encoding/decoding
- `encode_frame` (private, diag.sock): bincode serialize → u32 LE length prefix: [diag/lib.rs:347](crates/diag/src/lib.rs#L347)
- `read_frame` (private async, diag.sock): read u32 LE length then payload, `Ok(None)` on EOF: [diag/lib.rs:357](crates/diag/src/lib.rs#L357)
- Server encodes `DiagEvent` for broadcast via `DiagServer::emit`: [diag/lib.rs:252](crates/diag/src/lib.rs#L252)
- Server decodes `ControlCommand` from client in `serve_client`: [diag/lib.rs:322](crates/diag/src/lib.rs#L322)
- Client encodes `ControlCommand` via `DiagEventStream::send_cmd`: [diag/lib.rs:399](crates/diag/src/lib.rs#L399)
- Client decodes `DiagEvent` via `DiagEventReader::next`: [diag/lib.rs:394](crates/diag/src/lib.rs#L394)
- Up-daemon client: `UpDaemonReader::next_event` / `UpDaemonWriter::send_request`: [diag/lib.rs:703](crates/diag/src/lib.rs#L703) / [L713](crates/diag/src/lib.rs#L713)
- `DiagTracingLayer` log forwarding (diag + up broadcasts): [diag/lib.rs:523](crates/diag/src/lib.rs#L523) / [L540](crates/diag/src/lib.rs#L540)

### Diag protocol client (supervisor)
- `ensure_diag_client` / `ensure_up_client` — guard against double-spawn, create cmd channel, insert tx, spawn loop: [supervisor.rs:1140](crates/nsproxy-ui/src/supervisor.rs#L1140) / [L1122](crates/nsproxy-ui/src/supervisor.rs#L1122)
- `send_diag_cmd` — calls `ensure_diag_client` if needed, sends `ControlCommand`: [supervisor.rs:1020](crates/nsproxy-ui/src/supervisor.rs#L1020)
- `diag::connect` → `DiagEventStream` (wraps `UnixStream::connect`): [diag/lib.rs:377](crates/diag/src/lib.rs#L377)
- `diag::connect_up_daemon` → `UpDaemonStream`: [diag/lib.rs:719](crates/diag/src/lib.rs#L719)
- `diag_client_loop` — outer retry loop for `tun_diag.sock`; on connect sends 4 initial query cmds, delegates to `diag_stream_loop`: [supervisor.rs:1492](crates/nsproxy-ui/src/supervisor.rs#L1492)
- `diag_stream_loop` — inner connected loop: `tokio::select!` on `reader.next()` → `SupervisorEvent::DiagEvent` and `cmd_rx.recv()` → `writer.send_cmd`: [supervisor.rs:1595](crates/nsproxy-ui/src/supervisor.rs#L1595)
- `up_client_loop` — outer retry loop for `up.sock`, delegates to `up_stream_loop`: [supervisor.rs:1409](crates/nsproxy-ui/src/supervisor.rs#L1409)
- `up_stream_loop` — inner connected loop: `tokio::select!` on `reader.next_event()` → `SupervisorEvent::UpEvent` and `cmd_rx.recv()` → `writer.send_request`: [supervisor.rs:1331](crates/nsproxy-ui/src/supervisor.rs#L1331)

### Connection retry logic (supervisor)
- `retry_delay(attempt)` — capped exponential backoff: 200ms → 500ms → 1s → 2s → 4s → 8s max: [supervisor.rs:1376](crates/nsproxy-ui/src/supervisor.rs#L1376)
- `sleep_or_cancelled(dur, cmd_rx)` — sleeps `dur` but returns early (`true`) if `cmd_rx` is dropped (container stopped); discards commands received during sleep: [supervisor.rs:1390](crates/nsproxy-ui/src/supervisor.rs#L1390)
- `up_client_loop` retry pattern: skip delay on attempt 0, increment counter, connect, on success reset counter to 0, on error `continue`: [supervisor.rs:1409](crates/nsproxy-ui/src/supervisor.rs#L1409)
- `diag_client_loop` retry pattern: same as above for `tun_diag.sock`: [supervisor.rs:1492](crates/nsproxy-ui/src/supervisor.rs#L1492)
- Per-session attempt counters (`Arc<AtomicU32>`) created fresh in `ensure_up_client` / `ensure_diag_client`, so backoff resets when a new client loop is spawned: [supervisor.rs:1133](crates/nsproxy-ui/src/supervisor.rs#L1133) / [L1150](crates/nsproxy-ui/src/supervisor.rs#L1150)

## DiagServer internal state

- `DiagServer` holds a rolling `event_ring: Arc<Mutex<VecDeque<DiagEvent>>>` capped at `DIAG_EVENT_RING_CAP = 50`. New events are pushed in `emit()` and old ones popped when full.
- `conns: Arc<Mutex<ConnsState>>` tracks active connections: `ConnsState { active: BTreeMap<WireAddress, ConnsSummary>, pending: BTreeMap<ConnId, (WireAddress, Option<RoutingResovled>)> }`.
- `ConnsSummary` is `BTreeMap<RoutingResovled, u64>` (per-route active-connection counter).
- `track_conns: Arc<AtomicBool>` (default `DEFAULT_TRACK_CONNS = false`) gates all conn-table updates; shared across clones. Toggled via `SetTrackConns` command or `DiagServer::set_track_conns`.
- `SetTrackConns { enabled }` and `ResetConnsState` are handled directly in `serve_client` without forwarding to `cmd_tx`.
- `QueryRecentDiagEvents { limit }` is also handled directly in `serve_client`; responds with `DiagEvent::RecentDiagEvents`.

## UI architecture (actor-oriented)

- `Supervisor` is an actor-like task with command/event enums, mailbox channels, and a `tokio::select!` receive loop. ([SupervisorCommand](crates/nsproxy-ui/src/supervisor.rs#L87), [SupervisorEvent](crates/nsproxy-ui/src/supervisor.rs#L875), [Supervisor::run loop](crates/nsproxy-ui/src/supervisor.rs#L285), [select](crates/nsproxy-ui/src/supervisor.rs#L288))
- Handle/task split: UI sends commands through `SupervisorHandle::send`, receives snapshots through watch channel polling. ([SupervisorHandle](crates/nsproxy-ui/src/supervisor.rs#L130), [send](crates/nsproxy-ui/src/supervisor.rs#L157), [try_recv_snapshot](crates/nsproxy-ui/src/supervisor.rs#L163), [watch::channel](crates/nsproxy-ui/src/supervisor.rs#L138))
- Main UI initializes supervisor once, then primarily interacts through message sends and snapshot consumption each frame (actor-style boundary). ([SupervisorHandle::new usage](crates/nsproxy-ui/src/main.rs#L409), [spawn supervisor task](crates/nsproxy-ui/src/main.rs#L410), [send Init](crates/nsproxy-ui/src/main.rs#L413), [snapshot polling](crates/nsproxy-ui/src/main.rs#L1961), [command send example](crates/nsproxy-ui/src/main.rs#L2792))
- Diag/up socket clients also run as async message loops (`up_stream_loop`, `diag_stream_loop`) using channel + stream select. ([up_stream_loop](crates/nsproxy-ui/src/supervisor.rs#L918), [diag_stream_loop](crates/nsproxy-ui/src/supervisor.rs#L1092), [select in up loop](crates/nsproxy-ui/src/supervisor.rs#L932), [select in diag loop](crates/nsproxy-ui/src/supervisor.rs#L1101))

### nsproxy-ui — Visual components 

- `Left Sidebar` — Profiles list and global controls (container selection, reload, toggle secrets). UI anchored in `egui::SidePanel::left`. (ui start: [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2032); helper widgets: `sidebar_box` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L4197) and `sidebar_box_width` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L4207)).

- `Tabs Bar (CentralPanel)` — Top horizontal tab bar selecting main views (Proxies, Processes, Diagnostics, DNS, Hotconfig, Profile). (tab container: [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2124); tab items around [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2128)).

- `Proxies Tab` — Full proxies management view.
	- `render_proxies_tab` (entry): [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2262)
	- `Selected Proxy Summary`: small header showing currently-selected proxy. (`render_selected_proxy_summary` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2309))
	- `Proxy Filters` (type/group/sort): (`render_proxy_filters` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2350))
	- `Proxies Table`: scrollable table of proxies (`render_proxies_table` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2430))
	- `Proxy Row` rendering (per-row UI, hover actions, Select/Detail buttons): (`render_proxy_row` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2560))
	- `Proxy Detail Window` — separate `egui::Window` with plots and summary (`render_proxy_detail_window` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3378))
	- Mini sparklines: `render_mini_sparkline` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3719)

- `Processes Tab` — Process/daemon management for a profile.
	- `render_processes_tab` (entry): [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2766)
	- Process controls panel: `render_process_controls` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L2793)
	- Units / Daemons table: `render_units_table` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3040)
	- Hotconfig daemons section: `render_hotconfig_daemons_section` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3121)
	- Run-command form: `render_run_command_section` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3177)

- `Diagnostics Tab` — High-level diagnostic summary per-profile. (`render_diagnostics_tab` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3205))

- `Traffic Tab` — Per-profile live traffic view with a **Connections / Logs toggle** (`TrafficSubview` enum, stored as `App::traffic_subview`). (`render_traffic_tab` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3199))
	- **Connections sub-view** (default): scrollable connection table with per-row selectable detail panel; selected connection stored in `App::selected_traffic_conn`.
	- **Logs sub-view**: rolling list of raw `DiagEvent`s from the server-side ring buffer, stored as `ContainerState::diag_event_log` (capped at 512 entries). When the sub-view is first opened and the local buffer is empty, `QueryRecentDiagEvents { limit: DIAG_EVENT_RING_CAP }` is sent; subsequent events arrive live via the diag broadcast. Rendered per-event with `render_diag_event_row` (source-coloured type badge + fields).

- `DNS Tab` — (placeholder view). (`render_dns_tab` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3250))

- `Hotconfig Tab` — Hotconfig editor and apply controls.
	- `render_hotconfig_tab` (entry): [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3255)
	- Hotconfig editor split: `render_hotconfig_editor_split` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L1505)
	- Hotconfig form helpers: `render_hotconfig_form` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L1464)
	- In-editor `CodeEditor` usage: example at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L1530)

- `Profile Editor Tab` — Form-based template editor + formatted JSON view.
	- `render_profile_editor_tab` (entry): [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3294)
	- Template form: `render_template_form` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L1635)
	- Formatted JSON editor (CodeEditor) & sync: CodeEditor usage at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3349)

- `Plot / Detail helpers` — time-series plotting & helpers used by detail windows and sparklines:
	- `render_mini_sparkline` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3719)
	- `render_detail_latency_plot` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3839)
	- `render_detail_attempts_plot` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3897)
	- `render_detail_traffic_plot` at [crates/nsproxy-ui/src/main.rs](crates/nsproxy-ui/src/main.rs#L3995)

- `Form-field renderers` — reusable small widgets for forms used across editors:
	- `render_optional_u32` ([main.rs](crates/nsproxy-ui/src/main.rs#L828)), `render_optional_text` ([main.rs](crates/nsproxy-ui/src/main.rs#L911)), `render_path_field` ([main.rs](crates/nsproxy-ui/src/main.rs#L933)), `render_mount_list` ([main.rs](crates/nsproxy-ui/src/main.rs#L953)), `render_chmod_list` ([main.rs](crates/nsproxy-ui/src/main.rs#L1001)), `render_env_map` ([main.rs](crates/nsproxy-ui/src/main.rs#L1049)), `render_string_map` ([main.rs](crates/nsproxy-ui/src/main.rs#L1115)), `render_u32_map` ([main.rs](crates/nsproxy-ui/src/main.rs#L1195)), `render_path_map` ([main.rs](crates/nsproxy-ui/src/main.rs#L1359)), `render_shell_args_list` ([main.rs](crates/nsproxy-ui/src/main.rs#L1430)), `render_shell_args` ([main.rs](crates/nsproxy-ui/src/main.rs#L1558)).
