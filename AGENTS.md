This project is a namespace-based containerization/runtime system with persistent profile state rooted at `/nsp3` by default, overridable per process via `state_paths::set_persist_root`.

Searchable references:
- `PERSIST_ROOT`, `state_paths::persist_root`, `state_paths::set_persist_root` in `crates/common/src/lib.rs`
- `Cli.root` in `crates/nsproxy-core/src/lib.rs`

## Core runtime model

- CLI commands are centralized in `MainCommand`, including `Up`, `Serve`, and `Sandbox`.
  - Search: `enum MainCommand`, `MainCommand::Up`, `MainCommand::Serve`, `MainCommand::Sandbox`
  - File: `crates/nsproxy-core/src/lib.rs`

- Per-profile namespace/process metadata uses `NsAlive` (`child_pid`, `up_pid`, `serve_pid`, `bind_mount`, optional browser profile).
  - Search: `struct NsAlive`
  - Files: `crates/common/src/lib.rs`, usages in `crates/nsproxy-core/src/cmd_common.rs`

- `sp up` daemon exposes `/nsp3/{name}/up.sock` and exchanges `DaemonRequest`/`DaemonEvent` snapshots.
  - Search: `up_sock_path`, `enum DaemonRequest`, `enum DaemonEvent`, `run_up_daemon`, `handle_up_client`
  - Files: `crates/diag/src/lib.rs`, `crates/nsproxy-core/src/bin/nsproxy.rs`

- Structured CLI spawning uses memfd/fd handoff (`sp <fd>` style).
  - Search: `DaemonRequest::SpawnCli`, `CliDaemonRequest::SpawnCli`, `cli_to_memfd`, `cli_to_inheritable_fd`, `spawn_cli_process`
  - Files: `crates/diag/src/lib.rs`, `crates/nsproxy-core/src/lib.rs`, `crates/nsproxy-core/src/bin/nsproxy.rs`

## State + config model

- Persisted state shape is standardized by `PersistentState`; path helpers are in `state_paths`.
  - Search: `trait PersistentState`, `mod state_paths`, `profile_ns_meta`
  - Files: `crates/nsproxy-core/src/state_blueprint.rs`, `crates/common/src/lib.rs`

- `HotConfig` carries DNS/TUN/dev/mount/locals/daemon fields; `TemplateConfig` carries sandbox mode, mounts, chmod, env, hot-config linkage.
  - Search: `struct HotConfig`, `struct TemplateConfig`
  - File: `crates/nsproxy-core/src/lib.rs`

- Path expansion is stateful via `PathExpansionState`.
  - Search: `struct PathExpansionState`, `expand_with`, `expand_source`, `expand_target`
  - File: `crates/nsproxy-core/src/lib.rs`

- Domain normalization helper uses canonical trailing-dot behavior.
  - Search: `normalize_domain`
  - File: `crates/common/src/lib.rs`

## Sandboxing + mounts

- `SandboxMode` models pivot/overlay semantics.
  - Search: `enum SandboxMode`, `TemplateConfig.sandbox_mode`
  - File: `crates/nsproxy-core/src/lib.rs`

- Pivot flow is implemented in `sandbox.rs`.
  - Search: `apply_pivot`, `build_skeleton`, `apply_mounts`, `apply_chmod`, `detect_sandbox_state`, `assert_mount_ns_isolated`
  - File: `crates/nsproxy-core/src/sandbox.rs`

- Mount and pivot primitives are in `sys.rs`.
  - Search: `mount_bind_rw_explicit`, `mount_bind_ro_explicit`, `mount_tmpfs`, `pivot_root_into`, `mount_bind_root`
  - File: `crates/nsproxy-core/src/sys.rs`

- Pivot staging dir helper is profile-scoped.
  - Search: `state_paths::pivot_root_dir`
  - File: `crates/common/src/lib.rs`

## Networking + diagnostics

- `UplinkHub` owns proxy map and pluggable routing function.
  - Search: `struct UplinkHub`, `with_routing`, `set_routing`
  - File: `crates/nsproxy-core/src/uplink.rs`

- Diagnostic sockets:
  - `diag_sock_path` => `/nsp3/{name}/tun_diag.sock`
  - `up_sock_path` => `/nsp3/{name}/up.sock`
  - Search: `diag_sock_path`, `up_sock_path`
  - File: `crates/diag/src/lib.rs`

- Frame protocol is bincode + u32 little-endian length prefix.
  - Search: `encode_frame`, `read_frame`, `write_bincode_frame`, `read_bincode_frame`, `write_bincode_frame_async`, `read_bincode_frame_async`
  - Files: `crates/diag/src/lib.rs`, `crates/nsproxy-core/src/bin/nsproxy.rs`

## Diag protocol codepaths (symbol index)

### Server-side (`sp serve` path)

- Entry path and diag probe:
  - Search: `cmd_serve`
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`

- Diag server startup and command rx wiring:
  - Search: `Router::init_diag`, `DiagServer::start`, `Router::take_cmd_rx`
  - Files: `crates/nsproxy-core/src/uplink/router.rs`, `crates/diag/src/lib.rs`

- Per-client stream handling:
  - Search: `serve_client`, `DiagServer::emit`, `DiagServer::install_as_global`
  - File: `crates/diag/src/lib.rs`

### Server-side (`sp up` path)

- Up daemon listener:
  - Search: `run_up_daemon`, `diag::init_up_log_broadcast`
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`

- Per-client request/event loop:
  - Search: `handle_up_client`, `DaemonRequest::GetProcessList`, `DaemonRequest::Spawn`, `DaemonRequest::SpawnCli`, `DaemonRequest::Stop`
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`

- One-shot sync path (CLI -> up.sock):
  - Search: `write_bincode_frame`, `read_bincode_frame`
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`

### Client-side (UI supervisor)

- Up/diag client spawn guards:
  - Search: `ensure_up_client`, `ensure_diag_client`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

- Connected stream loops:
  - Search: `up_stream_loop`, `diag_stream_loop`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

- Retry loops and backoff:
  - Search: `up_client_loop`, `diag_client_loop`, `retry_delay`, `sleep_or_cancelled`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

## spawn in container as daaemon patttern

This repository already has both daemonized and non-daemonized spawn variants for container/ns execution.

### daemonized variant

Use when the spawned workload should outlive the immediate UI action and be supervised by `sp up`.

Flow:
- UI sends `SupervisorCommand::StartDaemon` or `SupervisorCommand::StartServe`.
  - Search: `enum SupervisorCommand`, `handle_command`
  - File: `crates/nsproxy-ui/src/supervisor.rs`
- Supervisor sends `DaemonRequest::Spawn` or `DaemonRequest::SpawnCli` to `up.sock`.
  - Search: `DaemonRequest::Spawn`, `DaemonRequest::SpawnCli`, `up_stream_loop`
  - Files: `crates/diag/src/lib.rs`, `crates/nsproxy-ui/src/supervisor.rs`
- `sp up` handles in `handle_up_client`, then forks/execs via:
  - `spawn_daemon_process` for raw command args
  - `spawn_cli_process` for structured `Cli` payload
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`
- Child process tracking lives in `UpDaemonState.process_list` and is emitted as `DaemonEvent::ProcessListSnapshot`.
  - Search: `struct UpDaemonState`, `ProcessListSnapshot`, `DaemonEvent::ProcessExit`
  - Files: `crates/nsproxy-core/src/bin/nsproxy.rs`, `crates/diag/src/lib.rs`

Supporting privileged wrapper:
- UI chooses SUID wrapper path (`sproxy`) via `nsproxy_path` in `Supervisor::new` and spawn helper `spawn_nsproxy_cli`.
- `sproxy` re-execs `nsproxy` after auth/cap checks.
  - Search: `spawn_nsproxy_cli`, `nsproxy_path`, `main`, `sudo_check`
  - Files: `crates/nsproxy-ui/src/supervisor.rs`, `crates/nsproxy-core/src/bin/sproxy.rs`

### non daemonized variant

Use when the action should run now and exit with the user process (interactive shell/tooling style), not managed by `sp up` process table.

- `enter_ns` enters target mount/net namespaces directly from `NsAlive`.
  - Search: `enter_ns`
  - File: `crates/nsproxy-core/src/cmd_common.rs`

- `ShellPrefs::spawn_in_ns` performs clone+setns+exec for one process tree and returns child handle for waiting.
  - Search: `ShellPrefs::spawn_in_ns`, `ShellPrefs::spawn`
  - File: `crates/nsproxy-core/src/shell.rs`

- `MainCommand::Sandbox` is currently implemented in this style plus pivot/mount orchestration.
  - Search: `MainCommand::Sandbox`, `watch_hot_mounts`
  - File: `crates/nsproxy-core/src/bin/nsproxy.rs`

## pattern: server on both sides, event driven no timers, inter process

This codebase uses a bidirectional server pattern over Unix sockets where both UI and service processes can act as listeners/initiators, enabling event-driven reconnection without polling timers.

### side A: sp processes listen on profile sockets

- `sp up` listens on `/nsp3/{profile}/up.sock` (`run_up_daemon`).
- `sp serve` listens on `/nsp3/{profile}/tun_diag.sock` (`DiagServer::start` via `Router::init_diag`).

Searchable symbols:
- `run_up_daemon`, `handle_up_client`
- `diag::up_sock_path`, `diag::diag_sock_path`
- `Router::init_diag`, `DiagServer::start`

### side B: UI also listens on control socket

- UI binds `/tmp/nsproxy-ui-{pid}.sock` and accepts process-initiated connections.
  - Search: `control_sock_path`, `control_socket_accept_loop`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

- Connecting process sends `ControlSocketGreeting` first frame:
  - `UpDaemon { name }` from `connect_and_greet_up`
  - `ServeDaemon { name }` from `connect_and_greet_serve`
  - Search: `ControlSocketGreeting`, `connect_and_greet_up`, `connect_and_greet_serve`
  - Files: `crates/diag/src/lib.rs`, `crates/nsproxy-core/src/bin/nsproxy.rs`

- UI injects live streams (`InjectUpStream` / `InjectDiagStream`) and runs `run_injected_up_stream` / injected diag loop path.
  - Search: `InjectUpStream`, `InjectDiagStream`, `run_injected_up_stream`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

### restart behavior (no polling requirement)

- When UI starts and `sp up` already exists, UI can connect to existing `up.sock` through `up_client_loop` + `diag::connect_up_daemon`.
  - Search: `up_client_loop`, `diag::connect_up_daemon`
  - Files: `crates/nsproxy-ui/src/supervisor.rs`, `crates/diag/src/lib.rs`

- When UI launches `sp up`, `sp up` also actively connects back to UI control socket if `Cli.control_socket` is set.
  - Search: `Cli.control_socket`, `run_up_daemon`, `connect_and_greet_up`
  - Files: `crates/nsproxy-core/src/lib.rs`, `crates/nsproxy-core/src/bin/nsproxy.rs`

Result:
- Either side can establish the active channel first.
- No periodic discovery timer is required for core IPC correctness.
- Connection lifecycle is event-driven via accept/connect and stream close events.

## DiagServer internal state

- Event ring:
  - Search: `event_ring`, `DIAG_EVENT_RING_CAP`
  - File: `crates/diag/src/lib.rs`

- Connection-tracking actor state:
  - Search: `ConnsState`, `ConnsSummary`, `ConnsActor`, `ConnsCmd`
  - File: `crates/diag/src/lib.rs`

- Runtime toggles and direct command handling in serve loop:
  - Search: `SetTrackConns`, `ResetConnsState`, `QueryRecentDiagEvents`
  - File: `crates/diag/src/lib.rs`

## UI architecture (actor-oriented)

- Supervisor actor and channel boundaries:
  - Search: `struct Supervisor`, `enum SupervisorCommand`, `enum SupervisorEvent`, `Supervisor::run`, `tokio::select!`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

- Handle/task split:
  - Search: `struct SupervisorHandle`, `SupervisorHandle::send`, `SupervisorHandle::try_recv_snapshot`, `watch::channel`
  - File: `crates/nsproxy-ui/src/supervisor.rs`

- Main UI integration:
  - Search: `SupervisorHandle::new`, `send(SupervisorCommand::Init`, `try_recv_snapshot`
  - File: `crates/nsproxy-ui/src/main.rs`

## terminal naming

- The special swap terminal window title is composed on the UI `swap` path as `container - program - uid`.
  - Search: `format_external_terminal_title`, `attach_swap_pty_window`
  - File: `crates/nsproxy-ui/src/main.rs`

- The same computed title is also reused for dedicated per-PTY windows opened via `open`.
  - Search: `open_dedicated_pty_window`, `format_external_terminal_title`
  - File: `crates/nsproxy-ui/src/main.rs`

- The computed title is forwarded to the child process in the control message and applied immediately during PTY swap/attach.
  - Search: `TermWindowRequest::Attach`, `shared.reset_terminal(&title)`
  - File: `crates/nsproxy-ui/src/alacritty_window.rs`

- Shell-originated title updates do not replace the assigned container title; the runtime composes them as `container - program - uid - shell-title` when a shell title is present.
  - Search: `compose_window_title`, `TerminalEvent::Title`, `TerminalEvent::ResetTitle`
  - Files: `crates/term-view/src/alacritty_port/window_context.rs`, `crates/term-view/src/alacritty_port/event.rs`

## nsproxy-ui visual components (search map)

- Left sidebar and helper cards:
  - Search: `egui::SidePanel::left`, `sidebar_box`, `sidebar_box_width`
  - File: `crates/nsproxy-ui/src/main.rs`

- Main tabs and entry renders:
  - Search: `render_proxies_tab`, `render_processes_tab`, `render_traffic_tab`, `render_diagnostics_tab`, `render_dns_tab`, `render_hotconfig_tab`, `render_profile_editor_tab`
  - File: `crates/nsproxy-ui/src/main.rs`

- Proxies table + detail windows:
  - Search: `render_proxies_table`, `render_proxy_row`, `render_proxy_detail_window`, `render_mini_sparkline`
  - File: `crates/nsproxy-ui/src/main.rs`

- Processes controls and daemon list:
  - Search: `render_process_controls`, `render_units_table`, `render_hotconfig_daemons_section`, `render_run_command_section`
  - File: `crates/nsproxy-ui/src/main.rs`

- Traffic sub-views:
  - Search: `TrafficSubview`, `selected_traffic_conn`, `diag_event_log`, `render_diag_event_row`
  - File: `crates/nsproxy-ui/src/main.rs`

- Form widgets:
  - Search: `render_optional_u32`, `render_optional_text`, `render_path_field`, `render_mount_list`, `render_chmod_list`, `render_env_map`, `render_string_map`, `render_u32_map`, `render_path_map`, `render_shell_args_list`, `render_shell_args`
  - File: `crates/nsproxy-ui/src/main.rs`

## term-view keyboard mapping (Ctrl+Backspace)

- External Alacritty runtime entrypoint (window boot + WindowContext wiring):
  - Search: `ExternalViewportRequest::create_window_context`, `WindowContext::external`
  - File: `crates/term-view/src/alacritty_runtime.rs`

- Alacritty default keybindings (external windows):
  - Search: `default_key_bindings`, `Backspace, ModifiersState::CONTROL`, `Action::Esc("\x17".into())`
  - File: `crates/term-view/src/alacritty_port/config/bindings.rs`

- Inline egui terminal input path (already maps Ctrl+Backspace => ^W):
  - Search: `egui::Event::Key`, `Key::Backspace if modifiers.ctrl => &[0x17]`
  - File: `crates/term-view/src/lib.rs`
