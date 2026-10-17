# Runtime, state, and sandboxing

Load this note for CLI commands, profile persistence, configuration, namespace entry, sandbox mounts, and process spawning.

## Runtime and state

- Commands are centralized in `MainCommand` (`Up`, `Serve`, `Sandbox`) in `crates/nsproxy-core/src/lib.rs`.
- Persistent profile state defaults to `/nsp3`; `sp --state <root>` and `nsproxy-ui --state <root>` select another root. Search `PERSIST_ROOT`, `state_paths::persist_root`, and `state_paths::set_persist_root` in `crates/common/src/lib.rs`. Child CLI payloads must carry the selected `Cli.root`.
- `NsAlive` records `child_pid`, `up_pid`, `serve_pid`, bind-mount state, and optional browser profile. Definition: `crates/common/src/lib.rs`; namespace-entry uses: `crates/nsproxy-core/src/cmd_common.rs`.
- The standardized state interface is `PersistentState`; path helpers are under `state_paths`. Search `profile_ns_meta` and `state_blueprint.rs`.
- `HotConfig` owns DNS, TUN, devices, mounts, locals, daemon fields, and `diag_conn_persist_secs`, which configures finished TCP/UDP diagnostic retention in `sp serve` (default 300 seconds; updated live). `TemplateConfig` owns sandbox mode, mounts, chmod, env, and hot-config linkage.
- `HotConfig.default_route` is the fallback routing decision; `route_map` maps shared `RoutingKey` filters to concrete `RoutingResovled` results. Normalize all domains in a route map to lowercase with a trailing dot after deserialization, and normalize incoming host keys before lookup or insertion. Within each key type prefer the exact port before the no-port entry. Lookup performs bounded ordered-map lookups; do not derive IP keys from virtual ingress addresses.
- `TemplateConfigV3.fcitx_default_input_method` is the declarative seed for a private-profile Fcitx default. `sp sandbox` stores the seed under that profile's persistent config directory and bind-mounts it at the user's Fcitx profile path, including for Overlay profiles. An existing profile file is copied on first seeding and subsequent Fcitx edits persist in the profile config directory.
- A HotConfig update with no network/service deltas still refreshes `sp serve`'s live config watch; runtime-only diagnostics settings must not depend on `calculate_hot_diff` producing an operation.
- Stateful path expansion uses `PathExpansionState::{expand_with,expand_source,expand_target}`.
- Domains use canonical trailing-dot normalization via `normalize_domain` in `crates/common/src/lib.rs`.
- Long-lived shell/daemon invocations log `{type, pid, start_ticks, nsid, args}` as one JSON object per line in the boot-scoped append-only JSONL file at `state_paths::process_log()` (`/nsp3/nsproxy-process-log.jsonl` by default). `args` is the serialized `Cli` JSON object, so memfd-launched commands retain their structured arguments across versions; definitely short-lived commands such as `completions`, `id`, and `version` are excluded. The boot ID marker at `process_log_boot()` rotates the logical history once per kernel boot; boot rotation is locked and normal writes use append mode.
- `state_file.rs` owns `SimpleCRDT` JSON updates and append-only process-WAL reads/appends. Persisted state types (including `HotConfig`) serialize directly and expose their update timestamp through `field_updated`; JSON updates use an exclusive sidecar lock and atomic replacement. Unchanged updates preserve a nonzero timestamp/file, while a zero timestamp is initialized on first framework write. Socket-driven HotConfig changes persist through `process_and_save`; use the returned/mutated persisted config as the next in-memory snapshot. WAL appends use a boot-scoped lock, boot rotation, and sync. `sp meta processes|kill` reads the process WAL; kill requires a matching logged PID/start-time and executable identity plus confirmation.
- `sp --state <source> migrate --to <target>` stages a distinct root with top-level symlinks, leaving the source unchanged. `--rm` removes an existing target through `sys::remove_path_recursive`, then stages the new migration. `--finish` removes all staged links first, then moves source entries to the target without traversing nested symlinks; Unix sockets are excluded. Legacy `<state-root>/rootfs` moves to global `/rootfs`, independent of the selected state root. A migration plan in the target permits resuming an interrupted move. State created under the target while staged may add ordinary entries alongside the links. Removal refuses the source, an ancestor of the source, or a symlink in place of the target directory. Migration and target removal check the selected root's process WAL and prompt before sending SIGTERM to attributable active processes. `sp rm <path> --recurse` uses the same recursive unmount/removal behavior.

## Sandboxing and mounts

- `SandboxMode` and `TemplateConfig.sandbox_mode`: `crates/nsproxy-core/src/lib.rs`.
- Pivot orchestration: `apply_pivot`, `build_skeleton`, `apply_mounts`, `apply_chmod`, `detect_sandbox_state`, `assert_mount_ns_isolated` in `crates/nsproxy-core/src/sandbox.rs`.
- Mount primitives: `mount_bind_rw_explicit`, `mount_bind_ro_explicit`, `mount_tmpfs`, `pivot_root_into`, `mount_bind_root` in `crates/nsproxy-core/src/sys.rs`.
- Profile-scoped staging path: `state_paths::pivot_root_dir`.

## Spawning in a namespace

Daemonized workloads should outlive the UI action and remain supervised by `sp up`:

- UI commands: `SupervisorCommand::{StartDaemon,StartServe}` in `crates/nsproxy-ui/src/supervisor.rs`.
- Wire requests: `DaemonRequest::{Spawn,SpawnCli}`.
- `handle_up_client` dispatches to `spawn_daemon_process` or structured memfd-based `spawn_cli_process` in `crates/nsproxy-core/src/bin/nsproxy.rs`.
- Tracking lives in `UpDaemonState.process_list`; updates use `ProcessListSnapshot` and `DaemonEvent::ProcessExit`.
- Privileged UI launches choose the `sproxy` wrapper via `nsproxy_path` and `spawn_nsproxy_cli`; `sproxy` authenticates and re-execs `nsproxy`.

Non-daemonized interactive work should exit with its process tree:

- `enter_ns` enters namespaces from `NsAlive` in `crates/nsproxy-core/src/cmd_common.rs`.
- `ShellPrefs::{spawn_in_ns,spawn}` performs clone, setns, and exec in `crates/nsproxy-core/src/shell.rs`.
- `MainCommand::Sandbox` uses this path with pivot/mount orchestration. See [case-sp-sandbox-hotconfig-mounts.md](case-sp-sandbox-hotconfig-mounts.md) for the current HotConfig mount behavior and risks.

## Hotconfig watcher boundary

- `sp sandbox` initially reads `hot.json`, expands paths, merges `mnt` and `mounts`, and applies those mounts after sandbox setup. This also applies in Overlay mode, where no pivot occurs; `TemplateConfig.mounts` are only applied by the pivot path.
- `sp serve` deliberately skips live HotConfig mount reconciliation. `watch_hot_mounts` exists but currently has no caller, so `hot.json` changes do not automatically reapply `mnt` / `mounts`.
- The watcher does not create, remove, or reconfigure veth pairs. `sp up` reconciles persisted `HotConfig.veth` entries and writes per-entry results to `veth_status.json`; temporary requests use the separate `MainCommand::Veth` path documented in `agentic/ui.md`.
