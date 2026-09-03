# nsproxy UI

Load this note for egui layout, widgets, profile editors, process/traffic views, and visual interaction conventions. IPC behavior belongs in `agentic/ipc-diagnostics.md`; external terminal windows belong in `agentic/terminal.md`.

## Architecture and search map

Most rendering is in `crates/nsproxy-ui/src/main.rs`.

- Sidebar: `egui::SidePanel::left`, `sidebar_box`, `sidebar_box_width`.
- Main tabs: `render_proxies_tab`, `render_processes_tab`, `render_traffic_tab`, `render_diagnostics_tab`, `render_dns_tab`, `render_hotconfig_tab`, `render_profile_editor_tab`.
- Proxy table/details: `render_proxies_table`, `render_proxy_row`, `render_proxy_detail_window`, `render_mini_sparkline`.
- Process controls: `render_process_controls`, `render_units_table`, `render_hotconfig_daemons_section`, `render_run_command_section`.
- Traffic: `TrafficSubview`, `selected_traffic_conn`, `diag_event_log`, `render_diag_event_row`.
- Form widgets: `render_optional_u32`, `render_optional_text`, `render_path_field`, `render_mount_list`, `render_chmod_list`, `render_env_map`, `render_string_map`, `render_u32_map`, `render_path_map`, `render_shell_args_list`, `render_shell_args`.

## Render-pass cost boundary

The system is actor-based: the egui UI actor renders and handles input, while
the supervisor actor and worker actors perform collection, parsing, filtering,
sorting, aggregation, filesystem access, and protocol work.

- Absolutely do not use `.iter()` or heavy `for` loops over collections in an egui render pass.
- Do not perform parsing, sorting, filtering, aggregation, filesystem access, blocking locks, or other heavy computation from `render_*` functions.
- Move that work to the supervisor or a dedicated worker actor and send back compact, render-ready snapshots through the existing message/snapshot paths.
- Keep render functions limited to cheap field reads, layout, widget construction, and small bounded UI interaction loops.
- If a mutable editor or view state is needed, keep it in the UI actor and replace it only when a newer asynchronous snapshot arrives; never recompute the source data during widget rendering.

Actor message passing must also be cheap in memory. Do not deep-copy large
vectors, strings, buffers, or snapshots merely to cross an actor boundary; use
`Arc`, shared immutable snapshots, ownership moves, or incremental/delta
messages. Avoid retaining duplicate full representations of the same payload.
At every boundary, make ownership and destruction bounded: do not synchronously
drop or replace a large collection/string in the UI or supervisor thread when
that would zero a large allocation at once. Move expensive construction and
teardown to an appropriate worker actor, or use chunked/incremental updates.

`egui_code_editor` requires a contiguous `TextBuffer` and is not virtualized.
For live or potentially large text, retain one bounded append-only buffer in the
UI actor, send ordered deltas from the producer, and expose only a bounded
suffix to the widget. Do not rebuild the full text, generate a full line-number
gutter, or drive polling through periodic egui repaint requests.

## Compact removal controls

Use `App::remove_icon_button` for compact row/card removal actions, including arguments, virtual DNS routes, and veth drafts.

Recurring UI patterns are worth unifying and documenting. Before adding another
button, indicator, field editor, or status treatment, search for an existing
renderer and extend the shared convention when the semantic role matches.

- Use the Phosphor `regular::X` glyph, not a text `×`, `X`, or `Remove` button.
- Keep the affordance borderless and fixed at 18×18 px so neighboring fields and table columns do not shift.
- Preserve the muted destructive rest color, brighter hover color, and subtle hover fill implemented by the helper.
- Always provide a specific tooltip such as `Remove argument` or `Remove veth pair`.
- Add a different control only when removal requires materially different semantics, such as an armed or confirmation state.

## Hotconfig and veth editor lifecycle

- Form edits mutate `hotconfig_editor_value` and regenerate the JSON editor text; valid JSON edits do the reverse. The UI shows `unsaved` beside `Apply Sandbox` when the editor differs from the loaded profile snapshot or has a JSON error.
- `Save` serializes the editor value and sends `SupervisorCommand::SaveHotconfigPrivileged`. The supervisor preserves the live proxy route, writes `hot.json` through the privileged root daemon, refreshes its cache, and starts sandbox reconciliation.
- The shared veth card has an `on container creation` toggle. Enabled cards serialize to `HotConfig.veth`; `sp up` reconciles those entries when the profile becomes alive. Disabled cards remain temporary UI state and `Create veth pair` sends the same command immediately without modifying `hot.json`.
- The veth command launches `nsproxy` with `MainCommand::Veth`, which resolves both running namespace endpoints, removes stale same-name links, allocates a free `100.64.0.0/10` subnet, creates the link with netlink, moves each endpoint into its namespace, and configures both addresses.
- `sp up` persists per-entry startup results in `veth_status.json`; the UI loads the latest persisted result after restart and overlays temporary request results while they are active. A failed attempt is reported and logged; it is not silently retried or assigned a different address.

## Editing convention

Preserve local source formatting. Do not run broad `cargo fmt` for focused UI work. Validate changes with the narrowest available check, normally `cargo check -p nsproxy-ui`.
