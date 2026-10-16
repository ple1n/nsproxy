# nsproxy UI

Load this note for egui layout, widgets, profile editors, process/traffic views, and visual interaction conventions. IPC behavior belongs in `agentic/ipc-diagnostics.md`; external terminal windows belong in `agentic/terminal.md`.

## Architecture and search map

Most rendering is in `crates/nsproxy-ui/src/main.rs`.

- Sidebar: `egui::SidePanel::left`, `sidebar_box`, `sidebar_box_width`; its contents scroll within the panel's available height.
- Main tabs: `render_proxies_tab`, `render_processes_tab`, `render_traffic_tab`, `render_diagnostics_tab`, `render_dns_tab`, `render_hotconfig_tab`, `render_profile_editor_tab`.
- Proxy table/details: `render_proxies_table`, `render_proxy_row`, `render_proxy_detail_window`, `render_mini_sparkline`.
- Process controls: `render_process_controls`, `render_units_table`, `render_hotconfig_daemons_section`, `render_run_command_section`.
- In the Processes tab, the profile heading expands to a `RUST_BACKTRACE=1/0` toggle. The setting applies to subsequent UI launches of both `sp up` and `sp serve`; it defaults to `0`. Direct terminal launches continue to honor the shell's `RUST_BACKTRACE` environment.
- Traffic: `TrafficSubview`, `selected_traffic_conn`, `diag_event_log`, `render_diag_event_row`.
- Proxies table: imported Clash proxies belong to user-owned groups. The import controls add a new group (defaulting its name to the file stem) or replace all data in an existing group. Group rows are collapsed by default; `App.expanded_proxy_groups` is the UI-owned expansion state, exposed as toggles below Sort Frequency. Group rows can select the whole group for routing; runtime selection prefers success rate, then latency, and retries another group member after failures. `HotRoute::Group` and `RoutingState.selected_group` carry the group selection. A separate NoProxy row selects `HotRoute::NoProxy`; `HotRoute::None` remains the no-route state. Route selection is backend-confirmed: the UI updates only after serve emits `RoutingState` for the successfully applied hot config.
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

`egui_log_viewer` is the independent, generic row viewer for structured logs.
It virtualizes rows with cached measured heights, tracks drag and Shift-click/
drag selection as an inclusive row range, paints the range with a subdued
rounded highlight and accent edge, and edge-scrolls while dragging outside the
viewport. Wheel/scrollbar scrolling remain available during selection
(drag-to-scroll is disabled). Render rich row contents through its callback;
egui label text selection is disabled by default throughout the callback UI, so
dragging selects rows instead of text. Ctrl+C copies the selected rows in the
plain-text format supplied by the caller; the widget handles selection,
focus, and clipboard output. Callback content gets compact default spacing
(8 points horizontally, 3 vertically) and rows have a 4-point gap; callbacks
can override their own `ui.spacing_mut()` when needed. Run
`cargo run -p egui_log_viewer --example interactive` to compare the nsproxy
log presentation (source, level, target, ANSI-highlighted message, and fields)
with a regular multiline editor. Nsproxy log rows and the interactive example
share a One Dark-inspired syntax palette on a near-black background.

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
- `Save` serializes the editor value and sends `SupervisorCommand::SaveHotconfigPrivileged`. The supervisor preserves the live proxy route, writes `hot.json` through the privileged root daemon, and refreshes its cache. Pivot sandbox reconciliation is manual through `Apply Sandbox`.
- The shared veth card has an `on container creation` toggle. Enabled cards serialize to `HotConfig.veth`; `sp up` reconciles those entries when the profile becomes alive. Disabled cards remain temporary UI state and `Create veth pair` sends the same command immediately without modifying `hot.json`.
- The veth command launches `nsproxy` with `MainCommand::Veth`, which resolves both running namespace endpoints, removes stale same-name links, allocates a free `100.64.0.0/10` subnet, creates the link with netlink, moves each endpoint into its namespace, and configures both addresses.
- `sp up` persists per-entry startup results in `veth_status.json`; the UI loads the latest persisted result after restart and overlays temporary request results while they are active. A failed attempt is reported and logged; it is not silently retried or assigned a different address.

## Traffic connection view

- The Traffic Connections sub-view renders supervisor-precomputed newest-first active and recently-finished ID lists; keep filtering and ordering out of egui render functions.
- Rows summarize the lifecycle phase and retain the last useful non-drop route. The `Routing` phase is displayed as `connecting`: the route decision has been selected and the upstream connection has not yet emitted `Connected`. Hovering the Route cell shows the final state/error and a bounded, scrollable transition timeline with relative age and local `HH:MM` timestamps.
- Finished TCP/UDP rows remain according to `HotConfig.diag_conn_persist_secs`; `ConnectionsExpired` deltas remove them promptly. The Traffic view also displays up to 512 of the most recently observed serve-computed TCP latency, success-rate, and separate TCP/UDP directional throughput estimates, keyed by full SOCKS5 `WireAddress` target and exact route. Throughput cells show the decayed estimate and expose the latest qualified event-window sample on hover; the UI does not calculate rates.
- The host/route table covers TCP and UDP and exposes Kill/Route actions only from the Route label's interactive egui tooltip, aligned to the right of the hovered label with `RectAlign::RIGHT_START`. Both the host/route action tooltip and connection-history Route tooltip summarize proxy routes with the matched proxy's name, redacted endpoint, latency, connection health, and UDP capability; resolve the route ID through the existing proxy catalog rather than formatting only its ID. The Traffic tab scopes `tooltip_delay = 0` and disables the still-pointer gate for that render pass so both popups open immediately. Attach tooltips directly to their label responses and register them every render pass; do not gate them on `hovered()` or `is_tooltip_open()`. Use native egui tooltip anchoring rather than custom pointer-position popup state. The "Click button to route to" popup includes a search field and selectable route keys with direct-route or proxy-URL summaries; it closes on outside clicks, stays open while clicking the search input, and reserves stable content height. Route display/filter data is prepared when proxy snapshots change, and filtered row indexes are rebuilt outside the egui render pass. Route applies a host-wide HotConfig override through `sp serve`; Kill closes active TCP/UDP flows for that host.

## Editing convention

Preserve local source formatting. Do not run broad `cargo fmt` for focused UI work. Validate changes with the narrowest available check, normally `cargo check -p nsproxy-ui`.
