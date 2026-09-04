# Case File: `sp sandbox` and HotConfig Mounts

## Scope

This records the current behavior and concerns around `HotConfig.mnt` / `HotConfig.mounts` and the `MainCommand::Sandbox` path.

## Current control flow

`MainCommand::Sandbox` enters the existing profile mount namespace and verifies it against the namespace registry before doing any mount work (`crates/nsproxy-core/src/bin/nsproxy.rs`, `MainCommand::Sandbox`).

- Pivot mode calls `sandbox::apply_pivot`, which builds the rootfs, applies `TemplateConfig.mounts`, pivots, and then applies the hot-config mounts.
- Overlay mode skips pivoting. It still reads `hot.json`, merges `mnt` and `mounts`, and calls `sandbox::apply_mounts` directly in the existing profile mount namespace.
- In pivot mode, hot-config source paths are expanded through `/pivot`; in Overlay mode they resolve directly in the existing namespace.
- `sp serve` updates DNS-related state but deliberately skips live hot-config mount reconciliation and tells the caller to run `sp sandbox`.

## Concerns

1. **Overlay is not a no-op.** Running `sp sandbox` for an Overlay profile can perform bind mounts directly against the profile's existing mount namespace. The operation must not be described as pivot-only.
2. **Template and hot mounts differ by mode.** `TemplateConfig.mounts` are applied by `apply_pivot`, so they are not applied for Overlay. Overlay receives only the hot-config mount list. Status bookkeeping starts with template mounts, which can make the recorded list look broader than the operations performed.
3. **Hot-config changes are not live.** The active serve path explicitly skips mount reconciliation. The `watch_hot_mounts` function exists, but currently has no caller, so changing `hot.json` does not itself apply new mounts.
4. **Repeated application must remain idempotent.** `sandbox::apply_mounts` checks mountinfo and source/target identity, detaches an existing differing target, and then remounts. Changes to this logic can affect both Pivot and Overlay profiles.
5. **Path meaning changes after pivot.** A source that is valid from the host root must be resolved through `/pivot` after pivot. Any future caller must preserve the matching `PathExpansionState` or risk mounting the wrong path or failing unexpectedly.
6. **Unpivoted profiles expose the host filesystem.** Before a Pivot profile is sandboxed, processes spawned into its namespace still operate on the host root. Applying hot mounts in that state has host-visible consequences and should remain clearly surfaced in warnings and status.

## Verification anchors

- `MainCommand::Sandbox`: `crates/nsproxy-core/src/bin/nsproxy.rs`
- `sandbox::apply_pivot` and `sandbox::apply_mounts`: `crates/nsproxy-core/src/sandbox.rs`
- Serve handoff skip: `crates/nsproxy-core/src/bin/nsproxy.rs`
- Inactive watcher definition: `watch_hot_mounts` in `crates/nsproxy-core/src/bin/nsproxy.rs`

When changing this behavior, validate both `SandboxMode::Pivot` and `SandboxMode::Overlay`, and verify the resulting mount namespace plus `sandbox_status.json`.
