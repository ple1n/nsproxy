# Workspace knowledge index

Use this file as a compact cognitive index. Its topology should be small-world:
concepts are nodes and references are edges, so a relevant note is reachable
through a short path from the task's concept. Minimize lookup time complexity
over tool calls: use the index to choose a high-value next edge, avoid broad
directory scans, and stop traversing when the needed evidence is reached.

Do not add co-author sign in commit.

## Core concept graph

- **Runtime lifecycle** → [`agentic/sp-commands.md`](../agentic/sp-commands.md)
  ↔ **persistent state and sandboxing** →
  [`agentic/runtime-state.md`](../agentic/runtime-state.md)
  ↔ **rootfs persistence and bind mounts** →
  [`agentic/concerns-rootfs.md`](../agentic/concerns-rootfs.md)
- **IPC, daemon lifecycle, and diagnostics** →
  [`agentic/ipc-diagnostics.md`](../agentic/ipc-diagnostics.md)
  ↔ **serve log API and network activity** →
  [`agentic/serve-log-api.md`](../agentic/serve-log-api.md)
- **UI views and interaction patterns** →
  [`agentic/ui.md`](../agentic/ui.md)
  ↔ **PTYs and terminal key mappings** →
  [`agentic/terminal.md`](../agentic/terminal.md)
- **Service manager prototype** →
  [`agentic/service-mgr.md`](../agentic/service-mgr.md)
- **Workflow and routing invariants** → [`docs/invariants.md`](../docs/invariants.md)
  ↔ **route-centric workflow** →
  [`docs/workflow-route-centric.md`](../docs/workflow-route-centric.md)
- **Adaptive mode** → [`docs/adaptive_mode.md`](../docs/adaptive_mode.md);
  **Firefox setup/reference** → [`docs/firefox.md`](../docs/firefox.md).

## Local reference and prototype graph

`local/` contains project-specific design material, work-in-progress plans,
configuration examples, and vendored projects. These are not all authoritative
descriptions of current behavior; confirm implementation details in current
source and tests.

- **Architecture and lifecycle overview** →
  [`local/ARCHITECTURE_BLUEPRINT.md`](../local/ARCHITECTURE_BLUEPRINT.md)
  ↔ **sandbox/hotconfig/mount case study** →
  [`agentic/case-sp-sandbox-hotconfig-mounts.md`](../agentic/case-sp-sandbox-hotconfig-mounts.md)
- **Terminal integration plan** →
  [`local/egui_term_integration_plan.md`](../local/egui_term_integration_plan.md)
  ↔ **terminal implementation conventions** →
  [`agentic/terminal.md`](../agentic/terminal.md)
- **Clash resolution refactor plan** →
  [`local/clash-resolution-refactor-plan.md`](../local/clash-resolution-refactor-plan.md)
  ↔ **routing workflow** → [`docs/workflow-route-centric.md`](../docs/workflow-route-centric.md)
- **Nix/Flatpak evaluation** →
  [`local/flatpak-nix-evaluation-report-2026-05-03.md`](../local/flatpak-nix-evaluation-report-2026-05-03.md)
- **Local operational notes**: [`local/local_instruct.md`](../local/local_instruct.md)
  links to [`local/squash_push.md`](../local/squash_push.md);
  [`local/todos.md`](../local/todos.md) is a task list, not a specification.
- **Vendored terminal projects**: [`local/alacritty/README.md`](../local/alacritty/README.md)
  and [`local/egui_term/README.md`](../local/egui_term/README.md) are the entry
  points for their respective codebases. Their nested documentation describes
  those projects, not nsproxy conventions.

## Using this index well

- Choose the closest concept node, then traverse only the links needed to
  understand its dependencies. Prefer this short path over reading whole
  directories.
- Treat implementation and tests as evidence of current behavior; treat
  plans, blueprints, reports, and TODOs as potentially stale until verified.
- When sources disagree, identify which source owns the behavior, inspect its
  code/tests, and report unresolved uncertainty rather than silently choosing
  the most convenient claim.
- After a durable change, update the narrowest owning note and this graph only
  if a concept, ownership edge, or entry point changed. Avoid duplicating
  detailed guidance here.
