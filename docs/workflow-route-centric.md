
# Workflow: Route centric

## Purpose and scope

“Workflow” names this user activity and the additive nsproxy feature layer that makes it easier. It is not an application concept, a replacement container type, or a replacement for existing profile, template, HotConfig, CLI, or GUI behavior.

A workflow centers on a small, reusable set of `RoutingPrefs`, typically for a program or environment: for example, Fedora DNF, `huggingface-cli`, or Docker. These activities may need separate containers because of network, identity, or isolation requirements. A user may start one with Pivot for an anonymized identity or without Pivot for ordinary use, while continuing to choose the existing template, sandbox, and runtime parameters.

The initial implementation layers workflow operations over existing containers and their lifecycle. Existing container and configuration workflows remain available; no existing fields or capabilities are removed or silently changed.

## Routing preferences

`RoutingPrefs` is a higher-order, standalone routing preference set with two lists:

- `symbols`: named variables with optional auxiliary user data such as a comment. The predefined names are `direct` and `alternate`. These names are reusable labels, not concrete proxy identities.
- `routes`: rules that reference a symbol by name. A rule may target one final destination endpoint (`SocketAddress` or `DomainAddress`, including its port); a rule with no `destination` is the default route used when no destination-specific rule matches.

The conceptual JSON shape is:

```json
{
  "symbols": [
    { "name": "direct", "comment": "Direct connection" },
    { "name": "alternate", "comment": "Alternate route" }
  ],
  "routes": [
    { "symbol": "direct" },
    { "destination": { "DomainAddress": ["huggingface.co", 443] }, "symbol": "alternate" }
  ]
}
```

The JSON field names and endpoint encoding follow the SOCKS `WireAddress` distinction: socket addresses and domain addresses are different endpoint types and retain their port. A route must reference a symbol declared in `symbols`; symbol names are unique; there is at most one default rule and at most one rule per canonical destination endpoint. Applying rules selects an exact destination match first and otherwise the default rule. A TUN virtual ingress IP is not a final destination selector and must never be converted to one; route matching receives only the resolved final destination. This distinction is semantic, not based solely on numeric IP equality. `RoutingPrefs` does not own DNS, mounts, daemons, applications, veths, Pivot settings, concrete route bindings, or other `HotConfig` / profile / template state. Applying routing preferences must preserve those unrelated settings.

At apply/start time, symbols are resolved to concrete routes separately from the preferences. `direct` resolves automatically; the user selects the concrete destination-supported route for `alternate`. That selection may differ between containers while the same preferences file is reused. Resolution must be complete before mutation. A missing or unsupported alternate binding is an explicit error, never a silent fallback. The resolved concrete routes are written into the existing `HotConfig` representation (`HotRoute` and `HostRouteRule` / `ObservedRoute`).

### Existing JSON compatibility

The existing `~/dnf_hotconfig.json` and `~/hf_hotconfig.json` are full `HotConfig` documents, not `RoutingPrefs` documents. Both demonstrate a direct default and host-specific use of the same concrete alternate route. Workflow import accepts either:

1. A `RoutingPrefs` document, read directly.
2. A legacy full `HotConfig` document, from which only `route` and `host_routes` are read, with an explicit mapping step from concrete routes to the predefined variables.

For these examples, import maps the concrete `NoProxy` route to `direct` and the shared proxy route to `alternate`; the user confirms/selects the alternate binding rather than persisting the example proxy ID as its meaning. For other legacy files, never infer symbolic equivalence from arbitrary proxy IDs: show the concrete routes and require the user to map them to `direct` / `alternate` or cancel. Exporting preferences from an existing container uses the same explicit mapping step; a concrete proxy ID is never silently assigned the symbolic meaning `alternate`. Legacy import must not apply the other `HotConfig` fields. New exports use the standalone symbolic shape, so they stay compact and safe to reuse. Parsing, mapping, or validation errors are shown and do not modify a profile.

## Workflow operations

The workflow layer provides the same core operations through CLI and GUI:

- **Inspect / export:** view or save a profile’s routing preferences as standalone JSON, explicitly mapping concrete runtime routes back to symbols when needed.
- **Import:** load a standalone preferences file or map concrete routes from a legacy `HotConfig` to symbolic variables; importing by itself only populates a draft and never changes a container.
- **Start with preferences:** create/start a container using the existing profile/template and lifecycle mechanisms, applying the selected routing preferences while retaining the user’s choices of template, Pivot/sandbox mode, identity, and other supported parameters.
- **Bind variables:** choose the concrete destination-supported route that realizes `alternate`. Keep the binding separate from the reusable preferences and make it visible/reviewable for each start or apply operation.
- **Apply to an existing container:** resolve variables for that destination, then choose an explicit mode before writing:
  - **Replace:** replace the container’s complete default/host routing rule set with the imported preferences.
  - **Merge:** retain current host rules whose canonical host is absent from the imported preferences; imported rules replace current rules for the same canonical host. An imported default rule replaces the current default rule; if absent, retain the current default.

Resolve every preference variable to a concrete runtime route before replace/merge. Host identity for duplicate detection is canonicalized using the existing `HostRouteHost` rules: domain names are trimmed, lowercased, and stripped of trailing dots; IP addresses compare by parsed address. A host has at most one resulting rule. Preserve deterministic output ordering (existing retained rules in their prior order, then imported rules in their input order, with replacements occupying the existing host’s position).

Both apply modes change only routing preferences. They preserve all unrelated `HotConfig` fields, profile/template settings, and running-state lifecycle choices. Applying to a running container uses the existing HotConfig update mechanism and reports success only after the normal update result is received; rejected updates are surfaced and do not appear as successful. Applying to a stopped container updates its persisted configuration through the existing profile/config write path.

The merge rule intentionally treats the imported default rule as authoritative when one is present, even when it references `direct`. A preferences document without a default rule does not change the destination’s default route. Do not silently infer intent from an empty route list.

## CLI and GUI requirements

The CLI and GUI are two front ends to the same `RoutingPrefs` parsing, validation, canonicalization, and apply/merge implementation. They must not maintain separate merge semantics.

- CLI exposes operations to inspect/export preferences, import/validate a file, start a container with preferences, bind `alternate` to a concrete route for that operation, and apply preferences to an existing container using explicit replace or merge mode.
- Starting with preferences composes with existing template/profile creation, Pivot/sandbox, and runtime options; it does not add a parallel container lifecycle or bypass existing validation and privilege boundaries.
- GUI presents preferences as an editable, reviewable draft before applying. It allows choosing the existing container/template, Pivot/sandbox mode, and other supported creation parameters when starting a container; for an existing container it shows the selected replace/merge behavior before confirmation.
- GUI and CLI report parse, validation, persistence, and live-apply failures explicitly. Every referenced symbol must be defined and every used symbol must resolve to a concrete route for the destination; unresolved symbols or bindings block the apply and identify the offending rule. Neither front end may silently fall back to defaults or partially apply invalid preferences.
- Existing profile HotConfig editing, container actions, and all unrelated UI and CLI behavior remain available.

## Acceptance criteria

1. The DNF and Hugging Face example HotConfigs import as preferences with a default rule referencing `direct` and their host rules referencing `alternate`; no DNS, device, mount, daemon, application, veth, diagnostics, or concrete proxy identity leaks into the workflow draft or export.
2. Exporting preferences and importing that export preserves symbolic route choices and host rules without requiring the original proxy ID.
3. Starting a new container with either example resolves the selected `alternate` binding and applies its routing preferences while respecting the user-selected existing template and Pivot/sandbox options.
4. Replace and merge produce the exact results defined above, including canonical domain duplicates, IP hosts, documents without a default rule, and explicit rules referencing `direct`.
5. Applying preferences leaves every non-routing `HotConfig` field and profile/template setting unchanged.
6. Invalid files, unresolved variables, unsupported alternate bindings, failed writes, and rejected live updates are reported; the prior configuration remains effective.
7. Existing container creation, profile editing, and CLI/UI operations still work without using the workflow layer.

## Implementation boundary

First define and test the shared `RoutingPrefs` type and pure conversion/replace/merge operations. Then add CLI commands and GUI workflow surfaces that call those operations and existing lifecycle/update APIs. Keep the first release focused on routing preferences and the two demonstrated use cases; do not move unrelated settings into `RoutingPrefs` or redesign existing container/profile abstractions as part of this work.