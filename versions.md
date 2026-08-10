
Document the versioning of config schema etc.

The version is a numeric field in any schema. All things related to migration and compatibility must be documented here.

---

## TemplateConfig (`profile.json`)

The `schema` field in `profile.json` controls per-profile config versioning.
`TemplateConfig::load()` applies migrations before returning.

### Schema 1 (legacy)

- No `dbus` field (or the field was a `bool`).
- **D-Bus behavior**: Pass — `DBUS_SESSION_BUS_ADDRESS` was inherited from the
  parent process environment via `ShellPrefs::adjust()`, which captured the full
  env before any dbus-mode logic ran. Result: the host session bus was always
  accessible inside the container unless the user manually unset it.
- **Migration in `load()`**: any schema-1 profile is unconditionally coerced to
  `dbus: Pass` regardless of what the JSON says.

### Schema 2 (current)

- Introduces the explicit `dbus` field with three modes:
  - `"block"` — `DBUS_SESSION_BUS_ADDRESS` is stripped from the spawn env after
    `adjust()` via `ShellPrefs::strip_dbus_env()`. The socket is not accessible
    inside the container. **This is the default for new configs.**
  - `"pass"` — nothing is done; the host `DBUS_SESSION_BUS_ADDRESS` propagates
    naturally through `adjust()`. The host session bus is accessible as-is.
    For Pivot sandbox this only works if the socket path is also bind-mounted in.
  - `"proxy"` — nsproxy runs a private `busd` daemon inside the container.
    `DBUS_SESSION_BUS_ADDRESS` is replaced with the per-profile socket path
    (`@/bus.sock`). Container processes talk to each other; host services are
    not reachable.
- Absent `dbus` field in schema-2 JSON defaults to `"block"`.
- `TemplateConfig::default()` and all wizard-created profiles start at schema 2.
- Legacy `"dbus": true` (old bool) is deserialized as `Proxy`.
  Legacy `"dbus": false` (old bool) is deserialized as `Pass`.

#### How Block is enforced

`ShellPrefs::adjust()` always captures the current process environment,
including any inherited `DBUS_SESSION_BUS_ADDRESS`. Block mode calls
`ShellPrefs::strip_dbus_env()` **after** `adjust()` to remove the entry from
`self.env` before `execve`. This is the only correct place to strip it.

For daemon-spawned processes (via `spawn_cli_process` / `build_spawn_env_cstrings`),
the env is built from scratch and `DBUS_SESSION_BUS_ADDRESS` is omitted for Block
(not added back) and included for Pass/Proxy.

#### Pass with Pivot sandbox

In Pivot mode the root is replaced. If the D-Bus socket lives under `/run/user/UID/`,
that path must be bind-mounted into the new root for Pass (or Proxy) to work.
The Firefox template includes the necessary mounts. Overlay mode requires no
extra mounts since the host filesystem remains visible.
