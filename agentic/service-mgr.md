# Service manager crate

Load this note for the independent `service-mgr` prototype.

- Crate root: `crates/service-mgr/src/lib.rs`.
- Demo binary: `crates/service-mgr/src/bin/demo.rs`.
- The crate is intentionally independent of `nsproxy-core` and existing daemon/UI code.
- `ServiceManager` owns PTY and pipe-backed services, lifecycle events, ownership metadata, process-group signaling, input, resize, and termination.
- `OutputHub` provides bounded replay plus live subscribers for PTY byte streams.
- `OutputHub` also exposes per-stream cursors and replay results that report when the bounded history has been truncated.
- Each service can use a bounded framed `Journal` under a runtime root; `ServiceManager::journal_path` and `journal_replay` expose crash-recoverable output history. Runtime selection prefers `$XDG_RUNTIME_DIR/nsproxy`, then `/run/nsproxy`, then `/tmp/nsproxy`.
- The demo uses `eframe`/`egui` and the existing `term-view` crate to render a nested supervisor topology: a root manager owns profile-manager services, and each profile manager owns independent PTY and pipe services.
- The demo aggregates manager events into a bounded event journal view, while retaining one terminal session per `(manager, service)` key.
- Each service row has `switch`, always-enabled `popup`/`close`, and `kill` controls. A popped-out service renders a placeholder in the embedded slot; `switch` is disabled for popped-out services.
- Popup and embedded terminals share the same per-service `TermSession`; the UI only renders one view for a service at a time to avoid concurrent terminal mutation and duplicate PTY handling.
- PTY events are bridged to the egui context with event-driven `request_repaint`; the demo does not use timer-based repaint polling.
- Linux PTY setup is currently implemented with `posix_openpt`, `fork`, `setsid`, `TIOCSCTTY`, and `execvp`; non-PTY services use piped stdin/stdout/stderr.
- Validate the prototype with `cargo check -p service-mgr`, `cargo test -p service-mgr`, and `cargo check -p service-mgr --bin service-mgr-demo`.

Keep nsproxy integration separate until the service-manager API and lifecycle semantics stabilize.
