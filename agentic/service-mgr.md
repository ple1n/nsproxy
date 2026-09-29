# Service manager crate

Load this note for the independent `service-mgr` prototype.

- Crate root: `crates/service-mgr/src/lib.rs`.
- Demo binary: `crates/service-mgr/src/bin/demo.rs`.
- The crate is intentionally independent of `nsproxy-core` and existing daemon/UI code.
- `ServiceManager` currently owns PTY-backed services, lifecycle events, input, resize, and termination.
- `OutputHub` provides bounded replay plus live subscribers for PTY byte streams.
- The demo uses `eframe`/`egui` and the existing `term-view` crate to render a service inventory with selectable embedded terminal sessions.
- The demo supports one egui deferred viewport per service as a popup terminal. A popped-out service renders a placeholder in the embedded slot; `switch` is disabled for popped-out services, while the always-enabled `popup`/`close` control opens or closes that service's viewport.
- Popup and embedded terminals share the same per-service `TermSession`; the UI only renders one view for a service at a time to avoid concurrent terminal mutation and duplicate PTY handling.
- PTY events are bridged to the egui context with event-driven `request_repaint`; the demo does not use timer-based repaint polling.
- Linux PTY setup is currently implemented with `posix_openpt`, `fork`, `setsid`, `TIOCSCTTY`, and `execvp`.
- Validate the prototype with `cargo check -p service-mgr`, `cargo test -p service-mgr`, and `cargo check -p service-mgr --bin service-mgr-demo`.

Keep nsproxy integration separate until the service-manager API and lifecycle semantics stabilize.
