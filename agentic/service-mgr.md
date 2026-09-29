# Service manager crate

Load this note for the independent `service-mgr` prototype.

- Crate root: `crates/service-mgr/src/lib.rs`.
- Demo binary: `crates/service-mgr/src/bin/demo.rs`.
- The crate is intentionally independent of `nsproxy-core` and existing daemon/UI code.
- `ServiceManager` currently owns PTY-backed services, lifecycle events, input, resize, and termination.
- `OutputHub` provides bounded replay plus live subscribers for PTY byte streams.
- The demo uses `eframe`/`egui` and `alacritty_terminal` to render a service inventory with selectable embedded terminal sessions.
- Linux PTY setup is currently implemented with `posix_openpt`, `fork`, `setsid`, `TIOCSCTTY`, and `execvp`.
- Validate the prototype with `cargo check -p service-mgr`, `cargo test -p service-mgr`, and `cargo check -p service-mgr --bin service-mgr-demo`.

Keep nsproxy integration separate until the service-manager API and lifecycle semantics stabilize.
