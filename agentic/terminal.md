# Terminal integration

Load this note for external/inline terminal windows, titles, PTY attach behavior, and keyboard mappings.

## Window titles

- UI title composition: `format_external_terminal_title`, `attach_swap_pty_window`, and `open_dedicated_pty_window` in `crates/nsproxy-ui/src/main.rs`.
- The base title is `container - program - uid` and is forwarded in `TermWindowRequest::Attach`.
- Immediate attach/reset: `shared.reset_terminal(&title)` in `crates/nsproxy-ui/src/alacritty_window.rs`.
- Shell title updates extend rather than replace the assigned title: `compose_window_title`, `TerminalEvent::Title`, and `TerminalEvent::ResetTitle` in `crates/term-view/src/alacritty_port/window_context.rs` and `event.rs`.

## Ctrl+Backspace

- External runtime wiring: `ExternalViewportRequest::create_window_context` and `WindowContext::external` in `crates/term-view/src/alacritty_runtime.rs`.
- External Alacritty default binding: search `default_key_bindings`, `Backspace, ModifiersState::CONTROL`, and `Action::Esc("\\x17".into())` in `crates/term-view/src/alacritty_port/config/bindings.rs`.
- Inline egui path already maps Ctrl+Backspace to `^W`; search `egui::Event::Key` and `Key::Backspace if modifiers.ctrl => &[0x17]` in `crates/term-view/src/lib.rs`.
