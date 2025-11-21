//! Wrapper for programs that do not handle segregated identities natively.
//! This is meant to drop in replace/mask executables.

use std::{
    borrow::Cow,
    collections::VecDeque,
    env,
    ffi::{CStr, CString, OsString},
    os::unix::ffi::OsStringExt,
    str::FromStr,
};

use atty::Stream;
use clap::Parser;
use notify_rust::Notification;
use nsproxy_core::{
    Cli, MainCommand,
    env::{ENV_NSWRAP, ENV_PROFILE, NswrapEnv},
    to_cstr,
};
use procfs::process::Process;
use std::fs::OpenOptions;
use std::io::{self, Write};

use nix::unistd::execve;

fn is_interactive() -> bool {
    // atty quick check
    if atty::is(Stream::Stdin) || atty::is(Stream::Stdout) || atty::is(Stream::Stderr) {
        return true;
    }

    false
}

fn prompt_confirm(prompt: &str, default: bool) -> bool {
    // If not interactive, return default
    if !is_interactive() {
        return default;
    }

    let hint = if default { "Y/n" } else { "y/N" };

    // Fallback to stdin/stdout
    print!("{} [{}] ", prompt, hint);
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let ans = input.trim().to_ascii_lowercase();
        if ans.is_empty() {
            return default;
        }
        return matches!(ans.chars().next(), Some('y'));
    }
    default
}

/// Abstraction for sending notifications and asking for confirmation.
trait Prompt {
    fn notify(&mut self, summary: Option<&str>, body: &str);
    fn confirm(&mut self, prompt: &str, default: bool) -> bool;
    fn set_silent(&mut self, silent: bool);
}

/// TTY-based prompt (interactive terminal)
struct TtyPrompt {
    /// Make this whole thing skipped. Confirms pass by True, and still print logs
    silent: bool,
}

impl Prompt for TtyPrompt {
    fn notify(&mut self, _summary: Option<&str>, body: &str) {
        // on TTY, just print the message
        eprintln!("{}", { body });
    }
    fn confirm(&mut self, prompt: &str, default: bool) -> bool {
        if !self.silent {
            prompt_confirm(prompt, default)
        } else {
            self.notify(None, prompt);
            true
        }
    }
    fn set_silent(&mut self, require: bool) {
        self.silent = require
    }
}

/// Desktop prompt implementation. Tries `zenity` or `kdialog` for confirmations
/// (graphical dialogs). For notifications, uses `notify-send` if available as a
/// fallback to DBus notifications.
struct DesktopPrompt {
    silent: bool,
}

impl DesktopPrompt {
    fn run_cmd_confirm(cmd: &str, args: &[&str]) -> Option<bool> {
        match std::process::Command::new(cmd).args(args).status() {
            Ok(status) => Some(status.success()),
            Err(_) => None,
        }
    }

    fn send_notification_cmd(summary: Option<&str>, body: &str) {
        // try DBus notification via notify-rust, fall back to notify-send
        if {
            let mut n = Notification::new();
            n.body(body);
            if let Some(s) = summary {
                n.summary(s);
            }
            n.show().is_err()
        }
        {
            let _ = std::process::Command::new("notify-send")
                .arg("nswrap")
                .arg(body)
                .status();
        }
    }
}

impl Prompt for DesktopPrompt {
    fn notify(&mut self, summary: Option<&str>, body: &str) {
        // best-effort: try notify-send, otherwise print to stderr
        if !self.silent {
            DesktopPrompt::send_notification_cmd(summary, body);
        }
    }
    fn set_silent(&mut self, require: bool) {
        self.silent = require
    }
    fn confirm(&mut self, prompt: &str, default: bool) -> bool {
        if self.silent {
            true
        } else {
            // try zenity
            if let Some(res) =
                DesktopPrompt::run_cmd_confirm("zenity", &["--question", "--text", prompt])
            {
                return res;
            }

            // try kdialog
            if let Some(res) = DesktopPrompt::run_cmd_confirm("kdialog", &["--yesno", prompt]) {
                return res;
            }

            // fall back to notify and default
            DesktopPrompt::send_notification_cmd(None, prompt);
            default
        }
    }
}

/// Choose appropriate prompt implementation:
/// - If we detect an interactive TTY, use TtyPrompt
/// - Otherwise, if desktop session env present, use DesktopPrompt
fn detect_prompt() -> Box<dyn Prompt> {
    let is_tty = is_interactive();
    if is_tty {
        return Box::new(TtyPrompt { silent: false });
    }

    // heuristics for desktop session
    let has_display = std::env::var_os("DISPLAY").is_some()
        || std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("XDG_SESSION_TYPE").is_some()
        || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();

    if has_display {
        return Box::new(DesktopPrompt { silent: false });
    }

    // final fallback to TTY behavior
    Box::new(TtyPrompt { silent: false })
}

use anyhow::Result;

fn main() -> Result<()> {
    let self_exe = std::env::current_exe().unwrap();
    let wrapped = self_exe.with_extension("wrapped");
    let args = env::args()
        .map(|k| CString::new(k).unwrap())
        .collect::<Vec<_>>();
    let mut env: VecDeque<CString> = env::vars()
        .map(|(k, v)| {
            let mut s = k;
            s.push('=');
            s.push_str(&v);
            CString::new(s).unwrap()
        })
        .collect();
    let program = self_exe.file_name();
    let Some(name) = program else {
        let mut prompt = detect_prompt();
        prompt.notify(None, &format!("{:?}. can not get file name", self_exe));
        return Ok(());
    };
    let name = name.to_string_lossy();
    let mut prompt = detect_prompt();
    if let Ok(flag) = env::var(ENV_NSWRAP) {
        if flag == NswrapEnv::Confirm.as_ref() {
            prompt.set_silent(true);
        }
    }

    let profile = std::env::var(ENV_PROFILE);
    if let Ok(profile) = profile {
        let profile = if profile == "UNSPEC" {
            None
        } else {
            Some(profile)
        };

        env.push_front(to_cstr(&format!("{}={}", ENV_NSWRAP, NswrapEnv::Confirm)));

        match name {
            Cow::Borrowed("librewolf") | Cow::Borrowed("firefox") => {
                if let Some(pp) = profile {
                    let url = {
                        if let Some(arg1) = args.get(1) {
                            if arg1.to_string_lossy().to_lowercase() == "-p" {
                                args.get(3)
                            } else {
                                Some(arg1)
                            }
                        } else {
                            None
                        }
                    };
                    if let Some(url) = url {
                        if !prompt.confirm(
                            &format!(
                                "Execute {:?} -P {} {:?}",
                                self_exe,
                                pp,
                                url.to_string_lossy()
                            ),
                            true,
                        ) {
                            prompt.notify(None, "Aborted by user.");
                            return Ok(());
                        }
                        let exe_args = [
                            to_cstr(wrapped.to_str().unwrap()),
                            to_cstr("-P"),
                            to_cstr(&pp),
                            url.to_owned(),
                        ];
                        let k = execve(
                            &CString::from_str(wrapped.to_str().unwrap()).unwrap(),
                            &exe_args,
                            env.make_contiguous(),
                        );
                        prompt.notify(None, &format!("exited with {:?}", k));
                    } else {
                        if !prompt.confirm(&format!("Execute {:?} -p {}", self_exe, pp), true) {
                            prompt.notify(None, "Aborted by user.");
                            return Ok(());
                        }
                        let exe_args = [
                            to_cstr(wrapped.to_str().unwrap()),
                            to_cstr("-P"),
                            to_cstr(&pp),
                        ];
                        let k = execve(
                            &CString::from_str(wrapped.to_str().unwrap()).unwrap(),
                            &exe_args,
                            env.make_contiguous(),
                        );
                    }
                } else {
                    prompt.notify(None, "can not find relevant nsproxy data");
                }
            }
            _ => {
                prompt.notify(None, "unsupported");
            }
        }
    } else {
        prompt.notify(Some("nswrap needs a context"), "Use sproxy enter or other commands to enter a shell. Application not started for security reasons");
    }

    Ok(())
}
