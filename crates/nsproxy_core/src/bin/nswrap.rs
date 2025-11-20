//! Wrapper for programs that do not handle segregated identities natively.
//! This is meant to drop in replace/mask executables.

use std::{
    borrow::Cow,
    env,
    ffi::{CStr, CString, OsString},
    os::unix::ffi::OsStringExt,
    str::FromStr,
};

use atty::Stream;
use clap::Parser;
use nsproxy_core::{Cli, MainCommand, to_cstr};
use procfs::process::Process;
use std::fs::OpenOptions;
use std::io::{self, Write};

use nix::unistd::execve;

fn is_interactive() -> bool {
    // common CI hint
    if std::env::var_os("CI").is_some() {
        return false;
    }

    // atty quick check
    if atty::is(Stream::Stdin) || atty::is(Stream::Stdout) || atty::is(Stream::Stderr) {
        return true;
    }

    // fallback: try /dev/tty (succeeds only when there's a controlling terminal)
    OpenOptions::new().read(true).open("/dev/tty").is_ok()
}

fn prompt_confirm(prompt: &str, default: bool) -> bool {
    // If not interactive, return default
    if !is_interactive() {
        return default;
    }

    let hint = if default { "Y/n" } else { "y/N" };

    // Prefer writing to /dev/tty so redirections don't interfere
    if let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
        let _ = write!(tty, "{} [{}] ", prompt, hint);
        let _ = tty.flush();
        let mut input = String::new();
        use std::io::BufRead;
        let mut reader = io::BufReader::new(tty);
        if reader.read_line(&mut input).is_ok() {
            let ans = input.trim().to_ascii_lowercase();
            if ans.is_empty() {
                return default;
            }
            return matches!(ans.chars().next(), Some('y'));
        }
        return default;
    }

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

/// Walk up the ancestor chain starting from the current process and return
/// the pid of the first process whose `cmdline` first element matches the
/// provided `matcher` closure.
fn find_ancestor_with_cmd_prefix<F>(mut matcher: F) -> Option<i32>
where
    F: FnMut(&str) -> bool,
{
    // First check current process
    let mut pid = std::process::id() as i32;

    // limit depth to avoid pathological loops
    for _depth in 0..128 {
        if pid <= 0 {
            break;
        }

        if let Ok(proc) = Process::new(pid) {
            if let Ok(cmdline) = proc.cmdline() {
                if let Some(first) = cmdline.first() {
                    if matcher(first) {
                        return Some(pid);
                    }
                }
            }

            // move to parent: for the first hop prefer libc::getppid()
            if pid == std::process::id() as i32 {
                let p = nix::unistd::getppid().as_raw() as i32;
                if p == 0 || p == pid {
                    break;
                }
                pid = p;
                continue;
            }

            // otherwise, read ppid from /proc/<pid>/stat
            if let Ok(stat) = proc.stat() {
                let p = stat.ppid as i32;
                if p == 0 || p == pid {
                    break;
                }
                pid = p;
                continue;
            }
            break;
        } else {
            break;
        }
    }

    None
}
use anyhow::Result;

fn main() -> Result<()> {
    let self_exe = std::env::current_exe().unwrap();
    let wrapped = self_exe.with_extension("wrapped");
    let args = env::args()
        .map(|k| CString::new(k).unwrap())
        .collect::<Vec<_>>();
    let env: Vec<CString> = env::vars()
        .map(|(k, v)| {
            let mut s = k;
            s.push('=');
            s.push_str(&v);
            CString::new(s).unwrap()
        })
        .collect();
    let program = self_exe.file_name();
    let Some(name) = program else {
        println!("{:?}. can not get file name", self_exe);
        return Ok(());
    };
    let name = name.to_string_lossy();

    match name {
        Cow::Borrowed("librewolf") | Cow::Borrowed("firefox") => {
            let pp = find_ancestor_with_cmd_prefix(|f| f.starts_with("sproxy"));
            if let Some(pp) = pp {
                let sproxy = Process::new(pp)?;
                let sargs = Cli::parse_from(sproxy.cmdline()?);
                let profile = match sargs.cmd {
                    MainCommand::Run { name, profile, .. } => profile,
                    _ => None,
                };
                let url = args.get(1);
                if let Some(url) = url
                    && let Some(profile) = profile
                {
                    if !prompt_confirm(
                        &format!(
                            "Execute {:?} -P {} {:?}",
                            self_exe,
                            profile,
                            url.to_string_lossy()
                        ),
                        true,
                    ) {
                        println!("Aborted by user.");
                        return Ok(());
                    }
                    let exe_args = [
                        to_cstr(wrapped.to_str().unwrap()),
                        to_cstr("-P"),
                        to_cstr(&profile),
                        url.to_owned(),
                    ];
                    let k = execve(
                        &CString::from_str(wrapped.to_str().unwrap()).unwrap(),
                        &exe_args,
                        &env,
                    );
                    println!("exited with {:?}", k);
                } else {
                    if let Some(profile) = profile {
                        if !prompt_confirm(&format!("Execute {:?} -p {}", self_exe, profile,), true)
                        {
                            println!("Aborted by user.");
                            return Ok(());
                        }

                        let k = execve(
                            &CString::from_str(wrapped.to_str().unwrap()).unwrap(),
                            &args,
                            &env,
                        );
                        println!("exited with {:?}", k);
                    } else {
                        println!("can not find a suitable profile. do nothing")
                    }
                }
            } else {
                println!("can not find relevant nsproxy process")
            }
        }
        _ => {
            println!("unsupported");
        }
    }

    Ok(())
}
