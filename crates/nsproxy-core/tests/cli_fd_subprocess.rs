//! Integration test: spawn the real `nsproxy` binary with a bincode-encoded
//! `Cli` passed via an inheritable memfd.  The `Id` subcommand is used because
//! it is stateless, requires no privileges, and exits immediately.

use std::fs::create_dir_all;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nsproxy_core::{Cli, MainCommand};

/// Create a **non-CLOEXEC** memfd, write a bincode-encoded [`Cli`] into it,
/// seek back to 0, and return the raw fd number.
///
/// The fd is intentionally not wrapped in `OwnedFd` here — the caller is
/// responsible for closing it after the child process exits.
fn cli_to_inheritable_memfd(cli: &Cli) -> i32 {
    // MFD_CLOEXEC is deliberately omitted so the child inherits the fd.
    let raw = unsafe { libc::memfd_create(c"nsp-test-cli".as_ptr(), 0) };
    assert!(
        raw >= 0,
        "memfd_create failed: {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: fresh fd, owned exclusively until `std::mem::forget` below.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    bincode::serialize_into(&mut file, cli).expect("bincode serialize");
    file.seek(SeekFrom::Start(0)).expect("seek");

    // Keep the fd alive past the `File` drop.
    std::mem::forget(file);
    raw
}

#[test]
fn subprocess_id_via_memfd() {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();
    let root = PathBuf::from(format!("/tmp/nsproxy-core-test-{unique_suffix}"));
    create_dir_all(&root).expect("create temp root");

    let cli = Cli {
        conf: None,
        root: Some(root.clone()),
        no_wrap_check: false,
        control_socket: None,
        cmd: MainCommand::Id { pid: None },
    };

    let fd = cli_to_inheritable_memfd(&cli);

    let bin = env!("CARGO_BIN_EXE_nsproxy");
    let output = Command::new(bin)
        .arg(fd.to_string())
        .output()
        .expect("failed to spawn nsproxy");

    // Close the fd in the parent after the child has exited.
    unsafe { libc::close(fd) };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "nsproxy exited with {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );

    println!("{stdout}");
}
