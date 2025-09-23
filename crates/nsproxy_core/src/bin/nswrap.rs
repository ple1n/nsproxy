//! Wrapper for programs that do not handle segregated identities natively.
//! This is meant to drop in replace/mask executables.

use std::{
    env,
    ffi::{CStr, CString, OsString},
    os::unix::ffi::OsStringExt,
    str::FromStr,
};

use nix::unistd::execve;

fn main() {
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
    println!("Executing wrapped binary: {:?}", wrapped);
    let k = execve(
        &CString::from_str(wrapped.to_str().unwrap()).unwrap(),
        &args,
        &env,
    );
    println!("exited with {:?}", k);
}
