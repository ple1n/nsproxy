/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use futures::AsyncWriteExt;
use futures_lite::future::block_on;
use nix::{
    sched::{CloneFlags, unshare},
    unistd::Pid,
};
use nsproxy_common::{ExactNS, NSFrom, forever};
use nsproxy_core::{
    NsproxyConfig, Paths, PathsBinds, TunMaker,
    sys::{Clone3Result, NSEnter},
    tokio_netlink_conn,
    utils::ToExactNs,
};
use passfd::FdPassingExt;
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, Permissions},
    io::ErrorKind,
    mem::ManuallyDrop,
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tun2socks5::{ArgMode, IArgs, aok, tun_rs::AsyncDevice};

/// NSProxy V3
/// Manage netns redirection with SOCKS5 proxy configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Working state directory
    #[arg(short, long, default_value = "./")]
    state: PathBuf,
    #[command(subcommand)]
    cmd: MainCommand,
}

/// Representation of a namespace input (PID or Path)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
enum NsInput {
    Pid(i32),
    Path(PathBuf),
    /// this process
    This,
    New,
}

#[derive(Debug, Serialize, Deserialize, Clone, Subcommand)]
enum MainCommand {
    /// Set up some containers
    Run {
        /// Source network namespace (src=/path OR src=1234)
        #[arg(long, default_value = "this")]
        src: NsInput,
        /// Target network namespace (dst=/path OR dst=1234)
        #[arg(long, default_value = "new")]
        dst: NsInput,
        #[command(flatten)]
        proxy: Option<IArgs>,
        /// Make veths (optional name, default "veth0")
        #[arg(long, value_name = "NAME", default_missing_value = "veth0")]
        veth: Option<Option<String>>,
        /// change uid after entering shell
        #[arg(short, long)]
        uid: Option<u32>,
        /// Persist this container, add it to config file
        #[arg(short, long)]
        keep: bool,
        /// Activate other containers too
        #[arg(short, long)]
        all: bool,
    },
    /// Activate all containers
    Up,
    /// Command the tool
    Exec,
    /// Install nsproxy to a folder
    Install {
        #[arg(default_value = "./install")]
        dir: PathBuf,
    },
}

impl std::str::FromStr for NsInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(pid) = s.parse::<i32>() {
            Ok(NsInput::Pid(pid))
        } else if s == "new" {
            Ok(NsInput::New)
        } else if s == "this" {
            Ok(NsInput::This)
        } else {
            Ok(NsInput::Path(PathBuf::from(s)))
        }
    }
}

/// this has to be studied because Tokio completely fucks up this tool.
#[test]
fn smoltcp_clone3() -> anyhow::Result<()> {
    let proc = procfs::process::Process::myself()?;
    let ns = proc.namespaces()?;
    let net = ns.0.get(OsStr::new("net"));
    let stat = proc.stat()?;
    println!("threads: {}, pid {}", stat.num_threads, stat.pid);
    dbg!(&net);
    println!("start async");
    block_on(async {
        smol::Timer::after(Duration::from_secs(1)).await;
        let mut call = clone3::Clone3::default();
        call.flag_newnet();
        let p = unsafe { call.call()? };
        println!("p {}", p);
        let proc = procfs::process::Process::myself()?;
        let ns = proc.namespaces()?;
        let net = ns.0.get(OsStr::new("net"));
        dbg!(&net);

        let proc = procfs::process::Process::myself()?;
        let stat = proc.stat()?;
        println!("threads: {}, pid {}", stat.num_threads, stat.pid);

        aok!()
    })?;
    println!("exit async");
    let proc = procfs::process::Process::myself()?;
    let stat = proc.stat()?;
    println!("threads: {}, pid {}", stat.num_threads, stat.pid);

    aok!()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry()
        .with(fmt::Layer::new().with_filter(LevelFilter::DEBUG))
        .init();

    let state_dir = PathBuf::from("./nsproxy.state");
    fs::create_dir_all(&state_dir)?;
    let pid = nix::unistd::Pid::this();

    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    info!(
        "open file limits, soft={}, hard={}. trying to raise soft limit to max",
        soft, hard
    );
    rl::Resource::NOFILE.set(hard, hard)?;

    match cli.cmd {
        MainCommand::Run {
            src,
            dst,
            proxy,
            veth,
            uid,
            keep,
            all,
        } => {
            let mtu = 1500;
            let tun_name = "tun2".to_owned();
            let proc = procfs::process::Process::myself()?;
            let ns = proc.namespaces()?;
            let self_net = ns.0.get(OsStr::new("net")).unwrap();
            let self_netns = self_net.clone().to_exactns();
            let dst_ns = try_resolve_nsinput(dst.clone())?;
            // Tun2socks runs in SRC ns, connects to the socks5 in it
            // We will get the TUN FD from DST ns
            if let Some(proxy) = proxy {
                let mut iargs = proxy;
                let tun_name = iargs.name.unwrap_or(tun_name.clone());
                iargs.name = Some(tun_name.clone());
                if dst != NsInput::This {
                    match nsproxy_core::sys::clone3::<true>()? {
                        Clone3Result::IsChild { tx } => {
                            if let Some(dst) = dst_ns {
                                dst.enter(CloneFlags::CLONE_NEWNET)?;
                            }
                            if dst != NsInput::New {
                                bail!("unexpected {:?}", &dst);
                            }
                            let mut tun = TunMaker::default();
                            tun.name = tun_name.clone();
                            tun.mtu = mtu;
                            let mut state = tun.make()?;
                            state.sync_basic()?;
                            let dev = Arc::into_inner(state.fd.unwrap()).unwrap();
                            // let dev = ManuallyDrop::new(dev);
                            let raw = dev.as_raw_fd();
                            info!("send TUN fd");
                            tx.send_fd(raw)?;
                            drop(dev);
                            
                            let rt = tokio::runtime::Builder::new_multi_thread()
                                .enable_all()
                                .build()?;
                            rt.block_on(async {
                                forever!().await;
                                info!("child waiting");
                            });
                        }
                        Clone3Result::Parent {
                            child_pid,
                            child_pidfd,
                            tx,
                        } => {
                            info!("recved fd");
                            let dev = tx.recv_fd()?;
                            let dev = Arc::new(unsafe { AsyncDevice::from_fd(dev) }?);
                            let rt = tokio::runtime::Builder::new_multi_thread()
                                .enable_all()
                                .build()?;
                            rt.block_on(async move {
                                tun2socks5::main_entry(dev, mtu, false, iargs).await
                            })?;
                        }
                    }
                } else {
                    let tun = TunMaker::default();
                    let mut state = tun.make()?;
                    state.sync_basic()?;
                    todo!()
                }
            }
        }
        MainCommand::Install { dir: dstdir } => {
            if !dstdir.exists() {
                bail!(
                    "target directory {:?} does not exist. you have to create it manually",
                    &dstdir
                )
            }
            let selfprog = std::env::current_exe()?;
            let mut sproxyf = selfprog.clone();
            let overwrite = |src: &Path, path: &Path| {
                warn!("installing {:?} to {:?}", src, path);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                std::fs::copy(src, path)?;
                aok!()
            };
            let selfprogdst = dstdir.join(selfprog.file_name().unwrap());
            overwrite(&selfprog, &selfprogdst)?;
            sproxyf.set_file_name("sproxy");
            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
            let f = std::fs::File::open(&fd)?;
            let perms = Permissions::from_mode(0o6755);
            f.set_permissions(perms)?;
            let meta = f.metadata()?;
            warn!(
                "sproxy, uid={:?}, gid={}, suid={}",
                meta.uid(),
                meta.gid(),
                meta.permissions().mode() & 0o4000 != 0
            );
        }
        _ => unimplemented!(),
    }

    Ok(())
}

use anyhow::{Result, bail};

pub fn try_resolve_nsinput(nsi: NsInput) -> Result<Option<ExactNS>> {
    match nsi {
        NsInput::Path(p) => Ok(Some(NSFrom::from_source(p)?)),
        NsInput::Pid(p) => Ok(Some(NSFrom::from_source(p)?)),
        _ => Ok(None),
    }
}
