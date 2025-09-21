use capctl::prctl;
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
    unistd::{Pid, getresgid, getresuid},
};
use nsproxy_common::{ExactNS, NSFrom, NSSource, UniqueFile, forever};
use nsproxy_core::{
    NetlinkOps, NsproxyConfig, Paths, PathsBinds, TunMaker,
    shell::ShellPrefs,
    sys::{Clone3Result, NSEnter, enable_ping_all},
    tokio_netlink_conn,
    utils::ToExactNs,
};
use passfd::FdPassingExt;
use pidfd::PidFd;
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, Permissions},
    io::{ErrorKind, Write},
    mem::ManuallyDrop,
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::exit,
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

#[derive(Debug, Clone, Subcommand)]
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
        /// Make veths, with inner IP defaulting to 100.120.0.2/24
        #[arg(short, long)]
        veth: bool,
        /// change uid after entering shell
        #[arg(short, long)]
        uid: Option<u32>,
        /// Persist this container, add it to config file
        #[arg(short, long)]
        keep: bool,
        /// Activate other containers too
        #[arg(short, long)]
        all: bool,
        #[arg(short, long)]
        shell: Option<String>,
        /// Set TUN as default route. This defaults to true for new net ns
        #[arg(short, long)]
        default: bool,
        /// Do not set TUN as default route.
        #[arg(short, long)]
        no_default: bool,
        #[arg(short, long)]
        log: Option<LevelFilter>,
        /// Mount namespaces that are created such that you can access them by paths later
        #[arg(short, long)]
        mount: bool,
    },
    /// Find by process and enter an existing nsproxy namespace
    /// Enter the best-match based on searching arguments provided
    Enter {
        /// List only
        #[arg(short, long)]
        list: bool,
        /// Search for proxy port
        #[arg(short, long)]
        port: Option<u16>,

        #[arg(short, long)]
        shell: Option<String>,
    },
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let (layer, reload_handle) =
        tracing_subscriber::reload::Layer::new(fmt::Layer::new().with_filter(LevelFilter::DEBUG));
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry().with(layer).init();

    let make_state_dir = || {
        let state_dir = PathBuf::from("./nsproxy.state");
        fs::create_dir_all(&state_dir)?;
        aok!()
    };

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
            shell,
            default,
            no_default,
            log,
            mount,
        } => {
            let mtu = 1500;
            let tun_name = "tun2".to_owned();
            let proc = procfs::process::Process::myself()?;
            let ns = proc.namespaces()?;
            let self_net = ns.0.get(OsStr::new("net")).unwrap();
            let self_netns = self_net.clone().to_exactns();
            let dst_ns = try_resolve_nsinput(dst.clone())?;
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.prefer_shell = shell;
            shell_prefs.adjust();
            let ns_moved = [0; 1];
            // Tun2socks runs in SRC ns, connects to the socks5 in it
            // We will get the TUN FD from DST ns
            if let Some(proxy) = proxy {
                let mut iargs = proxy;
                let tun_name = iargs.name.unwrap_or(tun_name.clone());
                iargs.name = Some(tun_name.clone());
                if dst != NsInput::This {
                    let clone = nsproxy_core::sys::clone3::<true>();
                    match clone {
                        Ok(clone) => match clone {
                            Clone3Result::IsChild { tx } => {
                                if let Some(dst) = dst_ns {
                                    dst.enter(CloneFlags::CLONE_NEWNET)?;
                                }
                                if dst != NsInput::New {
                                    bail!("unexpected {:?}", &dst);
                                }
                                enable_ping_all()?;

                                let mut tun = TunMaker::default();
                                tun.name = tun_name.clone();
                                tun.mtu = mtu;
                                let mut state = tun.make()?;
                                state.sync_basic()?;
                                let dev = Arc::into_inner(state.fd.unwrap()).unwrap();
                                let raw = dev.as_raw_fd();

                                info!("send TUN fd");
                                tx.send_fd(raw)?;
                                drop(dev);

                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()?;
                                rt.block_on(async {
                                    use tokio::io::AsyncReadExt;
                                    let mut read = vec![0; 1];
                                    tx.set_nonblocking(true)?;
                                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                                    let add_default = (dst == NsInput::New && !no_default)
                                        || (dst == NsInput::This && default);

                                    let nl = tokio_netlink_conn()?;
                                    nl.up_lo().await?;

                                    if add_default {
                                        warn!("adding TUN as default route");
                                        nl.ip_add_default_route(state.dev_index).await?;
                                    }
                                    if veth {
                                        tx.read(&mut read).await;
                                        let dev = nl.fetch_link_by_name("v_in".to_owned()).await?;
                                        nl.address()
                                            .add(dev.header.index, "100.120.0.2".parse()?, 24)
                                            .execute()
                                            .await?;

                                        nl.link()
                                            .set(
                                                LinkMessageBuilder::<LinkUnspec>::default()
                                                    .index(dev.header.index)
                                                    .up()
                                                    .build(),
                                            )
                                            .execute()
                                            .await?;
                                    }

                                    let clone = shell_prefs.spawn()?;
                                    clone.wait_for_child().await?;

                                    exit(0);
                                    aok!()
                                })?;
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
                                if let Some(log) = log {
                                    reload_handle.modify(|k| *k.filter_mut() = log)?;
                                }

                                rt.spawn(async move {
                                    let fd = unsafe { PidFd::from_raw_fd(child_pidfd) };
                                    let k = fd.into_future().await?;
                                    // Against Unix philosophy again, the tool does not confuse users. 
                                    warn!("Shell has exited but nsproxy is still running. Press CtrlC to exit.");
                                    aok!()
                                });

                                rt.block_on(async move {
                                    use tokio::io::AsyncWriteExt;

                                    let nl = tokio_netlink_conn()?;
                                    tx.set_nonblocking(true)?;
                                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                                    if veth {
                                        info!("attempting to add veths named, v_out, v_in");
                                        nl.add_veth("v_out", "v_in").await;
                                        let vin = nl.fetch_link_by_name("v_in".to_owned()).await?;
                                        let msg: LinkMessageBuilder<LinkVeth> =
                                            LinkMessageBuilder::default()
                                                .index(vin.header.index)
                                                .setns_by_pid(child_pid as u32);
                                        nl.link().set(msg.build()).execute().await;
                                        tx.write(&ns_moved).await?;

                                        let vout =
                                            nl.fetch_link_by_name("v_out".to_owned()).await?;
                                        nl.address()
                                            .add(vout.header.index, "100.120.0.1".parse()?, 24)
                                            .execute()
                                            .await?;
                                        nl.link()
                                            .set(
                                                LinkMessageBuilder::<LinkUnspec>::default()
                                                    .index(vout.header.index)
                                                    .up()
                                                    .build(),
                                            )
                                            .execute()
                                            .await?;
                                    }
                                    tun2socks5::main_entry(dev, mtu, false, iargs).await
                                })?;
                            }
                        },
                        // This is what you dont get in Unix philosophy. User experience.
                        Err(er) => {
                            warn!("Clone3 failed with {:?}", &er);
                            let res = getresuid()?;
                            if res.real.is_root() {
                                warn!("{:?}", res);
                            } else {
                                warn!("Is this the executable set with SUID? {:?}", res)
                            }
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
        /// We are just putting state in proc now, basically. Seems cleaner
        MainCommand::Enter { list, port, shell } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.prefer_shell = shell;
            shell_prefs.adjust();

            #[derive(Debug)]
            struct FoundProcess {
                cmd: Vec<String>,
                args: Cli,
                ns: Option<UniqueFile>,
                match_port: bool,
                score: u32,
                pid: i32,
            }
            let mut nsproxy_procs = Vec::new();
            let mut found = Vec::new();
            let procs = procfs::process::all_processes()?;
            for proc in procs {
                let proc = proc;
                if let Ok(p) = proc {
                    if let Ok(cmd) = p.cmdline() {
                        if cmd.get(0).map(|k| k.contains("sproxy")).unwrap_or_default() {
                            nsproxy_procs.push(p);
                        }
                    }
                }
            }
            for np in nsproxy_procs {
                let ns = np.namespaces();
                if let Ok(ns) = ns {
                    let net =
                        ns.0.get(OsStr::new("net"))
                            .map(|k| UniqueFile::new(k.identifier, k.device_id));

                    let cmds = np.cmdline()?;
                    if let Some(exe) = cmds.get(0) {
                        let path = PathBuf::from(exe);
                        let file = path.file_name();
                        if let Some(file) = file {
                            let file = file.to_string_lossy();
                            if file == "nsproxy" || file == "sproxy" {
                                if list {
                                    println!("{:?} {:?}", np.cmdline().unwrap(), net);
                                }
                                let args = Cli::parse_from(&cmds);
                                found.push(FoundProcess {
                                    cmd: cmds,
                                    args,
                                    ns: net,
                                    match_port: false,
                                    score: 0,
                                    pid: np.pid,
                                });
                            } else {
                                println!("{:?} {:?} filename={}, skipped", np.cmdline().unwrap(), net, file);
                            }
                        }
                    }
                }
            }
            for np in found.iter_mut() {
                match &np.args.cmd {
                    MainCommand::Run {
                        src,
                        dst,
                        proxy,
                        veth,
                        uid,
                        keep,
                        all,
                        shell,
                        default,
                        no_default,
                        log,
                        mount,
                    } => {
                        if *veth {
                            np.score += 1
                        }
                        if let Some(port) = port {
                            if let Some(p) = proxy {
                                if p.proxy.addr.port() == port {
                                    np.match_port = true;
                                    np.score += 1;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            warn!("Found {} nsproxy processes", found.len());
            let max = found.iter().max_by_key(|k| k.score);
            if let Some(max) = max {
                warn!("best match {:?}", max.cmd);
                let ns = NSSource::Pid(max.pid);
                ns.enter(CloneFlags::CLONE_NEWNET)?;

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async { shell_prefs.spawn_and_block().await })?;
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
