#![feature(decl_macro)]
#![feature(async_closure)]
#![feature(iter_next_chunk)]
#![feature(array_try_map)]
#![feature(ip_bits)]

use std::collections::HashSet;
use std::env::{current_exe, var};
use std::fmt::format;
use std::fs::{OpenOptions, Permissions};
use std::future::{ready, Future, IntoFuture, Ready};
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{exit, Command, Stdio};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, AtomicUsize};
use std::time::Duration;
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use crate::PidPath::Selfproc;
use anyhow::{anyhow, bail, ensure};
use atomic::Atomic;
use capctl::prctl;
use clap::{Parser, Subcommand, ValueEnum};
use daggy::NodeIndex;
use data::{forever, EdgeI};
use etc_resolv::cleanup_resolvconf;
use fork::Fork;
use futures::{FutureExt, SinkExt};
use id_alloc::NetRange;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use libc::{uid_t, SIGTERM};
use log::LevelFilter::{self, Debug};
use log::{debug, error};
use netlink_ops::netlink::{nl_ctx, GetPidOrFd, NLDriver, NLHandle, PidOrFd, VPairKey, VethConn};
use netlink_ops::rtnetlink::netlink_packet_utils::byteorder::{
    BigEndian, ReadBytesExt, WriteBytesExt,
};
use netlink_ops::rtnetlink::netlink_proto::{new_connection_from_socket, NetlinkCodec};
use netlink_ops::rtnetlink::netlink_sys::protocols::NETLINK_ROUTE;
use netlink_ops::rtnetlink::netlink_sys::{Socket, TokioSocket};
use netlink_ops::rtnetlink::Handle;
use netlink_ops::state::{Existence, ExpCollection};
use nix::fcntl::{open, OFlag};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{signal, SigHandler};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    close, fork, geteuid, getgid, getpid, getppid, getuid, sethostname, setresuid, setsid,
    ForkResult, Pid, Uid,
};
use nsproxy::data::{
    FDRecver, Graphs, NSAdd, NSAddRes, NSGroup, NSSlot, NSState, NodeAddr, NodeI, ObjectNode,
    PassFD, Relation, Validate, ValidateR, TUNC,
};
use nsproxy::flatpak::FlatpakID;
use nsproxy::graph::{check_veths, FResult};
use nsproxy::managed::{
    Indexed, ItemAction, ItemCreate, NodeIDPrint, NodeIndexed, NodeWDeps, ServiceM, Socks2TUN,
};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{
    check_capsys, cmd_uid, connect_ns_veth, enable_ping_all, enable_ping_gid, systemd_connection,
    unshare_user_standalone, what_uid, your_shell, UserNS,
};
use nsproxy::systemd::{match_root, UnitName};
use nsproxy::watcher::FlatpakWatcher;
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
use nsproxy_common::NSSource::{self, Unavail};
use nsproxy_common::{ExactNS, NSFrom, PidPath, VaCache};
use passfd::FdPassingExt;
use paths::PerIx;
use petgraph::visit::IntoNodeReferences;
use procfs::sys::kernel::random::uuid;
use rand::thread_rng;
use rand_distr::{Distribution, Normal};
use std::os::unix::net::{UnixListener, UnixStream};
use sys::NSEnter;
use tarpc::serde_transport::Transport;
use tokio::net::unix::pipe::Sender;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::instrument::WithSubscriber;
use tracing::{info, warn, Level};
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;
use tun::{AsyncDevice, Configuration, Device, Layer};
use tun2socks5::IArgs;
use zbus::zvariant::NoneValue;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "an alternative to proxychains based on linux kernel namespaces"
)]
struct Cli {
    #[arg(long, short)]
    log: Option<Level>,
    #[command(subcommand)]
    command: Commands,
    /// Require repeated signals to exit
    #[arg(long, short, default_value = "1")]
    sigint: u8,
}

#[derive(Subcommand)]
enum Commands {
    New {
        #[arg(long, short)]
        pid: Option<pid_t>,
        /// Config file for Tun2proxy
        #[arg(long, short)]
        tun2proxy: Option<PathBuf>,
        /// Command to run
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<uid_t>,
        #[arg(long, short)]
        name: Option<String>,
        /// Mount the new NS or not.
        #[arg(long, short)]
        mount: bool,
        #[arg(long, short, value_parser=parse_node)]
        out: Option<NodeAddr>,
        #[arg(long, short)]
        veth: bool,
        /// Use a persistent, or a temporary userns
        #[arg(long)]
        userns: bool,
        #[arg(long, short)]
        set_dns: bool,
        #[arg(long, short)]
        associated: Option<String>,
        #[arg(long, default_value = "192.168.2.1/24")]
        assoc_ip: Option<IpNetwork>,
    },
    /// Start as watcher daemon. This uses the socks2tun method.
    Watch {
        /// And you can only specify one config
        path: PathBuf,
        #[arg(long, short)]
        dryrun: bool,
    },
    /// Run probe process acccording to the graph. ID for Node ID
    Probe {
        id: Ix,
    },
    /// Preset for a container having a local interface
    Local {
        interface: String,
        /// Two ends of an ethernet link
        #[arg(long, short)]
        alt: bool,
        #[command(flatten)]
        iargs: IArgs,
    },
    Enter {
        name: WellKnown,
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    /// Run TUN2Proxy daemon.
    TUN2proxy {
        #[command(subcommand)]
        cmd: TUN2ProxyCmd,
        /// configure network routing
        #[arg(long)]
        setup: bool,
    },
    Info,
    /// Enter the initialized user&mnt ns
    Userns {
        #[arg(long, short)]
        rmall: bool,
        /// You can not set to UIDs that have not been mapped in uid_map
        #[arg(long, short)]
        uid: Option<u32>,
        #[arg(long, short, value_parser=parse_node)]
        node: Option<NodeAddr>,
        #[arg(long, short)]
        deinit: bool,
        #[arg(long, short)]
        exit: bool,
    },
    Node {
        #[arg(value_parser=parse_node, default_value="0")]
        id: Option<NodeAddr>,
        #[command(subcommand)]
        op: Option<NodeOps>,
    },
    Setns {
        pid: u32,
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    Sync,
    /// Install nsproxy to your system.
    Install {
        /// install sproxy binary too
        #[arg(long, short)]
        sproxy: bool,
        #[arg(long, short)]
        dstdir: Option<PathBuf>,
    },
    Noop,
    /// Quick command to get a container
    Socks {
        #[command(flatten)]
        args: IArgs,
        #[arg(long, short)]
        root: bool,
    },
    TestGUI {},
    /// Override DNS configuration for the mount namespace you are in. It performs a bind mount
    SetDNS,
    /// First line support for certain softwares
    Librewolf,
    Fractal,
    Geph,
}

#[derive(Subcommand)]
enum TUN2ProxyCmd {
    Systemd {
        path: PathBuf,
        #[arg(long)]
        id: Option<usize>,
    },
    FromArgs {
        #[command(flatten)]
        args: TUNC,
        #[command(flatten)]
        iargs: IArgs,
    },
}

#[derive(ValueEnum, Clone)]
enum WellKnown {
    Local,
}

fn parse_node(addr: &str) -> Result<NodeAddr> {
    if let Ok(ix) = addr.parse::<Ix>() {
        Ok(NodeAddr::Ix(ix.into()))
    } else {
        Ok(NodeAddr::Name(addr.into()))
    }
}

#[derive(Subcommand)]
enum NodeOps {
    Deps {
        #[arg(long, short = 'n', default_value = "30")]
        lines: u32,
        #[arg(long, short)]
        index: Option<usize>,
    },
    Run {
        /// Command to run
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    Reboot,
    RM {
        ids: Vec<Ix>,
    },
    /// return moved interfaces
    Restore {
        #[arg(long, short)]
        fd: i32,
    },
}

#[derive(Subcommand, Clone)]
enum LocalOps {
    Enter {
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
}

static SIGINT_RES: Atomic<SigintResponse> = Atomic::new(SigintResponse::Ignore);
static CURR_NODE: AtomicI32 = AtomicI32::new(-1);
static SIGINT_COUNTER: AtomicU8 = AtomicU8::new(0);
static SIGINT_GOAL: AtomicU8 = AtomicU8::new(1);
static TEARDOWN: Atomic<TeardownState> = Atomic::new(TeardownState::Disabled);
static FORK_DEPTH: AtomicUsize = AtomicUsize::new(0);

use bytemuck::NoUninit;

#[derive(NoUninit, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SigintResponse {
    TeardownCurrNode,
    Ignore,
    Exit,
}

#[derive(NoUninit, Clone, Copy, Debug)]
#[repr(u8)]
pub enum TeardownState {
    Disabled,
    Await,
    Doing,
    ChildAwait,
}

extern "C" fn handle_sigint(signal: libc::c_int) {
    let sig: nix::sys::signal::Signal = signal.try_into().unwrap();
    let p = SIGINT_RES.load(SeqCst);
    let ts = TEARDOWN.load(SeqCst);
    match ts {
        TeardownState::ChildAwait => unsafe {
            SOCK_CHILD
                .as_mut()
                .unwrap()
                .write_i32::<BigEndian>(CURR_NODE.load(SeqCst))
                .unwrap();
        },
        _ => {}
    };
    match p {
        SigintResponse::Exit => {
            SIGINT_COUNTER.fetch_add(1, SeqCst);
            let (c, g) = (SIGINT_COUNTER.load(SeqCst), SIGINT_GOAL.load(SeqCst));
            if c >= g {
                info!("exiting");
                exit(0);
            }
        }
        SigintResponse::Ignore => {
            info!("ignored");
        }
        SigintResponse::TeardownCurrNode => {
            TEARDOWN.store(TeardownState::Doing, SeqCst);
            SIGINT_RES.store(SigintResponse::Exit, SeqCst);
        }
    }
}

fn main() -> Result<()> {
    unsafe {
        signal(
            nix::sys::signal::Signal::SIGINT,
            SigHandler::Handler(handle_sigint),
        )
        .unwrap()
    };
    let mut nonecb = Some(Box::new(|| aok!()) as Box<dyn FnOnce() -> Result<()>>);
    nonecb.take();

    let cli = Cli::parse();
    match cli.command {
        Commands::Noop => exit(0),
        _ => (),
    }

    let subscriber = FmtSubscriber::builder()
        .compact()
        .without_time()
        .with_max_level(cli.log.unwrap_or(Level::INFO))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    LogTracer::init()?;
    info!("SHA1: {}", env!("VERGEN_GIT_SHA"));
    let cwd = std::env::current_dir()?;

    // set limits
    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    info!(
        "open file limits, soft={}, hard={}. trying to raise soft limit to max",
        soft, hard
    );
    rl::Resource::NOFILE.set(hard, hard)?;

    cmd(cli, cwd, nonecb)?;
    Ok(())
}

static mut SOCK_CHILD: Option<UnixStream> = None;

impl WellKnown {
    pub fn resolve(&self) -> &str {
        match self {
            Self::Local => "local",
        }
    }
}

use blockon::*;

fn cmd(
    cli: Cli,
    cwd: PathBuf,
    cb: Option<Box<dyn FnOnce() -> Result<()>>>,
) -> Result<(), anyhow::Error> {
    let mut nonecb = Some(Box::new(|| aok!()) as Box<dyn FnOnce() -> Result<()>>);
    nonecb.take();
    if cli.sigint > 1 {
        SIGINT_GOAL.store(cli.sigint, SeqCst);
    }

    let node_name = "local";

    Ok(match cli.command {
        Commands::TestGUI {} => {
            SIGINT_RES.store(SigintResponse::Exit, SeqCst);
            block_on(async {
                use tarpc::serde_transport::unix;
                let p: PathBuf = rpc_path_singleton();
                use futures::channel::mpsc::unbounded;
                use futures::StreamExt;
                use nsproxy_common::rpc::*;
                use tarpc::tokio_serde::formats::*;

                let reconn = async move || loop {
                    let rx = unix::connect(&p, Bincode::<FromServer, FromClient>::default).await;
                    if rx.is_ok() {
                        break rx.unwrap();
                    } else {
                        sleep(Duration::from_millis(800)).await;
                    }
                };
                let mut rpc = reconn().await;

                let (mut sx, mut rx) = unbounded::<FromClient>();
                tokio::spawn(
                    #[allow(unreachable_code)]
                    async move {
                        loop {
                            if let Some(d) = rx.next().await {
                                let r = rpc.send(d).await;
                                if r.is_err() {
                                    rpc = reconn().await;
                                }
                            }
                        }
                        aok!()
                    },
                );

                let hd = tokio::runtime::Handle::current();
                std::thread::spawn(move || {
                    let ls = tokio::task::LocalSet::new();
                    ls.spawn_local(async move {
                        let nm = Normal::new(500., 300.).unwrap();
                        let mut rng = thread_rng();
                        loop {
                            let v = nm.sample(&mut rng);
                            sx.send(FromClient::Data(Data::LoopTime(Duration::from_millis(
                                v as u64,
                            ))))
                            .await
                            .unwrap();
                            sleep(Duration::from_millis(50)).await;
                        }
                    });
                    hd.block_on(ls);
                });

                forever!().await;
                aok!()
            })??;
        }
        Commands::Enter { name, cmd: op, uid } => {
            let cl = Cli {
                log: cli.log,
                command: Commands::Node {
                    id: Some(NodeAddr::Name(name.resolve().to_owned())),
                    op: NodeOps::Run { cmd: op, uid }.into(),
                },
                sigint: cli.sigint,
            };
            cmd(cl, cwd, nonecb)?;
        }
        Commands::Local {
            interface,
            alt: role,
            mut iargs,
        } => {
            let (mut sp, sc) = UnixStream::pair()?;
            // fork before tokio runtime init
            iargs.name = Some("nsproxy".to_owned());
            match unsafe { fork() }? {
                ForkResult::Child => {
                    FORK_DEPTH.fetch_add(1, SeqCst);
                    SIGINT_RES.store(SigintResponse::Exit, SeqCst);
                    unsafe {
                        SOCK_CHILD = Some(sc);
                    }
                    TEARDOWN.store(TeardownState::ChildAwait, SeqCst);
                    cmd(
                        Cli {
                            log: cli.log,
                            sigint: 1,
                            command: Commands::New {
                                pid: None,
                                tun2proxy: None,
                                cmd: None,
                                uid: None,
                                name: node_name.to_owned().into(),
                                mount: true,
                                out: None,
                                veth: true,
                                userns: false,
                                set_dns: false,
                                associated: Some(interface),
                                assoc_ip: Some(if role {
                                    "192.168.2.1/24".parse()?
                                } else {
                                    "192.168.2.2/24".parse()?
                                }),
                            },
                        },
                        cwd.clone(),
                        Some(Box::new(move || {
                            warn!("netns created. now start tun2proxy right here");
                            cmd(
                                Cli {
                                    log: cli.log,
                                    sigint: 1,
                                    command: Commands::TUN2proxy {
                                        cmd: TUN2ProxyCmd::FromArgs {
                                            args: TUNC {
                                                layer: Layer::L3,
                                                tun_name: None,
                                                mtu: None,
                                            },
                                            iargs,
                                        },
                                        setup: true,
                                    },
                                },
                                cwd,
                                nonecb,
                            )?;

                            aok!()
                        })),
                    )?;
                }
                ForkResult::Parent { child } => {
                    // wait
                    TEARDOWN.store(TeardownState::Await, SeqCst);
                    SIGINT_RES.store(SigintResponse::TeardownCurrNode, SeqCst);
                    let node = sp.read_i32::<BigEndian>()?;
                    info!("wait for child to stop");
                    waitpid(child, None)?;
                    info!("child stopped");
                    if node < 0 {
                        error!("node < 0");
                        return aok!();
                    }
                    cmd(
                        Cli {
                            log: cli.log,
                            command: Commands::Node {
                                id: None,
                                op: NodeOps::RM {
                                    ids: vec![node as u32],
                                }
                                .into(),
                            },
                            sigint: 1,
                        },
                        cwd,
                        cb,
                    )?;
                }
            }
        }
        Commands::New {
            pid,
            mut tun2proxy,
            cmd,
            uid,
            name,
            mount,
            out,
            veth,
            userns,
            set_dns,
            associated,
            assoc_ip,
        } => {
            let current_uid = what_uid(None, true)?;

            let (pspath, paths): (PathBuf, PathState) = PathState::load(current_uid)?;
            let paths: Paths = paths.into();

            let mut graphs = Graphs::load_file(&paths)?;
            let target_uid = what_uid(uid, true)?;

            if let Some(ref mut tun2proxy) = tun2proxy {
                *tun2proxy = tun2proxy.canonicalize()?;
            }
            // Connect and authenticate to systemd before entering userns
            let rootful = geteuid().is_root();
            let pre = block_on(async { systemd_connection(rootful).await })??;
            let priv_ns;
            let mut va = VaCache::default();
            let mut serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
            let mut rmnode = Default::default();

            block_on(async {
                let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                let ctx = NSGroup::proc_path(Selfproc, None)?;
                nl.fill().await?;
                graphs
                    .prune(&ctx, &mut va, &mut serv, &mut rmnode, &mut nl)
                    .await?;
                graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                aok!()
            })??;

            let gid_out = getgid();
            let mut depriv_userns = false;
            let gid_in = {
                let user = uzers::get_user_by_uid(target_uid).unwrap();
                user.primary_group_id()
            };

            if userns {
                if mount {
                    use owo_colors::OwoColorize;
                    // It only makes sense when we have a persistent userns to mount
                    if !paths.userns().exist()? {
                        println!(
                            "User NS does not exist. Create it as root with command {}",
                            "sproxy userns".bright_yellow()
                        );
                        exit(-1);
                    }
                    priv_ns = Some(paths.userns().procns()?);

                    let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                    priv_ns.as_ref().unwrap().enter(&ctx)?;
                    log::info!("Entered user, mnt NS");
                } else {
                    // Not mounting defaults to use a new userns
                    priv_ns = Some(unshare_user_standalone(
                        target_uid,
                        Some(gid_in),
                        true,
                        current_uid,
                        Some(gid_out.as_raw()),
                    )?);
                    depriv_userns = true;
                }

                check_capsys()?;
            } else {
                let eu = geteuid();
                // The user is using SUID or sudo, or we are alredy in a userns, or user did setcap.
                // Probably intentional
                priv_ns = Some(NSGroup::proc_path(
                    PidPath::Selfproc,
                    Some(NSSource::Unavail(false)),
                )?);
            }
            if set_dns {
                etc_resolv::mount_conf()?;
            }
            let ns_add = if mount {
                NSAdd::RecordMountedPaths
            } else {
                NSAdd::RecordProcfsPaths
            };
            let mut rmnode = Default::default();
            block_on(async {
                let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                let ctx = NSGroup::proc_path(Selfproc, None)?;
                nl.fill().await?;
                graphs
                    .prune(&ctx, &mut va, &mut serv, &mut rmnode, &mut nl)
                    .await?;
                graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                aok!()
            })??;
            // Prune is called twice because some NSes are visible only in userns
            let (mut sp, mut sc) = UnixStream::pair()?;
            let mut buf = [0; 1];
            let mut nl_fd = None;
            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let (src_res, src) = if let Some(pid) = pid {
                graphs.add_ns(
                    PidPath::N(pid),
                    &paths,
                    priv_ns.as_ref(),
                    ns_add,
                    name,
                    rootful,
                )?
            } else {
                match unsafe { fork() }? {
                    ForkResult::Child => {
                        FORK_DEPTH.fetch_add(1, SeqCst);
                        drop(sp);
                        prctl::set_pdeathsig(Some(SIGTERM))?;
                        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                        sc.write_all(&[0])?; // #1
                                             // sethostname("proxied")?;
                                             // The line above caused XWayland to malfunction for me.
                                             // Librewolf and vscode launched in nsproxy had intermittent full-system lags.
                        if depriv_userns {
                            enable_ping_gid(gid_in.into())?
                        } else {
                            enable_ping_all()?;
                        }
                        let nl = Socket::new(NETLINK_ROUTE)?;
                        sc.send_fd(nl.as_raw_fd())?;
                        let currnode = sc.read_i32::<BigEndian>()?; // 2
                        CURR_NODE.store(currnode as i32, SeqCst);
                        if let Some(cb) = cb {
                            sc.read_exact(&mut buf)?; // 3
                            cb()?;
                        } else {
                            let mut cmd : Command = match cmd {
                                Some(c) => {
                                    let mut _cmd = Command::new("/bin/sh");
                                    _cmd.arg("-c");
                                    _cmd.arg(c);
                                    _cmd
                            },
    
                                _ => Command::new(your_shell(cmd, uid)?.ok_or(anyhow!(
                                    "--cmd must be specified when --pid is not provided"
                                ))?),
                            };


                            // We don't change uid of this process.
                            // Otherwise probe might fail due to perms
                            cmd.current_dir(cwd);
                            cmd_uid(Some(target_uid), true, false)?;
                            cmd.uid(target_uid);
                            cmd.env(PATH_VAR, &pspath);

                            sc.read_exact(&mut buf)?; // 3
                            let mut ch = cmd.spawn()?;
                            ch.wait()?;
                        }

                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        drop(sc);
                        sp.read_exact(&mut buf)?; // 1
                        nl_fd = Some(sp.recv_fd()?);
                        let k = graphs.add_ns(
                            PidPath::N(child.as_raw()),
                            &paths,
                            priv_ns.as_ref(),
                            // We have no privs to mount with when new_userns==true
                            ns_add,
                            name,
                            rootful,
                        )?;
                        CURR_NODE.store(k.1.index() as i32, SeqCst);
                        sp.write_i32::<BigEndian>(k.1.index() as i32)?; // 2
                        k
                    }
                }
            }; // Source of TUNFD/SocketFD
            let chid = graphs.data[src]
                .as_ref()
                .unwrap()
                .main
                .net
                .must()?
                .to_owned();

            block_on(async move {
                graphs.clear_ns(src, &serv).await?;

                let out = if let Some(out) = &out {
                    graphs.resolve(out)?
                } else {
                    let (_, out) = graphs.add_ns(
                        PidPath::Selfproc,
                        &paths,
                        priv_ns.as_ref(),
                        NSAdd::RecordNothing,
                        None,
                        rootful,
                    )?;
                    out
                };

                if let Some(ref tun2proxy) = tun2proxy {
                    let edge = graphs.data.add_edge(src, out, None);
                    log::info!(
                        "Src/Probe {src:?} {}, OutNode(This process), Src --TUN--> Out {edge:?}",
                        graphs.data[src].as_ref().unwrap().main.key()
                    );
                    let socks2t = Socks2TUN::new(&tun2proxy, edge)?;
                    let rel = socks2t
                        .write((Layer::L3, Some(pspath.clone())), &serv)
                        .await?;
                    graphs.data[edge].replace(rel);
                }
                let root = NLHandle::new_self_proc_tokio()?;

                if let Some(nl_fd) = nl_fd {
                    let (nl_ch_conn, handle_ch, _) =
                        new_connection_from_socket::<_, _, NetlinkCodec>(unsafe {
                            TokioSocket::from_raw_fd(nl_fd)
                        });
                    tokio::spawn(nl_ch_conn);

                    let sub = NLHandle::new(Handle::new(handle_ch), chid.clone());

                    if let Some(interface) = associated {
                        let link = root.get_link(interface.parse()?).await?;
                        let id = link.header.index;
                        let fd = chid.open()?;
                        info!("moving {} into the new netns", interface);
                        root.ip_setns(&fd, id).await?;
                        if let Some(ip) = assoc_ip {
                            let renamed = format!("{}_", interface);
                            let link = sub.get_link(interface.parse()?).await?;
                            let id = link.header.index;
                            sub.rawh
                                .link()
                                .set(id)
                                .name(renamed.clone())
                                .execute()
                                .await?;
                            info!("add ip to moved interface");
                            sub.add_addr_dev(ip, id).await?;
                            sub.set_link_up(id).await?;
                        } else {
                            warn!("no ip supplied");
                        }
                    }

                    if veth {
                        let veth_key: Option<VPairKey>;
                        veth_key = Some(format!("v{}to{}", src.index(), out.index()).try_into()?);
                        let vc = connect_ns_veth(sub, root.clone(), veth_key).await?;
                        let edge = graphs.data.add_edge(src, out, None);
                        graphs.data[edge].replace(Relation::Veth(vc));
                    }
                }

                let ctx = serv.ctx().await?;
                graphs.dump_file(&paths, target_uid)?;
                if tun2proxy.is_some() {
                    let nw = graphs.nodewdeps(src)?;
                    nw.write(Some(pspath.clone()), &serv).await?;
                    serv.reload(&ctx).await?;
                    nw.1.restart(&serv, &ctx).await?;
                    nw.0.restart(&serv, &ctx).await?;
                }

                aok!()
            })??;
            sp.write_all(&[2])?; // 3

            // Wait for the child, or it gets orphaned.
            waitpid(Some(Pid::from_raw(-1)), None)?;
        }
        Commands::Probe { id } => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();

            let graphs = Graphs::load_file(&paths)?;
            // Load graphs, send FDs over socket
            let (node, deps) = graphs.nodewdeps(NodeI::from(id))?;
            let mut va = VaCache::default();
            let mut nss = NSState {
                target: &node.item.main,
                va: &mut va,
            };
            log::info!("{:?}", &node.item.main);
            nss.validated_enter()?;

            for rel in deps {
                match rel.edge.item {
                    Relation::SendSocket(p) => p.pass()?,
                    Relation::SendTUN(p) => p.pass()?,
                    _ => (),
                }
            }
            block_on(async {
                let wh = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                // let mut nl = NLStateful::new(&wh);
                // nl.fill().await?;
                let li = wh.conn.get_link(crate::PROBE_TUN.parse()?).await?;
                wh.conn
                    .ip_add_route(li.header.index, None, Some(true))
                    .await?;
                wh.conn
                    .ip_add_route(li.header.index, None, Some(false))
                    .await?;
                wh.conn
                    .add_addr_dev(IpNetwork::new("100.64.0.2".parse()?, 16)?, li.header.index)
                    .await?;
                // It must have a source addr so the TUN driver can send packets back.
                // It shows as 0.0.0.0 if there isn't an ddress
                let li = wh.conn.get_link("lo".parse()?).await?;
                wh.conn.set_link_up(li.header.index).await?;
                aok!()
            })??;
        }
        Commands::TUN2proxy { cmd, setup } => {
            SIGINT_RES.store(SigintResponse::Exit, SeqCst);
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            let getfd_systemd = match &cmd {
                TUN2ProxyCmd::FromArgs { args, iargs } => false,
                TUN2ProxyCmd::Systemd { path, id } => true,
            };
            let default_tun_name = "tun0";

            let dev = if getfd_systemd {
                // Setns, recv FD, start daemon
                // Recv a TUN FD, and/or a upstream socket FD
                // Socket activation
                let mut fds = libsystemd::activation::receive_descriptors(true)?;
                let fdx = fds.pop().unwrap();
                let fdx = unsafe { UnixListener::from_raw_fd(fdx.into_raw_fd()) };
                log::info!("Waiting for device FD");
                let (conn, _addr) = fdx.accept()?;
                let devfd = conn.recv_fd()?;
                log::info!("Got FD");
                let devconf = Default::default();
                let dev = tun::platform::linux::Device::from_raw_fd(devfd.as_raw_fd(), &devconf)?;
                dev
            } else {
                let args = match &cmd {
                    TUN2ProxyCmd::Systemd { path, id } => {
                        bail!("creaeting tun device in systemd mode not supported");
                    }
                    TUN2ProxyCmd::FromArgs { args, iargs } => args,
                }
                .clone();
                let mut conf: Configuration = Default::default();
                #[cfg(target_os = "linux")]
                conf.platform(|config| {
                    config.packet_information(true);
                    config.apply_settings(false);
                });
                conf.layer(args.layer);
                if let Some(na) = args.tun_name {
                    conf.name(na);
                } else {
                    conf.name(default_tun_name);
                }
                let mut dev = tun::create(&conf)?;
                if let Some(mtu) = args.mtu.or(Some(DEFAULT_MTU)) {
                    dev.set_mtu((mtu).try_into().unwrap())?;
                }
                dev.enabled(true)?;
                dev.set_nonblock()?;
                dev.persist()?;
                assert!(dev.has_packet_information());
                dev
            };
            if setup {
                info!("configuring TUN and network routing");
                block_on(async {
                    let wh = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                    let li = wh.conn.get_link(default_tun_name.parse()?).await?;
                    wh.conn
                        .ip_add_route(li.header.index, None, Some(true))
                        .await?;
                    wh.conn
                        .ip_add_route(li.header.index, None, Some(false))
                        .await?;
                    wh.conn
                        .add_addr_dev(IpNetwork::new("100.64.0.2".parse()?, 16)?, li.header.index)
                        .await?;
                    // It must have a source addr so the TUN driver can send packets back.
                    // It shows as 0.0.0.0 if there isn't an ddress
                    let li = wh.conn.get_link("lo".parse()?).await?;
                    wh.conn.set_link_up(li.header.index).await?;
                    aok!()
                })??;
            }

            let mut iargs = match cmd {
                TUN2ProxyCmd::FromArgs { iargs, .. } => iargs,
                TUN2ProxyCmd::Systemd { path, id } => {
                    let mut cf = File::open(&path)?;
                    let mut k: IArgs = serde_json::from_reader(&mut cf)?;
                    if id.is_some() {
                        k.id = id;
                    }
                    k
                }
            };

            block_on_2(
                async {
                    use futures::StreamExt;
                    use nsproxy_common::rpc::*;
                    use tarpc::serde_transport::unix;
                    use tarpc::tokio_serde::formats::*;
                    use tokio::sync::mpsc::channel;

                    if let Some(ref mut p) = iargs.state {
                        let mut f = p.file_name().unwrap().to_owned();
                        let netns = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                        f.push(format!("_ns_{}", netns.unique));
                        // WARN This will cause problems when you have multiple TUNs in one NS, and use one config
                        p.set_file_name(f);
                    }
                    log::info!("{:?}", iargs);
                    let dev = AsyncDevice::new(dev)?;

                    let sock = paths.sock("rpc")?;

                    let path = if let Some(ei) = iargs.id {
                        let sp = sock.for_ix(EdgeI::from(ei as u32));
                        Some(sp)
                    } else if let Some(ref name) = iargs.name {
                        Some(std::env::current_dir()?.join(format!("{}.sock", name)))
                    } else {
                        None
                    };

                    let sx_report = if let Some(sp) = path {
                        if sp.exists() {
                            std::fs::remove_file(&sp)?;
                        }
                        info!("rpc on {:?} mode 777", &sp);
                        drop(paths);

                        let mut rpc =
                            unix::listen(&sp, Bincode::<FromServer, FromClient>::default).await?;
                        std::fs::set_permissions(&sp, Permissions::from_mode(0o777)).unwrap();
                        let (sx, mut rx) = channel::<FromClient>(5);

                        tokio::spawn(
                            #[allow(unreachable_code)]
                            async move {
                                let mut t = None;
                                loop {
                                    futures::select! {
                                        d = rpc.next().fuse() => {
                                            if let Some(d) = d {
                                                t = Some(d?);
                                            } else {
                                                break;
                                            }
                                        }
                                        x = rx.recv().fuse() => {
                                            if let Some(x) = x {
                                                if let Some(c) = &mut t {
                                                    let rx = c.send(x).await;
                                                    if rx.is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    };
                                }
                                aok!()
                            },
                        );
                        Some(sx)
                    } else {
                        warn!("supply --id or --name to enable RPC");
                        None
                    };
                    let (sx, rx) = mpsc::channel(1);
                    tun2socks5::main_entry(
                        dev,
                        DEFAULT_MTU.try_into()?,
                        true,
                        iargs,
                        rx,
                        sx,
                        sx_report,
                    )
                    .await?;

                    aok!()
                },
                true,
            )??;
        }

        Commands::Watch { mut path, dryrun } => {
            // I think there is no root flatpak /run/ dir. therefore false.
            let uid = what_uid(None, false)?;
            let (pspath, paths): (PathBuf, PathState) = PathState::load(uid)?;
            let paths: Paths = paths.into();
            let fpwatch = FlatpakWatcher::default();
            let fpath = paths.flatpak();
            path = path.canonicalize()?;
            if !fpath.exists() {
                tracing::error!("You must specify a list of apps to proxy at {:?}", &fpath);
                return Ok(());
            }
            // TODO, weird enoguh, for a flatpak process the mnt ns cant be entered EPERM
            info!("Load {:?}", &fpath);
            let mut fapps = std::fs::File::open(&fpath)?;
            let list_apps: Vec<FlatpakID> = serde_json::from_reader(&mut fapps)?;
            let brred: Vec<_> = list_apps.iter().map(|k| k).collect();
            crate::flatpak::adapt_flatpak(brred, dryrun)?;
            block_on(async {
                let (sx, mut rx) = mpsc::channel(5);
                let rootful = geteuid().is_root();
                let pre = systemd_connection(rootful).await?;
                let dae = tokio::spawn(fpwatch.daemon(uid, sx));
                let looper = async move {
                    let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                    let ctx = serv.ctx().await?;
                    while let Some(fe) = rx.recv().await {
                        if dryrun {
                            continue;
                        }
                        let mut graphs = Graphs::load_file(&paths)?;
                        let (_, out) = graphs.add_ns(
                            PidPath::Selfproc,
                            &paths,
                            None,
                            NSAdd::RecordNothing,
                            None,
                            rootful,
                        )?;
                        let (r, src) = graphs.add_ns(
                            PidPath::N(fe.pid.try_into()?),
                            &paths,
                            None,
                            NSAdd::Flatpak,
                            Some(fe.name()),
                            rootful,
                        )?;
                        if matches!(r, NSAddRes::Found) {
                            log::warn!("Net NS exists in state file");
                            // TODO: skip if everything is up
                            continue;
                        } else {
                            let edge = graphs.data.add_edge(src, out, None);
                            log::info!(
                                "Src/Probe {src:?} {}, OutNode(This process), Src -> Out {edge:?}",
                                graphs.data[src].as_ref().unwrap().main.key()
                            );
                            let socks2t = Socks2TUN::new(&path, edge)?;
                            let rel = socks2t
                                .write((Layer::L3, Some(pspath.clone())), &serv)
                                .await?;
                            graphs.data[edge].replace(rel);
                            graphs.dump_file(&paths, uid)?;
                        }
                        let nw = graphs.nodewdeps(src)?;
                        nw.write(Some(pspath.clone()), &serv).await?;

                        serv.reload(&ctx).await?;
                        nw.1.restart(&serv, &ctx).await?;
                        nw.0.restart(&serv, &ctx).await?;
                    }

                    aok!()
                };
                tokio::select! { h = dae => h??, h = looper => h?};

                aok!()
            })??;
        }
        Commands::SetDNS => {
            etc_resolv::mount_conf()?;
        }
        Commands::Userns {
            rmall,
            uid,
            exit,
            node,
            deinit,
        } => {
            let wuid = what_uid(None, false)?;
            let (pspath, paths): (PathBuf, PathState) = PathState::load(wuid)?;
            let paths: Paths = paths.into();
            let usern = UserNS(&paths);
            let rootful = geteuid().is_root();
            if usern.exist()? {
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                usern.procns()?.enter(&ctx)?;
                if rmall {
                    NSGroup::rmall(&paths, false)?;
                } else if deinit {
                    usern.deinit()?;
                } else {
                    // This process gains full caps after setns, so we can do whatever.
                    if let Some(uid) = uid {
                        let u = Uid::from_raw(uid);
                        setresuid(u, u, u)?;
                    }
                    if !exit {
                        let mut cmd = Command::new(
                            your_shell(None, uid)?.ok_or(anyhow!("specify env var SHELL"))?,
                        );
                        cmd.spawn()?.wait()?;
                    }
                }
            } else {
                log::warn!("UserNS does not exist");
                check_capsys()?;
                usern.init(wuid)?;
            }
        }
        Commands::Node { id, op } => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            // We gain full caps after setns
            if let Some(op) = op {
                match op {
                    NodeOps::Run { cmd, uid } => {
                        let graphs = Graphs::load_file(&paths)?;
                        let require_id = || {
                            if let Some(id) = id {
                                graphs.resolve(&id)
                            } else {
                                bail!("Node operation requires a node address (name/id)")
                            }
                        };
                        let ix = require_id()?;
                        let node = graphs
                            .data
                            .node_weight(ix)
                            .ok_or(anyhow!("Specified node does not exist"))?
                            .as_ref() // Second one is an invariant
                            .unwrap();
                        let mut va = VaCache::default();
                        let mut nss = NSState {
                            target: &node.main,
                            va: &mut va,
                        };
                        let cwd = std::env::current_dir()?;
                        nss.validated_enter()?;
                        drop(graphs);
                        cmd_uid(uid, true, true)?;
                        let mut cmd = Command::new(
                            your_shell(cmd, uid)?.ok_or(anyhow!("specify env var SHELL"))?,
                        );
                        cmd.current_dir(cwd);
                        cmd.spawn()?.wait()?;
                    }
                    NodeOps::Deps { lines, index } => {
                        let graphs = Graphs::load_file(&paths)?;
                        let require_id = || {
                            if let Some(id) = id {
                                graphs.resolve(&id)
                            } else {
                                bail!("Node operation requires a node address (name/id)")
                            }
                        };
                        let ix = require_id()?;
                        let mut cmd = Command::new("journalctl");
                        let (node, deps) = graphs.nodewdeps(ix)?;
                        if deps.len() == 0 {
                            println!("No dependencies.");
                        } else {
                            if let Some(index) = index {
                                let fdrc = deps[index].edge.item.fd_recver();
                                if let Some(recver) = fdrc {
                                    let serv = match recver {
                                        FDRecver::TUN2Proxy(ref path) => {
                                            Socks2TUN::new(path, deps[0].edge.id)?.service()?
                                        }
                                        FDRecver::Systemd(serv) => serv.to_owned(),
                                        _ => {
                                            warn!("No dependency known");
                                            return Ok(());
                                        }
                                    };
                                    cmd.args(
                                        format!(
                                            "-n{lines} -o cat --follow -b {}",
                                            if node.item.root {
                                                "--unit"
                                            } else {
                                                "--user-unit"
                                            }
                                        )
                                        .split(" ")
                                        .chain([serv.as_str()]),
                                    );
                                    let mut ch = cmd.spawn()?;
                                    ch.wait()?;
                                } else {
                                    log::error!("No FD receiver at {}", index)
                                }
                            } else {
                                summarize_graph(&graphs)?;
                            }
                        }
                    }
                    NodeOps::Reboot => {
                        let graphs = Graphs::load_file(&paths)?;
                        let require_id = || {
                            if let Some(id) = id {
                                graphs.resolve(&id)
                            } else {
                                bail!("Node operation requires a node address (name/id)")
                            }
                        };
                        let ix = require_id()?;
                        let (node, deps) = graphs.nodewdeps(ix)?;

                        block_on(async {
                            let rootful = geteuid().is_root();
                            let pre = systemd_connection(rootful).await?;
                            let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                            let ctx = serv.ctx().await?;
                            match_root(&serv, node.item.root)?;
                            // A node is root implies deps are located in root systemd directories too
                            deps.restart(&serv, &ctx).await?;
                            node.restart(&serv, &ctx).await?;
                            aok!()
                        })??;
                    }
                    NodeOps::Restore { fd } => {
                        let task = async move {
                            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
                            let ns = PidOrFd::Fd(Box::new(fd));
                            let graphs = Graphs::load_file(&paths)?;
                            let require_id = || {
                                if let Some(id) = id {
                                    graphs.resolve(&id)
                                } else {
                                    bail!("Node operation requires a node address (name/id)")
                                }
                            };
                            let ix = require_id()?;
                            let node = graphs
                                .data
                                .node_weight(ix)
                                .ok_or(anyhow!("Specified node does not exist"))?
                                .as_ref() // Second one is an invariant
                                .unwrap();
                            let mut va = VaCache::default();
                            let mut nss = NSState {
                                target: &node.main,
                                va: &mut va,
                            };
                            nss.validated_enter()?;
                            drop(graphs);

                            let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);

                            nl.fill().await?;
                            debug!("{:?}", &nl);
                            for (k, dev) in &nl.links {
                                let name = &k.0;
                                if let Ok(dev) = dev.exist_ref() {
                                    if name.ends_with("_") {
                                        let strip = name[..(name.len() - 1)].to_owned();
                                        warn!("rename interface back to {}", strip);
                                        nl.conn
                                            .rawh
                                            .link()
                                            .set(dev.index)
                                            .name(strip)
                                            .execute()
                                            .await?;
                                        warn!("moved {} back", name);
                                        nl.conn.ip_setns(&ns, dev.index).await?;
                                    }
                                }
                            }
                            aok!()
                        };

                        block_on(task)??;
                    }
                    NodeOps::RM { ids } => {
                        let ids: Vec<_> = ids.into_iter().map(NodeI::from).collect();
                        let mut va = VaCache::default();
                        let rootful = geteuid().is_root();
                        let mut serv = systemd::Systemd::new(&paths, None, rootful)?;
                        let mut rmnode = Default::default();
                        let graphs = {
                            let mut nl = block_on(async {
                                let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                                nl.fill().await?;
                                Ok::<_, anyhow::Error>(nl)
                            })??;
                            let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                            let fd = open("/proc/self/ns/net", OFlag::empty(), Mode::empty())?;

                            for id in &ids {
                                match unsafe { fork()? } {
                                    ForkResult::Child => {
                                        FORK_DEPTH.fetch_add(1, SeqCst);
                                        info!("forking for {:?}", id);
                                        cmd(
                                            Cli {
                                                log: None,
                                                sigint: 1,
                                                command: Commands::Node {
                                                    id: Some(NodeAddr::Ix(*id)),
                                                    op: NodeOps::Restore { fd }.into(),
                                                },
                                            },
                                            cwd.clone(),
                                            nonecb,
                                        )?;
                                        return Ok(());
                                    }
                                    ForkResult::Parent { child } => {
                                        let exit = waitpid(child, None)?;
                                        match exit {
                                            WaitStatus::Exited(p, c) => {
                                                if c != 0 {
                                                    panic!("removal cancelled");
                                                }
                                            }
                                            _ => {
                                                panic!("removal cancelled");
                                            }
                                        }
                                    }
                                }
                            }
                            let mut graphs = Graphs::load_file(&paths)?;
                            let require_id = || {
                                if let Some(id) = id {
                                    graphs.resolve(&id)
                                } else {
                                    bail!("Node operation requires a node address (name/id)")
                                }
                            };
                            block_on(async {
                                graphs
                                    .prune(&ctx, &mut va, &mut serv, &mut rmnode, &mut nl)
                                    .await?;
                                graphs
                                    .node_rm(&ctx, &ids[..], &mut va, &mut rmnode, &mut nl)
                                    .await?;
                                graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                                Ok::<_, anyhow::Error>(())
                            })??;

                            Ok::<_, anyhow::Error>(Some(graphs))
                        }?;
                        if let Some(graphs) = graphs {
                            graphs.dump_file(&paths, what_uid(None, true)?)?;
                        } else {
                            return Ok(());
                        }
                    }
                }
            } else {
                match op {
                    Some(op) => unimplemented!(),
                    None => {
                        let mut graphs = Graphs::load_file(&paths)?;
                        let require_id = || {
                            if let Some(id) = id {
                                graphs.resolve(&id)
                            } else {
                                bail!("Node operation requires a node address (name/id)")
                            }
                        };
                        summarize_graph(&graphs)?;
                    }
                }
            }
        }
        Commands::Info => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            log::info!("{:?}", &paths);
            log::info!(
                "UserNS, {:?}, mounted: {}",
                paths.userns().paths(),
                paths.userns().exist()?
            );
            let graphs = Graphs::load_file(&paths);
            match graphs {
                Ok(g) => summarize_graph(&g)?,
                Err(e) => println!("graphs not available, {:?}", e),
            }
        }
        Commands::Setns { pid, cmd, uid } => {
            let f = unsafe { pidfd::PidFd::open(pid.try_into().unwrap(), 0) }?;
            setns(f, CloneFlags::CLONE_NEWNET)?;
            cmd_uid(uid, true, true)?;
            let mut cmd =
                Command::new(your_shell(cmd, uid)?.ok_or(anyhow!("specify env var SHELL"))?);
            cmd.current_dir(cwd);
            cmd.spawn()?.wait()?;
        }
        Commands::Sync => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            let graphs = Graphs::load_file(&paths)?;

            block_on(async {
                let rootful = geteuid().is_root();
                let pre = systemd_connection(rootful).await?;
                let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                // let ctx = serv.ctx().await?;
                graphs.write_probes(&serv, Some(pspath), rootful).await?;
                aok!()
            })??;
        }
        Commands::Install { sproxy, dstdir } => {
            let selfprog = std::env::current_exe()?;
            let mut sproxyf = selfprog.clone();
            let dstdir: PathBuf = dstdir.unwrap_or("/usr/local/bin".parse()?);
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
            if sproxy {
                sproxyf.set_file_name("sproxy");
                let fd = dstdir.join(sproxyf.file_name().unwrap());
                overwrite(&sproxyf, &fd)?;
                let f = std::fs::File::open(&fd)?;
                let perms = Permissions::from_mode(0o6755);
                f.set_permissions(perms)?;
            } else {
                warn!("you might want to install sproxy binary too. use nsproxy install -s")
            }
        }
        Commands::Geph => {
            // generate config first
            use std::fs::File;
            use tun2socks5::*;
            let path = "./geph.json";
            let f = File::create(path)?;
            use serde_json::to_writer_pretty;
            let conf = IArgs {
                proxy: ArgProxy::from_url("socks5://127.0.0.1:9909")?,
                ipv6_enabled: true,
                dns: ArgDns::Handled,
                dns_addr: "127.0.0.1".parse()?,
                bypass: Default::default(),
                state: None,
                designated: Default::default(),
                id: None,
                name: Some("geph".to_owned()),
            };
            let uid = what_uid(None, false)?;
            info!("uid determined to be {}", uid);
            to_writer_pretty(f, &conf)?;
            info!("config written to {}", path);
            cmd(
                Cli {
                    log: None,
                    sigint: 1,
                    command: Commands::New {
                        pid: None,
                        tun2proxy: Some(path.into()),
                        cmd: your_shell(None, Some(uid))?,
                        uid: Some(uid),
                        name: Some("geph".into()),
                        mount: true,
                        out: None,
                        veth: true,
                        set_dns: false,
                        userns: false,
                        associated: None,
                        assoc_ip: None,
                    },
                },
                cwd,
                nonecb,
            )?;
        }
        Commands::Socks { args, root } => {
            let euid = geteuid();
            if euid.is_root() && !root {
                error!(
                    "use nsproxy socks ..... instead of sproxy socks ....
                    note you must create userns with `sproxy userns` first.
                    run sproxy socks .... --root to force the use of root user
                    warning, this temporarily changes global DNS configuration to make your container work
                    which may break some of softwares
                    that you do not run in the container"
                );
                return Ok(());
            }
            use std::fs::File;
            let path = format!("/tmp/proxy_{}.json", uuid()?);
            info!("write config to {}", &path);
            let f = File::create(&path)?;
            use serde_json::to_writer_pretty;
            let conf = args;
            let uid = what_uid(None, false)?;
            info!("uid determined to be {}", uid);
            to_writer_pretty(f, &conf)?;
            if euid.is_root() {
                if root {
                    warn!("attempting to create a netns in root mode");
                }
            } else {
                if root {
                    warn!("euid is not root but root mode is specified");
                }
            }
            cmd(
                Cli {
                    log: None,
                    sigint: 1,
                    command: Commands::New {
                        pid: None,
                        tun2proxy: Some(path.into()),
                        cmd: your_shell(None, Some(uid))?,
                        uid: Some(uid),
                        name: None,
                        mount: true,
                        out: None,
                        veth: false,
                        userns: !root,
                        set_dns: false,
                        associated: None,
                        assoc_ip: None,
                    },
                },
                cwd,
                nonecb,
            )?;
            cleanup_resolvconf()?;
        }
        Commands::Librewolf => {
            let cli = Cli {
                log: None,
                sigint: 1,
                command: Commands::Node {
                    id: Some(NodeAddr::Ix(0.into())),
                    op: Some(NodeOps::Run {
                        cmd: Some("librewolf".into()),
                        uid: None,
                    }),
                },
            };
            cmd(cli, cwd, nonecb)?;
        }
        Commands::Fractal => {
            let cli = Cli {
                log: None,
                sigint: 1,
                command: Commands::Node {
                    id: Some(NodeAddr::Ix(0.into())),
                    op: Some(NodeOps::Run {
                        cmd: Some("fractal".into()),
                        uid: None,
                    }),
                },
            };
            cmd(cli, cwd, nonecb)?;
        }
        _ => todo!(),
    })
}

fn summarize_graph(graphs: &Graphs) -> Result<()> {
    use owo_colors::OwoColorize;
    Ok(for ni in graphs.data.node_indices() {
        let nwdeps = graphs.nodewdeps(ni)?;
        print!("{}", nwdeps.0);
        for rel in nwdeps.1.iter() {
            println!("      {}", rel.edge.item);
            let fdrc = rel.edge.item.fd_recver();
            if let Some(recver) = fdrc {
                match recver {
                    FDRecver::TUN2Proxy(ref path) => {
                        let serv = Socks2TUN::new(path, rel.edge.id)?.service()?;
                        println!("      Tun2proxy {}", serv.bright_purple());
                    }
                    FDRecver::Systemd(serv) => {
                        println!("      Service {}", serv.bright_purple());
                    }
                    _ => (),
                };
            }
            let serv = rel.dst.service()?;
            let idp = NodeIDPrint(
                rel.dst.id,
                rel.dst.item.name.as_ref().map(|k| k.as_str()),
                &serv,
            );
            println!("          => {}", idp);
        }
        if nwdeps.1.len() == 0 {
            println!("      {}", "No dependencies".red());
        }
    })
}
