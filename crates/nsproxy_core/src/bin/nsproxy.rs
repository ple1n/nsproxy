#![feature(ip_as_octets)]

use capctl::prctl;
/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use futures::stream::TryStreamExt;
use futures::{
    AsyncWriteExt, SinkExt, StreamExt,
    channel::{
        mpsc::{self, unbounded},
        oneshot,
    },
    future::join_all,
};
use tokio::{io::AsyncWriteExt as TokioWriteExt, time::sleep};

use futures_lite::future::block_on;
use hardware_address::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network};
use libc::KERN_HOTPLUG;
use nix::{
    sched::{CloneFlags, unshare},
    unistd::{Pid, getresgid, getresuid},
};
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use nsproxy_common::{ExactNS, NSFrom, NSSource, PidPath, UniqueFile, forever};
use nsproxy_core::{
    Cli, HotConfig, MainCommand, NetlinkOps, NsproxyConfig, Paths, PathsBinds, TunMaker,
    env::{ENV_NS, args_deduce_mount, name_to_mount_path},
    shell::{ShellArgs, ShellPrefs},
    sys::{Clone3Result, NSEnter, check_selfns, enable_ping_all, mount_ns, rm_mount},
    tokio_netlink_conn,
    utils::ToExactNs,
};
use nsproxy_core::{env::ENV_PROFILE, *};
use passfd::FdPassingExt;
use pidfd::PidFd;
use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkExtentMask, LinkFlags, LinkHeader},
};
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    ffi::OsStr,
    fs::{self, Permissions},
    future::{pending, ready},
    io::{ErrorKind, Write},
    mem::ManuallyDrop,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::exit,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{select, sync};
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tun2socks5::{
    ArgMode, IArgs, VirtDNSChange, aok,
    dns::{TUNResponse, VirtDNSHandle},
    flume,
    ipstack::stream::{IpStackStream, IpStackTcpStream},
    tun_rs::AsyncDevice,
};
use warp::server::accept::Accept;

fn async_watcher() -> notify::Result<(RecommendedWatcher, sync::mpsc::Receiver<()>)> {
    let (mut tx, rx) = tokio::sync::mpsc::channel(1);
    let tx1 = tx.clone();
    tokio::spawn(async move { tx1.send(()).await });

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let watcher = RecommendedWatcher::new(
        move |res: std::result::Result<Event, notify::Error>| match res {
            Ok(res) => {
                if matches!(res.kind, EventKind::Modify(ModifyKind::Data(_))) {
                    info!("file data changed");
                    let _ = tx.try_send(());
                }
            }
            _ => {}
        },
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
}

struct ServerItem {
    marked: bool,
}

struct WarpAcceptor {
    path: PathBuf,
    rx: flume::Receiver<(PathBuf, IpStackTcpStream)>,
}

impl Accept for WarpAcceptor {
    type IO = hyper_util::rt::TokioIo<IpStackTcpStream>;
    type AcceptError = flume::RecvError;
    type Accepting = std::future::Ready<Result<Self::IO, Self::AcceptError>>;
    async fn accept(&mut self) -> std::result::Result<Self::Accepting, std::io::Error> {
        loop {
            let rx: std::result::Result<(PathBuf, IpStackTcpStream), flume::RecvError> =
                self.rx.recv_async().await;
            match rx {
                Ok((p, s)) => {
                    if p == self.path {
                        info!("accepted stream");
                        return Ok(ready(Ok(hyper_util::rt::TokioIo::new(s))));
                    }
                }
                Err(e) => {
                    return Ok(ready(Err(e)));
                }
            }
        }
    }
}

struct AssignedIps {
    vout: Ipv4Addr,
    vin: Ipv4Addr,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // DEBUG is annoying because its filled with TCP retransmission logs
    let (layer, reload_handle) =
        tracing_subscriber::reload::Layer::new(fmt::Layer::new().with_filter(LevelFilter::INFO));
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry().with(layer).init();

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
            tun: proxy,
            veth,
            keep,
            all,
            default,
            no_default,
            log,
            mut mount,
            sargs,
            name,
            profile,
        } => {
            let mtu = 1500;
            let tun_name = "tun2".to_owned();
            let proc = procfs::process::Process::myself()?;
            let ns = proc.namespaces()?;
            let self_net = ns.0.get(OsStr::new("net")).unwrap();
            let self_netns = self_net.clone().to_exactns();
            let dst_ns = try_resolve_nsinput(dst.clone())?;
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.adjust();
            shell_prefs.set_nsproxy_env(profile);
            let ns_moved = [0; 1];
            // Tun2socks runs in SRC ns, connects to the socks5 in it
            // We will get the TUN FD from DST ns
            let mut iargs = proxy;
            let tun_name = iargs.tun_name.unwrap_or(tun_name.clone());
            iargs.tun_name = Some(tun_name.clone());
            let vname = name.clone().unwrap_or("v".to_owned());
            let v_in = format!("{vname}_in");
            let v_out = format!("{vname}_out");
            let veth_net: Ipv4Network = "100.64.0.0/10".parse()?;
            let host_bits = 2;
            let subnet_prefix = 32 - host_bits;

            mount = args_deduce_mount(&name, &mount);
            if let Some(mount) = &mount {
                shell_prefs.set_ns_env(Some(mount.to_str().unwrap()));
            }

            if dst != NsInput::This {
                let clone = nsproxy_core::sys::clone3::<true>();
                match clone {
                    Ok(clone) => {
                        match clone {
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
                                    let mut read = [0u8; 4];
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
                                        let ip = veth_addr_for(
                                            Ipv4Addr::from_octets(read),
                                            host_bits,
                                            false,
                                        );

                                        let dev = nl.fetch_link_by_name(v_in).await?;
                                        nl.address()
                                            .add(dev.header.index, ip.into(), subnet_prefix)
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

                                    tokio::spawn(async move {
                                        let conf = cli.conf;
                                        let mut read = [0u8; 24];
                                        loop {
                                            let k = tx.read(&mut read[..]).await?;
                                            if k < 1 {
                                                continue;
                                            }
                                            let fc = tokio::fs::read_to_string(&conf).await?;
                                            match serde_json::from_str::<HotConfig>(&fc) {
                                                Ok(newconf) => {
                                                    enumerate_links(None, &newconf).await?;
                                                }
                                                _ => {}
                                            }
                                        }
                                        aok!()
                                    });

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

                                if let Some(mount) = mount {
                                    let path = format!("/proc/{}/ns/net", child_pid);
                                    let path = PathBuf::from(path);
                                    mount_ns(&path, &mount)?;
                                }

                                rt.spawn(async move {
                                    let fd = unsafe { PidFd::from_raw_fd(child_pidfd) };
                                    let k = fd.into_future().await?;
                                    // Against Unix philosophy again, the tool does not confuse users. 
                                    warn!("Shell has exited but nsproxy is still running. Press CtrlC to exit.");
                                    aok!()
                                });

                                let mut vethips = None;

                                rt.block_on(async move {
                                    use tokio::io::AsyncWriteExt;

                                    let nl = tokio_netlink_conn()?;
                                    tx.set_nonblocking(true)?;
                                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                                    if veth {
                                        info!(
                                            "attempting to add veths named, {}, {}",
                                            &v_out, &v_in
                                        );
                                        let addrs = nl.fetch_all_ip_addrs().await?;
                                        let ips: Vec<_> = addrs
                                            .iter()
                                            .filter_map(|f| match f {
                                                IpNetwork::V4(v4) => Some(v4.ip()),
                                                _ => None,
                                            })
                                            .collect();

                                        let v1: Option<Ipv4Addr> =
                                            find_vacant_ipv4_subnet(ips, veth_net, host_bits);
                                        if let Some(subnet) = v1 {
                                            vethips = Some(AssignedIps {
                                                vout: veth_addr_for(subnet, host_bits, true),
                                                vin: veth_addr_for(subnet, host_bits, false),
                                            });
                                            nl.add_veth(&v_out, &v_in).await;
                                            let vin = nl.fetch_link_by_name(v_in.clone()).await?;
                                            let msg: LinkMessageBuilder<LinkVeth> =
                                                LinkMessageBuilder::default()
                                                    .index(vin.header.index)
                                                    .setns_by_pid(child_pid as u32);
                                            nl.link().set(msg.build()).execute().await;
                                            tx.write(subnet.as_octets()).await?;

                                            let vout = nl.fetch_link_by_name(v_out.clone()).await?;
                                            nl.address()
                                                .add(
                                                    vout.header.index,
                                                    veth_addr_for(subnet, host_bits, true).into(),
                                                    subnet_prefix,
                                                )
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
                                        } else {
                                            tracing::error!("cannot find any vacant ip");
                                        }
                                    }

                                    let (mut vdns_sx, vdns_rx) = mpsc::channel(1);
                                    let (st_sx, acceptor) = flume::unbounded();

                                    tokio::spawn(watch_config(
                                        vdns_rx,
                                        cli.conf.clone(),
                                        acceptor,
                                        child_pid as u32,
                                        tx,
                                        vethips,
                                    ));

                                    tun2socks5::main_entry(
                                        dev,
                                        mtu,
                                        false,
                                        iargs,
                                        vdns_sx.clone(),
                                        st_sx,
                                    )
                                    .await?;
                                    warn!("tun exited");
                                    let _ = vdns_sx.send(None).await;

                                    std::future::pending::<()>().await;
                                    aok!()
                                })?;
                            }
                        }
                    }
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
                if let Some(url) = &iargs.proxy {
                    let tun = TunMaker::default();
                    let mut state = tun.make()?;
                    state.sync_basic()?;
                } else {
                    warn!("netns did not change");

                    let clone = shell_prefs.spawn()?;
                    let rt = tokio::runtime::Builder::new_current_thread().build()?;
                    rt.block_on(async { clone.wait_for_child().await })?;
                    warn!("exit");
                }
            }
        }
        MainCommand::Rm { file } => {
            rm_mount(&file)?;
        }
        MainCommand::Id {} => {
            let profile = std::env::var(ENV_PROFILE);
            println!("Browser profile {} {:?}", ENV_PROFILE, profile);
            let ns = std::env::var(ENV_NS);
            println!("Network namespace {} {:?}", ENV_NS, ns);
            if let Ok(ns) = ns {
                let path = PathBuf::from(ns);
                let ns = ExactNS::from_source(path)?;
                let ns_self = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                println!("env={} proc_self={}", ns.unique, ns_self.unique);
                if ns.unique == ns_self.unique {
                    println!("network namespace matches claim");
                } else {
                    warn!("netns mismatch");
                }
            }
        }
        /// We are just putting state in proc now, basically. Seems cleaner
        MainCommand::Enter {
            list,
            port,
            sargs,
            name,
            path,
        } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.adjust();

            if let Some(path) = path {
                let ns = NSSource::Path(path);
                ns.enter(CloneFlags::CLONE_NEWNET)?;
            } else {
                // enter through a found process
                #[derive(Debug)]
                struct FoundProcess {
                    cmd: Vec<String>,
                    args: Cli,
                    ns: Option<UniqueFile>,
                    match_port: bool,
                    score: u32,
                    pid: i32,
                    mount: Option<String>,
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
                                        println!(
                                            "{:?} {:?} {}",
                                            np.cmdline().unwrap(),
                                            net,
                                            np.pid
                                        );
                                    }
                                    let args = Cli::parse_from(&cmds);
                                    // let envs = np.environ()?;
                                    // let mount = envs.get(OsStr::new(ENV_NS));
                                    // let mount = mount.map(|k| k.to_str().unwrap().to_owned());
                                    let mount = None;
                                    found.push(FoundProcess {
                                        cmd: cmds,
                                        args,
                                        ns: net,
                                        match_port: false,
                                        score: 0,
                                        pid: np.pid,
                                        mount,
                                    });
                                } else {
                                    println!(
                                        "{:?} {:?} filename={}, skipped",
                                        np.cmdline().unwrap(),
                                        net,
                                        file
                                    );
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
                            tun,
                            veth,
                            keep,
                            all,
                            default,
                            no_default,
                            log,
                            mount,
                            sargs,
                            name: name1,
                            profile,
                        } => {
                            if *veth {
                                np.score += 1
                            }
                            if let Some(port) = port {
                                if let Some(p) = &tun.proxy {
                                    if p.addr.port() == port {
                                        np.match_port = true;
                                        np.score += 1;
                                    }
                                }
                            }
                            if &name == name1 {
                                np.score += 10;
                            }
                        }
                        _ => {}
                    }
                }
                warn!("Found {} nsproxy processes", found.len());
                let max = found.iter().max_by_key(|k| k.score);
                if let Some(max) = max {
                    warn!("best match {:?}", max.cmd);
                    let mut m = None;
                    let (profile) = match &max.args.cmd {
                        MainCommand::Run {
                            profile,
                            name,
                            mount,
                            ..
                        } => {
                            m = m.or_else(|| name.as_ref().map(name_to_mount_path));
                            (profile.clone())
                        }
                        _ => (None),
                    };
                    let m = m.as_ref().map(|k| k.to_str().unwrap());
                    shell_prefs.set_nsproxy_env(profile);
                    shell_prefs.set_ns_env(m);
                    let ns = NSSource::Pid(max.pid);
                    ns.enter(CloneFlags::CLONE_NEWNET)?;
                }
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let rx = shell_prefs.spawn()?;
                rx.wait_for_child().await?;

                aok!()
            })?;
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
                "{fd:?}, uid={:?}, gid={}, suid={}",
                meta.uid(),
                meta.gid(),
                meta.permissions().mode() & 0o4000 != 0
            );
            let short_path = dstdir.join("sp");
            warn!("Installing symlink {:?} -> {:?}", &short_path, &fd);
            symlink(&fd, short_path);
            let short_path_unpriv = dstdir.join("nsp");
            warn!("Installing symlink {:?} -> {:?}", &short_path_unpriv, &selfprogdst);
            symlink(&selfprogdst, short_path_unpriv);

            sproxyf.set_file_name("nswrap");
            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
        }
        MainCommand::Clean { veth } => {
            if veth {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async {
                    let cmd = tokio_netlink_conn()?;
                    info!("trying to remove v_out if it exists");
                    let default_v = cmd.fetch_link_by_name("v_out".to_owned()).await?;
                    cmd.link().del(default_v.header.index).execute().await?;
                    warn!("v_out removed");
                    aok!(())
                })?;
            }
        }
        // TODO: proper perms
        MainCommand::Wrap { bin, undo } => {
            let mut nswrap_path = std::env::current_exe()?;
            nswrap_path.set_file_name("nswrap");
            warn!("use nswrap at {:?}", &nswrap_path);
            let exist = nswrap_path.try_exists()?;
            if !exist {
                bail!("can not access nswrap");
            }
            let dst = which::which(bin)?;
            warn!("binary resolved to {:?}", &dst);
            let actual = dst.with_extension("wrapped");
            if actual.try_exists()? {
                if undo {
                    info!("mv {:?} {:?}", &actual, &dst);
                    fs::rename(&actual, &dst)?;
                } else {
                    info!("cp {:?} {:?}", &nswrap_path, &dst);
                    fs::copy(nswrap_path, dst)?;
                }
            } else {
                if undo {
                    warn!("nothing to do. there is no .wrapped file");
                } else {
                    info!("mv {:?} {:?}", &dst, &actual);
                    fs::rename(&dst, actual)?;
                    info!("cp {:?} {:?}", &nswrap_path, &dst);
                    fs::copy(nswrap_path, dst)?;
                }
            }
        }
        MainCommand::Gen { save_to } => {
            let conf = HotConfig::default();
            let json = serde_json::to_string_pretty(&conf)?;

            std::fs::write(&save_to, json)?;
        }
        MainCommand::Netlink => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let nl = tokio_netlink_conn()?;
                let addrs = nl.fetch_all_ip_addrs().await?;
                for a in addrs {
                    println!("{}", a);
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        _ => unimplemented!(),
    }

    Ok(())
}

async fn watch_config(
    mut vdns_rx: mpsc::Receiver<Option<VirtDNSHandle>>,
    conf: PathBuf,
    acceptor: flume::Receiver<(PathBuf, IpStackTcpStream)>,
    child_pid: u32,
    mut tx: tokio::net::UnixStream,
    veths: Option<AssignedIps>,
) -> Result<()> {
    let mut warps: HashMap<PathBuf, ServerItem> = HashMap::new();
    let vdns: Option<Option<VirtDNSHandle>> = vdns_rx.next().await;
    let vdns = vdns.unwrap();
    let mut futs = Vec::new();
    let mut prev_conf_ = None;

    if let Some(vdns) = &vdns
        && let Some(veth) = veths
    {
        vdns.pin(
            Some(veth.vout),
            "veth.host.".to_owned(),
            TUNResponse::Unreachable,
        );
        vdns.pin(
            Some(veth.vin),
            "veth.peer.".to_owned(),
            TUNResponse::Unreachable,
        );
    }

    let (mut wx, mut rx) = async_watcher()?;
    wx.watch(&conf, notify::RecursiveMode::NonRecursive)?;
    info!("watch config");

    loop {
        let vdns = vdns.clone();
        let conf = conf.clone();
        let warps = &mut warps;
        let acceptor = acceptor.clone();
        let prev_conf = &mut prev_conf_;
        let tx = &mut tx;
        let o = async move {
            warn!("config hot reload");

            let mut futs = Vec::new();
            let conf = conf;
            let fc = tokio::fs::read_to_string(&conf).await?;
            match serde_json::from_str::<HotConfig>(&fc) {
                Ok(newconf) => {
                    let cloned = newconf.clone();
                    if prev_conf.is_some() && prev_conf.as_ref().unwrap() == &cloned {
                        return Ok(futs);
                    }
                    use serde_json::Value;
                    warps.iter_mut().map(|(p, k)| k.marked = false);

                    info!("enumerate link devices in parent process");
                    enumerate_links(Some(child_pid), &newconf).await?;

                    if let Some(vdns) = &vdns {
                        for (domain, ip) in newconf.dns {
                            let target = TUNResponse::Unreachable;
                            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                                info!("DNS {} -> {}", &domain, addr);
                                vdns.pin(Some(addr), domain, target);
                            };
                        }
                        for (domain, spec) in newconf.tun {
                            match spec {
                                Value::String(mapstr) => {
                                    if let Ok(addr) = mapstr.parse::<SocketAddr>() {
                                        info!("NAT-out {} -> {}", &domain, addr);
                                        let target = TUNResponse::NATByTUN(addr);
                                    } else if let Ok(path) = mapstr.parse::<PathBuf>() {
                                        info!("Files {} -> {}", &domain, mapstr);
                                        match warps.entry(path.clone()) {
                                            Entry::Vacant(e) => {
                                                let f = warp::fs::dir(path.clone());
                                                let wa = WarpAcceptor {
                                                    rx: acceptor.clone(),
                                                    path: path.clone(),
                                                };
                                                let ws = warp::serve(f).incoming(wa);
                                                futs.push(ws.run());
                                                e.insert(ServerItem { marked: true });
                                            }
                                            Entry::Occupied(mut e) => {
                                                e.get_mut().marked = true;
                                            }
                                        }
                                        let target = TUNResponse::Files(path);
                                        vdns.pin(None, domain, target);
                                    }
                                }
                                Value::Number(port) => {
                                    let p = port.as_u64().ok_or(anyhow!("invalid port"))?;
                                    let p: u16 = p.try_into()?;
                                    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, p).into();
                                    info!("NAT-out {} -> {}", &domain, addr);
                                    let target = TUNResponse::NATByTUN(addr);
                                    vdns.pin(None, domain, target);
                                }
                                _ => (),
                            };
                        }
                    }
                    tx.write(&[1u8]).await?;

                    *prev_conf = Some(cloned);
                }
                _ => {
                    warn!("config changed, but is invalid");
                }
            }

            anyhow::Ok(futs)
        };

        info!("serving {} file roots", futs.len());
        futs = select! {
            k = rx.recv() => {if let Some(_) = k { o.await? } else {break;}},
            _ = join_all(futs), if futs.len() > 0 => {
                Vec::new()
            }
        }
    }

    warn!("config watching ended");
    aok!()
}

pub async fn enumerate_links(child_pid: Option<u32>, newconf: &HotConfig) -> Result<()> {
    let handle = tokio_netlink_conn()?;

    let mut links = handle.link().get().execute();
    'outer: loop {
        match links.try_next().await {
            Ok(Some(msg)) => {
                for nla in msg.attributes.into_iter() {
                    match nla {
                        LinkAttribute::IfName(name) => {
                            info!("found interface {}", &name);
                            if let Some(ipstr) = newconf.devs.get(&name) {
                                if let Some(pid) = child_pid {
                                    let msg: LinkMessageBuilder<LinkUnspec> =
                                        LinkMessageBuilder::default()
                                            .index(msg.header.index)
                                            .setns_by_pid(pid);
                                    handle.link().set(msg.build()).execute().await?;
                                    info!("set dev to ns");
                                }
                                if let Ok(ip) = ipstr.parse::<IpNetwork>() {
                                    info!("assigning IP {} to dev {}", ip, name);
                                    let _ = handle
                                        .address()
                                        .add(msg.header.index, ip.ip(), ip.prefix())
                                        .execute()
                                        .await;

                                    let _ = handle
                                        .link()
                                        .set(
                                            LinkUnspec::new_with_index(msg.header.index)
                                                .up()
                                                .build(),
                                        )
                                        .execute()
                                        .await;
                                }
                            }
                            continue 'outer;
                        }
                        LinkAttribute::Address(mac) => {
                            info!("found mac {:?}", mac);
                            if mac.len() == 6 {
                                let mac: [u8; 6] = mac[..6].try_into().unwrap();
                                let macstr = MacAddr::from_raw(mac).to_colon_separated();
                                if let Some(pid) = child_pid {
                                    let msg: LinkMessageBuilder<LinkUnspec> =
                                        LinkMessageBuilder::default()
                                            .index(msg.header.index)
                                            .setns_by_pid(pid);
                                    handle.link().set(msg.build()).execute().await?;
                                }
                                if let Some(ipstr) = newconf.devs.get(&macstr) {
                                    if let Ok(ip) = ipstr.parse::<IpNetwork>() {
                                        info!("assigning IP {} to dev {}", ip, macstr);
                                        let _ = handle
                                            .address()
                                            .add(msg.header.index, ip.ip(), ip.prefix())
                                            .execute()
                                            .await;
                                    }
                                }
                            };
                        }
                        LinkAttribute::PermAddress(addr) => {
                            info!("found PermAddress {:?}", addr);
                        }
                        _ => {}
                    }
                }
            }
            Err(er) => {
                warn!("link enumeration failed with {:?}", er);
                break 'outer;
            }
            Ok(None) => {
                break 'outer;
            }
        }
    }

    aok!()
}

use anyhow::{Result, anyhow, bail};

pub fn try_resolve_nsinput(nsi: NsInput) -> Result<Option<ExactNS>> {
    match nsi {
        NsInput::Path(p) => Ok(Some(NSFrom::from_source(p)?)),
        NsInput::Pid(p) => Ok(Some(NSFrom::from_source(p)?)),
        _ => Ok(None),
    }
}
