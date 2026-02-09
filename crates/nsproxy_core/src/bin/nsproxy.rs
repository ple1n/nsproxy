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
use reqwest::redirect::Policy;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as TokioWriteExt},
    time::sleep,
};

use futures_lite::future::block_on;
use hardware_address::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network};
use libc::KERN_HOTPLUG;
use nix::{
    sched::{CloneFlags, unshare},
    unistd::{Gid, Pid, Uid, chown, getresgid, getresuid},
};
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use nsproxy_common::{ExactNS, NSFrom, NSSource, PidPath, UniqueFile, forever};
use nsproxy_core::{
    BasisCommand, Cli, HotConfig, MainCommand, NetlinkOps, NsproxyConfig, Paths, PathsBinds,
    ProfileChmod, ProfileConfig, ProfileMount, RootfsMode, TunMaker,
    env::{ENV_NS, args_deduce_mount, name_to_mount_path},
    shell::{ShellArgs, ShellPrefs},
    state_paths,
    sys::{
        Clone3Result, NSEnter, check_selfns, enable_ping_all, mount_bind, mount_bind_ro_explicit,
        mount_bind_root, mount_bind_rw_explicit, mount_ns, mount_tmpfs, pivot_root_into, rm_mount,
    },
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
    collections::{HashMap, HashSet, hash_map::Entry},
    convert::Infallible,
    ffi::OsStr,
    fs::{self, Permissions},
    future::{pending, ready},
    io::{ErrorKind, Read, Write},
    mem::ManuallyDrop,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    pin::Pin,
    process::exit,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{select, sync};
use tracing::{error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tun2socks5::{
    ArgMode, IArgs, VirtDNSChange, aok, diag,
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

fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                let mut result = PathBuf::from(home);
                result.push(&path_str[2..]);
                return result;
            }
        } else if path_str == "~" {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home);
            }
        }
    }
    path.to_path_buf()
}

fn apply_profile_mounts(root: &Path, mounts: &[ProfileMount]) -> Result<()> {
    for m in mounts {
        let expanded_target = expand_tilde(&m.target);
        let rel = expanded_target.strip_prefix("/").unwrap();
        let target = root.join(rel);
        if m.read_only {
            mount_bind_ro_explicit(&m.source, &target, m.recursive)?;
        } else {
            mount_bind_rw_explicit(&m.source, &target, m.recursive)?;
        }
    }

    Ok(())
}

fn apply_profile_chmod(root: &Path, chmods: &[ProfileChmod]) -> Result<()> {
    for c in chmods {
        let expanded_path = expand_tilde(&c.path);
        let rel = expanded_path.strip_prefix("/").unwrap();
        let target = root.join(rel);

        if let Some(mode) = c.mode {
            let mut perms = std::fs::metadata(&target)?.permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&target, perms)?;
        }

        if c.uid.is_some() || c.gid.is_some() {
            let uid = c.uid.map(Uid::from_raw);
            let gid = c.gid.map(Gid::from_raw);
            chown(&target, uid, gid)?;
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    // DEBUG is annoying because its filled with TCP retransmission logs
    let (layer, reload_handle) = tracing_subscriber::reload::Layer::new(
        fmt::Layer::new()
            .without_time()
            .with_filter(LevelFilter::INFO),
    );
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
        MainCommand::Serve { port } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                use socks5_impl::protocol::*;
                use socks5_impl::server::*;
                warn!("starting socks server on 0.0.0.0:{}", port);
                let addr = format!("0.0.0.0:{}", port);
                let server = Server::bind(addr.parse()?, Arc::new(auth::NoAuth)).await?;
                loop {
                    let (conn, _) = server.accept().await?;
                    tokio::spawn(async {
                        if let Err(err) = handle_socks5_connection(conn).await {
                            warn!("socks5 connection error: {}", err);
                        }
                    });
                }

                aok!()
            })?;
        }
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
            bind: mut mount,
            sargs,
            name,
            profile,
            mnt,
            mut binds,
            no_proxy,
        } => {
            // Check wrapped binaries wellness before starting
            let wrapped_config = WrappedBinariesConfig::load()?;
            wrapped_config.check_all_wrapped()?;

            // Validate proxy and no_proxy are mutually exclusive
            let mut iargs = proxy;
            match (iargs.proxy.is_some(), no_proxy) {
                (true, true) => {
                    bail!(
                        "Cannot specify both --proxy and --no-proxy. They are mutually exclusive."
                    );
                }
                (false, false) => {
                    bail!("Must specify either --proxy <URL> or --no-proxy explicitly.");
                }
                _ => {} // Valid: (true, false) or (false, true)
            }

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
            shell_prefs.set_nsproxy_env(profile.clone());
            let ns_moved = [0; 1];
            // Tun2socks runs in SRC ns, connects to the socks5 in it
            // We will get the TUN FD from DST ns
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
            } else {
                // Clear any existing NS env if it exists
                shell_prefs.set_ns_env(None);
            }

            if cli.conf.is_none() {
                warn!("Live config is not specified. Use sp -c ./nsproxy.json run");
                if let Some(p) = &profile {
                    let conf = PathBuf::from(".").join(p).with_extension("json");
                    if conf.exists() {
                        cli.conf = Some(conf);
                        warn!("config file defaults to {:?}", &cli.conf);
                    } else {
                        warn!("config file defaults to {:?} but its not found", &conf);
                    }
                }
            }

            if !mnt {
                warn!(
                    "Not directed to use a new mount namespace. Mounts will operate on root namespace. Use --mnt"
                );
            }

            if mnt {
                binds = true
            }

            if dst != NsInput::This {
                let clone = nsproxy_core::sys::clone3::<true>(mnt, false);
                match clone {
                    Ok(clone) => {
                        match clone {
                            Clone3Result::IsChild { mut tx } => {
                                let mut buf = [0; 8];

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
                                let mut tun_state = tun.make()?;
                                tun_state.sync_basic()?;
                                let dev = Arc::into_inner(tun_state.fd.unwrap()).unwrap();
                                let raw = dev.as_raw_fd();

                                info!("send TUN fd");
                                tx.send_fd(raw)?;
                                drop(dev);

                                tx.read(&mut buf)?; // wait for bind mount;
                                if mnt {
                                    mount_bind_root()?;
                                    tx.write(&[0])?;
                                }

                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()?;
                                rt.block_on(async {
                                    use tokio::io::AsyncReadExt;
                                    use tokio_send_fd::SendFd;

                                    let mut read = [0u8; 4];
                                    tx.set_nonblocking(true)?;
                                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                                    let add_default = (dst == NsInput::New && !no_default)
                                        || (dst == NsInput::This && default);

                                    let nl = tokio_netlink_conn()?;
                                    nl.up_lo().await?;

                                    let initial_conf = if let Some(conf) = &cli.conf {
                                        let fc = std::fs::read_to_string(&conf)?;
                                        match serde_json::from_str::<HotConfig>(&fc) {
                                            Ok(newconf) => Some(newconf),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    };

                                    if add_default {
                                        warn!("adding TUN as default route");
                                        nl.ip_add_default_route(tun_state.dev_index).await?;
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

                                    // TODO: Top level async task should be wrapped and logged
                                    // Otherwise errors go silent
                                    tokio::spawn(async move {
                                        let conf = cli.conf;
                                        if let Some(conf) = conf {
                                            let mut mnt: HashMap<PathBuf, PathBuf> =
                                                Default::default();
                                            let mut read = [0u8; 24];
                                            loop {
                                                info!("in-ns wait for config");
                                                let k = tx.read(&mut read[..]).await?;
                                                if k < 1 {
                                                    error!("in-ns config watcher exits due to EOF");
                                                    // EOF??
                                                    break;
                                                }
                                                info!("in-ns reload config");
                                                let fc = tokio::fs::read_to_string(&conf).await?;
                                                match serde_json::from_str::<HotConfig>(&fc) {
                                                    Ok(newconf) => {
                                                        for (s, t) in mnt.clone() {
                                                            if let Some(new) = newconf.mnt.get(&s) {
                                                                // skip
                                                            } else {
                                                                rm_mount(&t);
                                                                mnt.remove(&s);
                                                            }
                                                        }

                                                        if binds {
                                                            for (s, t) in newconf.mnt.clone() {
                                                                if let Some(current) = mnt.get(&s)
                                                                    && current == &t
                                                                {
                                                                    // skip
                                                                } else {
                                                                    let x = mount_bind(&s, &t);
                                                                    if let Err(e) = x {
                                                                        error!(
                                                                            "Bind mount {:?}",
                                                                            &e
                                                                        );
                                                                    }
                                                                    mnt.insert(s, t);
                                                                }
                                                            }
                                                        }

                                                        tx.write(&[0, 0, 0, 0]).await?;
                                                        for (in_port, dst) in &newconf.locals {
                                                            // bind all tcp at 127.0.0.1:src and pass all descriptiors through the socket.
                                                            let bind = std::net::TcpListener::bind(
                                                                format!("127.0.0.1:{}", in_port),
                                                            )?;
                                                            let raw = bind.as_raw_fd();
                                                            tx.write(&in_port.to_le_bytes())
                                                                .await?;
                                                            tx.send_fd(raw).await?;
                                                        }
                                                        tx.write(&[0, 0, 0, 0]).await?;

                                                        let _ =
                                                            enumerate_links(None, &newconf).await;

                                                        // TODO: remove stale mounts
                                                    }
                                                    _ => {}
                                                }
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
                                mut tx,
                            } => {
                                info!("recved fd");
                                let dev = tx.recv_fd()?;
                                let dev = Arc::new(unsafe { AsyncDevice::from_fd(dev) }?);

                                if let Some(mount) = mount {
                                    // Ensure runtime directory exists
                                    std::fs::create_dir_all(RUNTIME_ROOT)?;

                                    let path = format!("/proc/{}/ns/net", child_pid);
                                    let path = PathBuf::from(path);
                                    mount_ns(&path, &mount)?;

                                    let ns_alive = nsproxy_core::NsAlive {
                                        browser_profile: profile.clone(),
                                        bind_mount: mount.clone(),
                                        child_pid: Some(child_pid as u32),
                                    };
                                    let json = serde_json::to_string_pretty(&ns_alive)?;
                                    let jsonpath = state_paths::metadata_for_bind(&mount);
                                    std::fs::write(&jsonpath, json)?;
                                    warn!("Auxiliary data written to {:?}", &jsonpath);
                                    tx.write(&[0]);

                                    // Also mount the mnt namespace if it was created
                                    if mnt {
                                        let mut buf = [0; 1];
                                        tx.read(&mut buf);
                                        // Somehow doesnt work
                                        // let mnt_path = format!("/proc/{}/ns/mnt", child_pid);
                                        // let mnt_path = PathBuf::from(mnt_path);
                                        // let mnt_ns_file = mount.with_extension("mntns");

                                        // let _ = mount_ns(&mnt_path, &mnt_ns_file);
                                        // warn!("Mount namespace mounted to {:?}", &mnt_ns_file);
                                    }
                                } else {
                                    warn!("not mounting this namespace");
                                }

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

                                    tokio::spawn(async move {
                                        let x = watch_config(
                                            vdns_rx,
                                            cli.conf.clone(),
                                            acceptor,
                                            child_pid as u32,
                                            tx,
                                            vethips,
                                        )
                                        .await;
                                        warn!("out-ns, watcher exited {:?}", x);
                                    });

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
        MainCommand::Make {
            src,
            dst,
            profile,
            tun: proxy,
            veth,
            keep,
            all,
            default,
            no_default,
            log,
            bind: mount,
            name,
            sargs,
            check,
            mut no_proxy,
            mut no_tun,
        } => {
            // Check wrapped binaries wellness before starting
            let wrapped_config = WrappedBinariesConfig::load()?;
            wrapped_config.check_all_wrapped()?;

            // Validate proxy and no_proxy are mutually exclusive
            let mut iargs = proxy;
            let has_tun_config = iargs.proxy.is_some();
            match (has_tun_config, no_tun) {
                (true, true) => {
                    bail!(
                        "Cannot specify both TUN options and --no-tun. They are mutually exclusive."
                    );
                }
                _ => {}
            }

            if no_tun {
                no_proxy = true;
            }

            match (iargs.proxy.is_some(), no_proxy) {
                (true, true) => {
                    bail!(
                        "Cannot specify both --proxy and --no-proxy. They are mutually exclusive."
                    );
                }
                (false, false) => {
                    bail!("Must specify either --proxy <URL> or --no-proxy explicitly.");
                }
                _ => {} // Valid: (true, false) or (false, true)
            }

            let mtu = 1500;
            let tun_name = "tun2".to_owned();
            let proc = procfs::process::Process::myself()?;
            let ns = proc.namespaces()?;
            let self_net = ns.0.get(OsStr::new("net")).unwrap();
            let self_netns = self_net.clone().to_exactns();
            let dst_ns = try_resolve_nsinput(dst.clone())?;

            // Derive profile path from name if not explicitly provided
            let mut profile = if let Some(profile_path) = &profile {
                ProfileConfig::load(profile_path)?
            } else if let Some(ref instance_name) = name {
                // Derive: /nsp3/{name}/profile.json
                let derived_path = PathBuf::from(PERSIST_ROOT)
                    .join(instance_name)
                    .join("profile.json");
                if !derived_path.exists() {
                    bail!(
                        "derived profile path does not exist: {:?}. Use 'profile' subcommand to create it.",
                        derived_path
                    );
                }
                ProfileConfig::load(&derived_path)?
            } else {
                bail!("either --profile or --name must be provided for 'make' command")
            };

            // Expand @ placeholders to instance state root
            if let Some(ref instance_name) = name {
                let instance_root = PathBuf::from(PERSIST_ROOT).join(instance_name);
                profile.expand_placeholders(&instance_root);
            }

            let hot = profile.hot.clone();
            if !hot.exists() {
                if let Some(parent) = hot.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let conf = profile.hot_init.clone().unwrap_or_default();
                let json = serde_json::to_string_pretty(&conf)?;
                std::fs::write(&hot, json)?;
            }
            let hot_conf: HotConfig = {
                let fc = std::fs::read_to_string(&hot)?;
                serde_json::from_str(&fc)?
            };

            if profile.rootfs.mode == RootfsMode::Pivot {
                bail!("not implemented");
            }

            if let Some(ref cwd) = profile.sargs.cwd {
                if !cwd.exists() {
                    std::fs::create_dir_all(cwd)?;
                }
            }
            for m in &profile.mounts {
                if !m.source.exists() {
                    bail!(
                        "mount source does not exist: {:?}. Create it with 'profile' command first.",
                        m.source
                    );
                }
            }
            for (s, t) in &hot_conf.mnt {
                if !s.exists() {
                    bail!("mnt source does not exist: {:?}", s);
                }
                if let Some(parent) = t.parent() {
                    if !parent.exists() {
                        bail!("mnt target parent does not exist: {:?}", parent);
                    }
                }
            }

            if check {
                warn!("validation passed");
                return Ok(());
            }

            let env = profile.env.clone();
            let inherit_env = profile.inherit_env;

            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(profile.sargs.clone());
            shell_prefs.take_args(sargs);

            if inherit_env {
                shell_prefs.adjust()?;
                shell_prefs.set_env_with_inheritance(env)?;
            } else {
                shell_prefs.set_env_explicit(env)?;
            }

            // For ::Make, bind mount lives inside instance dir: /nsp3/{name}/net
            let mount = mount.or_else(|| {
                name.as_ref().map(|n| {
                    let p = state_paths::profile_netns_bind(n);
                    warn!("Mount path defaults to {:?}", &p);
                    p
                })
            });

            // Set browser profile + namespace env vars for the spawned shell
            shell_prefs.set_nsproxy_env(profile.browser_profile.clone());
            if let Some(ref m) = mount {
                shell_prefs.set_ns_env(Some(m.to_str().unwrap()));
            } else {
                shell_prefs.set_ns_env(None);
            }

            let tun_name = iargs.tun_name.unwrap_or(tun_name.clone());
            iargs.tun_name = Some(tun_name.clone());
            let vname = name.clone().unwrap_or_else(|| "default".to_string());

            // Set diag socket path for tun2socks5 diagnostics
            iargs.diag_sock = Some(diag::diag_sock_path(&vname));

            let v_in = format!("{vname}_in");
            let v_out = format!("{vname}_out");
            let veth_net: Ipv4Network = "100.64.0.0/10".parse()?;
            let host_bits = 2;
            let subnet_prefix = 32 - host_bits;

            if dst != NsInput::This {
                let clone = nsproxy_core::sys::clone3::<true>(true, true);
                match clone {
                    Ok(clone) => {
                        match clone {
                            Clone3Result::IsChild { mut tx } => {
                                let mut buf = [0; 8];

                                if let Some(dst) = dst_ns {
                                    dst.enter(CloneFlags::CLONE_NEWNET)?;
                                }
                                if dst != NsInput::New {
                                    bail!("unexpected {:?}", &dst);
                                }
                                enable_ping_all()?;

                                let mut state: Option<TunState> = None;

                                if !no_tun {
                                    let mut tun = TunMaker::default();
                                    tun.name = tun_name.clone();
                                    tun.mtu = mtu;
                                    let tun_state = tun.make()?;
                                    state = Some(tun_state);
                                    state.as_mut().unwrap().sync_basic()?;
                                    let dev = state.as_mut().unwrap().fd.as_ref().unwrap();
                                    let raw = dev.as_raw_fd();

                                    info!("send TUN fd");
                                    tx.send_fd(raw)?;
                                    drop(dev);
                                } else {
                                    info!("Skipping TUN creation due to --no-tun flag");
                                };

                                tx.read(&mut buf)?; // wait for bind mount;
                                mount_bind_root()?;

                                if profile.rootfs.tmpfs {
                                    mount_tmpfs(&profile.rootfs.root)?;
                                } else if !profile.rootfs.root.exists() {
                                    std::fs::create_dir_all(&profile.rootfs.root)?;
                                }

                                apply_profile_mounts(&profile.rootfs.root, &profile.mounts)?;
                                apply_profile_chmod(&profile.rootfs.root, &profile.chmod)?;

                                if matches!(profile.rootfs.mode, RootfsMode::Pivot) {
                                    let put_old = profile.rootfs.put_old.clone().unwrap();
                                    pivot_root_into(&profile.rootfs.root, &put_old)?;
                                }

                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()?;
                                rt.block_on(async {
                                    use tokio::io::AsyncReadExt;
                                    use tokio_send_fd::SendFd;

                                    let mut read = [0u8; 4];
                                    tx.set_nonblocking(true)?;
                                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                                    let add_default = (dst == NsInput::New && !no_default)
                                        || (dst == NsInput::This && default);

                                    let nl = tokio_netlink_conn()?;
                                    nl.up_lo().await?;

                                    let initial_conf = {
                                        let fc = std::fs::read_to_string(&hot)?;
                                        let conf: HotConfig = serde_json::from_str(&fc)?;
                                        conf
                                    };

                                    for (s, t) in initial_conf.mnt.clone() {
                                        let x = mount_bind(&s, &t);
                                        if let Err(e) = x {
                                            error!("Bind mount {:?}", &e);
                                        }
                                    }

                                    if add_default {
                                        if let Some(ref state) = state {
                                            warn!("adding TUN as default route");
                                            nl.ip_add_default_route(state.dev_index).await?;
                                        } else {
                                            warn!("Skipping default route - no TUN device");
                                        }
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
                                        let mut mnt: HashMap<PathBuf, PathBuf> = Default::default();
                                        let mut read = [0u8; 24];
                                        loop {
                                            info!("in-ns wait for config");
                                            let k = tx.read(&mut read[..]).await?;
                                            if k < 1 {
                                                error!("in-ns config watcher exits due to EOF");
                                                break;
                                            }
                                            info!("in-ns reload config");
                                            let fc = tokio::fs::read_to_string(&hot).await?;
                                            match serde_json::from_str::<HotConfig>(&fc) {
                                                Ok(newconf) => {
                                                    for (s, t) in mnt.clone() {
                                                        if let Some(_new) = newconf.mnt.get(&s) {
                                                        } else {
                                                            rm_mount(&t);
                                                            mnt.remove(&s);
                                                        }
                                                    }

                                                    for (s, t) in newconf.mnt.clone() {
                                                        if let Some(current) = mnt.get(&s)
                                                            && current == &t
                                                        {
                                                        } else {
                                                            let x = mount_bind(&s, &t);
                                                            if let Err(e) = x {
                                                                error!("Bind mount {:?}", &e);
                                                            }
                                                            mnt.insert(s, t);
                                                        }
                                                    }

                                                    tx.write(&[0, 0, 0, 0]).await?;
                                                    for (in_port, dst) in &newconf.locals {
                                                        let bind = std::net::TcpListener::bind(
                                                            format!("127.0.0.1:{}", in_port),
                                                        )?;
                                                        let raw = bind.as_raw_fd();
                                                        tx.write(&in_port.to_le_bytes()).await?;
                                                        tx.send_fd(raw).await?;
                                                    }
                                                    tx.write(&[0, 0, 0, 0]).await?;

                                                    let _ = enumerate_links(None, &newconf).await;
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
                                mut tx,
                            } => {
                                let dev = if !no_tun {
                                    info!("recved fd");
                                    let dev = tx.recv_fd()?;
                                    Some(Arc::new(unsafe { AsyncDevice::from_fd(dev) }?))
                                } else {
                                    info!("Skipping TUN fd receive due to --no-tun flag");
                                    None
                                };

                                if let Some(mount) = mount {
                                    // Ensure runtime directory exists
                                    std::fs::create_dir_all(RUNTIME_ROOT)?;

                                    let path = format!("/proc/{}/ns/net", child_pid);
                                    let path = PathBuf::from(path);
                                    mount_ns(&path, &mount)?;

                                    let ns_alive = nsproxy_core::NsAlive {
                                        browser_profile: profile.browser_profile.clone(),
                                        bind_mount: mount.clone(),
                                        child_pid: Some(child_pid as u32),
                                    };
                                    let json = serde_json::to_string_pretty(&ns_alive)?;
                                    let jsonpath = state_paths::profile_ns_meta(&vname);
                                    std::fs::write(&jsonpath, json)?;
                                    warn!("Auxiliary data written to {:?}", &jsonpath);
                                } else {
                                    warn!("not mounting this /ns/net to any path");
                                }
                                tx.write(&[0]);

                                let rt = tokio::runtime::Builder::new_multi_thread()
                                    .enable_all()
                                    .build()?;
                                if let Some(log) = log {
                                    reload_handle.modify(|k| *k.filter_mut() = log)?;
                                }

                                rt.spawn(async move {
                                    let fd = unsafe { PidFd::from_raw_fd(child_pidfd) };
                                    let k = fd.into_future().await?;
                                    warn!("exit due to child process termination");
                                    exit(0);
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

                                    tokio::spawn(async move {
                                        let x = watch_config(
                                            vdns_rx,
                                            Some(hot.clone()),
                                            acceptor,
                                            child_pid as u32,
                                            tx,
                                            vethips,
                                        )
                                        .await;
                                        warn!("out-ns, watcher exited {:?}", x);
                                    });

                                    if let Some(dev) = dev {
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
                                    } else {
                                        info!("TUN not initialized, skipping tun2socks5");
                                    }

                                    std::future::pending::<()>().await;
                                    aok!()
                                })?;
                            }
                        }
                    }
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
                warn!("netns did not change");
                let clone = shell_prefs.spawn()?;
                let rt = tokio::runtime::Builder::new_current_thread().build()?;
                rt.block_on(async { clone.wait_for_child().await })?;
                warn!("exit");
            }
        }
        MainCommand::Rm { file } => {
            rm_mount(&file)?;
        }
        MainCommand::Id { pid } => {
            let profile = std::env::var(ENV_PROFILE);
            println!("Browser profile {} {:?}", ENV_PROFILE, profile);
            let ns = std::env::var(ENV_NS);
            println!("Network namespace {} {:?}", ENV_NS, ns);

            let proc = if let Some(pid) = pid {
                let ns_proc = ExactNS::from_source((PidPath::N(pid as i32), "net"))?;
                Some(ns_proc)
            } else {
                None
            };

            if let Ok(ns) = ns {
                if ns != "UNSPEC" {
                    let path = PathBuf::from(ns);
                    let ns = ExactNS::from_source(path)?;
                    let ns_self = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                    println!("env={} proc_self={}", ns.unique, ns_self.unique);
                    if ns.unique == ns_self.unique {
                        println!("network namespace matches claim");
                    } else {
                        warn!("netns mismatch");
                    }

                    if let Some(proc) = proc {
                        println!("PID-{} -> {}", pid.unwrap(), proc.unique);
                        if proc.unique == ns_self.unique {
                            println!("PID-{} = this process, regarding net-ns", pid.unwrap());
                        } else {
                            println!(
                                "PID-{} does NOT match this process, regarding net-ns",
                                pid.unwrap()
                            );
                        }
                    }
                }
            }
        }
        /// We are just putting state in proc now, basically. Seems cleaner
        MainCommand::Enter { sargs, target } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.adjust();

            // Resolve the bind mount path: profile name resolves to /nsp3/{name}/net,
            // otherwise treat as an explicit path if it starts with /, ./, or ~/
            let (resolved_path, nsdata) = {
                let t = &target;
                if t.starts_with('/') || t.starts_with("./") || t.starts_with("~/") {
                    let p = if let Some(rest) = t.strip_prefix("~/") {
                        let home = std::env::var("HOME").unwrap_or_default();
                        PathBuf::from(home).join(rest)
                    } else {
                        PathBuf::from(t)
                    };
                    (Some(p.clone()), state_paths::metadata_for_bind(&p))
                } else {
                    let p = state_paths::profile_netns_bind(t);
                    let m = state_paths::profile_ns_meta(t);
                    info!("Resolved profile name {:?} to {:?}", t, &p);
                    (Some(p), m)
                }
            };

            if let Some(path) = resolved_path {
                let ns_alive: Option<nsproxy_core::NsAlive> = if nsdata.exists() {
                    std::fs::read_to_string(&nsdata)
                        .ok()
                        .and_then(|content| serde_json::from_str(&content).ok())
                } else {
                    None
                };

                if let Some(ns_alive) = ns_alive {
                    // Use child_pid if available to enter both namespaces
                    if let Some(child_pid) = ns_alive.child_pid {
                        let ns_source = NSSource::Pid(child_pid as i32);
                        // Enter mount namespace first
                        ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                        info!("Entered mount namespace from child PID {}", child_pid);
                        // Then enter network namespace
                        ns_source.enter(CloneFlags::CLONE_NEWNET)?;
                        info!("Entered network namespace from child PID {}", child_pid);
                    } else {
                        // Fallback to path-based entry for backwards compatibility
                        let ns = NSSource::Path(path.clone());
                        ns.enter(CloneFlags::CLONE_NEWNET)?;
                    }

                    shell_prefs.set_nsproxy_env(ns_alive.browser_profile);
                    shell_prefs.set_ns_env(Some(&ns_alive.bind_mount.to_string_lossy()));
                } else {
                    error!("NS data not found at {:?}", nsdata)
                }
            } else {
                error!("specify --name <profile> or a path");
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
            let dstdir_abs = dstdir.canonicalize()?;
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
            let short_path = dstdir_abs.join("sp");
            let fd_abs = fd.canonicalize()?;
            warn!("Installing symlink {:?} -> {:?}", &short_path, &fd_abs);
            symlink(&fd_abs, &short_path);
            let short_path_unpriv = dstdir_abs.join("nsp");
            let selfprogdst_abs = selfprogdst.canonicalize()?;
            warn!(
                "Installing symlink {:?} -> {:?}",
                &short_path_unpriv, &selfprogdst_abs
            );
            symlink(&selfprogdst_abs, &short_path_unpriv);

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
        MainCommand::Wrap { undo, add } => {
            let mut config = WrappedBinariesConfig::load()?;

            if let Some(name) = add {
                if undo {
                    info!("not supported");
                    exit(0);
                }
                let resolved = config.add_binary(&name)?;
                println!("Added {:?} to wrapped binaries config", resolved);
                config.save()?;
                return Ok(());
            } else {
                if undo {
                    info!("Unwrapping all configured binaries...");
                    config.unwrap_all()?;
                } else {
                    info!("Wrapping all configured binaries...");
                    config.wrap_all()?;
                }
            }
        }
        MainCommand::Wrapped => {
            let config = WrappedBinariesConfig::load()?;

            println!("Wrapped Binaries Configuration");
            println!("================================");
            println!("Config file: {}", WRAPPED_BINARIES_CONFIG);
            println!();

            if config.binaries.is_empty() {
                println!("No binaries configured for wrapping.");
                println!();
                println!(
                    "Edit {} to add binaries (absolute paths).",
                    WRAPPED_BINARIES_CONFIG
                );
                return Ok(());
            }

            println!("Configured binaries ({}):", config.binaries.len());

            // Get cached hash
            let nswrap_hash = if let Some(ref hash) = config.nswrap_hash {
                println!("Cached nswrap hash: {}", hash);
                println!();
                Some(hash.clone())
            } else {
                println!("No cached hash found. Run 'sp wrap' to initialize.");
                println!();
                None
            };

            for binary_path in &config.binaries {
                if let Some(ref expected_hash) = nswrap_hash {
                    match config.check_single_wrapped(binary_path, expected_hash) {
                        Ok(_) => println!("  ✓ {:?}", binary_path),
                        Err(e) => println!("  ✗ {:?} - {}", binary_path, e),
                    }
                } else {
                    let wrapped_path = binary_path.with_extension("wrapped");
                    if wrapped_path.exists() {
                        println!("  ? {:?} (cannot verify)", binary_path);
                    } else {
                        println!("  ✗ {:?} (not wrapped)", binary_path);
                    }
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
        MainCommand::Curl { url, proxy } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let client = if let Some(proxy_addr) = proxy {
                    let proxy_url = format!("socks5h://{}", proxy_addr);
                    info!("using proxy: {}", proxy_url);
                    reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(proxy_url)?)
                        .build()?
                } else {
                    reqwest::Client::builder()
                        .redirect(Policy::default())
                        .build()?
                };

                info!("requesting: {}", url);
                match client.get(url).send().await {
                    Ok(response) => {
                        println!("Status: {}", response.status());
                        match response.text().await {
                            Ok(body) => println!("{}", body),
                            Err(e) => warn!("failed to read response body: {}", e),
                        }
                    }
                    Err(e) => warn!("request failed: {:?}", e),
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        MainCommand::Forward { src, dst } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            if dst == src {
                bail!("src==dst dead loop");
            }

            rt.block_on(async {
                let list = format!("0.0.0.0:{}", src);
                let listener = tokio::net::TcpListener::bind(&list).await?;
                info!("tcp forward listening on {}", &list);

                loop {
                    let (mut client, _) = listener.accept().await?;
                    let dst_addr = format!("127.0.0.1:{}", dst);

                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(&dst_addr).await {
                            Ok(mut server) => {
                                info!("forwarded connection to {}", dst_addr);
                                if let Err(e) =
                                    tokio::io::copy_bidirectional(&mut client, &mut server).await
                                {
                                    warn!("forward error: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("failed to connect to {}: {}", dst_addr, e);
                            }
                        }
                    });
                }

                aok!()
            })?;
        }
        MainCommand::Profile {
            path,
            name,
            reset,
            update,
        } => {
            if reset && update {
                bail!("Cannot use --reset and --update together");
            }

            info!("Profile Creation");
            info!("Creating profile instance with isolated state directory");
            info!("Each profile can only be instantiated once (e.g., for VS Code isolation)");
            info!("");

            // Derive name from config file stem if not provided
            let clean_name = if let Some(ref name) = name {
                // Sanitize provided name: extract filename, remove .json extension
                let name_path = PathBuf::from(name);
                name_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(name)
                    .to_string()
            } else {
                // Derive from config path
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow!("cannot derive profile name from path: {:?}", path))?
                    .to_string()
            };

            info!("Profile name: {}", clean_name);
            info!("Template config: {:?}", path);

            // Create target directory at /nsp3/{clean_name}
            let target_dir = PathBuf::from(PERSIST_ROOT).join(&clean_name);
            info!("Target directory: {:?}", target_dir);

            let profile_path = target_dir.join("profile.json");
            let hot_path = target_dir.join("hot.json");

            if update {
                // Update mode: check that profile exists
                if !profile_path.exists() {
                    bail!(
                        "profile does not exist at {:?}. Use without --update to create.",
                        profile_path
                    );
                }

                info!("Update mode - updating existing profile...");

                // Load the new template
                info!("Loading new template from {:?}...", path);
                let mut profile = ProfileConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders
                info!("Expanding @ placeholders to: {:?}", target_dir);
                profile.expand_placeholders(&target_dir);

                // Wellness checks
                info!("Running wellness checks...");

                // Check if mount sources exist
                let mut missing_sources = Vec::new();
                let mut existing_sources = Vec::new();
                for m in &profile.mounts {
                    if !m.source.exists() {
                        missing_sources.push(&m.source);
                    } else {
                        existing_sources.push(&m.source);
                    }
                }

                if !missing_sources.is_empty() {
                    warn!("Missing mount sources:");
                    for src in &missing_sources {
                        warn!("  ✗ {:?}", src);
                    }
                    bail!("Some mount sources do not exist. Create them manually or use --reset.");
                }

                info!("All mount sources available:");
                for src in &existing_sources {
                    info!("  ✓ {:?}", src);
                }

                // Check hot config
                if hot_path.exists() {
                    info!("✓ Hot config exists: {:?}", hot_path);
                } else {
                    warn!("Hot config does not exist at {:?}", hot_path);
                }

                // Check cwd if specified
                if let Some(ref cwd) = profile.sargs.cwd {
                    if cwd.exists() {
                        info!("✓ Working directory exists: {:?}", cwd);
                    } else {
                        warn!("Working directory does not exist: {:?}", cwd);
                    }
                }

                // Update profile config (overwrite profile.json, keep hot.json)
                info!("Updating profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile updated successfully");
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?} (unchanged)", new_profile.hot);
                info!("");
                info!("Note: Existing directories and files were not modified");
            } else {
                // Create mode (original logic)

                // If reset flag is set, remove the entire directory first
                if reset && target_dir.exists() {
                    warn!("Reset flag enabled - removing existing profile directory");

                    // Remove namespace bind mount if it exists
                    let ns_bind = state_paths::profile_netns_bind(&clean_name);
                    if ns_bind.exists() {
                        warn!("Removing namespace bind mount at {:?}", &ns_bind);
                        if let Err(e) = rm_mount(&ns_bind) {
                            warn!("Failed to unmount {:?}: {:?}", &ns_bind, e);
                        }
                    }
                    // Remove sidecar metadata JSON
                    let ns_meta = state_paths::profile_ns_meta(&clean_name);
                    if ns_meta.exists() {
                        std::fs::remove_file(&ns_meta)?;
                    }

                    std::fs::remove_dir_all(&target_dir)?;
                    info!("Removed existing directory");
                }

                info!("Creating profile directory structure...");
                std::fs::create_dir_all(&target_dir)?;

                if profile_path.exists() && !reset {
                    bail!(
                        "profile config already exists: {:?}. Use --reset to recreate from scratch or --update to update config.",
                        profile_path
                    );
                }

                // Load the profile template from provided path
                info!("Loading profile template from {:?}...", path);
                let mut profile = ProfileConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders for directory creation
                info!("Expanding @ placeholders to: {:?}", target_dir);
                profile.expand_placeholders(&target_dir);

                // Create all referenced directories
                if let Some(ref cwd) = profile.sargs.cwd {
                    if !cwd.exists() {
                        info!("Creating working directory: {:?}", cwd);
                        std::fs::create_dir_all(cwd)?;
                        warn!("Created cwd: {:?}", cwd);
                    }
                }

                // Determine ownership for created directories
                info!("Determining ownership for created directories...");
                let (owner_uid, owner_gid) = if let Some(uid) = profile.sargs.uid {
                    let gid = profile.sargs.gid.unwrap_or_else(|| {
                        uzers::get_user_by_uid(uid)
                            .map(|u| u.primary_group_id())
                            .unwrap_or(uid)
                    });
                    (uid, gid)
                } else {
                    use nix::unistd::getresuid;
                    use nsproxy_common::UID_HINT_VAR;

                    let uid = if let Ok(id) = std::env::var(UID_HINT_VAR) {
                        id.parse()?
                    } else if let Ok(id) = std::env::var("SUDO_UID") {
                        id.parse()?
                    } else {
                        let res = getresuid()?;
                        if !res.real.is_root() {
                            res.real.as_raw()
                        } else {
                            1000 // fallback
                        }
                    };

                    let gid = uzers::get_user_by_uid(uid)
                        .map(|u| u.primary_group_id())
                        .unwrap_or(uid);
                    (uid, gid)
                };
                info!("Using ownership: uid={}, gid={}", owner_uid, owner_gid);

                info!("Creating mount source directories...");
                for m in &profile.mounts {
                    if !m.source.exists() {
                        info!("  Creating: {:?}", m.source);
                        std::fs::create_dir_all(&m.source)?;
                        // Set ownership
                        nix::unistd::chown(
                            &m.source,
                            Some(nix::unistd::Uid::from_raw(owner_uid)),
                            Some(nix::unistd::Gid::from_raw(owner_gid)),
                        )?;
                        info!("  Set ownership to uid={}, gid={}", owner_uid, owner_gid);
                    } else {
                        info!("  Mount source exists: {:?}", m.source);
                    }
                }

                // Copy hot config if it exists, otherwise create from hot_init or default
                info!("Setting up hot config...");
                if profile.hot.exists() && profile.hot != hot_path {
                    info!("Copying hot config from {:?}", profile.hot);
                    std::fs::copy(&profile.hot, &hot_path)?;
                    warn!("Copied hot config: {:?} -> {:?}", profile.hot, hot_path);
                } else if !hot_path.exists() {
                    info!("Creating hot config from profile.hot_init");
                    let hot = profile.hot_init.clone().unwrap_or_default();
                    let hot_json = serde_json::to_string_pretty(&hot)?;
                    std::fs::write(&hot_path, hot_json)?;
                    warn!("Created hot config: {:?}", hot_path);
                }

                // Update profile to point to new hot config location
                info!("Writing profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile created successfully");
                info!("Location: {:?}", target_dir);
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?}", new_profile.hot);
                info!("");
                info!("Use with: sp make --name {}", clean_name);
            }
        }
        MainCommand::Up { profile } => {
            let wrapped_config = WrappedBinariesConfig::load()?;
            wrapped_config.check_all_wrapped()?;

            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let profile_conf = ProfileConfig::load(&profile_path)?;

            let bind_mount = state_paths::profile_netns_bind(&profile);
            if let Some(parent) = bind_mount.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let ns_meta = state_paths::profile_ns_meta(&profile);
            if ns_meta.exists() {
                if let Ok(content) = std::fs::read_to_string(&ns_meta) {
                    if let Ok(ns_alive) = serde_json::from_str::<nsproxy_core::NsAlive>(&content) {
                        if let Some(pid) = ns_alive.child_pid {
                            let proc_path = PathBuf::from("/proc").join(pid.to_string());
                            if proc_path.exists() {
                                bail!("profile already up; pid {} is alive", pid);
                            }
                        }
                    }
                }
            }

            // Always enter as many namespaces as possible here, since other processes can enter less.
            let clone = nsproxy_core::sys::clone3::<true>(true, true);
            match clone {
                Ok(clone) => match clone {
                    Clone3Result::IsChild { mut tx } => {
                        let mut buf = [0; 1];
                        enable_ping_all()?;
                        tx.read(&mut buf)?; // wait for bind mount
                        mount_bind_root()?;
                        loop {
                            std::thread::park();
                        }
                    }
                    Clone3Result::Parent {
                        child_pid, mut tx, ..
                    } => {
                        std::fs::create_dir_all(RUNTIME_ROOT)?;
                        let path = format!("/proc/{}/ns/net", child_pid);
                        let path = PathBuf::from(path);
                        mount_ns(&path, &bind_mount)?;

                        let ns_alive = nsproxy_core::NsAlive {
                            browser_profile: profile_conf.browser_profile.clone(),
                            bind_mount: bind_mount.clone(),
                            child_pid: Some(child_pid as u32),
                        };
                        let json = serde_json::to_string_pretty(&ns_alive)?;
                        std::fs::write(&ns_meta, json)?;
                        warn!("Auxiliary data written to {:?}", &ns_meta);

                        tx.write(&[0])?;
                    }
                },
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
        }
        MainCommand::Tun {
            profile,
            tun: proxy,
            no_default,
            no_proxy,
            log,
        } => {
            let wrapped_config = WrappedBinariesConfig::load()?;
            wrapped_config.check_all_wrapped()?;

            let mut iargs = proxy;
            match (iargs.proxy.is_some(), no_proxy) {
                (true, true) => {
                    bail!(
                        "Cannot specify both --proxy and --no-proxy. They are mutually exclusive."
                    );
                }
                (false, false) => {
                    bail!("Must specify either --proxy <URL> or --no-proxy explicitly.");
                }
                _ => {}
            }

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive: nsproxy_core::NsAlive = std::fs::read_to_string(&ns_meta)
                .ok()
                .and_then(|content| serde_json::from_str(&content).ok())
                .ok_or_else(|| anyhow!("NS data not found at {:?}", &ns_meta))?;

            let child_pid = ns_alive
                .child_pid
                .ok_or_else(|| anyhow!("ns_alive has no child_pid"))?;

            let hot_conf = state_paths::hot_config(&profile);
            if !hot_conf.exists() {
                bail!("hot config does not exist: {:?}", hot_conf);
            }

            let diag_path = diag::diag_sock_path(&profile);
            if diag_path.exists() {
                match std::os::unix::net::UnixStream::connect(&diag_path) {
                    Ok(_) => {
                        bail!(
                            "tun appears to be running (diag socket accepts connections): {:?}",
                            diag_path
                        );
                    }
                    Err(e) => {
                        warn!(
                            "diag socket probe failed ({}), proceeding with startup: {:?}",
                            e, diag_path
                        );
                    }
                }
            }
            iargs.diag_sock = Some(diag_path);

            let mtu = 1500;
            let tun_name = iargs.tun_name.unwrap_or_else(|| "tun2".to_owned());
            iargs.tun_name = Some(tun_name.clone());

            let clone = nsproxy_core::sys::clone3::<false>(false, false);
            match clone {
                Ok(clone) => match clone {
                    Clone3Result::IsChild { mut tx } => {
                        let hot_conf = hot_conf.clone();
                        let ns_source = NSSource::Pid(child_pid as i32);
                        ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                        ns_source.enter(CloneFlags::CLONE_NEWNET)?;
                        // already done in ::Up
                        // enable_ping_all()?;

                        let mut tun = TunMaker::default();
                        tun.name = tun_name.clone();
                        tun.mtu = mtu;
                        let mut tun_state = tun.make()?;
                        tun_state.sync_basic()?;
                        let dev = Arc::into_inner(tun_state.fd.unwrap()).unwrap();
                        let raw = dev.as_raw_fd();

                        info!("send TUN fd");
                        tx.send_fd(raw)?;
                        drop(dev);

                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(async {
                            use tokio::io::AsyncReadExt;
                            use tokio_send_fd::SendFd;
                            tx.set_nonblocking(true)?;
                            let mut tx = tokio::net::UnixStream::from_std(tx)?;

                            let nl = tokio_netlink_conn()?;
                            nl.up_lo().await?;

                            // Set txqueuelen for TUN device to handle bursty traffic
                            let txqueuelen = 500_000u32; // 
                            warn!("setting TUN txqueuelen to {} for high throughput", txqueuelen);
                            nl.link()
                                .set(
                                    LinkMessageBuilder::<LinkUnspec>::default()
                                        .index(tun_state.dev_index)
                                        .append_extra_attribute(LinkAttribute::TxQueueLen(txqueuelen))
                                        .build()
                                )
                                .execute()
                                .await?;

                            let add_default = !no_default;
                            if add_default {
                                warn!("adding TUN as default route");
                                nl.ip_add_default_route(tun_state.dev_index).await?;
                            }

                            tokio::spawn(async move {
                                let conf = Some(hot_conf);
                                if let Some(conf) = conf {
                                    let mut mnt: HashMap<PathBuf, PathBuf> = Default::default();
                                    let mut read = [0u8; 24];
                                    loop {
                                        info!("in-ns wait for config");
                                        let k = tx.read(&mut read[..]).await?;
                                        if k < 1 {
                                            error!("in-ns config watcher exits due to EOF");
                                            break;
                                        }
                                        info!("in-ns reload config");
                                        let fc = tokio::fs::read_to_string(&conf).await?;
                                        match serde_json::from_str::<HotConfig>(&fc) {
                                            Ok(newconf) => {
                                                for (s, t) in mnt.clone() {
                                                    if let Some(_new) = newconf.mnt.get(&s) {
                                                    } else {
                                                        rm_mount(&t);
                                                        mnt.remove(&s);
                                                    }
                                                }

                                                for (s, t) in newconf.mnt.clone() {
                                                    if let Some(current) = mnt.get(&s)
                                                        && current == &t
                                                    {
                                                    } else {
                                                        let x = mount_bind(&s, &t);
                                                        if let Err(e) = x {
                                                            error!("Bind mount {:?}", &e);
                                                        }
                                                        mnt.insert(s, t);
                                                    }
                                                }

                                                tx.write(&[0, 0, 0, 0]).await?;
                                                for (in_port, _dst) in &newconf.locals {
                                                    let bind = std::net::TcpListener::bind(
                                                        format!("127.0.0.1:{}", in_port),
                                                    )?;
                                                    let raw = bind.as_raw_fd();
                                                    tx.write(&in_port.to_le_bytes()).await?;
                                                    tx.send_fd(raw).await?;
                                                }
                                                tx.write(&[0, 0, 0, 0]).await?;

                                                let _ = enumerate_links(None, &newconf).await;
                                            }
                                            _ => {}
                                        }
                                    }
                                }

                                aok!()
                            });

                            std::future::pending::<()>().await;
                            aok!()
                        })?;
                    }
                    Clone3Result::Parent {
                        child_pid,
                        child_pidfd,
                        mut tx,
                    } => {
                        let hot_conf = hot_conf.clone();
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
                            let _ = fd.into_future().await?;
                            warn!("tun helper exited");
                            aok!()
                        });

                        rt.block_on(async move {
                            use tokio::io::AsyncWriteExt;

                            tx.set_nonblocking(true)?;
                            let mut tx = tokio::net::UnixStream::from_std(tx)?;

                            let (mut vdns_sx, vdns_rx) = mpsc::channel(1);
                            let (st_sx, acceptor) = flume::unbounded();

                            tokio::spawn(async move {
                                let x = watch_config(
                                    vdns_rx,
                                    Some(hot_conf),
                                    acceptor,
                                    child_pid as u32,
                                    tx,
                                    None,
                                )
                                .await;
                                warn!("out-ns, watcher exited {:?}", x);
                            });

                            tun2socks5::main_entry(dev, mtu, false, iargs, vdns_sx.clone(), st_sx)
                                .await?;
                            warn!("tun exited");
                            let _ = vdns_sx.send(None).await;

                            std::future::pending::<()>().await;
                            aok!()
                        })?;
                    }
                },
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
        }
        MainCommand::Veth {
            profile,
            veth_name,
            log,
        } => {
            let wrapped_config = WrappedBinariesConfig::load()?;
            wrapped_config.check_all_wrapped()?;

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive: nsproxy_core::NsAlive = std::fs::read_to_string(&ns_meta)
                .ok()
                .and_then(|content| serde_json::from_str(&content).ok())
                .ok_or_else(|| anyhow!("NS data not found at {:?}", &ns_meta))?;

            let child_pid = ns_alive
                .child_pid
                .ok_or_else(|| anyhow!("ns_alive has no child_pid"))?;

            let vname = veth_name.unwrap_or_else(|| profile.clone());
            let v_in = format!("{vname}_in");
            let v_out = format!("{vname}_out");
            let veth_net: Ipv4Network = "100.64.0.0/10".parse()?;
            let host_bits = 2;
            let subnet_prefix = 32 - host_bits;

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            if let Some(log) = log {
                reload_handle.modify(|k| *k.filter_mut() = log)?;
            }

            rt.block_on(async move {
                use tokio::io::AsyncWriteExt;

                let nl = tokio_netlink_conn()?;
                info!("attempting to add veths named, {}, {}", &v_out, &v_in);
                let addrs = nl.fetch_all_ip_addrs().await?;
                let ips: Vec<_> = addrs
                    .iter()
                    .filter_map(|f| match f {
                        IpNetwork::V4(v4) => Some(v4.ip()),
                        _ => None,
                    })
                    .collect();

                let v1: Option<Ipv4Addr> = find_vacant_ipv4_subnet(ips, veth_net, host_bits);
                if let Some(subnet) = v1 {
                    nl.add_veth(&v_out, &v_in).await;
                    let vin = nl.fetch_link_by_name(v_in.clone()).await?;
                    let msg: LinkMessageBuilder<LinkVeth> = LinkMessageBuilder::default()
                        .index(vin.header.index)
                        .setns_by_pid(child_pid as u32);
                    nl.link().set(msg.build()).execute().await;

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

                    let clone = nsproxy_core::sys::clone3::<false>(false, false);
                    match clone {
                        Ok(clone) => match clone {
                            Clone3Result::IsChild { mut tx } => {
                                let ns_source = NSSource::Pid(child_pid as i32);
                                ns_source.enter(CloneFlags::CLONE_NEWNET)?;

                                let mut buf = [0u8; 4];
                                tx.read_exact(&mut buf)?;
                                let ip =
                                    veth_addr_for(Ipv4Addr::from_octets(buf), host_bits, false);

                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()?;
                                rt.block_on(async {
                                    let nl = tokio_netlink_conn()?;
                                    nl.up_lo().await?;
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
                                    Ok::<(), anyhow::Error>(())
                                })?;
                            }
                            Clone3Result::Parent { mut tx, .. } => {
                                tx.write(subnet.as_octets())?;
                            }
                        },
                        Err(er) => {
                            warn!("Clone3 failed with {:?}", &er);
                        }
                    }
                } else {
                    tracing::error!("cannot find any vacant ip");
                }

                aok!()
            })?;
        }
        MainCommand::Basis { cmd } => match cmd {
            BasisCommand::Mount {} => {
                let source = PathBuf::from("/proc/self/ns/net");
                let bind_mount = state_paths::profile_netns_bind("basis");
                if let Some(parent) = bind_mount.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                mount_ns(&source, &bind_mount)?;
                info!("Basis netns mounted at {:?}", bind_mount);
            }
            BasisCommand::Enter { sargs } => {
                let mut shell_prefs = ShellPrefs::default();
                shell_prefs.take_args(sargs);
                shell_prefs.adjust();

                let bind_mount = state_paths::profile_netns_bind("basis");
                let nsdata = state_paths::profile_ns_meta("basis");

                let ns_alive: Option<nsproxy_core::NsAlive> = if nsdata.exists() {
                    std::fs::read_to_string(&nsdata)
                        .ok()
                        .and_then(|content| serde_json::from_str(&content).ok())
                } else {
                    None
                };

                if let Some(ns_alive) = ns_alive {
                    if let Some(child_pid) = ns_alive.child_pid {
                        let ns_source = NSSource::Pid(child_pid as i32);
                        ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                        info!("Entered mount namespace from child PID {}", child_pid);
                        ns_source.enter(CloneFlags::CLONE_NEWNET)?;
                        info!("Entered network namespace from child PID {}", child_pid);
                    } else {
                        let ns = NSSource::Path(bind_mount.clone());
                        ns.enter(CloneFlags::CLONE_NEWNET)?;
                    }

                    shell_prefs.set_nsproxy_env(ns_alive.browser_profile);
                    shell_prefs.set_ns_env(Some(&ns_alive.bind_mount.to_string_lossy()));
                } else {
                    let ns = NSSource::Path(bind_mount.clone());
                    ns.enter(CloneFlags::CLONE_NEWNET)?;
                    shell_prefs.set_ns_env(Some(&bind_mount.to_string_lossy()));
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
        },
        _ => unimplemented!(),
    }

    Ok(())
}

async fn handle_tcp_forward_local(fd: OwnedFd, port: u32, dst_port: u32) {
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd.into_raw_fd()) };
    std_listener.set_nonblocking(true).unwrap();
    match tokio::net::TcpListener::from_std(std_listener) {
        Ok(listener) => loop {
            match listener.accept().await {
                Ok((mut client, _)) => {
                    let dst_addr = format!("127.0.0.1:{}", dst_port);
                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(&dst_addr).await {
                            Ok(mut server) => {
                                info!("forwarded connection from port {} to {}", port, dst_addr);
                                if let Err(e) =
                                    tokio::io::copy_bidirectional(&mut client, &mut server).await
                                {
                                    warn!("forward error: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("failed to connect to {}: {}", dst_addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("accept error on port {}: {}", port, e);
                    break;
                }
            }
        },
        Err(e) => {
            warn!("failed to create async listener for port {}: {}", port, e);
        }
    }
}

async fn watch_config(
    mut vdns_rx: mpsc::Receiver<Option<VirtDNSHandle>>,
    conf: Option<PathBuf>,
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

    if let Some(conf) = conf {
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

                let mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
                let conf = conf;
                let fc = tokio::fs::read_to_string(&conf).await?;
                match serde_json::from_str::<HotConfig>(&fc) {
                    Ok(newconf) => {
                        let cloned = newconf.clone();
                        if prev_conf.is_some() && prev_conf.as_ref().unwrap() == &cloned {
                            return Ok(futs);
                        }
                        use serde_json::{self, Value};
                        warps.iter_mut().map(|(p, k)| k.marked = false);

                        info!("enumerate link devices in parent process");
                        enumerate_links(Some(child_pid), &newconf).await?;

                        if let Some(vdns) = &vdns {
                            for (domain, ip) in newconf.dns {
                                let target = TUNResponse::Unreachable;
                                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                                    info!("DNS {} -> {}", &domain, addr);
                                    vdns.pin(Some(addr), domain, target)?;
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
                                                    futs.push(Box::pin(ws.run()));
                                                    e.insert(ServerItem { marked: true });
                                                }
                                                Entry::Occupied(mut e) => {
                                                    e.get_mut().marked = true;
                                                }
                                            }
                                            let target = TUNResponse::Files(path);
                                            vdns.pin(None, domain, target)?;
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
                        info!("ping child");
                        tx.write(&[1u8]).await?;
                        use tokio_send_fd::SendFd;
                        let mut port_bytes = [0u8; 4];
                        let mut first = false;
                        while tx.read(&mut port_bytes).await.ok() == Some(4) {
                            let in_port = u32::from_le_bytes(port_bytes);
                            if in_port == 0 {
                                if !first {
                                    first = true;
                                    continue;
                                } else {
                                    break;
                                }
                            }
                            let fd = tx.recv_fd().await?;
                            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                            let dst_port = newconf.locals.get(&in_port).copied();
                            futs.push(Box::pin(async move {
                                if let Some(dst_port) = dst_port {
                                    handle_tcp_forward_local(fd, in_port, dst_port).await;
                                }
                            }));
                        }
                        info!("localhost forward {}", newconf.locals.len());
                        info!("received and spawned TCP listener tasks");

                        *prev_conf = Some(cloned);
                    }
                    _ => {
                        warn!("config changed, but is invalid");
                    }
                }

                anyhow::Ok(futs)
            };

            info!("serving {} file roots. wait for new event.", futs.len());
            futs = select! {
                k = rx.recv() => {if let Some(_) = k { o.await? } else {break;}},
                _ = join_all(futs), if futs.len() > 0 => {
                    Vec::new()
                }
            }
        }

        warn!("config watching ended");
    } else {
        error!("no config specified. config watcher stopped");
    }
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

async fn handle_socks5_connection<S>(
    conn: socks5_impl::server::IncomingConnection<S>,
) -> anyhow::Result<()>
where
    S: Send + Sync + 'static,
{
    use socks5_impl::protocol::*;
    use socks5_impl::server::*;
    use tokio::io;
    use tokio::net::TcpStream;

    let (conn, res) = conn.authenticate().await?;

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            info!("UDP associate not supported");
            let mut conn = associate
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Bind(bind, _) => {
            info!("Bind not supported");
            let mut conn = bind
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            info!("connect to {}", addr);
            let target = match &addr {
                WireAddress::DomainAddress(domain, port) => {
                    TcpStream::connect((domain.as_str(), *port)).await
                }
                WireAddress::SocketAddress(socket_addr) => TcpStream::connect(socket_addr).await,
            };

            match target {
                Ok(mut target_stream) => {
                    let mut conn = connect
                        .reply(Reply::Succeeded, WireAddress::unspecified())
                        .await?;
                    info!("established connection to {}", addr);
                    io::copy_bidirectional(&mut target_stream, &mut conn).await?;
                }
                Err(err) => {
                    warn!("failed to connect to {}: {}", addr, err);
                    let mut conn = connect
                        .reply(Reply::HostUnreachable, WireAddress::unspecified())
                        .await?;
                    conn.shutdown().await?;
                }
            }
        }
    }

    Ok(())
}
