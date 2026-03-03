use std::{
    collections::{HashMap, hash_map::Entry},
    future::{Future, ready},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use futures::{StreamExt, channel::mpsc, future::join_all, stream::TryStreamExt};
use hardware_address::MacAddr;
use ipnetwork::IpNetwork;
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec};
use rtnetlink::packet_route::link::LinkAttribute;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select, sync,
};
use tracing::{error, info, warn};
use tun2socks5::{
    dns::{VirtDNSHandle},
    flume,
    ipstack::stream::IpStackTcpStream,
};
use warp::server::accept::Accept;

use crate::{
    HotConfig,
    tokio_netlink_conn,
};
use nsproxy_common::routing::{DropReason, RoutingDecision};
use diag::{DiagEvent, DiagServer, Timestamp};

#[derive(Clone, Copy, Debug)]
pub enum HotReloadTrigger {
    FileChange,
    DirectReload,
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, sync::mpsc::Receiver<()>)> {
    let (mut tx, rx) = tokio::sync::mpsc::channel(1);
    let tx1 = tx.clone();
    tokio::spawn(async move { tx1.send(()).await });

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

#[derive(Clone, Copy)]
pub struct VethIps {
    pub vout: Ipv4Addr,
    pub vin: Ipv4Addr,
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

pub async fn watch_hot(
    mut vdns_rx: mpsc::Receiver<Option<VirtDNSHandle>>,
    conf: Option<PathBuf>,
    acceptor: flume::Receiver<(PathBuf, IpStackTcpStream)>,
    child_pid: u32,
    mut tx: tokio::net::UnixStream,
    veths: Option<VethIps>,
    diag: DiagServer,
    mut reload_rx: sync::mpsc::Receiver<HotReloadTrigger>,
    hot_tx: sync::watch::Sender<HotConfig>,
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
            RoutingDecision::Drop(DropReason::Preprocess),
        );
        vdns.pin(
            Some(veth.vin),
            "veth.peer.".to_owned(),
            RoutingDecision::Drop(DropReason::Preprocess),
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
            let diag = diag.clone();
            let hot_tx = hot_tx.clone();
            let reload = |source: &'static str| async move {
                warn!("config hot reload");

                let mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
                let fc = tokio::fs::read_to_string(&conf).await?;
                match serde_json::from_str::<HotConfig>(&fc) {
                    Ok(newconf) => {
                        let cloned = newconf.clone();
                        if prev_conf.is_some() && prev_conf.as_ref().unwrap() == &cloned {
                            diag.emit(DiagEvent::HotConfigReloaded {
                                ts: Timestamp::now(),
                                ok: true,
                                changed: false,
                                source: source.to_string(),
                                error: None,
                            });
                            return Ok(futs);
                        }

                        use serde_json::Value;
                        warps.iter_mut().for_each(|(_, k)| k.marked = false);

                        info!("enumerate link devices in parent process");
                        sync_links(Some(child_pid), &newconf).await?;

                        if let Some(vdns) = &vdns {
                            for (domain, ip) in newconf.dns {
                                let target = RoutingDecision::Drop(DropReason::Preprocess);
                                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                                    info!("DNS {} -> {}", &domain, addr);
                                    vdns.pin(Some(addr), domain, target)?;
                                }
                            }

                            for (domain, spec) in newconf.tun {
                                match spec {
                                    Value::String(mapstr) => {
                                        if let Ok(addr) = mapstr.parse::<SocketAddr>() {
                                            info!("NAT-out {} -> {}", &domain, addr);
                                            let target = RoutingDecision::NATByTUN(addr);
                                            vdns.pin(None, domain, target)?;
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
                                            let target = RoutingDecision::File(path);
                                            vdns.pin(None, domain, target)?;
                                        }
                                    }
                                    Value::Number(port) => {
                                        let p = port.as_u64().ok_or(anyhow!("invalid port"))?;
                                        let p: u16 = p.try_into()?;
                                        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, p).into();
                                        info!("NAT-out {} -> {}", &domain, addr);
                                        let target = RoutingDecision::NATByTUN(addr);
                                        vdns.pin(None, domain, target)?;
                                    }
                                    _ => {}
                                }
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
                                }
                                break;
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

                        *prev_conf = Some(cloned.clone());
                        let _ = hot_tx.send(cloned);
                        diag.emit(DiagEvent::HotConfigReloaded {
                            ts: Timestamp::now(),
                            ok: true,
                            changed: true,
                            source: source.to_string(),
                            error: None,
                        });
                    }
                    _ => {
                        warn!("config changed, but is invalid");
                        diag.emit(DiagEvent::HotConfigReloaded {
                            ts: Timestamp::now(),
                            ok: false,
                            changed: false,
                            source: source.to_string(),
                            error: Some("parse error".to_string()),
                        });
                    }
                }

                anyhow::Ok(futs)
            };

            info!("serving {} file roots. wait for new event.", futs.len());
            futs = select! {
                k = rx.recv() => {
                    if k.is_some() {
                        reload("file").await?
                    } else {
                        break;
                    }
                },
                Some(trigger) = reload_rx.recv() => {
                    match trigger {
                        HotReloadTrigger::DirectReload => {
                            reload("direct").await?
                        }
                        HotReloadTrigger::FileChange => {
                            reload("file").await?
                        }
                    }
                }
                _ = join_all(futs), if !futs.is_empty() => {
                    Vec::new()
                }
            }
        }

        warn!("config watching ended");
    } else {
        error!("no config specified. config watcher stopped");
    }
    Ok(())
}

pub async fn sync_links(child_pid: Option<u32>, newconf: &HotConfig) -> Result<()> {
    let handle: Handle = tokio_netlink_conn()?;

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
                                        .set(LinkUnspec::new_with_index(msg.header.index).up().build())
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
                            }
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
            Ok(None) => break 'outer,
        }
    }

    Ok(())
}
