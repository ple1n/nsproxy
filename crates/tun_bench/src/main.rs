#![allow(unreachable_code)]

use std::{future::pending, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use futures::channel::{mpsc::unbounded, oneshot::channel};
use nsproxy_core::{
    TunMaker, tokio_netlink_conn,
    tun2socks5::{self, ArgProxy, IArgs},
};
use socks5_impl::{
    client::Socks5Writer,
    protocol::{AsyncStreamOperation, AuthMethod, handshake},
    server::auth,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    time::sleep,
};
use tracing::{debug, info, level_filters::LevelFilter, subscriber::set_global_default, warn};
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<()> {
    let fmt = tracing_subscriber::fmt()
        .compact()
        .with_max_level(LevelFilter::WARN)
        .without_time()
        .finish();
    set_global_default(fmt)?;

    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    warn!(
        "open file limits, soft={}, hard={}. trying to raise soft limit to max",
        soft, hard
    );
    rl::Resource::NOFILE.set(hard, hard)?;

    info!("make tun");
    let tun = TunMaker::default();
    let mut state = tun.make()?;
    state.sync_basic()?;
    let nl = tokio_netlink_conn()?;
    let dev = state.fd.clone().unwrap();
    tokio::spawn(socks_serve());
    tokio::spawn(async move {
        let mtu = dev.mtu()?;
        let args = IArgs {
            proxy: ArgProxy::from_url("socks5://127.0.0.1:2080")?.into(),
            ipv6_enabled: false,
            dns: tun2socks5::ArgDns::Handled,
            dns_addr: "127.2.2.2".parse()?,
            bypass: Default::default(),
            designated: None,
            id: None,
            name: None,
        };

        let (sx, rx) = channel();
        tun2socks5::main_entry(dev, mtu, false, args, sx, todo!()).await?;

        anyhow::Ok(())
    });

    info!("tun made");
    sleep(Duration::from_secs(1)).await;

    let r = tun.test_route(&nl, &state).await?;
    warn!("tun routing {}", r);

    pending::<()>().await;
    Ok(())
}

async fn socks_serve() -> Result<()> {
    use socks5_impl::protocol::*;
    use socks5_impl::server::*;

    info!("starting socks server");

    let addr = "127.0.0.1:2080";
    let server = Server::bind(addr.parse()?, Arc::new(auth::NoAuth)).await?;
    loop {
        let (conn, _) = server.accept().await?;

        tokio::spawn(async {
            let (conn, res) = conn.authenticate().await?;
            match conn.wait_request().await? {
                ClientConnection::UdpAssociate(associate, _) => {}
                ClientConnection::Bind(bind, _) => {
                    let mut conn = bind
                        .reply(Reply::CommandNotSupported, Address::unspecified())
                        .await?;
                    conn.shutdown().await?;
                }
                ClientConnection::Connect(connect, addr) => {
                    info!("connect {}", addr);
                    let mut conn = connect
                        .reply(Reply::Succeeded, Address::unspecified())
                        .await?;
                    let rep = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345";
                    conn.write_all(rep).await?;
                    let mut buf = vec![0; 32];
                    loop {
                        if conn.read_buf(&mut buf).await? == 0 {
                            break;
                        }
                    }
                }
            }

            anyhow::Ok(())
        });
    }
    Ok(())
}
