#![feature(decl_macro)]
#![allow(async_fn_in_trait)]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::sync::Arc;

use anyhow::Ok;
use anyhow::Result;
use anyhow::bail;
use futures::StreamExt;
use futures::TryStreamExt;
use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use rtnetlink::Handle;
use rtnetlink::RouteAddRequest;
use rtnetlink::RouteGetResolve;
use rtnetlink::netlink_packet_route::AddressMessage;
use rtnetlink::netlink_packet_route::IFF_UP;
use rtnetlink::netlink_packet_route::LinkMessage;
use rtnetlink::netlink_packet_route::RouteFlags;
use rtnetlink::netlink_packet_route::RouteMessage;
use rtnetlink::netlink_packet_route::RtnlMessage;
use rtnetlink::netlink_packet_route::link;
use rtnetlink::netlink_packet_route::route;
use rtnetlink::netlink_proto::Connection;
use serde::Deserialize;
use serde::Serialize;
use tokio::fs;
pub use tun2socks5;
pub mod utils;

pub struct TunMaker {
    pub name: String,
    pub ipv4: Ipv4Network,
    pub ipv6: Ipv6Network,
}

#[derive(Default)]
pub struct TunState {
    pub fd: Option<TUNDev>,
    default_route: bool,
    tun_is_up: bool,
    name: String,
    dev_index: u32,
    sync: SyncStatus,
}

#[derive(Default)]
/// Does the data struct correctly represent Kernel state?
pub struct SyncStatus {
    basic_synced: bool,
    route_checked: bool,
}

/// Minimal utils atop netlink
pub trait NetlinkParseUpdate {
    type Repr;
    /// Continually updates a parser state. Allowing gradual buildup.
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()>;
}

pub trait NetlinkParse {
    type Repr;
    fn parse(&self) -> Result<Self::Repr>;
}

use ipnetwork::IpNetwork;

#[derive(Default)]
pub struct AddressResponse {
    pub addrs: Vec<IpNetwork>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct RouteEntry {
    pub source_addrs: Vec<IpNetwork>,
    pub dst_addrs: Vec<IpNetwork>,
    pub table: Option<u32>,
    pub oif: Option<u32>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct RoutingTable {
    pub tables: HashMap<u32, Vec<RouteEntry>>,
}

impl NetlinkParseUpdate for AddressMessage {
    type Repr = AddressResponse;
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()> {
        for msg in self.nlas.iter() {
            match msg {
                rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                    let ip = octets_to_addr(a, self.header.prefix_len)?;
                    if let Some(ip) = ip {
                        parsed.addrs.push(ip);
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}

pub fn octets_to_addr(a: &[u8], prefix: u8) -> Result<Option<IpNetwork>> {
    let ip = if a.len() == 4 {
        let con: [u8; 4] = a.to_owned().try_into().unwrap();
        let ip4: Ipv4Addr = con.into();
        Some(IpNetwork::new(ip4.into(), prefix)?)
    } else if a.len() == 16 {
        let con: [u8; 16] = a.to_owned().try_into().unwrap();
        let ip6: Ipv6Addr = con.into();
        Some(IpNetwork::new(ip6.into(), prefix)?)
    } else {
        None
    };
    Ok(ip)
}

impl NetlinkParseUpdate for RouteMessage {
    type Repr = RouteEntry;
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()> {
        use rtnetlink::netlink_packet_route::route::Nla;
        for msg in self.nlas.iter() {
            match msg {
                Nla::PrefSource(a) => {
                    let ip = octets_to_addr(a, self.header.source_prefix_length)?;
                    if let Some(ip) = ip {
                        parsed.source_addrs.push(ip);
                    }
                }
                Nla::Destination(a) => {
                    let ip = octets_to_addr(a, self.header.source_prefix_length)?;
                    if let Some(ip) = ip {
                        parsed.dst_addrs.push(ip);
                    }
                }
                Nla::Table(t) => parsed.table = Some(*t),
                Nla::Oif(t) => parsed.oif = Some(*t),
                _ => (),
            }
        }
        Ok(())
    }
}

pub struct LinkDev {
    pub up: bool,
    pub index: u32,
    pub max_mtu: Option<u32>,
    pub kind: Option<link::nlas::InfoKind>,
    pub name: Option<String>,
}

impl NetlinkParse for LinkMessage {
    type Repr = LinkDev;
    fn parse(&self) -> Result<Self::Repr> {
        use rtnetlink::netlink_packet_route::rtnl::link::nlas::Nla;
        let link = self;
        let up = link.header.flags & IFF_UP != 0;
        let index = link.header.index;
        let mut max_mtu = None;
        let mut kind = None;
        let mut name = None;

        for n in &self.nlas {
            match n {
                Nla::IfName(n) => name = Some(n.to_owned()),
                Nla::OperState(s) => match s {
                    _ => (),
                },
                Nla::Info(k) => {
                    for i in k {
                        match i {
                            link::nlas::Info::Kind(x) => {
                                kind = Some(x.to_owned());
                            }
                            _ => (),
                        }
                    }
                }
                Nla::MaxMtu(max) => {
                    max_mtu = Some(*max);
                }
                _ => (),
            }
        }
        Ok(LinkDev {
            up,
            index,
            max_mtu,
            kind,
            name,
        })
    }
}

pub fn tokio_netlink_conn() -> Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

/// this trait might be useful 'cause we might have wrappers over Handle, and Handles typed over net ns
pub trait NetlinkOps {
    async fn fetch_routing_table(&self) -> Result<RoutingTable>;
    async fn fetch_link_by_name(&self, name: String) -> Result<LinkMessage>;
    async fn fetch_link_addrs(&self, index: u32) -> Result<AddressResponse>;
    async fn add_veth(&self, name_a: String, name_b: String) -> Result<()>;
}

pub trait NetlinkOpsTyped<IP, NET> {
    async fn ip_add_route(&self, index: u32, pref_src: IP, dst: NET) -> Result<()>;
    async fn ip_add_default_route(&self, index: u32) -> Result<()>;
    async fn test_route(&self, ip: Ipv4Addr) -> Result<Option<RouteMessage>>;
}

use tun2socks5::ipstack::TUNDev;
use tun2socks5::tun_rs;
use tun2socks5::tun_rs::AsyncDevice;
use tun2socks5::tun_rs::DeviceBuilder;
use utils::MapExt;

use crate::utils::dump_as_json;
use crate::utils::dump_as_toml;

impl NetlinkOps for Handle {
    async fn fetch_routing_table(&self) -> Result<RoutingTable> {
        let mut k = self.route().get(rtnetlink::IpVersion::V4).execute();
        let mut table = RoutingTable::default();

        while let Some(msg) = k.try_next().await? {
            let mut entry = Default::default();
            msg.parse_update(&mut entry)?;
            if let Some(t) = &entry.table {
                table.tables.update(*t).push(entry);
            }
        }

        Ok(table)
    }
    async fn fetch_link_by_name(&self, name: String) -> Result<LinkMessage> {
        let mut links = self.link().get().match_name(name.into()).execute();
        if let Some(link) = links.try_next().await? {
            Ok(link)
        } else {
            bail!("can not find link")
        }
    }
    async fn fetch_link_addrs(&self, index: u32) -> Result<AddressResponse> {
        let mut addrs = self.address().get().set_link_index_filter(index).execute();
        let mut resp = AddressResponse::default();

        while let Some(msg) = addrs.try_next().await? {
            msg.parse_update(&mut resp)?;
        }

        Ok(resp)
    }
    async fn add_veth(&self, name_a: String, name_b: String) -> Result<()> {
        self.link().add().veth(name_a, name_b).execute().await?;
        Ok(())
    }
}

impl NetlinkOpsTyped<Ipv4Addr, Ipv4Network> for Handle {
    async fn ip_add_route(&self, index: u32, pref_src: Ipv4Addr, dst: Ipv4Network) -> Result<()> {
        self.route()
            .add()
            .output_interface(index)
            .v4()
            .pref_source(pref_src)
            .destination_prefix(dst.ip(), dst.prefix())
            .execute()
            .await?;

        Ok(())
    }
    async fn ip_add_default_route(&self, index: u32) -> Result<()> {
        self.route()
            .add()
            .output_interface(index)
            .v4()
            .execute()
            .await?;
        Ok(())
    }
    async fn test_route(&self, ip: Ipv4Addr) -> Result<Option<RouteMessage>> {
        let req = RouteGetResolve::new(self.clone(), ip);

        let mut k = req.lookup();
        let res = k.try_next().await;

        Ok(res?)
    }
}

pub enum PidOrFd {
    Pid(u32),
    Fd(Box<dyn AsFd + Send + Sync>),
}

#[tokio::test]
async fn dump_nl_data() -> Result<()> {
    let h = tokio_netlink_conn()?;
    let table = h.fetch_routing_table().await?;
    dump_as_json(&table, "table").await?;

    Ok(())
}

impl TunMaker {
    pub fn make(&self) -> Result<TunState> {
        let dev = DeviceBuilder::new()
            .name(self.name.to_owned())
            .ipv4(self.ipv4.ip(), self.ipv4.prefix(), None)
            .ipv6(self.ipv6.ip(), self.ipv6.prefix())
            .packet_information(false)
            .mtu(1400)
            // .offload(offload)
            .build_async()?;

        Ok(TunState {
            name: self.name.to_owned(),
            fd: Some(dev.into()),
            ..Default::default()
        })
    }
    /// There isnt a need to call this method after make()
    /// Not sure which part changed the routing. Kernel default, or some lib.
    pub async fn add_route(&self, nl: &Handle, dev: &TUNDev) -> Result<()> {
        nl.ip_add_route(dev.if_index()?, self.ipv4.ip(), self.ipv4)
            .await?;

        Ok(())
    }
    pub async fn test_route(&self, nl: &Handle, state: &TunState) -> Result<bool> {
        let test_ip = self.ipv4.nth(2).unwrap();
        let re = nl.test_route(test_ip).await?;
        let mut entry = RouteEntry::default();
        re.map(|m| m.parse_update(&mut entry));
        if !state.sync.basic_synced {
            bail!("TUN unsynced");
        }
        let test = entry.oif.map(|c| c == state.dev_index).unwrap_or_default();

        Ok(test)
    }
}

impl TunState {
    pub fn sync_basic(&mut self) -> Result<()> {
        if let Some(dev) = &self.fd {
            self.dev_index = dev.if_index()?;
            self.tun_is_up = dev.is_running()?;
            self.sync.basic_synced = true;
        }

        Ok(())
    }
}

impl Default for TunMaker {
    fn default() -> Self {
        Self {
            name: "tun1".to_owned(),
            ipv4: "100.68.0.1/24".try_into().unwrap(),
            ipv6: "fe80::bc2e:4aff:fe02:c223/64".try_into().unwrap(),
        }
    }
}
