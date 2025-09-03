#![feature(decl_macro)]
#![allow(async_fn_in_trait)]

use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Ok;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use futures::StreamExt;
use futures::TryStreamExt;
use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use libc::pid_t;
use nsproxy_common::ExactNS;
use nsproxy_common::NSFrom;
use rtnetlink::Handle;
use rtnetlink::RouteAddRequest;
use rtnetlink::{
    RouteGetResolve,
    netlink_packet_route::{
        AddressMessage, IFF_UP, LinkMessage, RouteFlags, RouteMessage, RtnlMessage, link, route,
    },
    netlink_proto::Connection,
};
use serde::Deserialize;
use serde::Serialize;
use serde_untagged::UntaggedEnumVisitor;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;
pub use tun2socks5;
pub mod sys;
pub mod utils;

pub struct TunMaker {
    pub name: String,
    pub ipv4: Ipv4Network,
    pub ipv6: Ipv6Network,
    pub mtu: u16,
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

pub fn smol_netlink_conn() -> Result<Handle> {
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
            .mtu(self.mtu)
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
            mtu: 1500
        }
    }
}

#[derive(Clone)]
pub struct PathState {
    root_config: PathBuf,
}

pub type Paths = Arc<PathState>;

pub trait PathsBinds {
    fn root(&self) -> PathBuf;
    fn mount(&self, ns: ExactNS) -> PathBuf;
    fn mount_user_space(&self, user_ns: ExactNS, ns: ExactNS) -> PathBuf;
    fn readable_config(&self) -> PathBuf;
    fn mount_private(&self) -> PathBuf;
    fn make_mount_point(&self, path: PathBuf) -> Result<()> {
        std::fs::File::create(&path)?;
        Ok(())
    }
    fn socket_server(&self) -> PathBuf {
        self.root().join("nsproxy.sock")
    }
}

use fs4::tokio::AsyncFileExt;

/// The entirety of persisted runtime state.
pub struct TotalConfig {
    fd: tokio::fs::File,
    path: Paths,
    data: Result<NsproxyConfig>,
}

#[derive(Deserialize, Clone, Serialize, Debug)]
pub struct NsproxyConfig {
    pub container: HashMap<String, Namespace>,
    pub veth: HashMap<String, VethConf>,
    pub link: Vec<LinkConf>,
}

#[derive(Deserialize, Clone, Serialize, Debug)]
pub struct LinkConf {
    pub global_route: bool,
    pub proxy: String,
    pub proxied: NSID,
    pub source: NSID,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct Namespace {
    pub user: Option<NSID>,
    pub mnt: Option<NSID>,
    pub net: NSID,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct VethConf {
    pub src_ip4: Ipv4Addr,
    pub dst_ip4: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub enum NSID {
    PID(i32),
    Path(PathBuf),
}

impl<'d> Deserialize<'d> for NSID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        use std::result::Result::Ok;
        UntaggedEnumVisitor::new()
            .string(|v| Ok(NSID::Path(PathBuf::from(v))))
            .i32(|v| Ok(NSID::PID(v)))
            .deserialize(deserializer)
    }
}

impl Serialize for NSID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::PID(p) => serializer.serialize_i32(*p),
            Self::Path(p) => serializer.serialize_str(
                p.to_str()
                    .ok_or(serde::ser::Error::custom("path invalid"))?,
            ),
        }
    }
}

#[test]
fn test_untag() {
    #[derive(Deserialize, Debug, Serialize)]
    struct Example {
        k: NSID,
    }

    let sx: Example = toml_edit::de::from_str("k = \"sss/ssss\"").unwrap();
    dbg!(&sx);
    let sx: Example = toml_edit::de::from_str("k = 2").unwrap();
    dbg!(&sx);

    let sx: Namespace = toml_edit::de::from_str(
        r#"
            user = 3 
            net = "/path/"
     "#,
    )
    .unwrap();
    dbg!(&sx);

    let sx = toml_edit::ser::to_string_pretty(&Example {
        k: NSID::Path(PathBuf::from("/test")),
    });
    dbg!(&sx);

    let sx: NsproxyConfig = toml_edit::de::from_str(
        r#"
            [container.geph]
            net = "/run/1.ns"
            [veth.geph]
            src_ip4 = "1.1.1.1"
            [[link]]
            global_route = false
            proxy = "socks5"
            proxied = 2
            source = 3
     "#,
    )
    .unwrap();
    dbg!(&sx);

    let sx = toml_edit::ser::to_string_pretty(&sx);
    println!("{}", sx.unwrap());
}

impl TotalConfig {
    pub async fn new(path: Paths) -> Result<TotalConfig> {
        let mut c = TotalConfig {
            fd: fs::File::open(path.readable_config()).await?,
            path,
            data: Err(anyhow!("not loaded")),
        };
        let re = c.fd.try_lock_exclusive()?;
        if re {
            Ok(c)
        } else {
            tracing::error!("config file locked.. waiting");
            let f = c.fd.unlock_async();
            let k: std::result::Result<
                std::result::Result<(), std::io::Error>,
                tokio::time::error::Elapsed,
            > = timeout(Duration::from_secs(20), f).await;
            match k {
                Result::Ok(_) => {}
                Err(_) => {
                    bail!("timeout reached");
                }
            }
            let mut buf = Vec::with_capacity(4096);
            c.fd.read_to_end(&mut buf).await?;
            c.data = Ok(toml_edit::de::from_slice(&buf)?);
            Ok(c)
        }
    }
    pub async fn save(&mut self) {}
}

impl PathsBinds for Paths {
    fn root(&self) -> PathBuf {
        self.root_config.clone()
    }
    fn mount(&self, ns: ExactNS) -> PathBuf {
        self.root_config.join(ns.unique.to_string() + ".ns")
    }
    fn mount_private(&self) -> PathBuf {
        self.root_config.join("priv_mnt")
    }
    fn mount_user_space(&self, user_ns: ExactNS, ns: ExactNS) -> PathBuf {
        self.mount_private()
            .join(user_ns.unique.to_string() + ".user")
            .join(ns.unique.to_string() + ".ns")
    }
    fn readable_config(&self) -> PathBuf {
        self.root_config.join("nsproxyd.toml")
    }
}
