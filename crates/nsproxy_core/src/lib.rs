#![feature(exact_size_is_empty)]
#![feature(decl_macro)]
#![allow(async_fn_in_trait)]
#![feature(ip_as_octets)]
#![feature(setgroups)]

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::str::FromStr;
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
use rtnetlink::LinkUnspec;
use rtnetlink::LinkVeth;
use rtnetlink::RouteAddRequest;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::packet_route::link::LinkInfo;
use rtnetlink::packet_route::link::LinkMessage;
use rtnetlink::packet_route::route::RouteAddress;
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::route::RouteMessage;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_untagged::UntaggedEnumVisitor;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tracing::level_filters::LevelFilter;
use tracing::warn;
pub use tun2socks5;
pub mod env;
pub mod prelude;
pub mod shell;
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
    pub dev_index: u32,
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
        for msg in &self.attributes {
            match msg {
                AddressAttribute::Address(ip) => {
                    parsed
                        .addrs
                        .push(IpNetwork::new(ip.to_owned(), self.header.prefix_len)?);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::{IpNetwork, Ipv4Network};
    use std::net::Ipv4Addr;

    #[test]
    fn test_find_vacant_ipv4() {
        let net: Ipv4Network = "100.64.0.0/10".parse().unwrap();
        let used: Vec<Ipv4Addr> = vec!["100.64.0.5".parse::<_>().unwrap()];

        let vacant = find_vacant_ipv4_subnet(used, net, 2).expect("should find a vacant addr");
        dbg!(vacant);
        dbg!(veth_addr_for(vacant, 2, true));
        dbg!(veth_addr_for(vacant, 2, false));
    }
}

pub fn find_vacant_ipv4_subnet(
    mut used: Vec<Ipv4Addr>,
    net: Ipv4Network,
    host_bits: u8,
) -> Option<Ipv4Addr> {
    let first = net.nth(0).unwrap();
    let last = Ipv4Addr::from_bits(net.network().to_bits() | (!0 >> net.prefix()));
    used.push(first);
    used.push(last);
    used.sort();
    let bits: Vec<_> = used.iter().map(|x| x.to_bits() >> host_bits).collect();

    let mut ix = None;
    for x in 0..bits.len() - 1 {
        let diff = bits[x + 1] - bits[x];
        // need 2 consecutive vacant ips
        if diff > 1 {
            ix = Some(x);
            break;
        }
    }
    if let Some(ix) = ix {
        let start = bits[ix];
        let ip = start + 1;
        let ip = Ipv4Addr::from_bits(ip << host_bits);
        Some(ip)
    } else {
        None
    }
}

pub fn veth_addr_for(subnet: Ipv4Addr, host_bits: u8, host: bool) -> Ipv4Addr {
    Ipv4Addr::from_bits(subnet.to_bits() & !0 << host_bits | if host { 1 } else { 2 })
}

pub trait IpExt {
    fn next(&self) -> Self;
}

impl IpExt for Ipv4Addr {
    fn next(&self) -> Self {
        Ipv4Addr::from_bits(self.to_bits() + 1)
    }
}

impl NetlinkParseUpdate for RouteMessage {
    type Repr = RouteEntry;
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()> {
        let make = |ip: RouteAddress| -> Result<Option<IpNetwork>> {
            let ip: Option<IpAddr> = match ip {
                RouteAddress::Inet(ip) => Some(ip.into()),
                RouteAddress::Inet6(ip) => Some(ip.into()),
                _ => None,
            };
            let ip = if let Some(ip) = ip {
                IpNetwork::new(ip, self.header.source_prefix_length)?.into()
            } else {
                None
            };

            Ok(ip)
        };

        for msg in &self.attributes {
            match msg {
                RouteAttribute::PrefSource(ip) => {
                    if let Some(ip) = make(ip.to_owned())? {
                        parsed.source_addrs.push(ip);
                    }
                }
                RouteAttribute::Destination(ip) => {
                    if let Some(ip) = make(ip.to_owned())? {
                        parsed.source_addrs.push(ip);
                    }
                }
                RouteAttribute::Table(t) => parsed.table = Some(*t),
                RouteAttribute::Oif(t) => parsed.oif = Some(*t),
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
    pub kind: Option<InfoKind>,
    pub name: Option<String>,
}

impl NetlinkParse for LinkMessage {
    type Repr = LinkDev;
    fn parse(&self) -> Result<Self::Repr> {
        let up = self.header.flags & LinkFlags::Up != LinkFlags::empty();
        let index = self.header.index;
        let mut max_mtu = None;
        let mut kind = None;
        let mut name = None;
        for a in &self.attributes {
            match a {
                LinkAttribute::IfName(n) => name = Some(n.to_owned()),
                LinkAttribute::OperState(s) => match s {
                    _ => (),
                },
                LinkAttribute::LinkInfo(k) => {
                    for i in k {
                        match i {
                            LinkInfo::Kind(x) => {
                                kind = Some(x.to_owned());
                            }
                            _ => (),
                        }
                    }
                }
                LinkAttribute::MaxMtu(max) => {
                    max_mtu = Some(*max);
                }
                _ => {}
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
    async fn fetch_all_ip_addrs(&self) -> Result<Vec<IpNetwork>>;
    async fn add_veth(&self, name_a: &str, name_b: &str) -> Result<()>;
    async fn remove_link_if_exists(&self, name: &str) -> Result<()>;
    async fn add_route(&self, index: u32, pref_src: IpAddr, dst: IpAddr, prefix: u8) -> Result<()>;
    async fn ip_add_default_route(&self, index: u32) -> Result<()>;
    async fn test_route(&self, ip: IpAddr) -> Result<Option<RouteMessage>>;
    async fn up_lo(&self) -> Result<()>;
}

use tun2socks5::IArgs;
use tun2socks5::ipstack::TUNDev;
use tun2socks5::tun_rs::AsyncDevice;
use tun2socks5::tun_rs::DeviceBuilder;
use utils::MapExt;

use crate::shell::ShellArgs;
use crate::utils::dump_as_json;
use crate::utils::dump_as_toml;

impl NetlinkOps for Handle {
    async fn fetch_routing_table(&self) -> Result<RoutingTable> {
        let m = RouteMessageBuilder::<IpAddr>::new().build();

        let mut k = self.route().get(m).execute();
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
    async fn fetch_all_ip_addrs(&self) -> Result<Vec<IpNetwork>> {
        let mut addrs = self.address().get().execute();
        let mut res: Vec<IpNetwork> = Vec::new();

        while let Some(msg) = addrs.try_next().await? {
            let mut resp = AddressResponse::default();
            msg.parse_update(&mut resp)?;
            for ip in resp.addrs {
                res.push(ip);
            }
        }

        Ok(res)
    }
    async fn add_veth(&self, name: &str, peer: &str) -> Result<()> {
        // remove existing links with these names if they exist
        let _ = self.remove_link_if_exists(name).await;
        let _ = self.remove_link_if_exists(peer).await;

        self.link()
            .add(LinkVeth::new(name, peer).build())
            .execute()
            .await?;

        Ok(())
    }
    async fn remove_link_if_exists(&self, name: &str) -> Result<()> {
        warn!("removed obsolete device {}", name);
        let mut links = self.link().get().match_name(name.to_owned()).execute();
        if let Some(link) = links.try_next().await? {
            self.link().del(link.header.index).execute().await?;
        }
        Ok(())
    }
    async fn add_route(&self, index: u32, pref_src: IpAddr, dst: IpAddr, prefix: u8) -> Result<()> {
        let route = RouteMessageBuilder::<IpAddr>::new()
            .destination(dst, prefix)?
            .output_interface(index)
            .pref_source(pref_src)?
            .build();
        self.route().add(route).execute().await?;
        Ok(())
    }
    async fn ip_add_default_route(&self, index: u32) -> Result<()> {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(index)
            .build();
        self.route().add(route).execute().await?;
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .output_interface(index)
            .build();
        self.route().add(route).execute().await?;
        Ok(())
    }
    async fn test_route(&self, ip: IpAddr) -> Result<Option<RouteMessage>> {
        let m = RouteMessageBuilder::<IpAddr>::new()
            .destination(ip, (ip.as_octets().len() * 8) as u8)?
            .build();
        let routes = self.route().get(m).execute();
        let vec: Vec<_> = routes.try_collect().await?;
        assert!(vec.len() <= 1);
        Ok(vec.get(0).cloned())
    }
    async fn up_lo(&self) -> Result<()> {
        let mut s = self.link().get().match_name("lo".to_owned()).execute();
        if let Some(lo) = s.next().await {
            let lo = lo?;
            self.link()
                .set(LinkUnspec::new_with_index(lo.header.index).up().build())
                .execute()
                .await?;
        }
        aok!()
    }
}

pub enum PidOrFd {
    Pid(u32),
    Fd(Box<dyn AsFd + Send + Sync>),
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
        nl.add_route(
            dev.if_index()?,
            self.ipv4.ip().into(),
            self.ipv4.ip().into(),
            self.ipv4.prefix(),
        )
        .await?;

        Ok(())
    }
    pub async fn test_route(&self, nl: &Handle, state: &TunState) -> Result<bool> {
        let test_ip = self.ipv4.nth(2).unwrap();
        let re = nl.test_route(test_ip.into()).await?;
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
            mtu: 1500,
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

pub macro aok {
    () => {
        ::core::result::Result::Ok::<(), anyhow::Error>(())
    },
    (#ty:ty) => {
        Ok::<#ty, anyhow::Error>(())
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct HotConfig {
    pub dns: HashMap<String, String>,
    pub tun: HashMap<String, Value>,
    /// Map devs from a mac address (or interface name) to an IP address
    /// This commands nsproxy to move the devices into the new namespace
    /// And assign them with the provided IP addresses
    pub devs: HashMap<String, String>,
}

use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};

/// NSProxy V3
/// Manage netns redirection with SOCKS5 proxy configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "./nsproxy.json")]
    pub conf: PathBuf,
    #[command(subcommand)]
    pub cmd: MainCommand,
}

/// Representation of a namespace input (PID or Path)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum NsInput {
    Pid(i32),
    Path(PathBuf),
    /// this process
    This,
    New,
}

#[derive(Debug, Clone, Subcommand)]
pub enum MainCommand {
    /// Set up some containers
    #[command(alias = "r")]
    Run {
        /// Source network namespace (src=/path OR src=1234)
        #[arg(long, default_value = "this")]
        src: NsInput,
        /// Target network namespace (dst=/path OR dst=1234)
        #[arg(long, default_value = "new")]
        dst: NsInput,
        #[command(flatten)]
        tun: IArgs,
        /// Make veths, with inner IP defaulting to 100.120.0.2/24
        /// Not supporting more than one veth for now
        #[arg(short, long)]
        veth: bool,
        /// Persist this container, add it to config file
        #[arg(short, long)]
        keep: bool,
        /// Activate other containers too
        #[arg(short, long)]
        all: bool,
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
        mount: Option<PathBuf>,
        #[command(flatten)]
        sargs: ShellArgs,
        /// Instance name
        #[arg(long)]
        name: Option<String>,
        /// Profile name for browsers
        #[arg(long)]
        profile: Option<String>,
    },
    #[command(alias = "e")]
    /// Find by process and enter an existing nsproxy namespace
    /// Enter the best-match based on searching arguments provided
    Enter {
        /// List processes found
        #[arg(short, long)]
        list: bool,
        /// Search for proxy port
        #[arg(short, long)]
        port: Option<u16>,
        /// Instance name
        #[arg(short, long)]
        name: Option<String>,
        /// Enter by path
        path: Option<PathBuf>,
        #[command(flatten)]
        sargs: ShellArgs,
    },

    /// Install nsproxy to a folder
    Install {
        #[arg(default_value = "./install")]
        dir: PathBuf,
    },
    /// Remove a bind-mount file
    Rm { file: PathBuf },
    /// VSCode could for example call xdg-open when logging into github, which calls librewolf from within a namespace, which communicates with a librewolf instance outside netns, which escapes the netns
    /// The wrapper handles such problems
    /// Warning. xdg-open takes the binary pointed by within .desktop file, which may differ from the path resolved by $PATH
    /// eg. /usr/share/librewolf/librewolf
    Wrap {
        /// The executable to hook.
        #[arg(short, long)]
        bin: String,
        #[arg(short, long)]
        undo: bool,
    },
    #[command(alias = "c")]
    Clean {
        /// Does a simple removal of default veth
        #[arg(short, long)]
        veth: bool,
    },
    #[command(alias = "n")]
    /// Netlink testing: print all IPv4 addresses
    Netlink,
    /// Generates an empty config file
    Gen { save_to: PathBuf },
    /// Identify current net-ns
    #[command(alias = "i")]
    Id {
        /// Optionally supply an PID
        pid: Option<u32>
    },
}

impl std::str::FromStr for NsInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::result::Result::Ok;

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

pub fn to_cstr(f: &str) -> CString {
    CString::from_str(f).unwrap()
}
