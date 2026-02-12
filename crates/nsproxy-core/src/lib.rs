#![feature(exact_size_is_empty)]
#![feature(decl_macro)]
#![allow(async_fn_in_trait)]
#![feature(ip_as_octets)]
#![feature(setgroups)]

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, create_dir_all};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use futures::StreamExt;
use futures::TryStreamExt;
use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use libc::pid_t;
use nsproxy_common::ExactNS;
use nsproxy_common::NSFrom;
pub use nsproxy_common::{NsAlive, PERSIST_ROOT, RUNTIME_ROOT, state_paths};
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
use tracing::{info, warn};
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
use nsproxy_common::routing::ProxyNym;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// Commands Virtual DNS to directly A to B
    pub dns: HashMap<String, String>,
    /// NAT by TUN
    pub tun: HashMap<String, Value>,
    /// Map devs from a mac address (or interface name) to an IP address
    /// This commands nsproxy to move the devices into the new namespace
    /// And assign them with the provided IP addresses
    pub devs: HashMap<String, String>,
    /// Bind mounts
    pub mnt: HashMap<PathBuf, PathBuf>,
    /// Mapping of localhost:port in container to localhost:port outside container
    pub locals: HashMap<u32, u32>,
}

/// Explicit, stable profile config for filesystem isolation and app launch
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileConfig {
    /// Schema version for compatibility checks
    pub schema: u32,
    /// Filesystem isolation plan
    pub rootfs: ProfileRootfs,
    /// Explicit bind mounts, in order
    pub mounts: Vec<ProfileMount>,
    /// Optional chmod operations to apply after mounts
    #[serde(default)]
    pub chmod: Vec<ProfileChmod>,
    /// Environment variables (overrides if inherit_env=true, replaces if false)
    pub env: HashMap<String, String>,
    /// Inherit parent environment and apply env as overrides (default: true)
    #[serde(default = "default_inherit_env")]
    pub inherit_env: bool,
    /// Hot config JSON path (frequently changed)
    pub hot: PathBuf,
    /// Initialize hot config with these values if missing
    #[serde(default)]
    pub hot_init: Option<HotConfig>,
    /// Explicit shell argument overrides
    #[serde(default)]
    pub sargs: ShellArgs,
    /// Browser profile name for env isolation (set NSPROXY_PROFILE_BROWSER)
    #[serde(default)]
    pub browser_profile: Option<String>,
}

fn default_inherit_env() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileRootfs {
    /// Overlay keeps current root, Pivot swaps root
    pub mode: RootfsMode,
    /// Root prefix. For overlay this must be "/"; for pivot this is the new root.
    pub root: PathBuf,
    /// Required when mode is Pivot. Must be under root.
    pub put_old: Option<PathBuf>,
    /// If true, mount tmpfs at root before constructing
    pub tmpfs: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RootfsMode {
    Overlay,
    Pivot,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileMount {
    /// Host path
    pub source: PathBuf,
    /// Target path inside the container root
    pub target: PathBuf,
    /// Mount read-only (default: false)
    #[serde(default)]
    pub read_only: bool,
    /// Mount recursively (default: true)
    #[serde(default = "default_recursive")]
    pub recursive: bool,
}

/// Permission/ownership operation to apply inside the container root
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileChmod {
    /// Target path inside the container root
    pub path: PathBuf,
    /// Mode bits (e.g. 0o755)
    pub mode: Option<u32>,
    /// Owner uid
    pub uid: Option<u32>,
    /// Owner gid
    pub gid: Option<u32>,
}

fn default_recursive() -> bool {
    true
}

impl ProfileConfig {
    pub fn load(path: &Path) -> Result<ProfileConfig> {
        create_dir_all(PERSIST_ROOT)?;
        let fc = std::fs::read_to_string(path)?;
        let conf: ProfileConfig = serde_json::from_str(&fc)?;
        conf.validate()?;
        Ok(conf)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema > 0, "schema must be > 0");
        ensure!(
            self.rootfs.root.is_absolute(),
            "rootfs.root must be absolute"
        );
        match self.rootfs.mode {
            RootfsMode::Overlay => {
                ensure!(
                    self.rootfs.root == PathBuf::from("/"),
                    "overlay root must be '/'"
                );
                ensure!(
                    self.rootfs.put_old.is_none(),
                    "overlay must not set put_old"
                );
                ensure!(!self.rootfs.tmpfs, "overlay must not set tmpfs");
            }
            RootfsMode::Pivot => {
                let put_old = self
                    .rootfs
                    .put_old
                    .clone()
                    .ok_or(anyhow!("pivot requires put_old"))?;
                ensure!(put_old.is_absolute(), "put_old must be absolute");
                ensure!(
                    put_old.starts_with(&self.rootfs.root),
                    "put_old must be under root"
                );
            }
        }
        if let Some(ref cwd) = self.sargs.cwd {
            ensure!(cwd.is_absolute(), "sargs.cwd must be absolute");
        }
        // Allow @ placeholder in hot path (will be expanded at runtime)
        if let Some(hot_str) = self.hot.to_str() {
            ensure!(
                self.hot.is_absolute() || hot_str.starts_with('@'),
                "hot must be absolute or use @ placeholder"
            );
        } else {
            ensure!(self.hot.is_absolute(), "hot must be absolute");
        }
        for m in &self.mounts {
            // Allow @ placeholder in source paths
            if let Some(source_str) = m.source.to_str() {
                ensure!(
                    m.source.is_absolute() || source_str.starts_with('@'),
                    "mount source must be absolute or use @ placeholder"
                );
            } else {
                ensure!(m.source.is_absolute(), "mount source must be absolute");
            }
            // Allow ~ prefix and @ placeholder for target paths (will be expanded at runtime)
            if let Some(target_str) = m.target.to_str() {
                ensure!(
                    m.target.is_absolute()
                        || target_str.starts_with("~/")
                        || target_str == "~"
                        || target_str.starts_with('@'),
                    "mount target must be absolute, start with ~/, or use @ placeholder"
                );
            } else {
                ensure!(m.target.is_absolute(), "mount target must be absolute");
            }
        }
        for c in &self.chmod {
            if let Some(path_str) = c.path.to_str() {
                ensure!(
                    c.path.is_absolute()
                        || path_str.starts_with("~/")
                        || path_str == "~"
                        || path_str.starts_with('@'),
                    "chmod path must be absolute, start with ~/, or use @ placeholder"
                );
            } else {
                ensure!(c.path.is_absolute(), "chmod path must be absolute");
            }
        }
        Ok(())
    }

    /// Expand @ placeholder to instance state root (/nsp3/{name})
    pub fn expand_placeholders(&mut self, instance_root: &Path) {
        let root_str = instance_root.to_string_lossy();

        // Expand hot path
        if let Some(hot_str) = self.hot.to_str() {
            if hot_str.starts_with('@') {
                self.hot = PathBuf::from(hot_str.replace('@', &root_str));
            }
        }

        // Expand mount paths
        for m in &mut self.mounts {
            if let Some(source_str) = m.source.to_str() {
                if source_str.starts_with('@') {
                    m.source = PathBuf::from(source_str.replace('@', &root_str));
                }
            }
            if let Some(target_str) = m.target.to_str() {
                if target_str.starts_with('@') {
                    m.target = PathBuf::from(target_str.replace('@', &root_str));
                }
            }
        }

        // Expand sargs.cwd
        if let Some(ref cwd) = self.sargs.cwd {
            if let Some(cwd_str) = cwd.to_str() {
                if cwd_str.starts_with('@') {
                    self.sargs.cwd = Some(PathBuf::from(cwd_str.replace('@', &root_str)));
                }
            }
        }

        // Expand chmod paths
        for c in &mut self.chmod {
            if let Some(path_str) = c.path.to_str() {
                if path_str.starts_with('@') {
                    c.path = PathBuf::from(path_str.replace('@', &root_str));
                }
            }
        }

        // Expand hot_init.mnt paths
        if let Some(ref mut hot_init) = self.hot_init {
            let mut expanded_mnt = HashMap::new();
            for (s, t) in &hot_init.mnt {
                let mut new_source = s.clone();
                let mut new_target = t.clone();

                if let Some(source_str) = s.to_str() {
                    if source_str.starts_with('@') {
                        new_source = PathBuf::from(source_str.replace('@', &root_str));
                    }
                }
                if let Some(target_str) = t.to_str() {
                    if target_str.starts_with('@') {
                        new_target = PathBuf::from(target_str.replace('@', &root_str));
                    }
                }

                expanded_mnt.insert(new_source, new_target);
            }
            hot_init.mnt = expanded_mnt;
        }
    }

    pub fn template(name: &str, hot_path: &Path) -> Result<ProfileConfig> {
        use nix::unistd::getresuid;
        use nsproxy_common::UID_HINT_VAR;
        use std::result::Result::Ok;
        use uzers::os::unix::UserExt;

        // Detect UID the same way ShellArgs does
        let uid = if let Ok(id) = std::env::var(UID_HINT_VAR) {
            id.parse()?
        } else if let Ok(id) = std::env::var("SUDO_UID") {
            id.parse()?
        } else {
            let res = getresuid()?;
            if !res.real.is_root() {
                res.real.as_raw()
            } else if let Ok(kde) = std::env::var("KDE_SESSION_UID") {
                kde.parse()?
            } else {
                1000 // fallback
            }
        };

        let user = uzers::get_user_by_uid(uid)
            .ok_or_else(|| anyhow!("cannot find user for uid {}", uid))?;

        let shell = user.shell().to_owned();
        let shell_path = PathBuf::from(shell);
        let shell_str = shell_path
            .to_str()
            .ok_or_else(|| anyhow!("invalid shell path"))?
            .to_string();

        let gid = user.primary_group_id();
        let gids: Vec<u32> = user
            .groups()
            .unwrap_or_default()
            .iter()
            .map(|g| g.gid())
            .collect();

        Ok(ProfileConfig {
            schema: 1,
            rootfs: ProfileRootfs {
                mode: RootfsMode::Overlay,
                root: PathBuf::from("/"),
                put_old: None,
                tmpfs: false,
            },
            mounts: vec![],
            env: HashMap::new(),
            inherit_env: true,
            hot: hot_path.to_path_buf(),
            hot_init: Some(HotConfig::default()),
            sargs: ShellArgs {
                uid: Some(uid),
                gid: Some(gid),
                gids: gids,
                shell: Some(shell_str),
                cwd: Some(user.home_dir().to_path_buf()),
            },
            chmod: Vec::new(),
            browser_profile: None,
        })
    }
}

/// Global wrapped binaries configuration path
pub const WRAPPED_BINARIES_CONFIG: &str = "/nsp3/wrapped_binaries.json";

/// Configuration for binaries that must be wrapped for security
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct WrappedBinariesConfig {
    /// List of absolute paths to binaries that must be wrapped
    pub binaries: Vec<PathBuf>,
    /// Cached BLAKE3 hash of nswrap binary
    pub nswrap_hash: Option<String>,
}

impl WrappedBinariesConfig {
    pub fn load() -> Result<Self> {
        use tracing::{info, warn};
        let path = Path::new(WRAPPED_BINARIES_CONFIG);
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        create_dir_all(PERSIST_ROOT)?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(WRAPPED_BINARIES_CONFIG, content)?;
        Ok(())
    }

    /// Add a binary by name (resolves via which) and save
    pub fn add_binary(&mut self, name: &str) -> Result<PathBuf> {
        let resolved_path = which::which(name)?;

        if self.binaries.contains(&resolved_path) {
            info!("Binary {:?} already in config", resolved_path);
            return Ok(resolved_path);
        }

        self.binaries.push(resolved_path.clone());
        self.save()?;
        info!("Added {:?} to wrapped binaries config", resolved_path);
        Ok(resolved_path)
    }

    /// Compute BLAKE3 hash of a file
    fn compute_file_hash(path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Get the expected nswrap hash (from cache or by computing)
    /// This will compute and cache the hash if not present
    pub fn get_or_compute_nswrap_hash(&mut self) -> Result<String> {
        if let Some(ref hash) = self.nswrap_hash {
            return Ok(hash.clone());
        }

        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        let hash = Self::compute_file_hash(&nswrap_path)?;
        self.nswrap_hash = Some(hash.clone());
        self.save()?;
        Ok(hash)
    }

    pub fn update_nswrap_hash(&mut self) -> Result<String> {
        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        let hash = Self::compute_file_hash(&nswrap_path)?;
        self.nswrap_hash = Some(hash.clone());
        self.save()?;
        Ok(hash)
    }

    /// Check if all configured binaries are properly wrapped
    /// Requires cached hash - will not compute it
    pub fn check_all_wrapped(&self) -> Result<()> {
        if self.binaries.is_empty() {
            return Ok(());
        }

        let expected_hash = self.nswrap_hash.as_ref().ok_or_else(|| {
            anyhow!("No cached nswrap hash found. Run 'sp wrap' first to initialize.")
        })?;

        let mut errors = Vec::new();

        for binary_path in &self.binaries {
            if let Err(e) = self.check_single_wrapped(binary_path, expected_hash) {
                errors.push(format!("{:?}: {}", binary_path, e));
            }
        }

        if !errors.is_empty() {
            bail!("Wrapped binaries check failed:\n{}", errors.join("\n"));
        }

        Ok(())
    }

    /// Check if a single binary is properly wrapped
    pub fn check_single_wrapped(&self, binary_path: &Path, expected_hash: &str) -> Result<()> {
        let wrapped_path = binary_path.with_extension("wrapped");

        if !wrapped_path.exists() {
            bail!("missing .wrapped file");
        }

        if !binary_path.exists() {
            bail!("binary does not exist");
        }

        // Verify the binary at binary_path has the expected nswrap hash
        let actual_hash = Self::compute_file_hash(binary_path)?;
        if actual_hash != expected_hash {
            bail!(
                "hash mismatch: expected {} but got {}",
                expected_hash,
                actual_hash
            );
        }

        Ok(())
    }

    /// Wrap all configured binaries
    pub fn wrap_all(&mut self) -> Result<()> {
        if self.binaries.is_empty() {
            warn!("No binaries configured for wrapping");
            return Ok(());
        }

        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        // Compute and cache the hash
        let _ = self.get_or_compute_nswrap_hash()?;

        info!("Wrapping {} binaries...", self.binaries.len());

        // Clone the list to avoid borrow checker issues
        let binaries = self.binaries.clone();
        for binary_path in &binaries {
            self.wrap_single(binary_path, &nswrap_path)?;
        }

        info!("All binaries wrapped successfully");
        Ok(())
    }

    /// Wrap a single binary
    fn wrap_single(&mut self, binary_path: &Path, nswrap_path: &Path) -> Result<()> {
        if !binary_path.exists() {
            bail!("Binary {:?} does not exist", binary_path);
        }

        let wrapped_path = binary_path.with_extension("wrapped");

        if wrapped_path.exists() {
            // Already wrapped, verify it's correct
            let expected_hash = self.get_or_compute_nswrap_hash()?;
            let check_result = self.check_single_wrapped(binary_path, &expected_hash);
            match check_result {
                Ok(_) => {
                    info!("Binary {:?} already properly wrapped", binary_path);
                    return Ok(());
                }
                Err(_) => {
                    warn!(
                        "Binary {:?} is wrapped but check failed. Re-wrapping...",
                        binary_path
                    );
                    // Remove the bad wrapped file and re-wrap
                    std::fs::remove_file(binary_path)?;
                    std::fs::rename(&wrapped_path, binary_path)?;
                }
            }
        }

        info!("Wrapping binary: {:?}", binary_path);
        std::fs::rename(binary_path, &wrapped_path)?;
        std::fs::copy(nswrap_path, binary_path)?;

        Ok(())
    }

    /// Unwrap all configured binaries
    pub fn unwrap_all(&mut self) -> Result<()> {
        if self.binaries.is_empty() {
            warn!("No binaries configured for unwrapping");
            return Ok(());
        }

        info!("Unwrapping {} binaries...", self.binaries.len());

        // Clone the list to avoid borrow checker issues
        let binaries = self.binaries.clone();
        for binary_path in &binaries {
            self.unwrap_single(binary_path)?;
        }

        // Clear cached hash after unwrapping
        self.nswrap_hash = None;
        self.save()?;

        info!("All binaries unwrapped successfully");
        Ok(())
    }

    /// Unwrap a single binary
    fn unwrap_single(&self, binary_path: &Path) -> Result<()> {
        let wrapped_path = binary_path.with_extension("wrapped");

        if !wrapped_path.exists() {
            info!("Binary {:?} not wrapped", binary_path);
            return Ok(());
        }

        info!("Unwrapping binary: {:?}", binary_path);

        if binary_path.exists() {
            std::fs::remove_file(binary_path)?;
        }

        std::fs::rename(&wrapped_path, binary_path)?;

        Ok(())
    }
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
    #[arg(short, long)]
    pub conf: Option<PathBuf>,
    #[arg(short, long)]
    pub no_wrap_check: bool,
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
        bind: Option<PathBuf>,
        #[command(flatten)]
        sargs: ShellArgs,
        /// Instance name
        #[arg(long)]
        name: Option<String>,
        /// Profile name for browsers
        #[arg(long)]
        profile: Option<String>,
        /// Use a new mount namespace
        #[arg(short, long)]
        mnt: bool,
        /// Enable bind mounts even when NOT using a new mount namspace
        /// Defaults to true when --mnt is enabled, false when --mnt is not enabled.
        #[arg(long)]
        binds: bool,
        /// Requires explicit flag for no proxying
        #[arg(long)]
        no_proxy: bool,
    },
    /// Run for profile isolation
    #[command(alias = "m")]
    Make {
        /// Source network namespace (src=/path OR src=1234)
        #[arg(long, default_value = "this")]
        src: NsInput,
        /// Target network namespace (dst=/path OR dst=1234)
        #[arg(long, default_value = "new")]
        dst: NsInput,
        /// Profile config JSON (stable schema)
        #[arg(long)]
        profile: Option<PathBuf>,
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
        bind: Option<PathBuf>,
        // This can derive profile path as /nsp3/name/various json files
        /// Instance name (explicit, used for veth names)
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        sargs: ShellArgs,
        /// Validate configs and paths without executing
        #[arg(long)]
        check: bool,
        /// Requires explicit flag for no proxying
        #[arg(long)]
        no_proxy: bool,
        /// Requires explicit flag for no TUN device
        #[arg(long)]
        no_tun: bool,
    },
    #[command(alias = "e")]
    /// Find by process and enter an existing nsproxy namespace
    /// Enter the best-match based on searching arguments provided
    Enter {
        /// Instance name or path (if starts with /, ./, or ~/)
        target: String,
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
    /// Manage wrapped binaries for security (wraps all configured binaries)
    /// VSCode could for example call xdg-open when logging into github, which calls librewolf from within a namespace, which communicates with a librewolf instance outside netns, which escapes the netns
    /// The wrapper handles such problems by requiring confirmation before executing
    /// Warning. xdg-open takes the binary pointed by within .desktop file, which may differ from the path resolved by $PATH
    /// eg. /usr/share/librewolf/librewolf
    Wrap {
        /// Unwrap all configured binaries instead of wrapping them
        #[arg(short, long)]
        undo: bool,
        /// Add a binary to the wrapped binaries config (resolves using which)
        #[arg(short, long)]
        add: Option<String>,
    },
    /// Show wrapped binaries status
    Wrapped,
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
        pid: Option<u32>,
    },
    /// Serve a socks5 proxy server that could be used to escape a container
    Serve { port: u32 },
    /// Fire a single HTTP request to a URL
    Curl {
        /// URL to request
        url: String,
        /// Use socks5 proxy (address:port)
        #[arg(short, long)]
        proxy: Option<String>,
    },
    /// TCP forward
    Forward { src: u32, dst: u32 },
    /// Create a new profile from a config template
    Profile {
        /// Path to a profile template
        path: PathBuf,
        /// Name of profile to create (defaults to config filename stem)
        name: Option<String>,
        /// Reset profile by removing existing directory and recreating from scratch
        #[arg(short, long)]
        reset: bool,
        /// Update existing profile config without recreating directories
        #[arg(short, long)]
        update: bool,
    },
    /// Create and persist a set of namespaces for a profile.
    /// A minimal long-lived process keeps the namespaces alive.
    /// Use `tun` and `veth` subcommands afterwards to attach networking.
    Up {
        /// Profile name (resolves to /nsp3/{name})
        #[arg(long)]
        profile: String,
    },
    /// Attach a TUN device + tun2socks5 proxy to an already-up profile namespace.
    /// Only one TUN process may exist per profile at a time.
    Tun {
        /// Profile name (must have been brought up with `up` first)
        #[arg(long)]
        profile: String,
        #[command(flatten)]
        tun: IArgs,
        /// Do not set TUN as default route
        #[arg(short, long)]
        no_default: bool,
        /// Requires explicit flag for no proxying
        #[arg(long)]
        no_proxy: bool,
        #[arg(short, long)]
        log: Option<LevelFilter>,
        /// Use Clash uplink profile for all TUN connections
        #[arg(long)]
        clash: Option<String>,
    },
    /// Create a veth pair between host and an already-up profile namespace.
    Veth {
        /// Profile name (must have been brought up with `up` first)
        #[arg(long)]
        profile: String,
        /// Veth pair base name (produces {name}_in and {name}_out)
        #[arg(long)]
        veth_name: Option<String>,
        #[arg(short, long)]
        log: Option<LevelFilter>,
    },
    /// Operations about basis network namespace, ie. the namespace where your system boots with
    Basis {
        #[command(subcommand)]
        cmd: BasisCommand,
    },
    /// Uplink by which you connect to freedom
    Uplink {
        #[command(subcommand)]
        kind: UplinkCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum UplinkCommand {
    Clash {
        #[command(subcommand)]
        cmd: ClashOps,
    },
    Geph,
    Instance {
        name: ProxyNym,
        #[command(subcommand)]
        cmd: UplinkInstanceCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum UplinkInstanceCommand {
    Test,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ClashOps {
    /// Import or override clash configs for a profile
    ProfileAdd {
        /// Name of target profile (defaults to config filename)
        #[arg(long)]
        name: Option<String>,
        /// Path to Clash YAML config file
        path: PathBuf,
    },
    /// Show status of imported Clash profiles
    Status,
    /// Analyze a Clash profile and explain the two-tier DNS bootstrap process
    ProfileExplain {
        /// Path to Clash YAML config file
        path: PathBuf,
    },
}

pub mod uplink;

#[derive(Debug, Clone, Subcommand)]
pub enum BasisCommand {
    /// Mount the basis network namespace
    Mount {},
    /// Enter the basis network namespace
    Enter {
        #[command(flatten)]
        sargs: ShellArgs,
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
