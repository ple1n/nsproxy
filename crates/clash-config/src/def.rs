use crate::{Error, Result};
use educe::Educe;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

const DEFAULT_ROUTE_TABLE: u32 = 2468;

fn default_tun_device_id() -> String {
    "utun1989".to_string()
}

fn default_tun_address() -> String {
    "198.18.0.1/24".to_string()
}

fn default_route_table() -> u32 {
    DEFAULT_ROUTE_TABLE
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsHijack {
    Switch(bool),
    List(Vec<String>),
}

impl Default for DnsHijack {
    fn default() -> Self {
        DnsHijack::Switch(false)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    pub enable: bool,
    #[serde(alias = "device-url", alias = "device")]
    #[serde(default = "default_tun_device_id")]
    pub device_id: String,
    #[serde(default = "default_tun_address")]
    pub gateway: String,
    #[serde(alias = "gateway-v6")]
    pub gateway_v6: Option<String>,
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub route_all: bool,
    pub mtu: Option<u16>,
    pub so_mark: Option<u32>,
    #[serde(default = "default_route_table")]
    pub route_table: u32,
    #[serde(default)]
    pub dns_hijack: DnsHijack,
}

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[serde(alias = "Global")]
    Global,
    #[default]
    #[serde(alias = "Rule")]
    Rule,
    #[serde(alias = "Direct")]
    Direct,
}

impl Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Global => write!(f, "global"),
            RunMode::Rule => write!(f, "rule"),
            RunMode::Direct => write!(f, "direct"),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    #[serde(alias = "warn")]
    Warning,
    Error,
    #[serde(alias = "off")]
    Silent,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warning => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Silent => write!(f, "off"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Port {
    Single(u16),
    Range(u16, u16),
}

impl Default for Port {
    fn default() -> Self {
        Port::Single(7890)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum BindAddress {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for BindAddress {
    fn default() -> Self {
        BindAddress::Single("*".to_string())
    }
}

#[derive(Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct Config {
    pub port: Option<Port>,
    pub socks_port: Option<Port>,
    pub redir_port: Option<Port>,
    pub tproxy_port: Option<Port>,
    pub mixed_port: Option<Port>,
    pub authentication: Vec<String>,
    pub allow_lan: Option<bool>,
    pub bind_address: BindAddress,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub dns: DNS,
    #[serde(rename = "proxies")]
    pub proxy: Option<Vec<HashMap<String, Value>>>,
    #[serde(rename = "proxy-groups")]
    pub proxy_group: Option<Vec<HashMap<String, Value>>>,
    #[serde(rename = "rules")]
    pub rule: Option<Vec<String>>,
    pub hosts: HashMap<String, String>,
    pub mmdb: Option<String>,
    pub mmdb_download_url: Option<String>,
    pub asn_mmdb: Option<String>,
    pub asn_mmdb_download_url: Option<String>,
    pub geosite: Option<String>,
    pub geosite_download_url: Option<String>,
    pub ipv6: bool,
    pub external_controller: Option<String>,
    #[cfg_attr(not(unix), serde(alias = "external-controller-pipe"))]
    #[cfg_attr(unix, serde(alias = "external-controller-unix"))]
    pub external_controller_ipc: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
    #[serde(rename = "cors-allow-origins")]
    pub cors_allow_origins: Option<Vec<String>>,
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    #[serde(rename = "proxy-providers")]
    pub proxy_provider: Option<HashMap<String, HashMap<String, Value>>>,
    #[serde(rename = "rule-providers")]
    pub rule_provider: Option<HashMap<String, HashMap<String, Value>>>,
    pub tun: Option<TunConfig>,
    pub listeners: Option<Vec<HashMap<String, Value>>>,
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self> {
        if !value.exists() {
            return Err(Error::FileNotFound(value));
        }
        let content = std::fs::read_to_string(value)?;
        content.parse::<Config>()
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut val: Value = serde_yaml::from_str(s)
            .map_err(|e| Error::parsing(format!("couldn't parse config content: {e}")))?;

        // Apply YAML merge keys (anchors and aliases)
        val.apply_merge()
            .map_err(|e| Error::parsing(format!("failed to process anchors: {e}")))?;

        serde_yaml::from_value(val)
            .map_err(|e| Error::parsing(format!("could not parse config: {e}")))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    Multiple(HashMap<String, Value>),
}

#[derive(Serialize, Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct DNS {
    pub enable: bool,
    pub ipv6: bool,
    #[educe(Default = true)]
    pub user_hosts: bool,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub fallback_filter: FallbackFilter,
    pub listen: Option<DNSListen>,
    pub enhanced_mode: DNSMode,
    #[educe(Default = "198.18.0.1/16")]
    pub fake_ip_range: String,
    pub fake_ip_filter: Vec<String>,
    #[educe(Default = vec![
        String::from("114.114.114.114"),
        String::from("8.8.8.8")
    ])]
    pub default_nameserver: Vec<String>,
    pub nameserver_policy: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}

#[derive(Serialize, Deserialize, Clone, Educe)]
#[serde(default)]
#[educe(Default)]
pub struct FallbackFilter {
    #[serde(rename = "geoip")]
    #[educe(Default = true)]
    pub geo_ip: bool,
    #[serde(rename = "geoip-code")]
    #[educe(Default = "CN")]
    pub geo_ip_code: String,
    #[serde(rename = "ipcidr")]
    pub ip_cidr: Vec<String>,
    pub domain: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_config() {
        let yaml = r#"
port: 7890
socks-port: 7891
mode: rule
log-level: info
"#;
        let config: Config = yaml.parse().expect("should parse simple config");
        assert_eq!(config.port, Some(Port::Single(7890)));
        assert_eq!(config.socks_port, Some(Port::Single(7891)));
        assert_eq!(config.mode, RunMode::Rule);
        assert_eq!(config.log_level, LogLevel::Info);
    }

    #[test]
    fn test_parse_with_dns() {
        let yaml = r#"
port: 7890
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
"#;
        let config: Config = yaml.parse().expect("should parse dns config");
        assert!(config.dns.enable);
        assert_eq!(config.dns.nameserver, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn test_parse_with_proxies() {
        let yaml = r#"
port: 7890
proxies:
  - name: "test-trojan"
    type: trojan
    server: example.com
    port: 443
    password: "password123"
"#;
        let config: Config = yaml.parse().expect("should parse proxies");
        assert_eq!(config.proxy.as_ref().unwrap().len(), 1);
        let proxy = &config.proxy.unwrap()[0];
        assert_eq!(proxy.get("name").unwrap().as_str().unwrap(), "test-trojan");
        assert_eq!(proxy.get("type").unwrap().as_str().unwrap(), "trojan");
    }

    #[test]
    fn test_yaml_anchors() {
        let yaml = r#"
defaults: &defaults
  interval: 300
  url: 'http://www.gstatic.com/generate_204'

proxy-groups:
  - name: "auto"
    type: url-test
    <<: *defaults
    proxies:
      - proxy1
"#;
        let config: Config = yaml.parse().expect("should parse yaml with anchors");
        let groups = config.proxy_group.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].get("interval").unwrap().as_u64().unwrap(),
            300
        );
    }

    #[test]
    fn test_invalid_yaml() {
        let yaml = r#"
port: not_a_number
"#;
        let result: Result<Config> = yaml.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_file_not_found() {
        let result = Config::try_from(PathBuf::from("/nonexistent/config.yaml"));
        assert!(matches!(result, Err(Error::FileNotFound(_))));
    }

    #[test]
    fn test_parse_example_yaml() {
        // Path relative to workspace root
        let example_path = PathBuf::from("/home/rald/clash-rs/clash-config/fixtures/example.yaml");
        let config = Config::try_from(example_path).expect("should parse example.yaml");

        // Verify basic settings
        assert_eq!(config.mixed_port, Some(Port::Single(7890)));
        assert!(config.allow_lan.unwrap());
        assert_eq!(config.mode, RunMode::Rule);
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.external_controller, Some("127.0.0.1:9090".to_string()));

        // Verify DNS config
        assert!(!config.dns.enable);
        assert!(config.dns.ipv6);
        assert_eq!(config.dns.default_nameserver.len(), 2);
        assert_eq!(config.dns.nameserver.len(), 2);
        assert_eq!(config.dns.fallback.len(), 4);
        assert_eq!(config.dns.fake_ip_range, "198.18.0.1/16");
        assert!(config.dns.user_hosts);
        assert_eq!(config.dns.fallback_filter.geo_ip_code, "CN");
        assert!(config.dns.fallback_filter.geo_ip);
        assert_eq!(config.dns.fallback_filter.ip_cidr.len(), 2);

        // Verify proxies
        let proxies = config.proxy.as_ref().expect("proxies should exist");
        assert!(!proxies.is_empty());
        assert!(proxies.len() >= 5); // At least 5 proxies defined

        // Check first proxy
        let first_proxy = &proxies[0];
        assert_eq!(first_proxy.get("name").unwrap().as_str().unwrap(), "test1");
        assert_eq!(first_proxy.get("type").unwrap().as_str().unwrap(), "trojan");
        assert_eq!(first_proxy.get("server").unwrap().as_str().unwrap(), "example-server-hk-01.example.com");

        // Verify proxy groups
        let groups = config.proxy_group.as_ref().expect("proxy groups should exist");
        assert!(!groups.is_empty());
        assert!(groups.len() >= 3); // At least 3 groups

        // Verify rules
        let rules = config.rule.as_ref().expect("rules should exist");
        assert!(!rules.is_empty());
        assert!(rules.len() > 50); // Should have many rules
    }
}
