//! Configuration for the bootstrap resolver

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::error::{Error, Result};

const DEFAULT_DNS_PORT: u16 = 53;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameServer {
    pub host: String,
    pub port: u16,
}

impl NameServer {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(Error::InvalidNameserver(host));
        }
        if port == 0 {
            return Err(Error::InvalidNameserver(host));
        }
        Ok(Self { host, port })
    }
}

/// Configuration for the Bootstrapper
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    /// Bootstrap nameservers (Tier 1) - MUST be IP addresses only
    /// Used to resolve main nameserver hostnames
    pub bootstrap_nameservers: Vec<NameServer>,

    /// Main nameservers (Tier 2) - Can be IPs or hostnames
    /// Used for actual proxy server resolution
    pub main_nameservers: Vec<NameServer>,

    /// Timeout for individual DNS queries
    pub query_timeout: Duration,

    /// Whether to prefer IPv6 addresses when available
    pub prefer_ipv6: bool,
}

impl BootstrapConfig {
    /// Create a new configuration with explicit bootstrap and main nameservers
    pub fn new(
        bootstrap_nameservers: Vec<NameServer>,
        main_nameservers: Vec<NameServer>,
    ) -> Self {
        Self {
            bootstrap_nameservers,
            main_nameservers,
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        }
    }

    /// Create configuration with default public nameservers
    /// Bootstrap and main both use Google/Cloudflare DNS
    pub fn defaults() -> Self {
        let default_servers = vec![
            NameServer::new("8.8.8.8", DEFAULT_DNS_PORT).unwrap(),
            NameServer::new("8.8.4.4", DEFAULT_DNS_PORT).unwrap(),
            NameServer::new("1.1.1.1", DEFAULT_DNS_PORT).unwrap(),
            NameServer::new("1.0.0.1", DEFAULT_DNS_PORT).unwrap(),
        ];
        Self {
            bootstrap_nameservers: default_servers.clone(),
            main_nameservers: default_servers,
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        }
    }

    /// Create configuration with custom nameservers (IP addresses only)
    /// Sets both bootstrap and main to the same IPs
    pub fn with_ips(ips: Vec<IpAddr>) -> Result<Self> {
        let nameservers: Result<Vec<NameServer>> = ips
            .into_iter()
            .map(|ip| NameServer::new(ip.to_string(), DEFAULT_DNS_PORT))
            .collect();

        let ns = nameservers?;
        Ok(Self {
            bootstrap_nameservers: ns.clone(),
            main_nameservers: ns,
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        })
    }

    /// Create configuration with nameserver strings (e.g., "8.8.8.8" or "8.8.8.8:53")
    /// Sets both bootstrap and main to the same servers
    pub fn with_nameserver_strings(servers: Vec<&str>) -> Result<Self> {
        let nameservers: Result<Vec<NameServer>> = servers
            .into_iter()
            .map(parse_nameserver)
            .collect();

        let ns = nameservers?;
        Ok(Self {
            bootstrap_nameservers: ns.clone(),
            main_nameservers: ns,
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        })
    }

    /// Create configuration with explicit bootstrap and main nameserver strings
    pub fn with_bootstrap_and_main(
        bootstrap: Vec<&str>,
        main: Vec<&str>,
    ) -> Result<Self> {
        let bootstrap_ns: Result<Vec<NameServer>> = bootstrap
            .into_iter()
            .map(parse_nameserver)
            .collect();

        let main_ns: Result<Vec<NameServer>> = main
            .into_iter()
            .map(parse_nameserver)
            .collect();

        Ok(Self {
            bootstrap_nameservers: bootstrap_ns?,
            main_nameservers: main_ns?,
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        })
    }

    /// Set the query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// Set whether to prefer IPv6 addresses
    pub fn with_prefer_ipv6(mut self, prefer: bool) -> Self {
        self.prefer_ipv6 = prefer;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.bootstrap_nameservers.is_empty() {
            return Err(Error::ConfigError("Bootstrap nameservers cannot be empty".to_string()));
        }

        if self.main_nameservers.is_empty() {
            return Err(Error::ConfigError("Main nameservers cannot be empty".to_string()));
        }

        // Validate bootstrap nameservers are IPs only
        for ns in &self.bootstrap_nameservers {
            if ns.host.parse::<IpAddr>().is_err() {
                return Err(Error::ConfigError(format!(
                    "Bootstrap nameserver must be IP address, got: {}",
                    ns.host
                )));
            }
        }

        if self.query_timeout.is_zero() {
            return Err(Error::ConfigError("Query timeout cannot be zero".to_string()));
        }

        Ok(())
    }
}

fn parse_nameserver(server: &str) -> Result<NameServer> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return NameServer::new(addr.ip().to_string(), addr.port());
    }

    if let Ok(ip) = server.parse::<IpAddr>() {
        return NameServer::new(ip.to_string(), DEFAULT_DNS_PORT);
    }

    if let Some((host, port)) = server.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::InvalidNameserver(server.to_string()))?;
        return NameServer::new(host, port);
    }

    NameServer::new(server, DEFAULT_DNS_PORT)
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let cfg = BootstrapConfig::defaults();
        assert!(!cfg.bootstrap_nameservers.is_empty());
        assert!(!cfg.main_nameservers.is_empty());
        assert_eq!(cfg.query_timeout.as_secs(), 5);
        assert!(!cfg.prefer_ipv6);
    }

    #[test]
    fn test_config_with_ips() {
        let ips = vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let cfg = BootstrapConfig::with_ips(ips).unwrap();
        assert_eq!(cfg.bootstrap_nameservers.len(), 2);
        assert_eq!(cfg.main_nameservers.len(), 2);
    }

    #[test]
    fn test_config_with_nameserver_strings() {
        let servers = vec!["8.8.8.8", "1.1.1.1:53"];
        let cfg = BootstrapConfig::with_nameserver_strings(servers).unwrap();
        assert_eq!(cfg.bootstrap_nameservers.len(), 2);
        assert_eq!(cfg.main_nameservers.len(), 2);
    }

    #[test]
    fn test_config_with_hostname_nameserver() {
        let servers = vec!["dns.example.com", "dns.example.com:5353"];
        let cfg = BootstrapConfig::with_nameserver_strings(servers).unwrap();
        assert_eq!(cfg.bootstrap_nameservers.len(), 2);
        assert_eq!(cfg.main_nameservers.len(), 2);
        assert_eq!(cfg.bootstrap_nameservers[0].port, DEFAULT_DNS_PORT);
        assert_eq!(cfg.bootstrap_nameservers[1].port, 5353);
    }

    #[test]
    fn test_config_with_bootstrap_and_main() {
        let bootstrap = vec!["8.8.8.8", "1.1.1.1"];
        let main = vec!["dns.google.com", "cloudflare-dns.com"];
        let cfg = BootstrapConfig::with_bootstrap_and_main(bootstrap, main).unwrap();
        assert_eq!(cfg.bootstrap_nameservers.len(), 2);
        assert_eq!(cfg.main_nameservers.len(), 2);
    }

    #[test]
    fn test_config_invalid_nameserver() {
        // Test that empty port causes parse error
        let servers = vec!["8.8.8.8:"];
        let result = BootstrapConfig::with_nameserver_strings(servers);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation() {
        let cfg = BootstrapConfig::defaults();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validation_no_nameservers() {
        let cfg = BootstrapConfig {
            bootstrap_nameservers: vec![],
            main_nameservers: vec![],
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validation_bootstrap_must_be_ip() {
        let cfg = BootstrapConfig {
            bootstrap_nameservers: vec![NameServer::new("dns.google.com", 53).unwrap()],
            main_nameservers: vec![NameServer::new("8.8.8.8", 53).unwrap()],
            query_timeout: Duration::from_secs(5),
            prefer_ipv6: false,
        };
        assert!(cfg.validate().is_err());
    }
}
