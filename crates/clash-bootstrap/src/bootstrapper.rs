//! Core bootstrapper implementation for DNS resolution
//!
//! This module implements Clash's two-tier DNS resolution:
//! - Tier 1 (Bootstrap): IP-only nameservers to resolve Tier 2 hostnames
//! - Tier 2 (Main): Can be IPs or hostnames, used for actual resolution
//!
//! Uses trust-dns-resolver 0.23.2 with explicit nameserver configuration.
//! No implicit defaults or system resolver - only uses provided servers.

use std::net::IpAddr;
use std::sync::Arc;

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup,
    ResolverConfig, ResolverOpts, Protocol,
};
use rand::seq::SliceRandom;
use tokio::sync::OnceCell;
use tracing::{debug, warn};

use crate::config::{BootstrapConfig, NameServer};
use crate::error::{Error, Result};

/// A two-tier DNS bootstrapper matching Clash's architecture
///
/// - Bootstrap tier: Resolves main nameserver hostnames
/// - Main tier: Resolves proxy server domains
pub struct Bootstrapper {
    config: BootstrapConfig,
    bootstrap_resolver: OnceCell<Arc<TokioAsyncResolver>>,
    main_resolver: OnceCell<Arc<TokioAsyncResolver>>,
}

impl Bootstrapper {
    /// Create a new bootstrapper with the given configuration
    pub fn new(config: BootstrapConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            bootstrap_resolver: OnceCell::new(),
            main_resolver: OnceCell::new(),
        })
    }

    /// Create a bootstrapper with default public nameservers
    pub fn with_default_nameservers() -> Result<Self> {
        Self::new(BootstrapConfig::defaults())
    }

    /// Create a bootstrapper with custom IP-based nameservers
    pub fn with_ips(ips: Vec<std::net::IpAddr>) -> Result<Self> {
        Self::new(BootstrapConfig::with_ips(ips)?)
    }

    /// Create a bootstrapper with nameserver strings
    pub fn with_nameserver_strings(servers: Vec<&str>) -> Result<Self> {
        Self::new(BootstrapConfig::with_nameserver_strings(servers)?)
    }

    /// Resolve a domain name to an IP address using the main tier
    ///
    /// This is what you use to resolve proxy server domains.
    /// Main nameservers are bootstrapped via the bootstrap tier.
    pub async fn resolve(&self, domain: &str) -> Result<IpAddr> {
        debug!("Resolving domain via main tier: {}", domain);

        if domain.is_empty() {
            return Err(Error::InvalidDomain(domain.to_string()));
        }

        let resolver = self.main_resolver().await?;
        let lookup = resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| Error::resolution_failed(domain, e))?;

        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            warn!("No addresses found for domain: {}", domain);
            return Err(Error::NoAddress(domain.to_string()));
        }

        let ip = *ips
            .choose(&mut rand::thread_rng())
            .ok_or_else(|| Error::NoAddress(domain.to_string()))?;
        debug!("Resolved {} to {}", domain, ip);
        Ok(ip)
    }

    /// Resolve a domain name, returning all matching IP addresses
    pub async fn resolve_all(&self, domain: &str) -> Result<Vec<IpAddr>> {
        debug!("Resolving all addresses via main tier: {}", domain);

        if domain.is_empty() {
            return Err(Error::InvalidDomain(domain.to_string()));
        }

        let resolver = self.main_resolver().await?;
        let lookup = resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| Error::resolution_failed(domain, e))?;

        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            warn!("No addresses found for domain: {}", domain);
            return Err(Error::NoAddress(domain.to_string()));
        }

        debug!("Resolved {} to {} addresses", domain, ips.len());
        Ok(ips)
    }

    /// Get a reference to the current configuration
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// Check if a string is a valid domain name
    pub fn is_valid_domain(domain: &str) -> bool {
        !domain.is_empty() && !domain.starts_with('-') && !domain.ends_with('-')
    }

    /// Get or build the bootstrap resolver (Tier 1)
    ///
    /// Uses bootstrap_nameservers (must be IPs) to resolve main nameserver hostnames
    async fn bootstrap_resolver(&self) -> Result<Arc<TokioAsyncResolver>> {
        let config = self.config.clone();
        self.bootstrap_resolver
            .get_or_try_init(|| async move {
                debug!("Building bootstrap resolver from {} nameservers", config.bootstrap_nameservers.len());
                let resolver = Self::build_bootstrap_resolver(&config).await?;
                Ok(Arc::new(resolver))
            })
            .await
            .map(Arc::clone)
    }

    /// Get or build the main resolver (Tier 2)
    ///
    /// Main nameservers are bootstrapped via Tier 1 if they're hostnames
    async fn main_resolver(&self) -> Result<Arc<TokioAsyncResolver>> {
        let config = self.config.clone();
        let bootstrap = self.bootstrap_resolver().await?;
        self.main_resolver
            .get_or_try_init(|| async move {
                debug!("Building main resolver from {} nameservers", config.main_nameservers.len());
                let resolver = Self::build_main_resolver(&config, bootstrap).await?;
                Ok(Arc::new(resolver))
            })
            .await
            .map(Arc::clone)
    }

    /// Build bootstrap resolver from IP-only nameservers
    /// 
    /// Uses ONLY the specified IP nameservers - no system resolver fallback.
    async fn build_bootstrap_resolver(config: &BootstrapConfig) -> Result<TokioAsyncResolver> {
        if config.bootstrap_nameservers.is_empty() {
            return Err(Error::NoNameservers);
        }

        // Build nameserver config from IPs only
        let mut nameservers = NameServerConfigGroup::new();
        
        for server in &config.bootstrap_nameservers {
            // Bootstrap nameservers MUST be IPs - enforce strict validation
            let ip = server.host.parse::<IpAddr>()
                .map_err(|_| Error::InvalidNameserver(format!(
                    "Bootstrap nameserver must be IP address, got: {}", server.host
                )))?;

            nameservers.push(NameServerConfig {
                socket_addr: (ip, server.port).into(),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }

        // Build resolver config with ONLY our custom nameservers
        // No system resolver, no defaults
        let resolver_config = ResolverConfig::from_parts(
            None,  // No domain
            vec![], // No search domains
            nameservers, // Our explicit nameservers
        );

        let mut opts = ResolverOpts::default();
        opts.timeout = config.query_timeout;
        opts.use_hosts_file = false;  // Don't use system hosts
        opts.ip_strategy = if config.prefer_ipv6 {
            LookupIpStrategy::Ipv6thenIpv4
        } else {
            LookupIpStrategy::Ipv4thenIpv6
        };

        debug!("Building bootstrap resolver with {} custom nameservers", 
               config.bootstrap_nameservers.len());
        
        Ok(TokioAsyncResolver::tokio(resolver_config, opts))
    }

    /// Build main resolver, bootstrapping nameserver hostnames via bootstrap tier
    /// 
    /// Resolves nameserver hostnames using bootstrap tier, then uses those IPs.
    async fn build_main_resolver(
        config: &BootstrapConfig,
        bootstrap: Arc<TokioAsyncResolver>,
    ) -> Result<TokioAsyncResolver> {
        if config.main_nameservers.is_empty() {
            return Err(Error::NoNameservers);
        }

        // Build nameserver config by resolving hostnames via bootstrap
        let mut nameservers = NameServerConfigGroup::new();
        
        for server in &config.main_nameservers {
            // Resolve hostname to IP via bootstrap tier
            let ips = resolve_nameserver_bootstrapped(
                server,
                bootstrap.clone(),
                config.query_timeout,
            ).await?;

            // Add all resolved IPs as nameservers
            for ip in ips {
                nameservers.push(NameServerConfig {
                    socket_addr: (ip, server.port).into(),
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                });
            }
        }

        if nameservers.is_empty() {
            return Err(Error::NoNameservers);
        }

        let ns_count = nameservers.len();
        
        // Build resolver config with resolved nameservers
        let resolver_config = ResolverConfig::from_parts(
            None,  // No domain
            vec![], // No search domains
            nameservers, // Our resolved nameservers
        );

        let mut opts = ResolverOpts::default();
        opts.timeout = config.query_timeout;
        opts.use_hosts_file = false;  // Don't use system hosts
        opts.ip_strategy = if config.prefer_ipv6 {
            LookupIpStrategy::Ipv6thenIpv4
        } else {
            LookupIpStrategy::Ipv4thenIpv6
        };

        debug!("Building main resolver with {} bootstrapped nameservers", ns_count);
        
        Ok(TokioAsyncResolver::tokio(resolver_config, opts))
    }
}

/// Resolve a nameserver hostname using the bootstrap resolver
async fn resolve_nameserver_bootstrapped(
    server: &NameServer,
    bootstrap: Arc<TokioAsyncResolver>,
    timeout: std::time::Duration,
) -> Result<Vec<IpAddr>> {
    // If it's already an IP, return it directly
    if let Ok(ip) = server.host.parse::<IpAddr>() {
        debug!("Nameserver {} is already an IP", server.host);
        return Ok(vec![ip]);
    }

    // Resolve hostname via bootstrap resolver
    debug!("Bootstrapping nameserver hostname: {}", server.host);
    let lookup = tokio::time::timeout(
        timeout,
        bootstrap.lookup_ip(server.host.as_str()),
    )
    .await
    .map_err(|_| Error::Timeout(server.host.clone()))
    .and_then(|result| {
        result.map_err(|e| Error::resolution_failed(server.host.clone(), e))
    })?;

    let ips: Vec<IpAddr> = lookup.iter().collect();
    if ips.is_empty() {
        return Err(Error::NoAddress(server.host.clone()));
    }

    debug!("Bootstrapped {} to {} IPs", server.host, ips.len());
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_domain() {
        assert!(Bootstrapper::is_valid_domain("example.com"));
        assert!(Bootstrapper::is_valid_domain("sub.example.com"));
    }

    #[test]
    fn test_invalid_domains() {
        assert!(!Bootstrapper::is_valid_domain(""));
        assert!(!Bootstrapper::is_valid_domain("-invalid.com"));
    }
}
