# clash-bootstrap

A minimal DNS bootstrapper implementing Clash's two-tier DNS resolution architecture.

## Architecture

This crate mirrors Clash's DNS bootstrap flow:

1. **Tier 1 (Bootstrap)**: IP-only nameservers resolve DNS server hostnames
2. **Tier 2 (Main)**: Can be IPs or hostnames, used for proxy server resolution

**Example scenario:**
```yaml
default-nameserver: [8.8.8.8, 1.1.1.1]           # Tier 1: Bootstrap
nameserver: ['https://doh.pub/dns-query']         # Tier 2: Main (hostname)
```

- `8.8.8.8` resolves `doh.pub` → `1.2.3.4`
- DoH client connects to `1.2.3.4:443`
- DoH server resolves proxy domains like `example.com`

## Features

- **Two-tier DNS architecture**: Matches Clash's bootstrap/main separation
- **Bootstrap validation**: Ensures bootstrap nameservers are IP addresses only
- **Hostname support**: Main nameservers can be IPs or hostnames
- **Minimal dependencies**: Uses hickory-resolver, tokio, and standard error handling
- **Resolver caching**: Instantiate once, resolve multiple domains
- **Flexible configuration**: Custom nameservers, timeouts, IPv4/IPv6 preference
- **No large runtime setup**: Perfect for testing and CLI tools
- **Easy to use**: Simple API with sensible defaults

## Usage

### Basic Usage

```rust
use clash_bootstrap::Bootstrapper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create with default public nameservers
    let bootstrapper = Bootstrapper::with_default_nameservers()?;
    
    // Resolve a domain
    let addr = bootstrapper.resolve("example.com").await?;
    println!("Resolved: {}", addr);
    
    Ok(())
}
```

### Custom Nameservers

```rust
use clash_bootstrap::Bootstrapper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use specific nameserver IPs
    let ips = vec!["8.8.8.8".parse()?, "1.1.1.1".parse()?];
    let bootstrapper = Bootstrapper::with_ips(ips)?;
    ### Custom Nameserver Hostnames

    ```rust
    use clash_bootstrap::Bootstrapper;

    #[tokio::main]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use DNS servers by hostname (resolved via bootstrap tier)
    let cfg = clash_bootstrap::BootstrapConfig::with_bootstrap_and_main(
        vec!["8.8.8.8", "1.1.1.1"],           // Bootstrap (must be IPs)
        vec!["dns.google.com", "one.one.one.one"], // Main (can be hostnames)
    )?;
    
    let bootstrapper = clash_bootstrap::Bootstrapper::new(cfg)?;
    let addr = bootstrapper.resolve("example.com").await?;
    println!("Resolved: {}", addr);
    
    Ok(())
}
```

### Resolving Your Proxy Server

```rust
use clash_bootstrap::Bootstrapper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve your Clash proxy server
    let bootstrapper = Bootstrapper::with_default_nameservers()?;
    let addr = bootstrapper
        .resolve("proxy.example.com")
        .await?;
    
    println!("Proxy server resolves to: {}", addr);
    
    Ok(())
}
```

### Advanced Configuration

```rust
use clash_bootstrap::{Bootstrapper, BootstrapConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = BootstrapConfig::defaults()
        .with_timeout(Duration::from_secs(10))
        .with_prefer_ipv6(false);
    
    let bootstrapper = Bootstrapper::new(config)?;
    
    let addr = bootstrapper.resolve("example.com").await?;
    println!("Resolved: {}", addr);
    
    Ok(())
}
```

## API

### Bootstrapper

Two-tier DNS resolver:

- `new(config: BootstrapConfig)` - Create with custom configuration
- `with_default_nameservers()` - Create with public nameservers (same for both tiers)
- `with_ips(ips: Vec<IpAddr>)` - Create with IP addresses (same for both tiers)
- `with_nameserver_strings(servers: Vec<&str>)` - Create with string addresses (same for both tiers)
- `resolve(domain: &str)` - Resolve domain via main tier to single IP
- `resolve_all(domain: &str)` - Resolve domain via main tier to all IPs
- `config()` - Get reference to current configuration
- `is_valid_domain(domain: &str)` - Static method to validate domain

### BootstrapConfig

Configuration object:

- `new(bootstrap: Vec<NameServer>, main: Vec<NameServer>)` - Create with explicit tiers
- `defaults()` - Create with Google and Cloudflare DNS for both tiers
- `with_ips(ips: Vec<IpAddr>)` - Create with IP addresses (same for both tiers)
- `with_nameserver_strings(servers: Vec<&str>)` - Create from strings (same for both tiers)
- `with_bootstrap_and_main(bootstrap: Vec<&str>, main: Vec<&str>)` - Create with separate tiers
- `with_timeout(timeout: Duration)` - Set query timeout
- `with_prefer_ipv6(prefer: bool)` - Prefer IPv6 addresses
- `validate()` - Validate configuration (checks bootstrap are IPs)

## Running Examples

```bash
# Simple resolution
cargo run --example simple_resolve

# Custom configuration
cargo run --example custom_config
```

## Use Cases

1. **DNS Bootstrapping**: Resolve DoH/DoT server hostnames before querying them
2. **Proxy Resolution**: Resolve proxy server addresses through bootstrapped DNS
3. **Testing**: Test DNS resolution without full Clash setup
4. **CLI Tools**: Quick DNS lookups with two-tier architecture
5. **Embedded**: Minimal DNS support matching Clash behavior

## Error Handling

All resolution methods return `Result<T>` with the custom `Error` type:

```rust
use clash_bootstrap::{Bootstrapper, Error};

match bootstrapper.resolve("example.com").await {
    Ok(addr) => println!("Resolved: {}", addr),
    Err(Error::InvalidDomain(d)) => println!("Invalid domain: {}", d),
    Err(Error::NoAddress(d)) => println!("No address found: {}", d),
    Err(Error::Timeout(d)) => println!("Timeout resolving: {}", d),
    Err(e) => println!("Error: {}", e),
}
```

## Performance

The `Bootstrapper` maintains an internal resolver cache. Create it once and reuse it for multiple queries:

```rust
let bootstrapper = Bootstrapper::with_default_nameservers()?;

// These queries reuse the same resolver instance
bootstrapper.resolve("example.com").await?;
bootstrapper.resolve("github.com").await?;
bootstrapper.resolve_all("google.com").await?;
```

## Testing

Run tests with:

```bash
cargo test
```

For tests that require internet access:

```bash
cargo test -- --ignored --test-threads=1
```

## Integration with clash-lib

This crate is designed to be used alongside the main `clash-lib` for bootstrapping connections to proxy servers whose addresses are specified as domain names.

See the parent project's documentation for integration examples.
