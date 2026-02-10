// Example showing custom nameserver configuration

use clash_bootstrap::{Bootstrapper, BootstrapConfig};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== Example 1: Using custom IP addresses ===");
    // Create bootstrapper with specific nameservers (same for both tiers)
    let custom_ips = vec![
        "223.5.5.5".parse::<IpAddr>()?,  // Ali DNS
        "119.29.29.29".parse::<IpAddr>()?, // Tencent DNS
        "8.8.8.8".parse::<IpAddr>()?,     // Google DNS
    ];

    let bootstrapper = Bootstrapper::with_ips(custom_ips)?;
    match bootstrapper.resolve("github.com").await {
        Ok(addr) => println!("Resolved via custom IPs: {}", addr),
        Err(e) => println!("Error: {}", e),
    }

    println!("\n=== Example 2: Two-tier architecture (IP bootstrap, hostname main) ===");
    // This is the Clash way: IP-only bootstrap, hostname-based main
    let cfg = BootstrapConfig::with_bootstrap_and_main(
        vec!["8.8.8.8", "1.1.1.1"],           // Bootstrap tier (must be IPs)
        vec!["dns.google.com", "one.one.one.one"], // Main tier (can be hostnames)
    )?;
    let bootstrapper = Bootstrapper::new(cfg)?;
    match bootstrapper.resolve("example.com").await {
        Ok(addr) => println!("Resolved via bootstrapped main nameservers: {}", addr),
        Err(e) => println!("Error: {}", e),
    }

    println!("\n=== Example 3: Custom configuration with timeout ===");
    // Or build configuration manually for more control
    let config = BootstrapConfig::defaults()
        .with_timeout(std::time::Duration::from_secs(10))
        .with_prefer_ipv6(false);

    let bootstrapper = Bootstrapper::new(config)?;
    match bootstrapper.resolve("rust-lang.org").await {
        Ok(addr) => println!("Resolved with custom config: {}", addr),
        Err(e) => println!("Error: {}", e),
    }

    println!("\n=== Example 4: Domain validation ===");
    // Validate domain names before resolving
    let domains = vec!["example.com", "sub.example.com", "invalid..domain", ""];
    for domain in domains {
        let valid = clash_bootstrap::Bootstrapper::is_valid_domain(domain);
        println!("Domain '{}' is {}", domain, if valid { "valid" } else { "invalid" });
    }

    Ok(())
}
