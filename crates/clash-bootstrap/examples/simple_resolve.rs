// Simple example showing how to use the Bootstrapper

use clash_bootstrap::Bootstrapper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Create a bootstrapper with default public nameservers
    // Both bootstrap and main tiers use the same IPs
    let bootstrapper = Bootstrapper::with_default_nameservers()?;
    println!("Created bootstrapper with {} bootstrap nameservers", 
        bootstrapper.config().bootstrap_nameservers.len());
    println!("Created bootstrapper with {} main nameservers", 
        bootstrapper.config().main_nameservers.len());

    // Resolve a single address
    match bootstrapper.resolve("example.com").await {
        Ok(addr) => println!("✓ Resolved example.com -> {}", addr),
        Err(e) => println!("✗ Failed to resolve example.com: {}", e),
    }

    // Resolve your proxy server domain
    match bootstrapper.resolve("proxy.example.com").await {
        Ok(addr) => println!("✓ Resolved proxy server -> {}", addr),
        Err(e) => println!("✗ Failed to resolve proxy server: {}", e),
    }

    // Resolve multiple addresses
    match bootstrapper.resolve_all("google.com").await {
        Ok(addrs) => {
            println!("✓ Resolved google.com to {} addresses:", addrs.len());
            for addr in addrs {
                println!("  - {}", addr);
            }
        }
        Err(e) => println!("✗ Failed to resolve google.com: {}", e),
    }

    Ok(())
}
