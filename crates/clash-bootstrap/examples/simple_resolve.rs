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

    Ok(())
}
