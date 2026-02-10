//! # clash-bootstrap
//!
//! A minimal DNS resolver crate implementing Clash's two-tier bootstrap architecture.
//!
//! This crate provides a two-tier DNS resolver that matches Clash's bootstrap flow:
//! - **Tier 1 (Bootstrap)**: IP-only nameservers resolve Tier 2 nameserver hostnames
//! - **Tier 2 (Main)**: Can be IPs or hostnames, used for proxy server resolution
//!
//! ## Design
//!
//! The `Bootstrapper` implements Clash's DNS architecture:
//! - Bootstrap tier resolves DNS server hostnames (e.g., `doh.pub`)
//! - Main tier resolves proxy server domains (e.g., `example.com`)
//! - Supports IPv4 and IPv6 resolution order
//!
//! ## Example
//!
//! ```no_run
//! use clash_bootstrap::Bootstrapper;
//! use std::str::FromStr;
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a bootstrapper with default nameservers
//!     let bootstrapper = Bootstrapper::with_default_nameservers()?;
//!
//!     // Resolve a proxy server domain (via main tier)
//!     let addr = bootstrapper.resolve("example.com").await?;
//!     println!("Resolved: {}", addr);
//!
//!     Ok(())
//! }
//! ```

pub mod bootstrapper;
pub mod config;
pub mod error;

pub use bootstrapper::Bootstrapper;
pub use config::{BootstrapConfig, NameServer};
pub use error::{Error, Result};
