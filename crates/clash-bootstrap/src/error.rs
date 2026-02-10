//! Error types for bootstrap resolver

use thiserror::Error;

/// Result type for bootstrap operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during bootstrap resolution
#[derive(Debug, Error)]
pub enum Error {
    /// Domain resolution failed
    #[error("Failed to resolve domain '{domain}': {source}")]
    ResolutionFailed {
        domain: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Invalid domain name
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    /// Invalid nameserver address
    #[error("Invalid nameserver address: {0}")]
    InvalidNameserver(String),

    /// No nameservers configured
    #[error("No nameservers configured")]
    NoNameservers,

    /// Resolution timeout
    #[error("Resolution timeout for domain '{0}'")]
    Timeout(String),

    /// No address found for domain
    #[error("No address found for domain: {0}")]
    NoAddress(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid IP address
    #[error("Invalid IP address: {0}")]
    InvalidIpAddr(String),
}

impl Error {
    /// Create a resolution failed error
    pub fn resolution_failed(domain: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Error::ResolutionFailed {
            domain: domain.into(),
            source: Box::new(source),
        }
    }
}
