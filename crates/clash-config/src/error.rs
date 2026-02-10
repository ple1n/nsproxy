use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config parsing error: {0}")]
    ParsingError(String),

    #[error("invalid config value: {0}")]
    InvalidValue(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("config file not found: {0}")]
    FileNotFound(PathBuf),
}

impl Error {
    pub fn parsing<S: Into<String>>(msg: S) -> Self {
        Error::ParsingError(msg.into())
    }

    pub fn invalid_value<S: Into<String>>(msg: S) -> Self {
        Error::InvalidValue(msg.into())
    }
}
