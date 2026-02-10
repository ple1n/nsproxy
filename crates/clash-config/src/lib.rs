pub mod def;
pub mod error;
pub mod utils;

pub use def::Config;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
