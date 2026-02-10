# clash-config

Configuration parser for clash-rs proxy software.

## Features

- Parse YAML configuration files
- Support for YAML anchors and merge keys
- Validate configuration structure
- Extensible config schema

## Usage

```rust
use clash_config::{Config, Result};
use std::path::PathBuf;

// Parse from file
let config = Config::try_from(PathBuf::from("config.yaml"))?;

// Parse from string
let yaml = r#"
port: 7890
socks-port: 7891
mode: rule
"#;
let config: Config = yaml.parse()?;

// Access configuration
println!("Port: {:?}", config.port);
println!("Mode: {}", config.mode);
```

## Configuration Schema

The configuration supports:

- **Ports**: HTTP, SOCKS5, redir, tproxy, and mixed ports
- **DNS**: DNS server configuration with enhanced modes (fake-ip, redir-host)
- **Proxies**: Proxy server definitions (parsed as raw YAML for flexibility)
- **Proxy Groups**: Load balancing, failover, and selection groups
- **Rules**: Routing rules
- **TUN**: TUN device configuration for transparent proxying
- **Providers**: External proxy and rule providers

## Testing

```bash
cargo test
```

## License

See the main clash-rs repository for license information.
