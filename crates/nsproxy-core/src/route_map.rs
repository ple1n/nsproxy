use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::{HotConfig, RoutePrefs, state_file, state_paths};

fn validate_container_name(container: &str) -> Result<()> {
    ensure!(
        !container.is_empty()
            && container.chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            ),
        "container name `{container}` may only contain ASCII letters, digits, `-` and `_`"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    Merge,
    Replace,
}

pub fn apply_to_hotconfig(
    config: &mut HotConfig,
    preferences: &RoutePrefs,
    mode: ApplyMode,
) -> Result<()> {
    if mode == ApplyMode::Replace {
        config.route_map.clear();
    }
    config.route_map.extend(preferences.route_map.clone());
    config.default_route = preferences.default_route.clone();
    nsproxy_common::routing::normalize_route_map_domains(&mut config.route_map)
        .map_err(anyhow::Error::msg)
}

pub fn read(path: &Path) -> Result<RoutePrefs> {
    let content =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&content)
        .with_context(|| format!("invalid route preferences {}", path.display()))
}

pub fn apply_to_container(
    container: &str,
    preferences: &RoutePrefs,
    mode: ApplyMode,
) -> Result<PathBuf> {
    validate_container_name(container)?;
    let path = state_paths::hot_config(container);
    state_file::try_update(&path, |config: &mut HotConfig| {
        apply_to_hotconfig(config, preferences, mode)
    })
    .with_context(|| format!("updating {}", path.display()))?;
    Ok(path)
}

pub fn export_container(container: &str, destination: &Path, force: bool) -> Result<PathBuf> {
    validate_container_name(container)?;
    let hot_path = state_paths::hot_config(container);
    let config: HotConfig = state_file::read(&hot_path)?
        .with_context(|| format!("missing hot config {}", hot_path.display()))?;
    let destination = if destination.is_dir() {
        destination.join(format!("{container}.json"))
    } else {
        destination.to_owned()
    };
    ensure!(
        force || !destination.exists(),
        "destination {} already exists; pass --force to overwrite",
        destination.display()
    );
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let preferences = RoutePrefs {
        default_route: config.default_route,
        route_map: config.route_map,
    };
    let bytes = serde_json::to_vec_pretty(&preferences)?;
    std::fs::write(&destination, bytes)
        .with_context(|| format!("failed to write {}", destination.display()))?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsproxy_common::routing::{RoutingKey, RoutingResovled};

    #[test]
    fn applying_route_prefs_updates_both_hotconfig_fields() {
        let imported = RoutePrefs {
            default_route: crate::HotRoute::NoProxy,
            route_map: [(
                RoutingKey::host("huggingface.co", Some(443)),
                RoutingResovled::NoProxyDomain {
                    host: "huggingface.co.".to_string(),
                    port: 443,
                },
            )]
            .into(),
        };
        let mut config = HotConfig::default();

        apply_to_hotconfig(&mut config, &imported, ApplyMode::Replace).unwrap();

        assert_eq!(config.default_route, crate::HotRoute::NoProxy);
        assert_eq!(config.route_map, imported.route_map);
    }

    #[test]
    fn standalone_route_preferences_round_trip_both_fields() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            RoutingKey::host("Example.COM.", Some(443)),
            RoutingResovled::NoProxyDomain {
                host: "example.com.".to_string(),
                port: 443,
            },
        );
        let preferences = RoutePrefs {
            default_route: crate::HotRoute::NoProxy,
            route_map: map.clone(),
        };
        let encoded = serde_json::to_vec(&preferences).unwrap();
        let decoded: RoutePrefs = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, preferences);
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["default_route"], "NoProxy");
        assert!(value["route_map"].is_array());
    }

    #[test]
    fn checked_in_route_examples_are_importable() {
        for example in [
            include_str!("../../../routing_examples/dnf.json"),
            include_str!("../../../routing_examples/huggingface.json"),
        ] {
            let preferences: RoutePrefs = serde_json::from_str(example).unwrap();
            assert!(!preferences.route_map.is_empty());
        }
    }
}
