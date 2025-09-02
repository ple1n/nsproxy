use std::{
    collections::{HashMap, hash_map::Entry},
    hash::Hash,
};
use anyhow::Result;
use serde::Serialize;
use tokio::fs;

pub trait MapExt {
    type K;
    type V: Default;
    fn update(&mut self, key: Self::K) -> &mut Self::V;
}

impl<K: Eq + Hash, V: Default> MapExt for HashMap<K, V> {
    type K = K;
    type V = V;
    fn update(&mut self, key: Self::K) -> &mut Self::V {
        match self.entry(key) {
            Entry::Occupied(p) => p.into_mut(),
            Entry::Vacant(p) => p.insert(Default::default()),
        }
    }
}

pub async fn dump_as_toml<V: Serialize>(val: &V, name: &str) -> Result<()> {
    let s = toml_edit::ser::to_string_pretty(val)?;
    fs::write(format!("./{}.out.toml", name), s).await?;
    Ok(())
}

pub async fn dump_as_json<V: Serialize>(val: &V, name: &str) -> Result<()> {
    let s = serde_json::to_string_pretty(val)?;
    fs::write(format!("./{}.out.json", name), s).await?;
    Ok(())
}
