//! Data meant to be compatible across versions to backup data that can not be easily recovered without proxies
//!

use serde::{Deserialize, Serialize};

use crate::uplink::{DomainsSolved, clash::ClashState};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UplinkBackup {
    /// Aggregate cache from all UplinkHub state
    pub dns: DomainsSolved,
}

impl UplinkBackup {
    pub fn from_clash_state(state: &ClashState) -> Self {
        let mut dns = state.proxies.clone();
        for group in state.groups.values() {
            merge_domains(&mut dns, &group.tier2_cache);
        }
        Self { dns }
    }

    pub fn merge_into_clash_state(&self, state: &mut ClashState) {
        merge_domains(&mut state.proxies, &self.dns);
        for group in state.groups.values_mut() {
            merge_domains(&mut group.tier2_cache, &self.dns);
        }
    }
}

fn merge_domains(dst: &mut DomainsSolved, src: &DomainsSolved) {
    for (domain, responses) in src {
        let bucket = dst.entry(domain.clone()).or_default();
        for (at, response) in responses {
            bucket.insert(*at, response.clone());
        }
    }
}
