use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::crdt::CRDT;

pub const MICROS_PER_SEC: u64 = 1_000_000;
pub const MINUTE_US: u64 = 60 * MICROS_PER_SEC;
pub const HOUR_US: u64 = 3_600 * MICROS_PER_SEC;
pub const DAY_US: u64 = 86_400 * MICROS_PER_SEC;
pub const WEEK_US: u64 = 7 * DAY_US;
const MAX_RETENTION_US: u64 = 4 * WEEK_US;
const SLOT_QUOTA: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Trojan,
    Geph,
    File,
    Socks4,
    Socks5,
    Http,
}

pub fn default_udp_expectation(protocol: ProxyProtocol) -> bool {
    match protocol {
        ProxyProtocol::Trojan => true,
        ProxyProtocol::Geph => true,
        ProxyProtocol::File => false,
        ProxyProtocol::Socks4 => false,
        ProxyProtocol::Socks5 => true,
        ProxyProtocol::Http => false,
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(d.as_micros() as u64)
    }

    pub fn as_secs(self) -> u64 {
        self.0 / MICROS_PER_SEC
    }

    pub fn elapsed_since(self, earlier: Timestamp) -> std::time::Duration {
        std::time::Duration::from_micros(self.0.saturating_sub(earlier.0))
    }
}

impl rangemap::StepLite for Timestamp {
    fn add_one(&self) -> Self {
        Timestamp(self.0 + 1)
    }
    fn sub_one(&self) -> Self {
        Timestamp(self.0.saturating_sub(1))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SlotData {
    pub attempts: u128,
    pub successes: u128,
    pub bytes_up: u128,
    pub bytes_down: u128,
    pub latency_sum_ms: u128,
    pub latency_count: u128,
}

impl SlotData {
    pub fn success_rate(&self) -> Option<f64> {
        (self.attempts > 0).then(|| self.successes as f64 / self.attempts as f64)
    }

    pub fn avg_latency_ms(&self) -> Option<f64> {
        (self.latency_count > 0).then(|| self.latency_sum_ms as f64 / self.latency_count as f64)
    }
}

impl Eq for SlotData {}

impl CRDT for SlotData {
    fn merge(self, other: Self) -> Self {
        Self {
            attempts: self.attempts + other.attempts,
            successes: self.successes + other.successes,
            bytes_up: self.bytes_up + other.bytes_up,
            bytes_down: self.bytes_down + other.bytes_down,
            latency_sum_ms: self.latency_sum_ms + other.latency_sum_ms,
            latency_count: self.latency_count + other.latency_count,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyStats {
    pub minute_data: BTreeMap<Timestamp, SlotData>,
    pub hour_data: BTreeMap<Timestamp, SlotData>,
    pub day_data: BTreeMap<Timestamp, SlotData>,
    pub udp_ability: Option<bool>,
    pub expected_udp: Option<bool>,
    pub udp_ability_ts: Option<Timestamp>,
}

impl ProxyStats {
    pub fn record(&mut self, ts: Timestamp, slot: SlotData) {
        let now = Timestamp::now();
        let key = Timestamp(ts.0 / MINUTE_US * MINUTE_US);
        self.minute_data
            .entry(key)
            .and_modify(|d| *d = d.clone().merge(slot.clone()))
            .or_insert(slot);
    }

    pub fn record_traffic(&mut self, bytes_up: u128, bytes_down: u128) {
        self.record(
            Timestamp::now(),
            SlotData {
                bytes_up,
                bytes_down,
                ..Default::default()
            },
        );
    }

    pub fn record_attempt(&mut self, success: bool) {
        self.record(
            Timestamp::now(),
            SlotData {
                attempts: 1,
                successes: if success { 1 } else { 0 },
                ..Default::default()
            },
        );
    }

    pub fn record_latency_ms(&mut self, ms: u64) {
        self.record(
            Timestamp::now(),
            SlotData {
                latency_sum_ms: ms as u128,
                latency_count: 1,
                ..Default::default()
            },
        );
    }

    pub fn simplify(&mut self) {
        let now = Timestamp::now();
        let cutoff = Timestamp(now.0.saturating_sub(MAX_RETENTION_US));
        let hour_ago = Timestamp(now.0.saturating_sub(HOUR_US));
        let day_ago = Timestamp(now.0.saturating_sub(DAY_US));

        let recent_minutes = self.minute_data.split_off(&hour_ago);
        for (ts, data) in &self.minute_data {
            if *ts >= cutoff {
                let hr_key = Timestamp(ts.0 / HOUR_US * HOUR_US);
                self.hour_data
                    .entry(hr_key)
                    .and_modify(|d| *d = d.clone().merge(data.clone()))
                    .or_insert(data.clone());
            }
        }
        // the numbers go into hours map and are removed from minutes map, so total traffic remain constant
        self.minute_data = recent_minutes;

        let recent_hours = self.hour_data.split_off(&day_ago);
        for (ts, data) in &self.hour_data {
            if *ts >= cutoff {
                let day_key = Timestamp(ts.0 / DAY_US * DAY_US);
                self.day_data
                    .entry(day_key)
                    .and_modify(|d| *d = d.clone().merge(data.clone()))
                    .or_insert(data.clone());
            }
        }
        self.hour_data = recent_hours;

        self.minute_data.retain(|&ts, _| ts >= cutoff);
        self.hour_data.retain(|&ts, _| ts >= cutoff);
        self.day_data.retain(|&ts, _| ts >= cutoff);
    }

    pub fn simplify_if_needed(&mut self) -> bool {
        let total = self.minute_data.len() + self.hour_data.len();
        if total <= SLOT_QUOTA {
            return false;
        }
        self.simplify();
        true
    }

    pub fn query_since(&self, duration_us: u64) -> SlotData {
        let now = Timestamp::now();
        let start = Timestamp(now.0.saturating_sub(duration_us));

        let mut result = SlotData::default();

        for (ts, data) in self.minute_data.iter() {
            if *ts >= start && *ts <= now {
                result = result.merge(data.clone());
            }
        }
        for (ts, data) in self.hour_data.iter() {
            if *ts >= start && *ts <= now {
                result = result.merge(data.clone());
            }
        }
        for (ts, data) in self.day_data.iter() {
            if *ts >= start && *ts <= now {
                result = result.merge(data.clone());
            }
        }

        result
    }

    pub fn past_minute(&self) -> SlotData {
        self.query_since(MINUTE_US)
    }
    pub fn past_hour(&self) -> SlotData {
        self.query_since(HOUR_US)
    }
    pub fn past_day(&self) -> SlotData {
        self.query_since(DAY_US)
    }
    pub fn past_week(&self) -> SlotData {
        self.query_since(WEEK_US)
    }

    pub fn total_bytes_up(&self) -> u128 {
        self.past_week().bytes_up
    }
    pub fn total_bytes_down(&self) -> u128 {
        self.past_week().bytes_down
    }

    pub fn set_expected_udp_default(&mut self, expected: bool) {
        if self.expected_udp.is_none() {
            self.expected_udp = Some(expected);
        }
    }

    pub fn observe_udp_ability(&mut self, ts: Timestamp, udp_ok: bool) {
        if self.udp_ability_ts.map(|cur| ts >= cur).unwrap_or(true) {
            self.udp_ability = Some(udp_ok);
            self.udp_ability_ts = Some(ts);
        }
    }
}

impl CRDT for ProxyStats {
    fn merge(mut self, other: Self) -> Self {
        for (ts, data) in other.minute_data {
            self.minute_data
                .entry(ts)
                .and_modify(|d| *d = d.clone().merge(data.clone()))
                .or_insert(data);
        }
        for (ts, data) in other.hour_data {
            self.hour_data
                .entry(ts)
                .and_modify(|d| *d = d.clone().merge(data.clone()))
                .or_insert(data);
        }
        for (ts, data) in other.day_data {
            self.day_data
                .entry(ts)
                .and_modify(|d| *d = d.clone().merge(data.clone()))
                .or_insert(data);
        }

        if let Some(other_ts) = other.udp_ability_ts {
            if self
                .udp_ability_ts
                .map(|self_ts| other_ts >= self_ts)
                .unwrap_or(true)
            {
                self.udp_ability = other.udp_ability;
                self.udp_ability_ts = Some(other_ts);
            }
        }

        if self.expected_udp.is_none() {
            self.expected_udp = other.expected_udp;
        }

        self
    }
}

impl std::fmt::Display for ProxyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = self.past_hour();
        let lat = h
            .avg_latency_ms()
            .map(|ms| format!("{:.0}ms", ms))
            .unwrap_or_else(|| "-".to_string());
        let succ = h
            .success_rate()
            .map(|p| format!("{:.0}%", p * 100.0))
            .unwrap_or_else(|| "?".to_string());
        write!(f, "ttfb≈{} succ≈{}", lat, succ)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChronoData {
    pub map: BTreeMap<Timestamp, BTreeSet<IpAddr>>,
}

impl ChronoData {
    pub fn record(&mut self, ips: BTreeSet<IpAddr>) {
        self.map.insert(Timestamp::now(), ips);
    }

    pub fn all_ips(&self) -> BTreeSet<IpAddr> {
        self.map.values().flatten().copied().collect()
    }

    pub fn latest(&self) -> Option<&BTreeSet<IpAddr>> {
        self.map.values().next_back()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxystats_tolerates_missing_fields() {
        let old_json = r#"{
            "minute_data": {},
            "hour_data": {},
            "day_data": {}
        }"#;

        let stats: ProxyStats = serde_json::from_str(old_json).unwrap();

        assert_eq!(stats.udp_ability, None);
        assert_eq!(stats.expected_udp, None);
        assert_eq!(stats.udp_ability_ts, None);
        assert!(stats.minute_data.is_empty());
    }

    #[test]
    fn proxystats_merge_prefers_latest_udp_observation() {
        let mut older = ProxyStats::default();
        older.observe_udp_ability(Timestamp(100), true);

        let mut newer = ProxyStats::default();
        newer.observe_udp_ability(Timestamp(200), false);

        let merged = older.merge(newer);
        assert_eq!(merged.udp_ability, Some(false));
        assert_eq!(merged.udp_ability_ts, Some(Timestamp(200)));
    }
}
