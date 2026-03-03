use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    ops::RangeInclusive,
    time::{SystemTime, UNIX_EPOCH},
};

use rangemap::RangeInclusiveMap;
use serde::{Deserialize, Serialize};

use crate::crdt::CRDT;

const MICROS_PER_SEC: u64 = 1_000_000;
const LEVEL_US: [u64; 4] = [
    60 * MICROS_PER_SEC,
    3_600 * MICROS_PER_SEC,
    86_400 * MICROS_PER_SEC,
    7 * 86_400 * MICROS_PER_SEC,
];
const MAX_RETENTION_US: u64 = 4 * LEVEL_US[3];
const SLOT_QUOTA: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
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
    pub attempts: f32,
    pub successes: f32,
    pub bytes_up: f32,
    pub bytes_down: f32,
    pub latency_sum_ms: f32,
    pub latency_count: f32,
}

impl SlotData {
    pub fn success_rate(&self) -> Option<f64> {
        (self.attempts > 0.).then(|| self.successes as f64 / self.attempts as f64)
    }

    pub fn avg_latency_ms(&self) -> Option<f64> {
        (self.latency_count > 0.).then(|| self.latency_sum_ms as f64 / self.latency_count as f64)
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

fn bucket_floor(ts: Timestamp, now: Timestamp) -> (Timestamp, u64) {
    let age = now.0.saturating_sub(ts.0);
    let bucket_us = match age {
        a if a < LEVEL_US[0] => 1,
        a if a < LEVEL_US[1] => LEVEL_US[0],
        a if a < LEVEL_US[2] => LEVEL_US[1],
        a if a < LEVEL_US[3] => LEVEL_US[2],
        _ => LEVEL_US[3],
    };
    (Timestamp(ts.0 / bucket_us * bucket_us), bucket_us)
}

fn slots_similar(a: &SlotData, a_us: u64, b: &SlotData, b_us: u64, tol: f64) -> bool {
    if *a == SlotData::default() && *b == SlotData::default() {
        return true;
    }
    let (da, db) = (a_us.max(1) as f64, b_us.max(1) as f64);
    for (ra, rb) in [
        (a.attempts as f64 / da, b.attempts as f64 / db),
        (a.successes as f64 / da, b.successes as f64 / db),
        (a.bytes_up as f64 / da, b.bytes_up as f64 / db),
        (a.bytes_down as f64 / da, b.bytes_down as f64 / db),
        (a.latency_sum_ms as f64 / da, b.latency_sum_ms as f64 / db),
        (a.latency_count as f64 / da, b.latency_count as f64 / db),
    ] {
        let mx = ra.max(rb);
        if mx > 1e-12 && (ra - rb).abs() / mx > tol {
            return false;
        }
    }
    true
}

// there are problems in the merging of data. calc is wrong.

fn map_insert_merge(
    map: &mut RangeInclusiveMap<Timestamp, SlotData>,
    range: RangeInclusive<Timestamp>,
    data: SlotData,
) {
    let overlapping: Vec<(RangeInclusive<Timestamp>, SlotData)> = map
        .overlapping(&range)
        .map(|(r, d)| (r.clone(), d.clone()))
        .collect();
    for (r, _) in &overlapping {
        map.remove(r.clone());
    }
    let start = overlapping
        .iter()
        .map(|(r, _)| *r.start())
        .chain(std::iter::once(*range.start()))
        .min()
        .unwrap();
    let end = overlapping
        .iter()
        .map(|(r, _)| *r.end())
        .chain(std::iter::once(*range.end()))
        .max()
        .unwrap();
    let merged = overlapping
        .into_iter()
        .map(|(_, d)| d)
        .fold(data, |acc, d| acc.merge(d));
    map.insert(start..=end, merged);
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStats {
    /// No two ranges should overlap, to avoid repeated data.
    pub data: RangeInclusiveMap<Timestamp, SlotData>,
}

impl ProxyStats {
    pub fn record(&mut self, ts: Timestamp, slot: SlotData) {
        let merged = match self.data.get(&ts) {
            Some(existing) => existing.clone().merge(slot),
            None => slot,
        };
        self.data.insert(ts..=ts, merged);
    }

    pub fn record_traffic(&mut self, bytes_up: f32, bytes_down: f32) {
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
                attempts: 1.,
                successes: if success { 1. } else { 0. },
                ..Default::default()
            },
        );
    }

    pub fn record_latency_ms(&mut self, ms: u64) {
        self.record(
            Timestamp::now(),
            SlotData {
                latency_sum_ms: ms as f32,
                latency_count: 1.,
                ..Default::default()
            },
        );
    }

    pub fn simplify(&mut self) {
        let now = Timestamp::now();
        let cutoff = Timestamp(now.0.saturating_sub(MAX_RETENTION_US));

        let mut buckets: BTreeMap<Timestamp, (SlotData, u64)> = BTreeMap::new();
        for (range, data) in self.data.iter() {
            if *range.end() < cutoff {
                continue;
            }
            let (floor, size) = bucket_floor(*range.start(), now);
            let e = buckets
                .entry(floor)
                .or_insert_with(|| (SlotData::default(), size));
            e.0 = std::mem::take(&mut e.0).merge(data.clone());
        }

        let n = buckets.len();
        let pressure = if n > SLOT_QUOTA {
            (n as f64 / SLOT_QUOTA as f64).ln().max(0.0)
        } else {
            0.0
        };
        let tol = 0.25 + pressure;

        self.data = RangeInclusiveMap::new();
        let mut it = buckets.into_iter();
        let Some((mut cs, (mut cd, csz))) = it.next() else {
            return;
        };
        let mut ce = Timestamp(cs.0 + csz.saturating_sub(1));
        for (floor, (data, size)) in it {
            let ne = Timestamp(floor.0 + size.saturating_sub(1));
            if slots_similar(&cd, ce.0 - cs.0 + 1, &data, ne.0 - floor.0 + 1, tol) {
                ce = ne;
                cd = cd.merge(data);
            } else {
                self.data.insert(cs..=ce, cd);
                cs = floor;
                ce = ne;
                cd = data;
            }
        }
        self.data.insert(cs..=ce, cd);
    }

    pub fn simplify_if_needed(&mut self) -> bool {
        if self.data.len() <= SLOT_QUOTA {
            return false;
        }
        self.simplify();
        true
    }

    pub fn query(&self, duration_us: u64) -> SlotData {
        let now = Timestamp::now();
        let start = Timestamp(now.0.saturating_sub(duration_us));
        self.data
            .overlapping(&(start..=now))
            .map(|(_, d)| d)
            .cloned()
            .fold(SlotData::default(), SlotData::merge)
    }

    pub fn past_minute(&self) -> SlotData {
        self.query(LEVEL_US[0])
    }
    pub fn past_hour(&self) -> SlotData {
        self.query(LEVEL_US[1])
    }
    pub fn past_day(&self) -> SlotData {
        self.query(LEVEL_US[2])
    }
    pub fn past_week(&self) -> SlotData {
        self.query(LEVEL_US[3])
    }

    pub fn total_bytes_up(&self) -> f32 {
        self.past_week().bytes_up
    }
    pub fn total_bytes_down(&self) -> f32 {
        self.past_week().bytes_down
    }
}

impl CRDT for ProxyStats {
    fn merge(mut self, other: Self) -> Self {
        for (range, data) in other.data.iter() {
            map_insert_merge(&mut self.data, range.clone(), data.clone());
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
