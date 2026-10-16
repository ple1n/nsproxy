use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;

use crate::crdt::CRDT;
use crate::routing::ProxyID;

pub const MICROS_PER_SEC: u64 = 1_000_000;
pub const MINUTE_US: u64 = 60 * MICROS_PER_SEC;
pub const HOUR_US: u64 = 3_600 * MICROS_PER_SEC;
pub const DAY_US: u64 = 86_400 * MICROS_PER_SEC;
pub const WEEK_US: u64 = 7 * DAY_US;
const MAX_RETENTION_US: u64 = 4 * WEEK_US;
const SLOT_QUOTA: usize = 256;
const ROUTE_AVERAGE_HALF_LIFE: Duration = Duration::from_secs(30);
const MIN_ROUTE_AVERAGE_WEIGHT: f64 = 0.1;
const ROUTE_RATE_WINDOW: Duration = Duration::from_secs(5);
const ROUTE_RATE_BUCKET: Duration = Duration::from_millis(100);
const MIN_ROUTE_RATE_SPAN: Duration = Duration::from_secs(1);
const MIN_ROUTE_RATE_EVENTS: u64 = 3;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservedRoute {
    NoProxy,
    Proxy(ProxyID),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HostRouteKey {
    pub target: WireAddress,
    pub route: ObservedRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostRouteHost {
    Domain(String),
    Ip(IpAddr),
}

impl HostRouteHost {
    pub fn from_wire_address(target: &WireAddress) -> Self {
        match target {
            WireAddress::SocketAddress(address) => Self::Ip(address.ip()),
            WireAddress::DomainAddress(host, _) => Self::domain(host),
        }
    }

    pub fn domain(host: &str) -> Self {
        Self::Domain(host.trim().trim_end_matches('.').to_ascii_lowercase())
    }

    pub fn display_host(&self) -> String {
        match self {
            Self::Domain(host) => host.clone(),
            Self::Ip(ip) => ip.to_string(),
        }
    }

    pub fn canonicalized(&self) -> Self {
        match self {
            Self::Domain(host) => Self::domain(host),
            Self::Ip(ip) => Self::Ip(*ip),
        }
    }
}

impl HostRouteKey {
    pub fn new(mut target: WireAddress, route: ObservedRoute) -> Self {
        if let WireAddress::DomainAddress(host, _) = &mut target {
            *host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        }
        Self {
            target,
            route,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRouteMetric {
    pub key: HostRouteKey,
    pub observed_at: Timestamp,
    pub last_observed: Option<Timestamp>,
    pub connect_latency_ms: Option<f64>,
    pub connect_success_rate: Option<f64>,
    pub upload_bytes_per_sec: Option<f64>,
    pub download_bytes_per_sec: Option<f64>,
    pub upload_sample: Option<TransferRateSample>,
    pub download_sample: Option<TransferRateSample>,
    pub udp_upload_bytes_per_sec: Option<f64>,
    pub udp_download_bytes_per_sec: Option<f64>,
    pub udp_upload_sample: Option<TransferRateSample>,
    pub udp_download_sample: Option<TransferRateSample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TransferRateSample {
    pub bytes: u128,
    pub duration_micros: u64,
    pub event_count: u64,
    pub observed_at: Timestamp,
}

impl TransferRateSample {
    pub fn bytes_per_sec(self) -> f64 {
        self.bytes as f64 * 1_000_000.0 / self.duration_micros as f64
    }

    pub fn duration_secs(self) -> f64 {
        self.duration_micros as f64 / 1_000_000.0
    }
}

#[derive(Debug, Clone, Copy)]
struct TransferRateBucket {
    id: u128,
    first_at: Duration,
    last_at: Duration,
    bytes: u128,
    events: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TransferRateTracker {
    buckets: VecDeque<TransferRateBucket>,
}

impl TransferRateTracker {
    pub fn record(&mut self, bytes: u128, at: Duration) {
        if bytes == 0
            || self
                .buckets
                .back()
                .is_some_and(|bucket| at < bucket.last_at)
        {
            return;
        }

        let bucket_id = at.as_millis() / ROUTE_RATE_BUCKET.as_millis();
        match self.buckets.back_mut() {
            Some(bucket) if bucket.id == bucket_id => {
                bucket.last_at = at;
                bucket.bytes = bucket.bytes.saturating_add(bytes);
                bucket.events = bucket.events.saturating_add(1);
            }
            _ => self.buckets.push_back(TransferRateBucket {
                id: bucket_id,
                first_at: at,
                last_at: at,
                bytes,
                events: 1,
            }),
        }

        while self
            .buckets
            .front()
            .is_some_and(|bucket| at.saturating_sub(bucket.first_at) > ROUTE_RATE_WINDOW)
        {
            self.buckets.pop_front();
        }
    }

    pub fn sample(&self, observed_at: Timestamp) -> Option<TransferRateSample> {
        let first = self.buckets.front()?;
        let last = self.buckets.back()?;
        let duration = last.last_at.checked_sub(first.first_at)?;
        let event_count = self
            .buckets
            .iter()
            .fold(0u64, |count, bucket| count.saturating_add(bucket.events));
        if duration < MIN_ROUTE_RATE_SPAN || event_count < MIN_ROUTE_RATE_EVENTS {
            return None;
        }

        let bytes = self
            .buckets
            .iter()
            .fold(0u128, |total, bucket| total.saturating_add(bucket.bytes));
        Some(TransferRateSample {
            bytes,
            duration_micros: duration.as_micros().min(u64::MAX as u128) as u64,
            event_count,
            observed_at,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimeDecayedAverage {
    weighted_sum: f64,
    weight: f64,
    updated_at: Option<Timestamp>,
}

impl TimeDecayedAverage {
    pub fn observe(&mut self, value: f64, weight: f64, at: Timestamp) {
        if !value.is_finite() || value < 0.0 || !weight.is_finite() || weight <= 0.0 {
            return;
        }

        if let Some(previous) = self.updated_at {
            if at < previous {
                return;
            }
            let elapsed_secs = at.elapsed_since(previous).as_secs_f64();
            let decay = 0.5_f64.powf(elapsed_secs / ROUTE_AVERAGE_HALF_LIFE.as_secs_f64());
            self.weighted_sum *= decay;
            self.weight *= decay;
        }

        self.weighted_sum += value * weight;
        self.weight += weight;
        self.updated_at = Some(at);
    }

    pub fn estimate(&self, at: Timestamp) -> Option<f64> {
        let updated_at = self.updated_at?;
        if at < updated_at {
            return None;
        }

        let elapsed_secs = at.elapsed_since(updated_at).as_secs_f64();
        let decay = 0.5_f64.powf(elapsed_secs / ROUTE_AVERAGE_HALF_LIFE.as_secs_f64());
        let weight = self.weight * decay;
        (weight >= MIN_ROUTE_AVERAGE_WEIGHT).then(|| self.weighted_sum / self.weight)
    }
}

#[derive(Debug, Clone, Default)]
pub struct HostRouteStats {
    connect_latency_secs: TimeDecayedAverage,
    connect_success_rate: TimeDecayedAverage,
    upload_bytes_per_sec: TimeDecayedAverage,
    download_bytes_per_sec: TimeDecayedAverage,
    upload_sample: Option<TransferRateSample>,
    download_sample: Option<TransferRateSample>,
    udp_upload_bytes_per_sec: TimeDecayedAverage,
    udp_download_bytes_per_sec: TimeDecayedAverage,
    udp_upload_sample: Option<TransferRateSample>,
    udp_download_sample: Option<TransferRateSample>,
    pub last_observed: Option<Timestamp>,
}

impl HostRouteStats {
    pub fn record_tcp_attempt(&mut self, connect_latency: Duration, success: bool, at: Timestamp) {
        self.connect_latency_secs
            .observe(connect_latency.as_secs_f64(), 1.0, at);
        self.connect_success_rate
            .observe(if success { 1.0 } else { 0.0 }, 1.0, at);
        self.last_observed = Some(at);
    }

    pub fn record_tcp_connection(
        &mut self,
        connect_latency: Duration,
        upload_sample: Option<TransferRateSample>,
        download_sample: Option<TransferRateSample>,
        at: Timestamp,
    ) {
        self.record_tcp_attempt(connect_latency, true, at);
        self.record_tcp_transfer_samples(upload_sample, download_sample, at);
    }

    pub fn record_tcp_transfer_samples(
        &mut self,
        upload_sample: Option<TransferRateSample>,
        download_sample: Option<TransferRateSample>,
        at: Timestamp,
    ) {
        if upload_sample.is_some() || download_sample.is_some() {
            self.last_observed = Some(at);
        }

        if let Some(mut sample) = upload_sample {
            sample.observed_at = at;
            self.upload_bytes_per_sec
                .observe(sample.bytes_per_sec(), sample.duration_secs(), at);
            self.upload_sample = Some(sample);
        }
        if let Some(mut sample) = download_sample {
            sample.observed_at = at;
            self.download_bytes_per_sec
                .observe(sample.bytes_per_sec(), sample.duration_secs(), at);
            self.download_sample = Some(sample);
        }
    }

    pub fn record_udp_transfer_samples(
        &mut self,
        upload_sample: Option<TransferRateSample>,
        download_sample: Option<TransferRateSample>,
        at: Timestamp,
    ) {
        if upload_sample.is_some() || download_sample.is_some() {
            self.last_observed = Some(at);
        }

        if let Some(mut sample) = upload_sample {
            sample.observed_at = at;
            self.udp_upload_bytes_per_sec
                .observe(sample.bytes_per_sec(), sample.duration_secs(), at);
            self.udp_upload_sample = Some(sample);
        }
        if let Some(mut sample) = download_sample {
            sample.observed_at = at;
            self.udp_download_bytes_per_sec
                .observe(sample.bytes_per_sec(), sample.duration_secs(), at);
            self.udp_download_sample = Some(sample);
        }
    }

    pub fn connect_latency_ms(&self, at: Timestamp) -> Option<f64> {
        self.connect_latency_secs
            .estimate(at)
            .map(|secs| secs * 1_000.0)
    }

    pub fn connect_success_rate(&self, at: Timestamp) -> Option<f64> {
        self.connect_success_rate.estimate(at)
    }

    pub fn upload_bytes_per_sec(&self, at: Timestamp) -> Option<f64> {
        self.upload_bytes_per_sec.estimate(at)
    }

    pub fn download_bytes_per_sec(&self, at: Timestamp) -> Option<f64> {
        self.download_bytes_per_sec.estimate(at)
    }

    pub fn metric(&self, key: HostRouteKey, at: Timestamp) -> HostRouteMetric {
        HostRouteMetric {
            key,
            observed_at: at,
            last_observed: self.last_observed,
            connect_latency_ms: self.connect_latency_ms(at),
            connect_success_rate: self.connect_success_rate(at),
            upload_bytes_per_sec: self.upload_bytes_per_sec(at),
            download_bytes_per_sec: self.download_bytes_per_sec(at),
            upload_sample: self.upload_sample,
            download_sample: self.download_sample,
            udp_upload_bytes_per_sec: self.udp_upload_bytes_per_sec.estimate(at),
            udp_download_bytes_per_sec: self.udp_download_bytes_per_sec.estimate(at),
            udp_upload_sample: self.udp_upload_sample,
            udp_download_sample: self.udp_download_sample,
        }
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
    fn time_decayed_average_weights_new_samples_and_expires_stale_data() {
        let mut average = TimeDecayedAverage::default();
        average.observe(10.0, 1.0, Timestamp(0));
        average.observe(20.0, 1.0, Timestamp(30 * MICROS_PER_SEC));

        let estimate = average.estimate(Timestamp(30 * MICROS_PER_SEC)).unwrap();
        assert!((estimate - (25.0 / 1.5)).abs() < 0.001);
        assert_eq!(average.estimate(Timestamp(180 * MICROS_PER_SEC)), None);
    }

    #[test]
    fn host_route_host_normalizes_domains_and_ignores_ports() {
        let first = HostRouteHost::from_wire_address(&WireAddress::DomainAddress(
            "Example.COM.".to_string(),
            443,
        ));
        let second = HostRouteHost::from_wire_address(&WireAddress::DomainAddress(
            "example.com".to_string(),
            80,
        ));

        assert_eq!(first, HostRouteHost::Domain("example.com".to_string()));
        assert_eq!(first, second);
    }

    #[test]
    fn host_route_stats_track_latency_and_directional_transfer_rates() {
        let mut upload = TransferRateTracker::default();
        upload.record(500_000, Duration::ZERO);
        upload.record(1, Duration::from_secs(1));
        upload.record(1, Duration::from_secs(2));

        let mut download = TransferRateTracker::default();
        download.record(1_000_000, Duration::ZERO);
        download.record(1, Duration::from_secs(1));
        download.record(999_999, Duration::from_secs(2));

        let mut stats = HostRouteStats::default();
        stats.record_tcp_connection(
            Duration::from_millis(250),
            upload.sample(Timestamp(0)),
            download.sample(Timestamp(0)),
            Timestamp(0),
        );

        assert_eq!(stats.connect_latency_ms(Timestamp(0)), Some(250.0));
        assert_eq!(stats.upload_bytes_per_sec(Timestamp(0)), Some(250_001.0));
        assert!(stats.upload_bytes_per_sec(Timestamp(0)).unwrap() < 1_000_000.0);
        assert_eq!(stats.upload_sample.unwrap().event_count, 3);
        assert_eq!(
            stats.download_bytes_per_sec(Timestamp(0)),
            Some(1_000_000.0)
        );

        stats.record_tcp_attempt(
            Duration::from_secs(1),
            false,
            Timestamp(30 * MICROS_PER_SEC),
        );
        let success_rate = stats
            .connect_success_rate(Timestamp(30 * MICROS_PER_SEC))
            .unwrap();
        assert!((success_rate - 1.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn transfer_rate_uses_data_event_span_and_ignores_trailing_idle() {
        let mut tracker = TransferRateTracker::default();
        for index in 0..10 {
            tracker.record(100, Duration::from_millis(index * 200));
        }

        let sample = tracker.sample(Timestamp(10 * MICROS_PER_SEC)).unwrap();
        assert_eq!(sample.bytes, 1_000);
        assert_eq!(sample.duration_micros, 1_800_000);
        assert_eq!(sample.event_count, 10);
        assert!((sample.bytes_per_sec() - (1_000.0 / 1.8)).abs() < 0.001);
    }

    #[test]
    fn transfer_rate_rejects_short_bursts_and_drops_old_events() {
        let mut burst = TransferRateTracker::default();
        for index in 0..10 {
            burst.record(100, Duration::from_millis(index));
        }
        assert_eq!(burst.sample(Timestamp(0)), None);

        let mut tracker = TransferRateTracker::default();
        tracker.record(1_000_000, Duration::ZERO);
        tracker.record(1, Duration::from_secs(1));
        tracker.record(1_000_000, Duration::from_secs(2));
        tracker.record(1, Duration::from_secs(7));
        tracker.record(1_000_000, Duration::from_millis(7_500));
        tracker.record(1, Duration::from_secs(8));

        let sample = tracker.sample(Timestamp(0)).unwrap();
        assert_eq!(sample.bytes, 1_000_002);
        assert_eq!(sample.duration_micros, 1_000_000);
        assert_eq!(sample.event_count, 3);
    }

    #[test]
    fn host_route_udp_rates_are_separate_from_tcp_rates() {
        let mut tracker = TransferRateTracker::default();
        tracker.record(2_000_000, Duration::ZERO);
        tracker.record(1_000_000, Duration::from_secs(1));
        tracker.record(1_000_000, Duration::from_secs(2));
        let sample = tracker.sample(Timestamp(0));
        let mut stats = HostRouteStats::default();
        stats.record_udp_transfer_samples(sample, sample, Timestamp(0));

        let metric = stats.metric(
            HostRouteKey::new(
                WireAddress::DomainAddress("udp.example".to_string(), 443),
                ObservedRoute::NoProxy,
            ),
            Timestamp(0),
        );
        assert_eq!(metric.udp_upload_bytes_per_sec, Some(2_000_000.0));
        assert_eq!(metric.udp_download_bytes_per_sec, Some(2_000_000.0));
        assert_eq!(metric.upload_bytes_per_sec, None);
        assert_eq!(metric.download_bytes_per_sec, None);
        assert_eq!(metric.udp_upload_sample.unwrap().event_count, 3);
    }

    #[test]
    fn host_route_keys_distinguish_proxies_for_the_same_host() {
        let proxy_a = ProxyID::for_remote("127.0.0.1:1080".parse().unwrap());
        let proxy_b = ProxyID::for_remote("127.0.0.1:1081".parse().unwrap());
        let mut stats = std::collections::HashMap::new();

        stats.insert(
            HostRouteKey::new(
                WireAddress::DomainAddress("Packages.Example.".to_string(), 443),
                ObservedRoute::NoProxy,
            ),
            HostRouteStats::default(),
        );
        stats.insert(
            HostRouteKey::new(
                WireAddress::DomainAddress("packages.example".to_string(), 443),
                ObservedRoute::Proxy(proxy_a),
            ),
            HostRouteStats::default(),
        );
        stats.insert(
            HostRouteKey::new(
                WireAddress::DomainAddress("packages.example".to_string(), 443),
                ObservedRoute::Proxy(proxy_b),
            ),
            HostRouteStats::default(),
        );

        assert_eq!(stats.len(), 3);
        assert!(stats.keys().all(|key| {
            key.target == WireAddress::DomainAddress("packages.example".to_string(), 443)
        }));
        assert_ne!(
            HostRouteKey::new(
                WireAddress::DomainAddress("packages.example".to_string(), 80),
                ObservedRoute::NoProxy,
            ),
            HostRouteKey::new(
                WireAddress::DomainAddress("packages.example".to_string(), 443),
                ObservedRoute::NoProxy,
            )
        );
    }

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
