//! Brutal congestion control implementation for QUIC.
//!
//! Ported from [brutal_quinn](https://github.com/hrimfaxi/brutal_quinn) by hrimfaxi,
//! as used in [shadowquic#109](https://github.com/spongebob888/shadowquic/pull/109).
//!
//! Brutal is a bandwidth-hint-driven congestion controller that derives its
//! congestion window from an estimated bandwidth-delay product (BDP) rather
//! than using traditional additive-increase/multiplicative-decrease behavior.
//! This makes it particularly effective in high-loss network environments.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use log::trace;

const SLOT_COUNT: usize = 5;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Brutal congestion controller.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// Default target bandwidth in bits per second.
    pub default_bandwidth_bps: u64,
    /// Initial RTT estimate used before enough RTT samples are available.
    pub initial_rtt: Duration,
    /// Minimum congestion window in bytes.
    pub min_window: u64,
    /// Multiplier applied to BDP when calculating cwnd.
    pub cwnd_gain: f64,
    /// Minimum ACK rate clamp (only when ack_compensate is true).
    pub min_ack_rate: f64,
    /// Minimum sample count before ACK-rate estimation becomes active.
    pub min_sample_count: u64,
    /// Whether to compensate cwnd by dividing by ack_rate.
    pub enable_ack_rate_compensation: bool,
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            default_bandwidth_bps: 1_000_000, // 1 Mbps
            initial_rtt: Duration::from_millis(100),
            min_window: 16 * 1024, // 16 KB
            cwnd_gain: 1.25,
            min_ack_rate: 0.8,
            min_sample_count: 50,
            enable_ack_rate_compensation: false,
        }
    }
}

impl BrutalConfig {
    pub fn new(bandwidth_bps: u64) -> Self {
        Self {
            default_bandwidth_bps: bandwidth_bps,
            ..Default::default()
        }
    }

    pub fn with_cwnd_gain(mut self, gain: f64) -> Self {
        self.cwnd_gain = gain;
        self
    }

    pub fn with_ack_compensate(mut self, enabled: bool) -> Self {
        self.enable_ack_rate_compensation = enabled;
        self
    }

    pub fn with_min_window(mut self, bytes: u64) -> Self {
        self.min_window = bytes;
        self
    }
}

// ---------------------------------------------------------------------------
// Controller implementation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct PktInfoSlot {
    timestamp_sec: u64,
    ack_count: u64,
    loss_count: u64,
}

/// A bandwidth-hint-based congestion controller using a BDP-style window model.
#[derive(Clone)]
pub struct BrutalController {
    config: Arc<BrutalConfig>,
    base_time: Instant,

    mtu: u64,
    bytes_in_flight: u64,

    smoothed_rtt: Option<Duration>,
    bandwidth_hint_bps: Option<u64>,

    ack_rate: f64,
    slots: [PktInfoSlot; SLOT_COUNT],
    acked_packets_in_batch: u64,
    lost_packets_in_batch: u64,

    cwnd: u64,
}

impl BrutalController {
    pub fn new(config: Arc<BrutalConfig>, now: Instant, current_mtu: u16) -> Self {
        let mtu = current_mtu as u64;
        let mut me = Self {
            config,
            base_time: now,
            mtu,
            bytes_in_flight: 0,
            smoothed_rtt: None,
            bandwidth_hint_bps: None,
            ack_rate: 1.0,
            slots: [PktInfoSlot::default(); SLOT_COUNT],
            acked_packets_in_batch: 0,
            lost_packets_in_batch: 0,
            cwnd: 0,
        };
        me.cwnd = me.compute_cwnd();
        me
    }

    fn target_bps(&self) -> u64 {
        self.bandwidth_hint_bps
            .unwrap_or(self.config.default_bandwidth_bps)
    }

    fn current_rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.config.initial_rtt)
    }

    fn effective_ack_rate(&self) -> f64 {
        if self.config.enable_ack_rate_compensation {
            self.ack_rate.max(self.config.min_ack_rate)
        } else {
            1.0
        }
    }

    fn estimate_packets(&self, bytes: u64) -> u64 {
        if bytes == 0 {
            return 0;
        }
        let mtu = self.mtu.max(1);
        bytes.div_ceil(mtu)
    }

    fn now_sec(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.base_time).as_secs()
    }

    fn compute_cwnd(&self) -> u64 {
        let bps = self.target_bps() as f64;
        let rtt = self.current_rtt().as_secs_f64();
        let ack_rate = self.effective_ack_rate();

        let cwnd = (bps * rtt * self.config.cwnd_gain / ack_rate / 8.0) as u64;
        cwnd.max(self.config.min_window).max(self.mtu)
    }

    fn update_ack_rate(&mut self, now: Instant) {
        let ts = self.now_sec(now);
        let idx = (ts % SLOT_COUNT as u64) as usize;

        if self.slots[idx].timestamp_sec == ts {
            self.slots[idx].ack_count += self.acked_packets_in_batch;
            self.slots[idx].loss_count += self.lost_packets_in_batch;
        } else {
            self.slots[idx] = PktInfoSlot {
                timestamp_sec: ts,
                ack_count: self.acked_packets_in_batch,
                loss_count: self.lost_packets_in_batch,
            };
        }

        let min_ts = ts.saturating_sub(SLOT_COUNT as u64);

        let mut ack = 0u64;
        let mut loss = 0u64;
        for slot in &self.slots {
            if slot.timestamp_sec >= min_ts {
                ack += slot.ack_count;
                loss += slot.loss_count;
            }
        }

        let total = ack + loss;
        if total < self.config.min_sample_count {
            self.ack_rate = 1.0;
        } else {
            self.ack_rate = ack as f64 / total as f64;
        }
    }

    fn refresh_cwnd(&mut self) {
        self.cwnd = self.compute_cwnd();
    }

    fn update_smoothed_rtt(&mut self, rtt: Duration) {
        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(rtt);
            }
            Some(srtt) => {
                // SRTT = (7/8 * SRTT) + (1/8 * Sample)
                let srtt_ns = srtt.as_nanos() as f64;
                let sample_ns = rtt.as_nanos() as f64;
                let new_srtt_ns = (0.875 * srtt_ns) + (0.125 * sample_ns);
                self.smoothed_rtt = Some(Duration::from_nanos(new_srtt_ns as u64));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// quinn::congestion::ControllerFactory
// ---------------------------------------------------------------------------

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self, now, current_mtu))
    }
}

// ---------------------------------------------------------------------------
// quinn::congestion::Controller
// ---------------------------------------------------------------------------

impl Controller for BrutalController {
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.compute_cwnd()
    }

    fn window(&self) -> u64 {
        self.cwnd
    }

    fn on_sent(&mut self, _now: Instant, bytes: u64, _last_packet_number: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.acked_packets_in_batch += self.estimate_packets(bytes);

        // Use RTT estimate from Quinn's estimator
        self.update_smoothed_rtt(rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.update_ack_rate(now);
        self.refresh_cwnd();

        trace!(
            "[brutal] end_acks: target_bps={}, rtt_ms={}, ack_rate={:.3}, effective_ack_rate={:.3}, cwnd_gain={}, cwnd={}, in_flight={}, acked_pkts_batch={}, lost_pkts_batch={}, ack_comp={}",
            self.target_bps(),
            self.current_rtt().as_millis(),
            self.ack_rate,
            self.effective_ack_rate(),
            self.config.cwnd_gain,
            self.cwnd,
            self.bytes_in_flight,
            self.acked_packets_in_batch,
            self.lost_packets_in_batch,
            self.config.enable_ack_rate_compensation,
        );

        self.acked_packets_in_batch = 0;
        self.lost_packets_in_batch = 0;
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Brutal does NOT reduce cwnd on loss - this is its key design:
        // it keeps the BDP-based window regardless of packet loss.
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        if lost_bytes > 0 {
            self.lost_packets_in_batch += self.estimate_packets(lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
        self.refresh_cwnd();

        trace!("[brutal] mtu updated: mtu={}, cwnd={}", self.mtu, self.cwnd);
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics::default()
    }
}

// ---------------------------------------------------------------------------
// Bandwidth parser for human-readable format (e.g., "100m", "1.5g")
// ---------------------------------------------------------------------------

/// Parse a human-readable bandwidth string into bits per second.
///
/// Supported suffixes:
/// - `K` / `k` → kbps (×1024)
/// - `M` / `m` → Mbps (×1024²)
/// - `G` / `g` → Gbps (×1024³)
///
/// Examples: `"100m"`, `"1.5g"`, `"30k"`, `"1000000"` (raw bps)
pub fn parse_bandwidth_bps(input: &str) -> Result<u64, String> {
    let s = input.trim();

    if s.is_empty() {
        return Err("empty bandwidth string".to_string());
    }

    let (num_str, multiplier) = match s.as_bytes().last().copied() {
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1024f64),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1024f64 * 1024f64),
        Some(b'G') | Some(b'g') => (&s[..s.len() - 1], 1024f64 * 1024f64 * 1024f64),
        Some(b'0'..=b'9') => (s, 1f64),
        _ => {
            return Err(format!("invalid bandwidth suffix in: {input}"));
        }
    };

    let num: f64 = num_str
        .parse()
        .map_err(|e| format!("invalid bandwidth number \"{num_str}\": {e}"))?;

    if num <= 0.0 {
        return Err(format!("bandwidth must be positive, got {num}"));
    }

    let bps = num * multiplier;
    Ok(bps as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth_bps("100m").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_bandwidth_bps("1.5g").unwrap(), (1.5 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_bandwidth_bps("30k").unwrap(), 30 * 1024);
        assert_eq!(parse_bandwidth_bps("1000000").unwrap(), 1_000_000);
        assert_eq!(parse_bandwidth_bps("512K").unwrap(), 512 * 1024);
        assert!(parse_bandwidth_bps("").is_err());
        assert!(parse_bandwidth_bps("abc").is_err());
        assert!(parse_bandwidth_bps("-1m").is_err());
        assert!(parse_bandwidth_bps("0m").is_err());
    }

    #[test]
    fn test_brutal_config_default() {
        let config = BrutalConfig::default();
        assert_eq!(config.default_bandwidth_bps, 1_000_000);
        assert_eq!(config.min_window, 16 * 1024);
        assert!((config.cwnd_gain - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_brutal_config_builder() {
        let config = BrutalConfig::new(100_000_000) // 100 Mbps
            .with_cwnd_gain(1.5)
            .with_ack_compensate(true)
            .with_min_window(32 * 1024);

        assert_eq!(config.default_bandwidth_bps, 100_000_000);
        assert!((config.cwnd_gain - 1.5).abs() < f64::EPSILON);
        assert!(config.enable_ack_rate_compensation);
        assert_eq!(config.min_window, 32 * 1024);
    }

    #[test]
    fn test_brutal_controller_basic() {
        let config = Arc::new(BrutalConfig::new(100 * 1024 * 1024)); // 100 Mbps
        let now = Instant::now();
        let ctrl = BrutalController::new(config, now, 1200);

        let initial = ctrl.initial_window();
        assert!(initial > 0);

        let window = ctrl.window();
        assert!(window > 0);
        assert_eq!(window, initial);
    }

    #[test]
    fn test_brutal_controller_factory() {
        let config = Arc::new(BrutalConfig::new(50 * 1024 * 1024)); // 50 Mbps
        let now = Instant::now();
        let mut ctrl = config.clone().build(now, 1200);

        ctrl.on_sent(now, 1000, 1);
        // Note: on_ack requires &RttEstimator which has no public constructor,
        // so we test the factory creation and on_sent/on_congestion_event instead
        ctrl.on_congestion_event(now, now, false, 500);

        let window = ctrl.window();
        assert!(window > 0);
        // Brutal should NOT reduce cwnd on congestion event
        assert_eq!(window, ctrl.initial_window());
    }

    #[test]
    fn test_brutal_no_cwnd_reduction_on_loss() {
        let config = Arc::new(BrutalConfig::new(100 * 1024 * 1024)); // 100 Mbps
        let now = Instant::now();
        let mut ctrl = BrutalController::new(config, now, 1200);

        let initial_cwnd = ctrl.cwnd;
        ctrl.on_sent(now, 10000, 1);
        ctrl.on_congestion_event(now, now, false, 10000);

        // Brutal should NOT reduce cwnd on loss
        assert_eq!(ctrl.cwnd, initial_cwnd);
        assert_eq!(ctrl.bytes_in_flight, 0);
    }

    #[test]
    fn test_brutal_ack_compensate() {
        let config = Arc::new(BrutalConfig::new(100 * 1024 * 1024)) // 100 Mbps
            .with_ack_compensate(true)
            .with_cwnd_gain(1.25);
        let now = Instant::now();
        let ctrl = BrutalController::new(config, now, 1200);

        // With ack compensate enabled, effective_ack_rate should use min_ack_rate (0.8)
        // which means cwnd should be larger than without compensation
        let cwnd = ctrl.cwnd;
        assert!(cwnd > 0);

        // Verify cwnd calculation: bps * rtt * gain / ack_rate / 8
        // 100Mbps * 0.1s * 1.25 / 0.8 / 8 = 1,953,125 bytes
        let expected = (100_000_000.0 * 0.1 * 1.25 / 0.8 / 8.0) as u64;
        assert_eq!(cwnd, expected);
    }
}
