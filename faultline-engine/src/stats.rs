use std::{
    collections::HashMap,
    io::{self, Write as _},
    time::Instant,
};

use anyhow::Context as _;
use aya::maps::PerCpuArray;
use clap::ValueEnum;
use faultline_common::{DiagnosticStats, RuleStats};
use log::info;
use serde::Serialize;
use tokio::sync::broadcast;

pub(crate) trait Accumulate: Default {
    fn accumulate(self, value: &Self) -> Self;
}

pub(crate) trait CounterDelta {
    fn delta_since(self, previous: Self) -> Self;
}

pub(crate) fn accumulate<T: Accumulate>(values: &[T]) -> T {
    values.iter().fold(T::default(), T::accumulate)
}

impl Accumulate for RuleStats {
    fn accumulate(mut self, value: &Self) -> Self {
        self.matched += value.matched;
        self.dropped += value.dropped;
        self.matched_segments += value.matched_segments;
        self.dropped_segments += value.dropped_segments;
        self.matched_bytes += value.matched_bytes;
        self.dropped_bytes += value.dropped_bytes;
        self.gso_skbs += value.gso_skbs;
        self.duplicated += value.duplicated;
        self.reordered += value.reordered;
        self.delayed += value.delayed;
        self.pacing_dropped += value.pacing_dropped;
        self
    }
}

impl CounterDelta for RuleStats {
    fn delta_since(self, previous: Self) -> Self {
        Self {
            matched: self.matched.saturating_sub(previous.matched),
            dropped: self.dropped.saturating_sub(previous.dropped),
            matched_segments: self
                .matched_segments
                .saturating_sub(previous.matched_segments),
            dropped_segments: self
                .dropped_segments
                .saturating_sub(previous.dropped_segments),
            matched_bytes: self.matched_bytes.saturating_sub(previous.matched_bytes),
            dropped_bytes: self.dropped_bytes.saturating_sub(previous.dropped_bytes),
            gso_skbs: self.gso_skbs.saturating_sub(previous.gso_skbs),
            duplicated: self.duplicated.saturating_sub(previous.duplicated),
            reordered: self.reordered.saturating_sub(previous.reordered),
            delayed: self.delayed.saturating_sub(previous.delayed),
            pacing_dropped: self.pacing_dropped.saturating_sub(previous.pacing_dropped),
        }
    }
}

impl Accumulate for DiagnosticStats {
    fn accumulate(mut self, value: &Self) -> Self {
        self.seen += value.seen;
        self.duplicate_bypass += value.duplicate_bypass;
        self.non_ip += value.non_ip;
        self.malformed += value.malformed;
        self.no_rules += value.no_rules;
        self.destination_miss += value.destination_miss;
        self.source_miss += value.source_miss;
        self.protocol_miss += value.protocol_miss;
        self.fragment_port_miss += value.fragment_port_miss;
        self.port_miss += value.port_miss;
        self.invalid_rule += value.invalid_rule;
        self
    }
}

impl CounterDelta for DiagnosticStats {
    fn delta_since(self, previous: Self) -> Self {
        Self {
            seen: self.seen.saturating_sub(previous.seen),
            duplicate_bypass: self
                .duplicate_bypass
                .saturating_sub(previous.duplicate_bypass),
            non_ip: self.non_ip.saturating_sub(previous.non_ip),
            malformed: self.malformed.saturating_sub(previous.malformed),
            no_rules: self.no_rules.saturating_sub(previous.no_rules),
            destination_miss: self
                .destination_miss
                .saturating_sub(previous.destination_miss),
            source_miss: self.source_miss.saturating_sub(previous.source_miss),
            protocol_miss: self.protocol_miss.saturating_sub(previous.protocol_miss),
            fragment_port_miss: self
                .fragment_port_miss
                .saturating_sub(previous.fragment_port_miss),
            port_miss: self.port_miss.saturating_sub(previous.port_miss),
            invalid_rule: self.invalid_rule.saturating_sub(previous.invalid_rule),
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum StatsFormat {
    /// Human-readable log output.
    Text,
    /// One JSON object per report, suitable for streaming consumers.
    Json,
    /// Length-delimited MessagePack frames written to stdout.
    Msgpack,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub(crate) struct StatsSnapshot {
    pub(crate) rule_id: u32,
    pub(crate) elapsed_ms: u64,
    pub(crate) interval_ms: u64,
    pub(crate) matched: u64,
    pub(crate) dropped: u64,
    pub(crate) matched_segments: u64,
    pub(crate) dropped_segments: u64,
    pub(crate) matched_bytes: u64,
    pub(crate) dropped_bytes: u64,
    pub(crate) gso_skbs: u64,
    pub(crate) duplicated: u64,
    pub(crate) reordered: u64,
    pub(crate) delayed: u64,
    pub(crate) pacing_dropped: u64,
    pub(crate) matched_delta: u64,
    pub(crate) dropped_delta: u64,
    pub(crate) matched_segments_delta: u64,
    pub(crate) dropped_segments_delta: u64,
    pub(crate) matched_bytes_delta: u64,
    pub(crate) dropped_bytes_delta: u64,
    pub(crate) gso_skbs_delta: u64,
    pub(crate) duplicated_delta: u64,
    pub(crate) reordered_delta: u64,
    pub(crate) delayed_delta: u64,
    pub(crate) pacing_dropped_delta: u64,
}

#[derive(Serialize)]
pub(crate) struct StatsEvent {
    #[serde(rename = "type")]
    pub(crate) kind: &'static str,
    #[serde(flatten)]
    pub(crate) snapshot: StatsSnapshot,
    pub(crate) skb_loss_percent: f64,
    pub(crate) segment_loss_percent: f64,
    pub(crate) byte_loss_percent: f64,
    pub(crate) skb_loss_interval_percent: f64,
    pub(crate) segment_loss_interval_percent: f64,
    pub(crate) byte_loss_interval_percent: f64,
    pub(crate) matched_pps: f64,
    pub(crate) dropped_pps: f64,
    pub(crate) wire_mbps: f64,
    pub(crate) dropped_mbps: f64,
    pub(crate) gso_interval_percent: f64,
    pub(crate) duplicated_interval_percent: f64,
    pub(crate) reordered_interval_percent: f64,
    pub(crate) delayed_interval_percent: f64,
    pub(crate) pacing_dropped_interval_percent: f64,
    /// Backwards-compatible alias for skb_loss_percent.
    pub(crate) loss_percent: f64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct DiagnosticEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    elapsed_ms: u64,
    interval_ms: u64,
    seen: u64,
    duplicate_bypass: u64,
    non_ip: u64,
    malformed: u64,
    no_rules: u64,
    destination_miss: u64,
    source_miss: u64,
    protocol_miss: u64,
    fragment_port_miss: u64,
    port_miss: u64,
    invalid_rule: u64,
    seen_delta: u64,
    duplicate_bypass_delta: u64,
    non_ip_delta: u64,
    malformed_delta: u64,
    no_rules_delta: u64,
    destination_miss_delta: u64,
    source_miss_delta: u64,
    protocol_miss_delta: u64,
    fragment_port_miss_delta: u64,
    port_miss_delta: u64,
    invalid_rule_delta: u64,
    seen_pps: f64,
}

impl From<StatsSnapshot> for StatsEvent {
    fn from(snapshot: StatsSnapshot) -> Self {
        Self {
            kind: "stats",
            snapshot,
            skb_loss_percent: snapshot.skb_loss_percent(),
            segment_loss_percent: snapshot.segment_loss_percent(),
            byte_loss_percent: snapshot.byte_loss_percent(),
            skb_loss_interval_percent: snapshot.skb_loss_interval_percent(),
            segment_loss_interval_percent: snapshot.segment_loss_interval_percent(),
            byte_loss_interval_percent: snapshot.byte_loss_interval_percent(),
            matched_pps: snapshot.per_second(snapshot.matched_delta),
            dropped_pps: snapshot.per_second(snapshot.dropped_delta),
            wire_mbps: snapshot.mbps(snapshot.matched_bytes_delta),
            dropped_mbps: snapshot.mbps(snapshot.dropped_bytes_delta),
            gso_interval_percent: StatsSnapshot::percent(
                snapshot.gso_skbs_delta,
                snapshot.matched_delta,
            ),
            duplicated_interval_percent: StatsSnapshot::percent(
                snapshot.duplicated_delta,
                snapshot.matched_delta,
            ),
            reordered_interval_percent: StatsSnapshot::percent(
                snapshot.reordered_delta,
                snapshot.matched_delta,
            ),
            delayed_interval_percent: StatsSnapshot::percent(
                snapshot.delayed_delta,
                snapshot.matched_delta,
            ),
            pacing_dropped_interval_percent: StatsSnapshot::percent(
                snapshot.pacing_dropped_delta,
                snapshot.matched_delta,
            ),
            loss_percent: snapshot.loss_percent(),
        }
    }
}

impl StatsSnapshot {
    pub(crate) fn loss_percent(self) -> f64 {
        self.skb_loss_percent()
    }

    pub(crate) fn skb_loss_percent(self) -> f64 {
        Self::percent(self.dropped, self.matched)
    }

    pub(crate) fn segment_loss_percent(self) -> f64 {
        Self::percent(self.dropped_segments, self.matched_segments)
    }

    pub(crate) fn byte_loss_percent(self) -> f64 {
        Self::percent(self.dropped_bytes, self.matched_bytes)
    }

    pub(crate) fn skb_loss_interval_percent(self) -> f64 {
        Self::percent(self.dropped_delta, self.matched_delta)
    }

    pub(crate) fn segment_loss_interval_percent(self) -> f64 {
        Self::percent(self.dropped_segments_delta, self.matched_segments_delta)
    }

    pub(crate) fn byte_loss_interval_percent(self) -> f64 {
        Self::percent(self.dropped_bytes_delta, self.matched_bytes_delta)
    }

    pub(crate) fn per_second(self, value: u64) -> f64 {
        if self.interval_ms == 0 {
            0.0
        } else {
            value as f64 * 1_000.0 / self.interval_ms as f64
        }
    }

    pub(crate) fn mbps(self, bytes: u64) -> f64 {
        self.per_second(bytes) * 8.0 / 1_000_000.0
    }

    pub(crate) fn percent(part: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            part as f64 * 100.0 / total as f64
        }
    }
}

pub(crate) struct StatsReporter {
    pub(crate) format: StatsFormat,
    pub(crate) started: Instant,
    pub(crate) previous: HashMap<u32, Previous<RuleStats>>,
    pub(crate) previous_diagnostics: Previous<DiagnosticStats>,
    pub(crate) events: Option<broadcast::Sender<String>>,
}

#[derive(Default)]
pub(crate) struct Previous<T> {
    pub(crate) total: T,
    pub(crate) elapsed_ms: u64,
}

impl StatsReporter {
    pub(crate) fn new(format: StatsFormat) -> Self {
        Self {
            format,
            started: Instant::now(),
            previous: HashMap::new(),
            previous_diagnostics: Previous::default(),
            events: None,
        }
    }

    pub(crate) fn publish_to(&mut self, events: broadcast::Sender<String>) {
        self.events = Some(events);
    }

    pub(crate) fn snapshot(&mut self, rule_id: u32, total: RuleStats) -> StatsSnapshot {
        let elapsed_ms = self.elapsed_ms();
        let previous = self.previous.entry(rule_id).or_default();
        let delta = total.delta_since(previous.total);
        let snapshot = StatsSnapshot {
            rule_id,
            elapsed_ms,
            interval_ms: elapsed_ms.saturating_sub(previous.elapsed_ms),
            matched: total.matched,
            dropped: total.dropped,
            matched_segments: total.matched_segments,
            dropped_segments: total.dropped_segments,
            matched_bytes: total.matched_bytes,
            dropped_bytes: total.dropped_bytes,
            gso_skbs: total.gso_skbs,
            duplicated: total.duplicated,
            reordered: total.reordered,
            delayed: total.delayed,
            pacing_dropped: total.pacing_dropped,
            matched_delta: delta.matched,
            dropped_delta: delta.dropped,
            matched_segments_delta: delta.matched_segments,
            dropped_segments_delta: delta.dropped_segments,
            matched_bytes_delta: delta.matched_bytes,
            dropped_bytes_delta: delta.dropped_bytes,
            gso_skbs_delta: delta.gso_skbs,
            duplicated_delta: delta.duplicated,
            reordered_delta: delta.reordered,
            delayed_delta: delta.delayed,
            pacing_dropped_delta: delta.pacing_dropped,
        };
        *previous = Previous { total, elapsed_ms };
        snapshot
    }

    fn emit(&self, snapshot: StatsSnapshot) -> anyhow::Result<()> {
        let event = StatsEvent::from(snapshot);
        self.emit_value(&event, || {
            info!(
                "rule_id={} matched={} dropped={} matched_segments={} dropped_segments={} matched_bytes={} dropped_bytes={} gso_skbs={} duplicated={} reordered={} delayed={} pacing_dropped={} matched_delta={} dropped_delta={} matched_segments_delta={} dropped_segments_delta={} matched_bytes_delta={} dropped_bytes_delta={} gso_skbs_delta={} duplicated_delta={} reordered_delta={} delayed_delta={} pacing_dropped_delta={} skb_loss={:.2}% segment_loss={:.2}% byte_loss={:.2}% interval_loss={:.2}% matched_pps={:.2} wire_mbps={:.3} interval_ms={} elapsed_ms={}",
                snapshot.rule_id,
                snapshot.matched,
                snapshot.dropped,
                snapshot.matched_segments,
                snapshot.dropped_segments,
                snapshot.matched_bytes,
                snapshot.dropped_bytes,
                snapshot.gso_skbs,
                snapshot.duplicated,
                snapshot.reordered,
                snapshot.delayed,
                snapshot.pacing_dropped,
                snapshot.matched_delta,
                snapshot.dropped_delta,
                snapshot.matched_segments_delta,
                snapshot.dropped_segments_delta,
                snapshot.matched_bytes_delta,
                snapshot.dropped_bytes_delta,
                snapshot.gso_skbs_delta,
                snapshot.duplicated_delta,
                snapshot.reordered_delta,
                snapshot.delayed_delta,
                snapshot.pacing_dropped_delta,
                snapshot.skb_loss_percent(),
                snapshot.segment_loss_percent(),
                snapshot.byte_loss_percent(),
                snapshot.skb_loss_interval_percent(),
                snapshot.per_second(snapshot.matched_delta),
                snapshot.mbps(snapshot.matched_bytes_delta),
                snapshot.interval_ms,
                snapshot.elapsed_ms
            )
        })
    }

    fn emit_diagnostics(&mut self, total: DiagnosticStats) -> anyhow::Result<()> {
        let elapsed_ms = self.elapsed_ms();
        let interval_ms = elapsed_ms.saturating_sub(self.previous_diagnostics.elapsed_ms);
        let previous = self.previous_diagnostics.total;
        let delta = total.delta_since(previous);
        let event = DiagnosticEvent {
            kind: "diagnostics",
            elapsed_ms,
            interval_ms,
            seen: total.seen,
            duplicate_bypass: total.duplicate_bypass,
            non_ip: total.non_ip,
            malformed: total.malformed,
            no_rules: total.no_rules,
            destination_miss: total.destination_miss,
            source_miss: total.source_miss,
            protocol_miss: total.protocol_miss,
            fragment_port_miss: total.fragment_port_miss,
            port_miss: total.port_miss,
            invalid_rule: total.invalid_rule,
            seen_delta: delta.seen,
            duplicate_bypass_delta: delta.duplicate_bypass,
            non_ip_delta: delta.non_ip,
            malformed_delta: delta.malformed,
            no_rules_delta: delta.no_rules,
            destination_miss_delta: delta.destination_miss,
            source_miss_delta: delta.source_miss,
            protocol_miss_delta: delta.protocol_miss,
            fragment_port_miss_delta: delta.fragment_port_miss,
            port_miss_delta: delta.port_miss,
            invalid_rule_delta: delta.invalid_rule,
            seen_pps: if interval_ms == 0 {
                0.0
            } else {
                delta.seen as f64 * 1_000.0 / interval_ms as f64
            },
        };
        self.previous_diagnostics = Previous { total, elapsed_ms };
        self.emit_value(&event, || {
            info!(
                "diagnostics seen={} malformed={} non_ip={} destination_miss={} source_miss={} protocol_miss={} port_miss={} fragment_port_miss={} invalid_rule={} seen_delta={} seen_pps={:.2}",
                event.seen,
                event.malformed,
                event.non_ip,
                event.destination_miss,
                event.source_miss,
                event.protocol_miss,
                event.port_miss,
                event.fragment_port_miss,
                event.invalid_rule,
                event.seen_delta,
                event.seen_pps,
            )
        })
    }

    fn emit_value(&self, value: &impl Serialize, emit_text: impl FnOnce()) -> anyhow::Result<()> {
        match self.format {
            StatsFormat::Text => emit_text(),
            StatsFormat::Json => println!("{}", serde_json::to_string(value)?),
            StatsFormat::Msgpack => {
                let frame = encode_msgpack_value(value)?;
                let mut stdout = io::stdout().lock();
                stdout.write_all(&frame)?;
                stdout.flush()?;
            }
        }
        if let Some(events) = &self.events {
            let _ = events.send(serde_json::to_string(value)?);
        }
        Ok(())
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

#[cfg(test)]
pub(crate) fn encode_msgpack(snapshot: StatsSnapshot) -> anyhow::Result<Vec<u8>> {
    encode_msgpack_value(&StatsEvent::from(snapshot))
}

fn encode_msgpack_value(value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let payload = rmp_serde::to_vec_named(value)?;
    let length = u32::try_from(payload.len()).context("stats MessagePack frame is too large")?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(crate) fn report_stats(
    stats: &PerCpuArray<aya::maps::MapData, RuleStats>,
    diagnostics: &PerCpuArray<aya::maps::MapData, DiagnosticStats>,
    rule_ids: &[u32],
    reporter: &mut StatsReporter,
) -> anyhow::Result<()> {
    let diagnostic_total = accumulate(&diagnostics.get(&0, 0)?);
    reporter.emit_diagnostics(diagnostic_total)?;
    rule_ids.iter().try_for_each(|&rule_id| {
        let total = accumulate(&stats.get(&rule_id, 0)?);
        let snapshot = reporter.snapshot(rule_id, total);
        reporter.emit(snapshot)
    })
}
